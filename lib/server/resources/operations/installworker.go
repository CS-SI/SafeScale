/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package operations

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	txttmpl "text/template"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/securitygroupruledirection"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/app"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

const (
	yamlPaceKeyword    = "pace"
	yamlStepsKeyword   = "steps"
	yamlTargetsKeyword = "targets"
	yamlRunKeyword     = "run"
	yamlPackageKeyword = "package"
	// yamlOptionsKeyword = "options"
	yamlTimeoutKeyword = "timeout"
	yamlSerialKeyword  = "serialized"
)

const (
	featureScriptTemplateContent = `#!/bin/bash -x

set -u -o pipefail

print_error() {
    read line file <<<$(caller)
    echo "An error occurred in line $line of file $file:" "{"` + "`" + `sed "${line}q;d" "$file"` + "`" + `"}" >&2
}
trap print_error ERR

# Redirects outputs
LOGFILE=%s/feature.{{.reserved_Name}}.{{.reserved_Action}}_{{.reserved_Step}}.log

### All output to one file and all output to the screen
exec > >(tee -a ${LOGFILE} /opt/safescale/var/log/ss.log) 2>&1
set -x

date

{{ .reserved_BashLibrary }}

{{ .reserved_Content }}
`
)

// var featureScriptTemplate *template.Template
var featureScriptTemplate atomic.Value

type alterCommandCB func(string) string

type worker struct {
	service   iaas.Service
	feature   *Feature
	target    resources.Targetable
	method    installmethod.Enum
	action    installaction.Enum
	variables data.Map
	settings  resources.FeatureSettings
	startTime time.Time

	host    *Host
	cluster *Cluster

	availableMaster  resources.Host
	availableNode    resources.Host
	availableGateway resources.Host

	allMasters  []resources.Host
	allNodes    []resources.Host
	allGateways []resources.Host

	concernedMasters  []resources.Host
	concernedNodes    []resources.Host
	concernedGateways []resources.Host

	rootKey string
	// function to alter the content of 'run' key of specification file
	commandCB alterCommandCB
}

// newWorker ...
// alterCmdCB is used to change the content of keys 'run' or 'package' before executing
// the requested action. If not used, must be nil
func newWorker(ctx context.Context, f resources.Feature, target resources.Targetable, method installmethod.Enum, action installaction.Enum, cb alterCommandCB) (*worker, fail.Error) {
	w := worker{
		feature:   f.(*Feature),
		target:    target,
		method:    method,
		action:    action,
		commandCB: cb,
	}
	switch target.TargetType() {
	case featuretargettype.Cluster:
		var ok bool
		w.cluster, ok = target.(*Cluster)
		if !ok {
			return nil, fail.InconsistentError("target should be a *Cluster")
		}
		w.service = w.cluster.Service()
	case featuretargettype.Host:
		var ok bool
		w.host, ok = target.(*Host)
		if !ok {
			return nil, fail.InconsistentError("target should be a *Host")
		}
		w.service = w.host.Service()
	default:
		return nil, fail.InconsistentError("target should be either a *Cluster or a *Host, it's not: %v", target.TargetType())
	}

	if method != installmethod.None {
		w.rootKey = "feature.install." + strings.ToLower(method.String()) + "." + strings.ToLower(action.String())
		if !f.(*Feature).Specs().IsSet(w.rootKey) {
			msg := `syntax error in Feature '%s' specification file (%s):
				no key '%s' found`
			return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename(ctx), w.rootKey)
		}
	}

	return &w, nil
}

// ConcernsCluster returns true if the target of the worker is a cluster
func (w *worker) ConcernsCluster() bool {
	return w.cluster != nil
}

// CanProceed tells if the combination Feature/Target can work
func (w *worker) CanProceed(ctx context.Context, s resources.FeatureSettings) fail.Error {
	switch w.target.TargetType() {
	case featuretargettype.Cluster:
		xerr := w.validateContextForCluster(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr == nil && !s.SkipSizingRequirements {
			xerr = w.validateClusterSizing(ctx)
		}
		return xerr
	case featuretargettype.Host:
		// If the target is a host inside a worker for a cluster, validate unconditionally
		if w.cluster != nil {
			return nil
		}
		return w.validateContextForHost(s)
	}
	return nil
}

// identifyAvailableMaster finds a master available, and keep track of it
// for all the life of the action (prevent to request too often)
func (w *worker) identifyAvailableMaster(ctx context.Context) (_ resources.Host, ferr fail.Error) {
	if w.cluster == nil {
		return nil, abstract.ResourceNotAvailableError("cluster", "")
	}
	if w.availableMaster == nil {
		var xerr fail.Error
		w.availableMaster, xerr = w.cluster.unsafeFindAvailableMaster(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}
	return w.availableMaster, nil
}

// identifyAvailableNode finds a node available and will use this one during all the install session
func (w *worker) identifyAvailableNode(ctx context.Context) (_ resources.Host, ferr fail.Error) {
	if w.cluster == nil {
		return nil, abstract.ResourceNotAvailableError("cluster", "")
	}
	if w.availableNode == nil {
		var xerr fail.Error
		w.availableNode, xerr = w.cluster.unsafeFindAvailableNode(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}
	return w.availableNode, nil
}

// identifyConcernedMasters returns a list of all the hosts acting as masters and keep this list
// during all the install session
func (w *worker) identifyConcernedMasters(ctx context.Context) ([]resources.Host, fail.Error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.concernedMasters == nil {
		hosts, xerr := w.identifyAllMasters(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		concernedHosts, xerr := w.extractHostsFailingCheck(ctx, hosts)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		w.concernedMasters = concernedHosts
	}
	return w.concernedMasters, nil
}

// extractHostsFailingCheck identifies from the list passed as parameter which
// hosts fail Feature check.
// The checks are done in parallel.
func (w *worker) extractHostsFailingCheck(ctx context.Context, hosts []resources.Host) ([]resources.Host, fail.Error) {
	var concernedHosts []resources.Host
	dones := map[resources.Host]chan fail.Error{}
	res := map[resources.Host]chan resources.Results{}

	settings := w.settings
	if w.cluster != nil {
		settings.IgnoreSuitability = true
	}

	for _, h := range hosts {
		d := make(chan fail.Error)
		r := make(chan resources.Results)
		dones[h] = d
		res[h] = r
		go func(host resources.Host, res chan resources.Results, done chan fail.Error) {
			r2, innerXErr := w.feature.Check(ctx, host, w.variables, settings)
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				res <- nil
				done <- innerXErr
				return
			}
			res <- r2
			done <- nil
		}(h, r, d)
	}
	for h := range dones {
		r := <-res[h]
		d := <-dones[h]
		if d != nil {
			return nil, d
		}
		if !r.Successful() {
			concernedHosts = append(concernedHosts, h)
		}
	}
	return concernedHosts, nil
}

// identifyAllMasters returns a list of all the hosts acting as masters and keep this list
// during all the install session
func (w *worker) identifyAllMasters(ctx context.Context) ([]resources.Host, fail.Error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.allMasters == nil || len(w.allMasters) == 0 {
		w.allMasters = []resources.Host{}
		masters, xerr := w.cluster.unsafeListMasterIDs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		for _, i := range masters {
			hostInstance, xerr := LoadHost(ctx, w.cluster.Service(), i)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			w.allMasters = append(w.allMasters, hostInstance)
		}
	}
	return w.allMasters, nil
}

// identifyConcernedNodes returns a list of all the hosts acting nodes and keep this list
// during all the install session
func (w *worker) identifyConcernedNodes(ctx context.Context) ([]resources.Host, fail.Error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.concernedNodes == nil {
		hosts, xerr := w.identifyAllNodes(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		concernedHosts, xerr := w.extractHostsFailingCheck(ctx, hosts)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		w.concernedNodes = concernedHosts
	}
	return w.concernedNodes, nil
}

// identifyAllNodes returns a list of all the hosts acting as public of private nodes and keep this list
// during all the install session
func (w *worker) identifyAllNodes(ctx context.Context) ([]resources.Host, fail.Error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.allNodes == nil {
		var allHosts []resources.Host
		list, xerr := w.cluster.unsafeListNodeIDs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		for _, i := range list {
			hostInstance, xerr := LoadHost(ctx, w.cluster.Service(), i)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			allHosts = append(allHosts, hostInstance)
		}
		w.allNodes = allHosts
	}
	return w.allNodes, nil
}

// identifyAvailableGateway finds a gateway available, and keep track of it
// for all the life of the action (prevent to request too often)
func (w *worker) identifyAvailableGateway(ctx context.Context) (resources.Host, fail.Error) {
	if w.availableGateway != nil {
		return w.availableGateway, nil
	}

	timings, xerr := w.service.Timings()
	if xerr != nil {
		return nil, xerr
	}

	// Not in cluster context
	if w.cluster == nil {
		subnetInstance, xerr := w.host.GetDefaultSubnet(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		// look 1st for primary gateway, if not found then for the secondary gateway
		found := true
		var nilErrNotFound *fail.ErrNotFound = nil // nolint
		gw, xerr := subnetInstance.InspectGateway(ctx, true)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil && xerr != nilErrNotFound {
			if _, ok := xerr.(*fail.ErrNotFound); !ok { // nolint, typed nil already taken care of in previous line
				return nil, xerr
			}
			found = false
			debug.IgnoreError(xerr)
		}

		if !found {
			if gw, xerr = subnetInstance.InspectGateway(ctx, false); xerr != nil {
				return nil, fail.NotAvailableError("no gateway available")
			}
		}

		// if either primary o 2ary found, then wait for ssh to be ready
		_, xerr = gw.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "unable to connect to gateway")
		}

		w.availableGateway = gw
	} else {
		// In cluster context
		netCfg, xerr := w.cluster.GetNetworkConfig(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		found := true
		var nilErrNotFound *fail.ErrNotFound = nil // nolint
		var gw resources.Host
		svc := w.cluster.Service()
		gw, xerr = LoadHost(ctx, svc, netCfg.GatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil && xerr != nilErrNotFound {
			if _, ok := xerr.(*fail.ErrNotFound); !ok { // nolint, typed nil already taken care of in previous line
				return nil, xerr
			}
			found = false
			debug.IgnoreError(xerr)
		}

		if !found {
			gw, xerr = LoadHost(ctx, svc, netCfg.SecondaryGatewayID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, fail.Wrap(xerr, "failed to find an available gateway")
			}
		}

		_, xerr = gw.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "unable to connect to gateway")
		}

		w.availableGateway = gw
	}
	return w.availableGateway, nil
}

// identifyConcernedGateways returns a list of all the hosts acting as gateway that can accept the action
// and keep this list during all the installation session
func (w *worker) identifyConcernedGateways(ctx context.Context) (_ []resources.Host, ferr fail.Error) {
	var hosts []resources.Host

	var xerr fail.Error
	hosts, xerr = w.identifyAllGateways(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	concernedHosts, xerr := w.extractHostsFailingCheck(ctx, hosts)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	w.concernedGateways = concernedHosts
	return w.concernedGateways, nil
}

// identifyAllGateways returns a list of all the hosts acting as gateways and keep this list
// during all the installation session
func (w *worker) identifyAllGateways(ctx context.Context) (_ []resources.Host, ferr fail.Error) {
	if w.allGateways != nil {
		return w.allGateways, nil
	}

	var (
		list []resources.Host
		rs   resources.Subnet
	)

	timings, xerr := w.service.Timings()
	if xerr != nil {
		return nil, xerr
	}

	if w.cluster != nil {
		var netCfg *propertiesv3.ClusterNetwork
		netCfg, xerr = w.cluster.GetNetworkConfig(ctx)
		if xerr != nil {
			return nil, xerr
		}
		rs, xerr = LoadSubnet(ctx, w.service, "", netCfg.SubnetID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	} else {
		rs, xerr = w.host.GetDefaultSubnet(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}

	gw, xerr := rs.InspectGateway(ctx, true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		debug.IgnoreError(xerr)
	} else {
		if _, xerr = gw.WaitSSHReady(ctx, timings.SSHConnectionTimeout()); xerr != nil {
			debug.IgnoreError(xerr)
		} else {
			list = append(list, gw)
		}
	}

	if gw, xerr = rs.InspectGateway(ctx, false); xerr != nil {
		debug.IgnoreError(xerr)
	} else {
		if _, xerr = gw.WaitSSHReady(ctx, timings.SSHConnectionTimeout()); xerr != nil {
			debug.IgnoreError(xerr)
		} else {
			list = append(list, gw)
		}
	}

	if len(list) == 0 {
		return nil, fail.NotAvailableError("no gateways currently available")
	}

	w.allGateways = list
	return list, nil
}

// Proceed executes the action
func (w *worker) Proceed(ctx context.Context, params data.Map, settings resources.FeatureSettings) (outcomes resources.Results, ferr fail.Error) {
	w.variables = params
	w.settings = settings

	outcomes = &results{}

	// 'pace' tells the order of execution
	var (
		pace     string
		stepsKey string
		steps    map[string]interface{}
		order    []string
	)
	if w.method != installmethod.None {
		pace = w.feature.Specs().GetString(w.rootKey + "." + yamlPaceKeyword)
		if pace == "" {
			return nil, fail.SyntaxError("missing or empty key %s.%s", w.rootKey, yamlPaceKeyword)
		}

		// 'steps' describes the steps of the action
		stepsKey = w.rootKey + "." + yamlStepsKeyword
		steps = w.feature.Specs().GetStringMap(stepsKey)
		if len(steps) == 0 {
			return nil, fail.InvalidRequestError("nothing to do")
		}

		order = strings.Split(pace, ",")
	}

	// Applies reverseproxy rules and security to make Feature functional (Feature may need it during the install)
	switch w.action {
	case installaction.Add:
		if !settings.SkipProxy {
			xerr := w.setReverseProxy(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, fail.Wrap(xerr, "failed to set reverse proxy rules on Subnet")
			}
		}

		xerr := w.setSecurity(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to set security rules on Subnet")
		}
	case installaction.Remove:
		// FIXME: currently removing feature does not clear proxy rules...
		// if !settings.SkipProxy {
		// 	rgw, xerr := w.identifyAvailableGateway()
		// 	if xerr == nil {
		// 		var found bool
		// 		if found, xerr = rgw.IsFeatureInstalled(w.feature.task, "edgeproxy4subnet"); xerr == nil && found {
		// 			xerr = w.unsetReverseProxy()
		// 		}
		// 	}
		// 	if xerr != nil {
		// 		return nil, fail.Wrap(xerr, "failed to set reverse proxy rules on Subnet")
		// 	}
		// }
		//
		// if xerr := w.unsetSecurity(); xerr != nil {
		// 	return nil, xerr
		// }
	}

	var xerr fail.Error
	xerr = w.target.ComplementFeatureParameters(ctx, params)
	if xerr != nil {
		return nil, xerr
	}

	// w.reduceFeatureParameters(&params)
	//
	// // Checks required parameters have their values
	// xerr = checkRequiredParameters(*w.feature, params)
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return nil, xerr
	// }

	// Now enumerate steps and execute each of them
	for _, k := range order {
		stepKey := stepsKey + "." + k
		stepMap, ok := steps[strings.ToLower(k)].(map[string]interface{})
		if !ok {
			msg := `syntax error in Feature '%s' specification file (%s): no key '%s' found`
			return outcomes, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(ctx), stepKey)
		}

		// Determine list of hosts concerned by the step
		var hostsList []resources.Host
		if w.target.TargetType() == featuretargettype.Host {
			hostsList, xerr = w.identifyHosts(ctx, map[string]string{"hosts": "1"})
		} else {
			stepT := stepTargets{}
			anon, ok := stepMap[yamlTargetsKeyword]
			if ok {
				for i, j := range anon.(map[string]interface{}) {
					switch j := j.(type) {
					case bool:
						if j {
							stepT[i] = "true"
						} else {
							stepT[i] = "false"
						}
					case string:
						stepT[i] = j
					}
				}
			} else {
				msg := `syntax error in Feature '%s' specification file (%s): no key '%s.%s' found`
				return nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(ctx), stepKey, yamlTargetsKeyword)
			}

			hostsList, xerr = w.identifyHosts(ctx, stepT)
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		if len(hostsList) == 0 {
			continue
		}

		var problem error
		subtask, xerr := concurrency.NewTaskWithContext(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return outcomes, xerr
		}

		subtask, xerr = subtask.Start(w.taskLaunchStep, taskLaunchStepParameters{
			stepName:  k,
			stepKey:   stepKey,
			stepMap:   stepMap,
			variables: params,
			hosts:     hostsList,
		}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/feature/%s/%s/target/%s/step/%s", w.feature.GetName(), strings.ToLower(w.action.String()), strings.ToLower(w.target.TargetType().String()), k)))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			problem = xerr
			abErr := subtask.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warn("problem aborting task")
			}
		}

		var tr concurrency.TaskResult
		tr, xerr = subtask.Wait()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if problem != nil {
				_ = xerr.AddConsequence(problem)
			}
			if tr != nil {
				if outcome, ok := tr.(*resources.UnitResults); ok {
					_ = outcomes.Add(k, *outcome)
				}
			}
			return outcomes, xerr
		}

		if tr != nil {
			if outcome, ok := tr.(*resources.UnitResults); ok {
				_ = outcomes.Add(k, *outcome)
			}
		}
	}

	return outcomes, nil
}

// // reduceFeatureParameters cleans up params accordingly to the current context. Ensures that:
// // - every parameter that is not prefixed by feature name are kept
// // - every parameter that is prefixed by current feature name sees it's prefix removed
// // - every parameter that is not prefixed by current feature name is removed
// //
// // Example:
// //   if current feature is docker, and we have these params:
// //     - Version -> 21.03
// //     - kubernetes:Version -> 18.1
// //     - docker:HubLogin -> toto
// //   the call to this method will leave this:
// //     - Version -> 21.03
// //     - HubLogin -> toto
// func (w *worker) reduceFeatureParameters(params *data.Map) {
// 	for k, v := range *params {
// 		splitted := strings.Split(k, ":")
// 		if len(splitted) > 1 {
// 			if splitted[0] == w.feature.GetName() {
// 				(*params)[splitted[1]] = v
// 			}
// 			delete(*params, k)
// 		}
// 	}
// }

type taskLaunchStepParameters struct {
	stepName  string
	stepKey   string
	stepMap   map[string]interface{}
	variables data.Map
	hosts     []resources.Host
}

// taskLaunchStep starts the step
func (w *worker) taskLaunchStep(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if w == nil {
		return nil, fail.InvalidInstanceError()
	}
	if w.feature == nil {
		return nil, fail.InvalidInstanceContentError("w.Feature", "cannot be nil")
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if params == nil {
		return nil, fail.InvalidParameterError("params", "can't be nil")
	}

	var (
		anon interface{}
		ok   bool
	)
	p, ok := params.(taskLaunchStepParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "should be taskLaunchStepParameters")
	}

	if p.stepName == "" {
		return nil, fail.InvalidParameterError("param.stepName", "cannot be empty string")
	}
	if p.stepKey == "" {
		return nil, fail.InvalidParameterError("param.stepKey", "cannot be empty string")
	}
	if p.stepMap == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.stepMap")
	}
	if p.variables == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params[variables]")
	}
	if len(p.hosts) == 0 {
		return nil, fail.InvalidParameterError("p.hosts", "cannot be empty slice")
	}

	if task.Aborted() {
		lerr, err := task.LastError()
		if err != nil {
			return nil, fail.AbortedError(nil, "parent task killed (without last error recovered)")
		}
		return nil, fail.AbortedError(lerr, "parent task killed")
	}

	defer fail.OnExitLogError(&ferr, fmt.Sprintf("executed step '%s::%s'", w.action.String(), p.stepName))
	defer temporal.NewStopwatch().OnExitLogWithLevel(
		fmt.Sprintf("Starting execution of step '%s::%s'...", w.action.String(), p.stepName),
		fmt.Sprintf("Ending execution of step '%s::%s' with error '%s'", w.action.String(), p.stepName, ferr),
		logrus.DebugLevel,
	)

	timings, xerr := w.service.Timings()
	if xerr != nil {
		return nil, xerr
	}

	var (
		runContent string
		// stepT      = stepTargets{}
		// options    = map[string]string{}
	)

	// // Determine list of hosts concerned by the step
	// var hostsList []resources.Host
	// if w.target.TargetType() == featuretargettype.Host {
	// 	hostsList, xerr = w.identifyHosts(task.Context(), map[string]string{"hosts": "1"})
	// } else {
	// 	anon, ok = p.stepMap[yamlTargetsKeyword]
	// 	if ok {
	// 		for i, j := range anon.(map[string]interface{}) {
	// 			switch j := j.(type) {
	// 			case bool:
	// 				if j {
	// 					stepT[i] = "true"
	// 				} else {
	// 					stepT[i] = "false"
	// 				}
	// 			case string:
	// 				stepT[i] = j
	// 			}
	// 		}
	// 	} else {
	// 		msg := `syntax error in Feature '%s' specification file (%s): no key '%s.%s' found`
	// 		return nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(), p.stepKey, yamlTargetsKeyword)
	// 	}
	//
	// 	hostsList, xerr = w.identifyHosts(task.Context(), stepT)
	// }
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return nil, xerr
	// }
	// if len(hostsList) == 0 {
	// 	return nil, nil
	// }

	// // Marks hosts instances as unsafeReleased after use
	// defer func() {
	// 	for _, v := range hostsList {
	// 		v.Released()
	// 	}
	// }()

	// Get the content of the action based on method
	var keyword string
	switch w.method {
	case installmethod.Apt, installmethod.Yum, installmethod.Dnf:
		keyword = yamlPackageKeyword
	default:
		keyword = yamlRunKeyword
	}
	runContent, ok = p.stepMap[keyword].(string)
	if ok {
		// If 'run' content has to be altered, do it
		if w.commandCB != nil {
			runContent = w.commandCB(runContent)
		}
	} else {
		msg := `syntax error in Feature '%s' specification file (%s): no key '%s.%s' found`
		return nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(task.Context()), p.stepKey, yamlRunKeyword)
	}

	wallTime := timings.HostLongOperationTimeout()
	if anon, ok = p.stepMap[yamlTimeoutKeyword]; ok {
		if _, ok = anon.(int); ok {
			wallTime = time.Duration(anon.(int)) * time.Minute
		} else {
			wallTimeConv, inner := strconv.Atoi(anon.(string))
			if inner != nil {
				logrus.Warnf("Invalid value '%s' for '%s.%s', ignored.", anon.(string), w.rootKey, yamlTimeoutKeyword)
			} else {
				wallTime = time.Duration(wallTimeConv) * time.Minute
			}
		}
	}

	templateCommand, xerr := normalizeScript(timings, &p.variables, data.Map{
		"reserved_Name":    w.feature.GetName(),
		"reserved_Content": runContent,
		"reserved_Action":  strings.ToLower(w.action.String()),
		"reserved_Step":    p.stepName,
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Checks if step can be performed in parallel on selected hosts
	serial := false
	anon, ok = p.stepMap[yamlSerialKeyword]
	if ok {
		value, ok := anon.(string)
		if ok {
			if strings.ToLower(value) == "yes" || strings.ToLower(value) != "true" {
				serial = true
			}
		}
	}

	stepInstance := step{
		Worker:   w,
		Name:     p.stepName,
		Action:   w.action,
		Script:   templateCommand,
		WallTime: wallTime,
		// OptionsFileContent: optionsFileContent,
		YamlKey: p.stepKey,
		Serial:  serial,
	}
	r, xerr := stepInstance.Run(task, p.hosts, p.variables, w.settings) // If an error occurred, do not execute the remaining steps, fail immediately
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if !r.Successful() {
		// If there are some not completed steps, reports them and break
		if !r.Completed() {
			var errpack []error
			for _, key := range r.Keys() {
				cuk := r.ResultOfKey(key)
				if cuk != nil {
					if !cuk.Successful() && !cuk.Completed() {
						var msg error
						if app.Verbose && app.Debug { // log more details if in trace mode
							msg = fmt.Errorf("execution unsuccessful and incomplete of step '%s::%s' failed on: %v with result: [%s]", w.action.String(), p.stepName, cuk.Error(), spew.Sdump(cuk))
						} else {
							msg = fmt.Errorf("execution unsuccessful and incomplete of step '%s::%s' failed on: %v", w.action.String(), p.stepName, cuk.Error())
						}
						logrus.Warnf(msg.Error())
						errpack = append(errpack, msg)
					}
				}
			}

			if len(errpack) > 0 {
				return &r, fail.NewErrorList(errpack)
			}
		}

		// not successful but completed, if action is check means the Feature is not installed, it's an information not a failure
		if w.action == installaction.Check {
			return &r, nil
		}

		var newerrpack []error
		for _, key := range r.Keys() {
			cuk := r.ResultOfKey(key)
			if cuk != nil {
				if !cuk.Successful() && cuk.Completed() {
					var msg error
					if app.Verbose && app.Debug { // log more details if in trace mode
						msg = fmt.Errorf("execution unsuccessful of step '%s::%s' failed on: %s with result: [%v]", w.action.String(), p.stepName, key /*cuk.Error()*/, spew.Sdump(cuk))
					} else {
						msg = fmt.Errorf("execution unsuccessful of step '%s::%s' failed on: %s", w.action.String(), p.stepName, key)
					}

					newerrpack = append(newerrpack, msg)
				}
			}
		}

		if len(newerrpack) > 0 {
			return &r, fail.NewErrorList(newerrpack)
		}
	}

	return &r, nil
}

// validateContextForCluster checks if the flavor of the cluster is listed in Feature specification
// 'feature.suitableFor.cluster'.
// If no flavors is listed, no flavors are authorized (but using 'cluster: no' is strongly recommended)
func (w *worker) validateContextForCluster(ctx context.Context) fail.Error {
	clusterFlavor, xerr := w.cluster.unsafeGetFlavor(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	const yamlKey = "feature.suitableFor.cluster"
	if w.feature.Specs().IsSet(yamlKey) {
		yamlFlavors := strings.Split(w.feature.Specs().GetString(yamlKey), ",")
		for _, k := range yamlFlavors {
			k = strings.ToLower(k)
			e, xerr := clusterflavor.Parse(k)
			if (xerr == nil && clusterFlavor == e) || (xerr != nil && k == "all") {
				return nil
			}
		}
	}
	msg := fmt.Sprintf("Feature '%s' not suitable for flavor '%s' of the targeted cluster", w.feature.GetName(), clusterFlavor.String())
	return fail.NotAvailableError(msg)
}

// validateContextForHost ...
func (w *worker) validateContextForHost(settings resources.FeatureSettings) fail.Error {
	if settings.IgnoreSuitability /* || w.node*/ {
		return nil
	}

	ok := false
	const yamlKey = "feature.suitableFor.host"
	if w.feature.Specs().IsSet(yamlKey) {
		value := strings.ToLower(w.feature.Specs().GetString(yamlKey))
		ok = value == "ok" || value == "yes" || value == "true" || value == "1"
	}
	if ok {
		return nil
	}

	return fail.NotAvailableError("Feature '%s' not suitable for host", w.feature.GetName())
}

func (w *worker) validateClusterSizing(ctx context.Context) (ferr fail.Error) {
	clusterFlavor, xerr := w.cluster.unsafeGetFlavor(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// yamlKey := "feature.dependencies.clusterSizing." + strings.ToLower(clusterFlavor.String())
	// if !w.feature.Specs().IsSet(yamlKey) {
	// 	return nil
	// }
	sizing, xerr := w.feature.ClusterSizingRequirementsForFlavor(strings.ToLower(clusterFlavor.String()))
	if xerr != nil {
		return xerr
	}

	if sizing == nil {
		// No sizing requirement for the cluster flavor, so everything is ok
		return nil
	}

	if anon, ok := sizing["masters"]; ok {
		request, ok := anon.(string)
		if !ok {
			return fail.SyntaxError("invalid masters key")
		}

		count, _, _, xerr := w.parseClusterSizingRequest(request)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		masters, xerr := w.cluster.unsafeListMasterIDs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		curMasters := len(masters)
		if curMasters < count {
			return fail.NotAvailableError("cluster does not meet the minimum number of masters (%d < %d)", curMasters, count)
		}
	}
	if anon, ok := sizing["nodes"]; ok {
		request, ok := anon.(string)
		if !ok {
			return fail.SyntaxError("invalid nodes key")
		}

		count, _, _, xerr := w.parseClusterSizingRequest(request)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		list, xerr := w.cluster.unsafeListNodeIDs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		curNodes := len(list)
		if curNodes < count {
			return fail.NotAvailableError("cluster does not meet the minimum number of nodes (%d < %d)", curNodes, count)
		}
	}

	return nil
}

// parseClusterSizingRequest returns count, cpu and ram components of request
func (w *worker) parseClusterSizingRequest(request string) (int, int, float32, fail.Error) {
	_ = request
	return 0, 0, 0.0, fail.NotImplementedError("parseClusterSizingRequest() not yet implemented") // FIXME: Technical debt
}

// setReverseProxy applies the reverse proxy rules defined in specification file (if there are some)
func (w *worker) setReverseProxy(ctx context.Context) (ferr fail.Error) {
	const yamlKey = "feature.proxy.rules"
	rules, ok := w.feature.Specs().Get(yamlKey).([]interface{})
	if !ok || len(rules) == 0 {
		return nil
	}

	// TODO: there are valid scenarios for reverse proxy settings when Feature applied to Host...
	if w.cluster == nil {
		return fail.InvalidParameterError("w.cluster", "nil cluster in setReverseProxy, cannot be nil")
	}

	rgw, xerr := w.identifyAvailableGateway(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	found, xerr := rgw.IsFeatureInstalled(ctx, "edgeproxy4subnet")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	if !found {
		return nil
	}

	netprops, xerr := w.cluster.GetNetworkConfig(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	subnetInstance, xerr := LoadSubnet(ctx, w.service, "", netprops.SubnetID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	primaryKongController, xerr := NewKongController(ctx, w.service, subnetInstance, true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to apply reverse proxy rules")
	}

	var secondaryKongController *KongController
	if ok, _ := subnetInstance.HasVirtualIP(ctx); ok {
		secondaryKongController, xerr = NewKongController(ctx, w.service, subnetInstance, false)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to apply reverse proxy rules")
		}
	}

	// Now submits all the rules to reverse proxy
	primaryGatewayVariables, cerr := w.variables.FakeClone()
	if cerr != nil {
		return fail.Wrap(cerr)
	}
	var secondaryGatewayVariables data.Map
	if secondaryKongController != nil {
		secondaryGatewayVariables, cerr = w.variables.FakeClone()
		if cerr != nil {
			return fail.Wrap(cerr)
		}
	}
	for _, r := range rules {
		if r == nil {
			continue
		}
		rule, ok := r.(map[interface{}]interface{})
		if !ok {
			return fail.InconsistentError("wrong r type %T, it should be a map[interface{}]interface{}", r)
		}
		targets := w.interpretRuleTargets(rule)
		hosts, xerr := w.identifyHosts(ctx, targets)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to apply proxy rules: %s")
		}

		for _, h := range hosts { // FIXME: make no mistake, this does NOT run in parallel, it's a HUGE bottleneck
			primaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			primaryGatewayVariables["ShortHostname"] = h.GetName()
			domain := ""
			xerr = h.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Inspect(hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
					hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					domain = hostDescriptionV1.Domain
					if domain != "" {
						domain = "." + domain
					}
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			primaryGatewayVariables["Hostname"] = h.GetName() + domain

			tg, xerr := concurrency.NewTaskGroupWithContext(ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/proxy/rule/"))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			right := false
			waited := false

			// FIXME: Refactoring, this defer is actually dangerous
			// each host iteration will trigger a defer function, and ALL the functions run at the same time at the end, triggered by the ferr error
			// shared by everyone, this it clearly a bad idea, this needs refactoring
			//goland:noinspection GoDeferInLoop
			defer func(tag concurrency.TaskGroup, iwaited *bool, iright *bool) { // nolint
				if ferr != nil {
					if !*iright { // not for us
						return
					}

					logrus.Warnf("aborting, then waiting because of %s", ferr.Error())
					if !tag.Aborted() {
						abErr := tag.AbortWithCause(ferr)
						if abErr != nil {
							_ = ferr.AddConsequence(fail.Wrap(abErr, "cleaning up on failure, failed to abort TaskGroup"))
						}
					}

					if !*iwaited {
						_, derr := tag.WaitGroup()
						if derr != nil {
							_ = ferr.AddConsequence(derr)
						}
					}
				}
			}(tg, &waited, &right)

			_, xerr = tg.Start(taskApplyProxyRule, taskApplyProxyRuleParameters{
				controller: primaryKongController,
				rule:       r.(map[interface{}]interface{}),
				variables:  &primaryGatewayVariables,
			}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/apply", primaryKongController.GetHostname())))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil { // we should abort then wait, but the previous defer takes care of it
				return xerr
			}

			if secondaryKongController != nil {
				secondaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				secondaryGatewayVariables["ShortHostname"] = h.GetName()
				domain = ""
				xerr = h.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Inspect(hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
						hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
						if !ok {
							return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}

						domain = hostDescriptionV1.Domain
						if domain != "" {
							domain = "." + domain
						}
						return nil
					})
				})
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				secondaryGatewayVariables["Hostname"] = h.GetName() + domain

				_, xerr = tg.Start(taskApplyProxyRule, taskApplyProxyRuleParameters{
					controller: secondaryKongController,
					rule:       rule,
					variables:  &secondaryGatewayVariables,
				}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/apply", secondaryKongController.GetHostname())))
				if xerr != nil { // we should abort then wait, but defer above takes care of it
					return xerr
				}
			}

			waited = true
			_, xerr = tg.WaitGroup()
			if xerr != nil {
				return xerr
			}

			right = true
		}
	}
	return nil
}

type taskApplyProxyRuleParameters struct {
	controller *KongController
	rule       map[interface{}]interface{}
	variables  *data.Map
}

func taskApplyProxyRule(task concurrency.Task, params concurrency.TaskParameters) (tr concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	p, ok := params.(taskApplyProxyRuleParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "is not a taskApplyProxyRuleParameters")
	}
	hostName, ok := (*p.variables)["Hostname"].(string)
	if !ok {
		return nil, fail.InvalidParameterError("variables['Hostname']", "is not a string")
	}

	if task.Aborted() {
		lerr, err := task.LastError()
		if err != nil {
			return nil, fail.AbortedError(nil, "parent task killed (without last error recovered)")
		}
		return nil, fail.AbortedError(lerr, "parent task killed")
	}

	ruleName, xerr := p.controller.Apply(task.Context(), p.rule, p.variables)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		msg := "failed to apply proxy rule"
		if ruleName != "" {
			msg += " '" + ruleName + "'"
		}
		msg += " for host '" + hostName
		logrus.Error(msg + "': " + xerr.Error())
		return nil, fail.Wrap(xerr, msg)
	}
	logrus.Debugf("successfully applied proxy rule '%s' for host '%s'", ruleName, hostName)
	return nil, nil
}

// identifyHosts identifies hosts concerned based on 'targets' and returns a list of hosts
func (w *worker) identifyHosts(ctx context.Context, targets stepTargets) ([]resources.Host, fail.Error) {
	hostT, masterT, nodeT, gwT, xerr := targets.parse()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	var (
		hostsList []resources.Host
		all       []resources.Host
	)

	if w.cluster == nil {
		if hostT != "" {
			hostsList = append(hostsList, w.host)
		}
		return hostsList, nil
	}

	switch masterT {
	case "1":
		hostInstance, xerr := w.identifyAvailableMaster(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, hostInstance)
	case "*":
		if w.action == installaction.Add {
			all, xerr = w.identifyConcernedMasters(ctx)
		} else {
			all, xerr = w.identifyAllMasters(ctx)
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, all...)
	}

	switch nodeT {
	case "1":
		hostInstance, xerr := w.identifyAvailableNode(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, hostInstance)
	case "*":
		if w.action == installaction.Add {
			all, xerr = w.identifyConcernedNodes(ctx)
		} else {
			all, xerr = w.identifyAllNodes(ctx)
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, all...)
	}

	switch gwT {
	case "1":
		hostInstance, xerr := w.identifyAvailableGateway(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, hostInstance)
	case "*":
		if w.action == installaction.Add {
			all, xerr = w.identifyConcernedGateways(ctx)
		} else {
			all, xerr = w.identifyAllGateways(ctx)
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, all...)
	}
	return hostsList, nil
}

// normalizeScript envelops the script with log redirection to /opt/safescale/var/log/feature.<name>.<action>.log
// and ensures BashLibrary are there
func normalizeScript(timings temporal.Timings, params *data.Map, reserved data.Map) (string, fail.Error) {
	var (
		err         error
		tmplContent string
	)

	// Configures BashLibrary template var
	bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition(timings)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	bashLibraryVariables, xerr := bashLibraryDefinition.ToMap()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	for k, v := range reserved {
		(*params)[k] = v
	}
	for k, v := range bashLibraryVariables {
		(*params)[k] = v
	}

	anon := featureScriptTemplate.Load()
	if anon == nil {
		if suffixCandidate := os.Getenv("SAFESCALE_SCRIPTS_FAIL_FAST"); suffixCandidate != "" {
			tmplContent = strings.Replace(featureScriptTemplateContent, "set -u -o pipefail", "set -Eeuxo pipefail", 1)
		} else {
			tmplContent = featureScriptTemplateContent
		}

		// parse then execute the template
		tmpl := fmt.Sprintf(tmplContent, utils.LogFolder, utils.LogFolder, utils.LogFolder)
		r, xerr := template.Parse("normalize_script", tmpl)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return "", fail.SyntaxError("error parsing bash template: %s", xerr.Error())
		}

		// Set template to generate error if there is missing key in params during Execute
		r = r.Option("missingkey=error")
		featureScriptTemplate.Store(r)
		anon = featureScriptTemplate.Load()
	}

	dataBuffer := bytes.NewBufferString("")
	tmpl, ok := anon.(*txttmpl.Template)
	if !ok {
		return "", fail.InconsistentError("failed to cast anon to '*txttmpl.Template'")
	}

	err = tmpl.Execute(dataBuffer, *params)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.ConvertError(err)
	}

	return dataBuffer.String(), nil
}

// setSecurity applies the security rules defined in specification file (if there are some)
func (w *worker) setSecurity(ctx context.Context) (ferr fail.Error) {
	xerr := w.setNetworkingSecurity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	return nil
}

// setNetworkingSecurity applies the network security rules defined in specification file (if there are some)
func (w *worker) setNetworkingSecurity(ctx context.Context) (ferr fail.Error) {
	const yamlKey = "feature.security.networking"
	if ok := w.feature.Specs().IsSet(yamlKey); !ok {
		return nil
	}

	rules, ok := w.feature.Specs().Get(yamlKey).([]interface{})
	if !ok || len(rules) == 0 {
		return nil
	}

	var rs resources.Subnet
	var xerr fail.Error
	if w.cluster != nil {
		if netprops, xerr := w.cluster.GetNetworkConfig(ctx); xerr != nil {
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		} else {
			rs, xerr = LoadSubnet(ctx, w.service, netprops.NetworkID, netprops.SubnetID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	} else if w.host != nil {
		rs, xerr = w.host.GetDefaultSubnet(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	forFeature := " for Feature '" + w.feature.GetName() + "'"

	for k, rule := range rules {
		r, ok := rule.(map[interface{}]interface{})
		if !ok {
			return fail.InvalidParameterError("rule", "should be a map[interface{}][interface{}]")
		}
		targets := w.interpretRuleTargets(r)

		// If security rules concerns gateways, update subnet Security Group for gateways
		if _, ok := targets["gateways"]; ok {
			description, ok := r["name"].(string)
			if !ok {
				return fail.SyntaxError("missing field 'name' from rule '%s' in '%s'", k, yamlKey)
			}

			gwSG, xerr := rs.InspectGatewaySecurityGroup(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			sgRule := abstract.NewSecurityGroupRule()
			sgRule.Direction = securitygroupruledirection.Ingress // Implicit for gateways
			sgRule.EtherType = ipversion.IPv4
			sgRule.Protocol, _ = r["protocol"].(string) // nolint
			sgRule.Sources = []string{"0.0.0.0/0"}
			sgRule.Targets = []string{gwSG.GetID()}

			var commaSplitted []string
			if ports, ok := r["ports"].(int); ok {
				sgRule.Description = description + fmt.Sprintf(" (port %d)", ports) + forFeature
				if ports > 65535 {
					return fail.SyntaxError("invalid value '%s' for field 'ports'", ports)
				}
				sgRule.PortFrom = int32(ports)

				xerr = gwSG.AddRule(ctx, sgRule)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						// This rule already exists, considered as a success and continue
						debug.IgnoreError(xerr)
					default:
						return xerr
					}
				}
			} else if ports, ok := r["ports"].(string); ok {
				commaSplitted = strings.Split(ports, ",")
				if len(commaSplitted) > 0 {
					var (
						portFrom, portTo int
						err              error
					)
					for _, v := range commaSplitted {
						sgRule.Description = description
						dashSplitted := strings.Split(v, "-")
						if dashCount := len(dashSplitted); dashCount > 0 {
							portFrom, err = strconv.Atoi(dashSplitted[0])
							err = debug.InjectPlannedError(err)
							if err != nil {
								return fail.SyntaxError("invalid value '%s' for field 'ports'", ports)
							}
							if len(dashSplitted) == 2 {
								portTo, err = strconv.Atoi(dashSplitted[0])
								err = debug.InjectPlannedError(err)
								if err != nil {
									return fail.SyntaxError("invalid value '%s' for field 'ports'", ports)
								}
							}
							sgRule.Description += fmt.Sprintf(" (port%s %s)", strprocess.Plural(uint(dashCount)), dashSplitted)

							if portFrom > 65535 {
								return fail.SyntaxError("invalid value '%d' for field 'portFrom'", portFrom)
							}
							if portTo > 65535 {
								return fail.SyntaxError("invalid value '%d' for field 'portTo'", portTo)
							}
							sgRule.PortFrom = int32(portFrom)
							sgRule.PortTo = int32(portTo)
						}

						sgRule.Description += forFeature
						xerr = gwSG.AddRule(ctx, sgRule)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							switch xerr.(type) {
							case *fail.ErrDuplicate:
								// This rule already exists, considered as a success and continue
								debug.IgnoreError(xerr)
							default:
								return xerr
							}
						}
					}
				}
			} else {
				return fail.SyntaxError("invalid value for ports in rule '%s'")
			}
		}
	}

	// VPL: for the future ? For now, targets == gateways only supported...
	// hosts, xerr := w.identifyHosts(targets)
	// if xerr != nil {
	// 	return fail.Wrap(xerr, "failed to apply proxy rules: %s")
	// }
	//
	// 	if _, ok = targets["masters"]; ok {
	// 	}
	//
	// 	if _, ok = targets["nodes"]; ok {
	// 	}
	//
	// 	for _, h := range hosts {
	// 		if primaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP(w.feature.task); xerr != nil {
	// 			return xerr
	// 		}
	// 		primaryGatewayVariables["ShortHostname"] = h.GetName()
	// 		domain := ""
	// 		xerr = h.Inspect(w.feature.task, func(clonable data.Clonable, props *unsafeSerialize.JSONProperties) fail.Error {
	// 			return props.Inspect(w.feature.task, hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
	// 				hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
	// 				if !ok {
	// 					return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 				}
	// 				domain = hostDescriptionV1.Domain
	// 				if domain != "" {
	// 					domain = "." + domain
	// 				}
	// 				return nil
	// 			})
	// 		})
	// 		if xerr != nil {
	// 			return xerr
	// 		}
	//
	// 		primaryGatewayVariables["Hostname"] = h.GetName() + domain
	//
	// 		tP, xerr := w.feature.task.StartInSubtask(taskApplyProxyRule, data.Map{
	// 			"ctrl": primaryKongController,
	// 			"rule": rule,
	// 			"vars": &primaryGatewayVariables,
	// 		})
	// 		if xerr != nil {
	// 			return fail.Wrap(xerr, "failed to apply proxy rules")
	// 		}
	//
	// 		var errS fail.Error
	// 		if secondaryKongController != nil {
	// 			if secondaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP(w.feature.task); xerr != nil {
	// 				return xerr
	// 			}
	// 			secondaryGatewayVariables["ShortHostname"] = h.GetName()
	// 			domain = ""
	// 			xerr = h.Inspect(w.feature.task, func(clonable data.Clonable, props *unsafeSerialize.JSONProperties) fail.Error {
	// 				return props.Inspect(w.feature.task, hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
	// 					hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
	// 					if !ok {
	// 						return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 					}
	// 					domain = hostDescriptionV1.Domain
	// 					if domain != "" {
	// 						domain = "." + domain
	// 					}
	// 					return nil
	// 				})
	// 			})
	// 			if xerr != nil {
	// 				return xerr
	// 			}
	// 			secondaryGatewayVariables["Hostname"] = h.GetName() + domain
	//
	// 			tS, errOp := w.feature.task.StartInSubtask(taskApplyProxyRule, data.Map{
	// 				"ctrl": secondaryKongController,
	// 				"rule": rule,
	// 				"vars": &secondaryGatewayVariables,
	// 			})
	// 			if errOp == nil {
	// 				_, errOp = tS.Wait()
	// 			}
	// 			errS = errOp
	// 		}
	//
	// 		_, errP := tP.Wait()
	// 		if errP != nil {
	// 			return errP
	// 		}
	// 		if errS != nil {
	// 			return errS
	// 		}
	// 	}
	// }
	return nil
}

// interpretRuleTargets interprets the targets of a rule
func (w worker) interpretRuleTargets(rule map[interface{}]interface{}) stepTargets {
	targets := stepTargets{}

	anon, ok := rule["targets"].(map[interface{}]interface{})
	if !ok {
		// If no 'targets' key found, applies on host only
		if w.cluster != nil {
			return nil
		}
		targets[targetHosts] = "yes"
	} else {
		for i, j := range anon {
			switch j := j.(type) {
			case bool:
				if j {
					targets[i.(string)] = "yes"
				} else {
					targets[i.(string)] = "no"
				}
			case string:
				targets[i.(string)] = j
			}
		}
	}

	return targets
}

// Terminate cleans up resources
func (w *worker) Terminate() {
}
