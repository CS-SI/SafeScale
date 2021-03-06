/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	txttmpl "text/template"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv3 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/template"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	yamlPaceKeyword    = "pace"
	yamlStepsKeyword   = "steps"
	yamlTargetsKeyword = "targets"
	yamlRunKeyword     = "run"
	yamlPackageKeyword = "package"
	yamlOptionsKeyword = "options"
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

set +x
rm -f %s/feature.{{.reserved_Name}}.{{.reserved_Action}}_{{.reserved_Step}}.log
exec 1<&-
exec 2<&-
exec 1<>%s/feature.{{.reserved_Name}}.{{.reserved_Action}}_{{.reserved_Step}}.log
exec 2>&1
set -x

{{ .reserved_BashLibrary }}

{{ .reserved_Content }}
`
)

// var featureScriptTemplate *template.Template
var featureScriptTemplate atomic.Value

type alterCommandCB func(string) string

type worker struct {
	feature   *Feature
	target    resources.Targetable
	method    installmethod.Enum
	action    installaction.Enum
	variables data.Map
	settings  resources.FeatureSettings
	startTime time.Time

	host *Host
	// node    bool
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
func newWorker(f resources.Feature, t resources.Targetable, m installmethod.Enum, a installaction.Enum, cb alterCommandCB) (*worker, fail.Error) {
	w := worker{
		feature:   f.(*Feature),
		target:    t,
		method:    m,
		action:    a,
		commandCB: cb,
	}
	switch t.TargetType() {
	case featuretargettype.Cluster:
		w.cluster = t.(*Cluster)
	// case featuretargettype.Node:
	// 	w.node = true
	// 	fallthrough
	case featuretargettype.Host:
		w.host = t.(*Host)
	}

	if m != installmethod.None {
		w.rootKey = "feature.install." + strings.ToLower(m.String()) + "." + strings.ToLower(a.String())
		if !f.(*Feature).Specs().IsSet(w.rootKey) {
			msg := `syntax error in Feature '%s' specification file (%s):
				no key '%s' found`
			return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename(), w.rootKey)
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
		xerr := w.validateContextForCluster()
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
func (w *worker) identifyAvailableMaster() (_ resources.Host, xerr fail.Error) {
	if w.cluster == nil {
		return nil, abstract.ResourceNotAvailableError("cluster", "")
	}
	if w.availableMaster == nil {
		w.availableMaster, xerr = w.cluster.UnsafeFindAvailableMaster(context.TODO())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}
	return w.availableMaster, nil
}

// identifyAvailableNode finds a node available and will use this one during all the install session
func (w *worker) identifyAvailableNode() (_ resources.Host, xerr fail.Error) {
	if w.cluster == nil {
		return nil, abstract.ResourceNotAvailableError("cluster", "")
	}
	if w.availableNode == nil {
		w.availableNode, xerr = w.cluster.UnsafeFindAvailableNode(context.TODO())
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
		masters, xerr := w.cluster.UnsafeListMasterIDs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		for _, i := range masters {
			hostInstance, xerr := LoadHost(w.cluster.GetService(), i)
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
		list, xerr := w.cluster.UnsafeListNodeIDs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		for _, i := range list {
			hostInstance, xerr := LoadHost(w.cluster.GetService(), i)
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

	// Not in cluster context
	if w.cluster == nil {
		subnetInstance, xerr := w.host.GetDefaultSubnet()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		gw, xerr := subnetInstance.InspectGateway(true)
		if xerr == nil {
			_, xerr = gw.WaitSSHReady(ctx, temporal.GetConnectSSHTimeout())
		}

		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if gw, xerr = subnetInstance.InspectGateway(false); xerr == nil {
				_, xerr = gw.WaitSSHReady(ctx, temporal.GetConnectSSHTimeout())
			}
		}

		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.NotAvailableError("no gateway available")
		}

		w.availableGateway = gw
	} else {
		// In cluster context
		netCfg, xerr := w.cluster.GetNetworkConfig()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		var gw resources.Host
		if gw, xerr = LoadHost(w.cluster.GetService(), netCfg.GatewayID); xerr == nil {
			_, xerr = gw.WaitSSHReady(ctx, temporal.GetConnectSSHTimeout())
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if gw, xerr = LoadHost(w.cluster.GetService(), netCfg.SecondaryGatewayID); xerr == nil {
				_, xerr = gw.WaitSSHReady(ctx, temporal.GetConnectSSHTimeout())
			}
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to find an available gateway")
		}

		w.availableGateway = gw
	}
	return w.availableGateway, nil
}

// identifyConcernedGateways returns a list of all the hosts acting as gateway that can accept the action
// and keep this list during all the install session
func (w *worker) identifyConcernedGateways(ctx context.Context) (_ []resources.Host, xerr fail.Error) {
	var hosts []resources.Host

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
// during all the install session
func (w *worker) identifyAllGateways(ctx context.Context) (_ []resources.Host, xerr fail.Error) {
	if w.allGateways != nil {
		return w.allGateways, nil
	}

	var (
		list []resources.Host
		rs   resources.Subnet
	)

	if w.cluster != nil {
		var netCfg *propertiesv3.ClusterNetwork
		if netCfg, xerr = w.cluster.GetNetworkConfig(); xerr == nil {
			rs, xerr = LoadSubnet(w.cluster.GetService(), "", netCfg.SubnetID)
		}
	} else {
		rs, xerr = w.host.GetDefaultSubnet()
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	defer rs.Released() // mark the instance as released at the end of the function, for cache considerations

	gw, xerr := rs.InspectGateway(true)
	if xerr == nil {
		if _, xerr = gw.WaitSSHReady(ctx, temporal.GetConnectSSHTimeout()); xerr == nil {
			list = append(list, gw)
		}
	}
	if gw, xerr = rs.InspectGateway(false); xerr == nil {
		if _, xerr = gw.WaitSSHReady(ctx, temporal.GetConnectSSHTimeout()); xerr == nil {
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
func (w *worker) Proceed(ctx context.Context, v data.Map, s resources.FeatureSettings) (outcomes resources.Results, xerr fail.Error) {
	w.variables = v
	w.settings = s

	outcomes = &results{}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return outcomes, xerr
	}

	// 'pace' tells the order of execution
	var (
		pace     string
		stepsKey string
		steps    map[string]interface{}
		order    []string
	)
	if w.method != installmethod.None {
		pace = w.feature.specs.GetString(w.rootKey + "." + yamlPaceKeyword)
		if pace == "" {
			return nil, fail.SyntaxError("missing or empty key %s.%s", w.rootKey, yamlPaceKeyword)
		}

		// 'steps' describes the steps of the action
		stepsKey = w.rootKey + "." + yamlStepsKeyword
		steps = w.feature.specs.GetStringMap(stepsKey)
		if len(steps) == 0 {
			return nil, fail.InvalidRequestError("nothing to do")
		}
		order = strings.Split(pace, ",")
	}

	// Applies reverseproxy rules and security to make Feature functional (Feature may need it during the install)
	switch w.action {
	case installaction.Add:
		if !s.SkipProxy {
			xerr = w.setReverseProxy(ctx)
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
		// FIXME: Uncomplete ??
		// if !s.SkipProxy {
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

	// Now enumerate steps and execute each of them
	for _, k := range order {
		stepKey := stepsKey + "." + k
		stepMap, ok := steps[strings.ToLower(k)].(map[string]interface{})
		if !ok {
			msg := `syntax error in Feature '%s' specification file (%s): no key '%s' found`
			return outcomes, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(), stepKey)
		}

		subtask, xerr := task.StartInSubtask(w.taskLaunchStep, taskLaunchStepParameters{
			stepName:  k,
			stepKey:   stepKey,
			stepMap:   stepMap,
			variables: v,
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return outcomes, xerr
		}

		tr, xerr := subtask.Wait()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return outcomes, xerr
		}

		if tr != nil {
			outcome := tr.(*resources.UnitResults)
			_ = outcomes.Add(k, *outcome)
		}
	}

	return outcomes, nil
}

type taskLaunchStepParameters struct {
	stepName  string
	stepKey   string
	stepMap   map[string]interface{}
	variables data.Map
}

// taskLaunchStep starts the step
func (w *worker) taskLaunchStep(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

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

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	var (
		anon interface{}
		ok   bool
	)
	p := params.(taskLaunchStepParameters)

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

	defer fail.OnExitLogError(&xerr, fmt.Sprintf("executed step '%s::%s'", w.action.String(), p.stepName))
	defer temporal.NewStopwatch().OnExitLogWithLevel(
		fmt.Sprintf("Starting execution of step '%s::%s'...", w.action.String(), p.stepName),
		fmt.Sprintf("Ending execution of step '%s::%s'", w.action.String(), p.stepName),
		logrus.DebugLevel,
	)

	var (
		runContent string
		stepT      = stepTargets{}
		options    = map[string]string{}
	)

	// Determine list of hosts concerned by the step
	var hostsList []resources.Host
	if w.target.TargetType() == featuretargettype.Host {
		hostsList, xerr = w.identifyHosts(task.GetContext(), map[string]string{"hosts": "1"})
	} else {
		anon, ok = p.stepMap[yamlTargetsKeyword]
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
			return nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(), p.stepKey, yamlTargetsKeyword)
		}

		hostsList, xerr = w.identifyHosts(task.GetContext(), stepT)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	if len(hostsList) == 0 {
		return nil, nil
	}

	// Marks hosts instances as released after use
	defer func() {
		for _, v := range hostsList {
			v.Released()
		}
	}()

	// Get the content of the action based on method
	keyword := yamlRunKeyword
	switch w.method {
	case installmethod.Apt:
		fallthrough
	case installmethod.Yum:
		fallthrough
	case installmethod.Dnf:
		keyword = yamlPackageKeyword
	}
	runContent, ok = p.stepMap[keyword].(string)
	if ok {
		// If 'run' content has to be altered, do it
		if w.commandCB != nil {
			runContent = w.commandCB(runContent)
		}
	} else {
		msg := `syntax error in Feature '%s' specification file (%s): no key '%s.%s' found`
		return nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(), p.stepKey, yamlRunKeyword)
	}

	// If there is an options file (for now specific to DCOS), upload it to the remote host
	optionsFileContent := ""
	if anon, ok = p.stepMap[yamlOptionsKeyword]; ok {
		for i, j := range anon.(map[string]interface{}) {
			options[i] = j.(string)
		}
		var (
			avails  = map[string]interface{}{}
			content interface{}
		)
		complexity, xerr := w.cluster.GetComplexity()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		c := strings.ToLower(complexity.String())
		for k, anon := range options {
			avails[strings.ToLower(k)] = anon
		}
		if content, ok = avails[c]; !ok {
			if c == strings.ToLower(clustercomplexity.Large.String()) {
				c = clustercomplexity.Normal.String()
			}
			if c == strings.ToLower(clustercomplexity.Normal.String()) {
				if content, ok = avails[c]; !ok {
					content, ok = avails[clustercomplexity.Small.String()]
				}
			}
		}
		if ok {
			optionsFileContent = content.(string)
			p.variables["options"] = fmt.Sprintf("--options=%s/options.json", utils.TempFolder)
		}
	} else {
		p.variables["options"] = ""
	}

	wallTime := temporal.GetLongOperationTimeout()
	if anon, ok = p.stepMap[yamlTimeoutKeyword]; ok {
		if _, ok := anon.(int); ok {
			wallTime = time.Duration(anon.(int)) * time.Minute
		} else {
			wallTimeConv, inner := strconv.Atoi(anon.(string))
			if inner != nil {
				logrus.Warningf("Invalid value '%s' for '%s.%s', ignored.", anon.(string), w.rootKey, yamlTimeoutKeyword)
			} else {
				wallTime = time.Duration(wallTimeConv) * time.Minute
			}
		}
	}

	templateCommand, xerr := normalizeScript(data.Map{
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
		Worker:             w,
		Name:               p.stepName,
		Action:             w.action,
		Script:             templateCommand,
		WallTime:           wallTime,
		OptionsFileContent: optionsFileContent,
		YamlKey:            p.stepKey,
		Serial:             serial,
	}
	r, xerr := stepInstance.Run(task.GetContext(), hostsList, p.variables, w.settings)
	// If an error occurred, do not execute the remaining steps, fail immediately
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if !r.Successful() {
		// If there are some not completed steps, reports them and break
		if !r.Completed() {
			msg := fmt.Sprintf("execution of step '%s::%s' failed on: %v", w.action.String(), p.stepName, r.Uncompleted())
			logrus.Errorf(strprocess.Capitalize(msg))
			return &r, fail.NewError(msg)
		}
		// not successful but completed, if action is check means the Feature is not installed, it's an information not a failure
		if w.action == installaction.Check {
			return &r, nil
		}

		// For any other situations, raise error and break
		msg := fmt.Sprintf("execution of step '%s::%s' failed on: %v", w.action.String(), p.stepName, r.ErrorMessages())
		logrus.Errorf(strprocess.Capitalize(msg))
		return &r, fail.NewError(msg)
	}

	return &r, nil
}

// validateContextForCluster checks if the flavor of the cluster is listed in Feature specification
// 'feature.suitableFor.cluster'.
// If no flavors is listed, no flavors are authorized (but using 'cluster: no' is strongly recommended)
func (w *worker) validateContextForCluster() fail.Error {
	clusterFlavor, xerr := w.cluster.UnsafeGetFlavor()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	const yamlKey = "feature.suitableFor.cluster"
	if w.feature.specs.IsSet(yamlKey) {
		yamlFlavors := strings.Split(w.feature.specs.GetString(yamlKey), ",")
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
	if w.feature.specs.IsSet(yamlKey) {
		value := strings.ToLower(w.feature.specs.GetString(yamlKey))
		ok = value == "ok" || value == "yes" || value == "true" || value == "1"
	}
	if ok {
		return nil
	}

	return fail.NotAvailableError("Feature '%s' not suitable for host", w.feature.GetName())
}

func (w *worker) validateClusterSizing(ctx context.Context) (xerr fail.Error) {
	clusterFlavor, xerr := w.cluster.UnsafeGetFlavor()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	yamlKey := "feature.requirements.clusterSizing." + strings.ToLower(clusterFlavor.String())
	if !w.feature.specs.IsSet(yamlKey) {
		return nil
	}

	sizing := w.feature.specs.GetStringMap(yamlKey)
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

		masters, xerr := w.cluster.ListMasterIDs(ctx)
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

		list, xerr := w.cluster.ListNodeIDs(ctx)
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
	return 0, 0, 0.0, fail.NotImplementedError("parseClusterSizingRequest() not yet implemented")
}

// setReverseProxy applies the reverse proxy rules defined in specification file (if there are some)
func (w *worker) setReverseProxy(ctx context.Context) (xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	const yamlKey = "feature.proxy.rules"
	// rules, ok := w.feature.specs.Get(yamlKey).(map[string]map[string]interface{})
	rules, ok := w.feature.specs.Get(yamlKey).([]interface{})
	if !ok || len(rules) == 0 {
		return nil
	}

	// FIXME: there are valid scenarii for reverse proxy settings when Feature applied to Host...
	if w.cluster == nil {
		return fail.InvalidParameterError("w.cluster", "nil cluster in setReverseProxy, cannot be nil")
	}

	rgw, xerr := w.identifyAvailableGateway(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	found, xerr := rgw.IsFeatureInstalled("edgeproxy4subnet")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	if !found {
		return nil
	}

	svc := w.cluster.GetService()

	netprops, xerr := w.cluster.GetNetworkConfig()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	subnetInstance, xerr := LoadSubnet(svc, "", netprops.SubnetID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer subnetInstance.Released() // mark instance as released at the end of the function, for cache considerations

	primaryKongController, xerr := NewKongController(ctx, svc, subnetInstance, true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to apply reverse proxy rules")
	}

	var secondaryKongController *KongController
	if ok, _ := subnetInstance.HasVirtualIP(); ok {
		secondaryKongController, xerr = NewKongController(ctx, svc, subnetInstance, false)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to apply reverse proxy rules")
		}
	}

	// Now submits all the rules to reverse proxy
	primaryGatewayVariables := w.variables.Clone()
	var secondaryGatewayVariables data.Map
	if secondaryKongController != nil {
		secondaryGatewayVariables = w.variables.Clone()
	}
	for _, r := range rules {

		rule := r.(map[interface{}]interface{})
		targets := w.interpretRuleTargets(rule)
		hosts, xerr := w.identifyHosts(ctx, targets)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to apply proxy rules: %s")
		}

		//goland:noinspection ALL
		defer func(list []resources.Host) {
			for _, v := range list {
				v.Released()
			}
		}(hosts)

		for _, h := range hosts {
			primaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			primaryGatewayVariables["ShortHostname"] = h.GetName()
			domain := ""
			xerr = h.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

			tP, xerr := task.StartInSubtask(taskApplyProxyRule, taskApplyProxyRuleParameters{
				controller: primaryKongController,
				rule:       r.(map[interface{}]interface{}),
				variables:  &primaryGatewayVariables,
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to apply proxy rules")
			}

			var errS fail.Error
			if secondaryKongController != nil {
				secondaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP()
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				secondaryGatewayVariables["ShortHostname"] = h.GetName()
				domain = ""
				xerr = h.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

				tS, errOp := task.StartInSubtask(taskApplyProxyRule, taskApplyProxyRuleParameters{
					controller: secondaryKongController,
					rule:       rule,
					variables:  &secondaryGatewayVariables,
				})
				if errOp == nil {
					_, errOp = tS.Wait()
				}
				errS = errOp
			}

			_, errP := tP.Wait()
			if errP != nil {
				return errP
			}
			if errS != nil {
				return errS
			}
		}
	}
	return nil
}

type taskApplyProxyRuleParameters struct {
	controller *KongController
	rule       map[interface{}]interface{}
	variables  *data.Map
}

func taskApplyProxyRule(task concurrency.Task, params concurrency.TaskParameters) (tr concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	p := params.(taskApplyProxyRuleParameters)
	hostName, ok := (*p.variables)["Hostname"].(string)
	if !ok {
		return nil, fail.InvalidParameterError("variables['Hostname']", "is not a string")
	}

	ruleName, xerr := p.controller.Apply(p.rule, p.variables)
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
		hostInstance, xerr := w.identifyAvailableMaster()
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
		hostInstance, xerr := w.identifyAvailableNode()
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
func normalizeScript(params map[string]interface{}) (string, fail.Error) {
	var (
		err         error
		tmplContent string
	)

	anon := featureScriptTemplate.Load()
	if anon == nil {
		if suffixCandidate := os.Getenv("SAFESCALE_SCRIPTS_FAIL_FAST"); suffixCandidate != "" {
			tmplContent = strings.Replace(featureScriptTemplateContent, "set -u -o pipefail", "set -Eeuxo pipefail", 1)
		} else {
			tmplContent = featureScriptTemplateContent
		}

		// parse then execute the template
		tmpl := fmt.Sprintf(tmplContent, utils.LogFolder, utils.LogFolder)
		r, xerr := template.Parse("normalize_script", tmpl)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return "", fail.SyntaxError("error parsing bash template: %s", xerr.Error())
		}
		featureScriptTemplate.Store(r)
		anon = featureScriptTemplate.Load()
	}

	// Configures BashLibrary template var
	bashLibrary, xerr := system.GetBashLibrary()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}
	params["reserved_BashLibrary"] = bashLibrary

	dataBuffer := bytes.NewBufferString("")
	err = anon.(*txttmpl.Template).Execute(dataBuffer, params)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.ConvertError(err)
	}

	return dataBuffer.String(), nil
}

// setSecurity applies the security rules defined in specification file (if there are some)
func (w *worker) setSecurity(ctx context.Context) (xerr fail.Error) {
	xerr = w.setNetworkingSecurity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	return nil
}

// setNetworkingSecurity applies the network security rules defined in specification file (if there are some)
func (w *worker) setNetworkingSecurity(ctx context.Context) (xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	const yamlKey = "feature.security.networking"
	if ok := w.feature.specs.IsSet(yamlKey); !ok {
		return nil
	}

	rules, ok := w.feature.specs.Get(yamlKey).([]interface{})
	if !ok || len(rules) == 0 {
		return nil
	}

	var (
		svc iaas.Service
		rs  resources.Subnet
	)
	if w.cluster != nil {
		svc = w.cluster.GetService()
		var netprops *propertiesv3.ClusterNetwork
		if netprops, xerr = w.cluster.GetNetworkConfig(); xerr == nil {
			rs, xerr = LoadSubnet(svc, netprops.NetworkID, netprops.SubnetID)
		}
	} else if w.host != nil {
		rs, xerr = w.host.GetDefaultSubnet()
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer rs.Released() // mark instance as released at the end of the function, for cache considerations

	forFeature := " for Feature '" + w.feature.GetName() + "'"

	for k, rule := range rules {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		r := rule.(map[interface{}]interface{})
		targets := w.interpretRuleTargets(r)

		// If security rules concerns gateways, update subnet Security Group for gateways
		if _, ok := targets["gateways"]; ok {

			description, ok := r["name"].(string)
			if !ok {
				return fail.SyntaxError("missing field 'name' from rule '%s' in '%s'", k, yamlKey)
			}

			gwSG, xerr := rs.InspectGatewaySecurityGroup()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			//goland:noinspection ALL
			defer gwSG.Released()

			sgRule := abstract.NewSecurityGroupRule()
			sgRule.Direction = securitygroupruledirection.Ingress // Implicit for gateways
			sgRule.EtherType = ipversion.IPv4
			sgRule.Protocol, _ = r["protocol"].(string)
			sgRule.Sources = []string{"0.0.0.0/0"}
			sgRule.Targets = []string{gwSG.GetID()}

			var commaSplitted []string
			if ports, ok := r["ports"].(int); ok {
				sgRule.Description = description + fmt.Sprintf(" (port %d)", ports) + forFeature
				sgRule.PortFrom = int32(ports)

				xerr = gwSG.AddRule(ctx, sgRule)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						// This rule already exists, consider as a success and continue
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

							sgRule.PortFrom = int32(portFrom)
							sgRule.PortTo = int32(portTo)
						}

						sgRule.Description += forFeature
						xerr = gwSG.AddRule(ctx, sgRule)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							switch xerr.(type) {
							case *fail.ErrDuplicate:
								// This rule already exists, consider as a success and continue
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
	// 		xerr = h.Inspect(w.feature.task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	// 			xerr = h.Inspect(w.feature.task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	for _, v := range w.allGateways {
		v.Released()
	}
	for _, v := range w.allMasters {
		v.Released()
	}
	for _, v := range w.allNodes {
		v.Released()
	}
	for _, v := range w.concernedGateways {
		v.Released()
	}
	for _, v := range w.concernedMasters {
		v.Released()
	}
	for _, v := range w.concernedNodes {
		v.Released()
	}
	if w.availableGateway != nil {
		w.availableGateway.Released()
	}
	if w.availableMaster != nil {
		w.availableMaster.Released()
	}
	if w.availableNode != nil {
		w.availableNode.Released()
	}
}
