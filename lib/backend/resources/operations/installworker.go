/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"sync"
	"sync/atomic"
	txttmpl "text/template"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/app"
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

# BashLib
{{ .reserved_BashLibrary }}

# Reserved
{{ .reserved_Content }}

# End
`
)

// var featureScriptTemplate *template.Template
var featureScriptTemplate atomic.Value

type alterCommandCB func(string) string

type worker struct {
	mu        *sync.RWMutex
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

	machines map[string]resources.Host

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
func newWorker(
	ctx context.Context, f resources.Feature, target resources.Targetable, method installmethod.Enum,
	action installaction.Enum, cb alterCommandCB,
) (*worker, fail.Error) {
	w := worker{
		mu:        &sync.RWMutex{},
		feature:   f.(*Feature),
		target:    target,
		method:    method,
		action:    action,
		commandCB: cb,
		machines:  make(map[string]resources.Host),
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

// SetStartTime Updates startTime
func (w *worker) SetStartTime(at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.startTime = at
}

// GetStartTime return startTime
func (w *worker) GetStartTime() time.Time {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.startTime
}

// ConcernsCluster returns true if the target of the worker is a cluster
func (w *worker) ConcernsCluster() bool {
	return w.cluster != nil
}

// CanProceed tells if the combination Feature/Target can work
func (w *worker) CanProceed(inctx context.Context, s resources.FeatureSettings) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		switch w.target.TargetType() {
		case featuretargettype.Cluster:
			xerr := w.validateContextForCluster(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr == nil && !s.SkipSizingRequirements {
				xerr = w.validateClusterSizing(ctx)
			}
			chRes <- result{xerr}
			return
		case featuretargettype.Host:
			// If the target is a host inside a worker for a cluster, validate unconditionally
			if w.cluster != nil {
				chRes <- result{nil}
				return
			}
			chRes <- result{w.validateContextForHost(s)}
			return
		}
		chRes <- result{nil}

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

// identifyAvailableMaster finds a master available, and keep track of it
// for all the life of the action (prevent to request too often)
func (w *worker) identifyAvailableMaster(ctx context.Context) (_ resources.Host, ferr fail.Error) {
	defer elapsed("identifyAvailableMaster")()
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

// identifyAvailableNode finds a node available and will use this one during all the installation session
func (w *worker) identifyAvailableNode(ctx context.Context) (_ resources.Host, ferr fail.Error) {
	defer elapsed("identifyAvailableNode")()
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
// during all the installation session
func (w *worker) identifyConcernedMasters(ctx context.Context) ([]resources.Host, fail.Error) {
	defer elapsed("identifyConcernedMasters")()
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if len(w.concernedMasters) == 0 {
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

		for _, v := range concernedHosts {
			if does, xerr := v.Exists(ctx); xerr == nil {
				if does {
					w.concernedMasters = append(w.concernedMasters, v)
				}
			}
		}
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
// during all the installation session
func (w *worker) identifyAllMasters(ctx context.Context) ([]resources.Host, fail.Error) {
	defer elapsed("identifyAllMasters")()
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if len(w.allMasters) == 0 {
		w.allMasters = []resources.Host{}
		masters, xerr := w.cluster.unsafeListMasterIDs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		for _, i := range masters {
			i := i
			hostInstance, xerr := w.loadHost(ctx, i)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			if does, xerr := hostInstance.Exists(ctx); xerr == nil {
				if does {
					w.allMasters = append(w.allMasters, hostInstance)
				}
			}
		}
	}
	return w.allMasters, nil
}

// identifyConcernedNodes returns a list of all the hosts acting nodes and keep this list
// during all the installation session
func (w *worker) identifyConcernedNodes(ctx context.Context) ([]resources.Host, fail.Error) {
	defer elapsed("identifyConcernedNodes")()
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if len(w.concernedNodes) == 0 {
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

		for _, v := range concernedHosts {
			if does, xerr := v.Exists(ctx); xerr == nil {
				if does {
					w.concernedNodes = append(w.concernedNodes, v)
				}
			}
		}
	}
	return w.concernedNodes, nil
}

// identifyAllNodes returns a list of all the hosts acting as public of private nodes and keep this list
// during all the installation session
func (w *worker) identifyAllNodes(ctx context.Context) ([]resources.Host, fail.Error) {
	defer elapsed("identifyAllNodes")()
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if len(w.allNodes) == 0 {
		var allHosts []resources.Host
		list, xerr := w.cluster.unsafeListNodeIDs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		for _, i := range list {
			i := i
			hostInstance, xerr := w.loadHost(ctx, i)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			if does, xerr := hostInstance.Exists(ctx); xerr == nil {
				if does {
					allHosts = append(allHosts, hostInstance)
				}
			}
		}
		w.allNodes = allHosts
	}
	return w.allNodes, nil
}

func (w *worker) loadHost(ctx context.Context, id string) (resources.Host, fail.Error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	hostInstance, ok := w.machines[id]
	if ok {
		return hostInstance, nil
	}

	hostInstance, xerr := LoadHost(ctx, w.service, id)
	if xerr != nil {
		return nil, xerr
	}

	w.machines[id] = hostInstance
	return hostInstance, nil
}

// identifyAvailableGateway finds a gateway available, and keep track of it
// for all the life of the action (prevent to request too often)
func (w *worker) identifyAvailableGateway(ctx context.Context) (resources.Host, fail.Error) {
	defer elapsed("identifyAvailableGateway")()
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
			debug.IgnoreError2(ctx, xerr)
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
		gw, xerr = w.loadHost(ctx, netCfg.GatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil && xerr != nilErrNotFound {
			if _, ok := xerr.(*fail.ErrNotFound); !ok { // nolint, typed nil already taken care of in previous line
				return nil, xerr
			}
			found = false
			debug.IgnoreError2(ctx, xerr)
		}

		if !found {
			gw, xerr = w.loadHost(ctx, netCfg.SecondaryGatewayID)
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
	defer elapsed("identifyConcernedGateways")()
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

	for _, v := range concernedHosts {
		if does, xerr := v.Exists(ctx); xerr == nil {
			if does {
				w.concernedGateways = append(w.concernedGateways, v)
			}
		}
	}

	return w.concernedGateways, nil
}

// identifyAllGateways returns a list of all the hosts acting as gateways and keep this list
// during all the installation session
func (w *worker) identifyAllGateways(inctx context.Context) (_ []resources.Host, ferr fail.Error) {
	defer elapsed("identifyAllGateways")()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []resources.Host
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		if w.allGateways != nil {
			chRes <- result{w.allGateways, nil}
			return
		}

		var (
			list []resources.Host
			rs   resources.Subnet
		)

		timings, xerr := w.service.Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		if w.cluster != nil {
			var netCfg *propertiesv3.ClusterNetwork
			netCfg, xerr = w.cluster.GetNetworkConfig(ctx)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
			}
			rs, xerr = LoadSubnet(ctx, w.service, "", netCfg.SubnetID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
			}
		} else {
			rs, xerr = w.host.GetDefaultSubnet(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
			}
		}

		gw, xerr := rs.InspectGateway(ctx, true)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			debug.IgnoreError2(ctx, xerr)
		} else {
			if _, xerr = gw.WaitSSHReady(ctx, timings.SSHConnectionTimeout()); xerr != nil {
				debug.IgnoreError2(ctx, xerr)
			} else {
				list = append(list, gw)
			}
		}

		if gw, xerr = rs.InspectGateway(ctx, false); xerr != nil {
			debug.IgnoreError2(ctx, xerr)
		} else {
			if _, xerr = gw.WaitSSHReady(ctx, timings.SSHConnectionTimeout()); xerr != nil {
				debug.IgnoreError2(ctx, xerr)
			} else {
				list = append(list, gw)
			}
		}

		if len(list) == 0 {
			chRes <- result{nil, fail.NotAvailableError("no gateways currently available")}
			return
		}

		w.allGateways = list
		chRes <- result{list, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

// Proceed executes the action
func (w *worker) Proceed(
	inctx context.Context, params data.Map, settings resources.FeatureSettings,
) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Results
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		w.variables = params
		w.settings = settings

		var outcomes = &results{}

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
				chRes <- result{nil, fail.SyntaxError("missing or empty key %s.%s", w.rootKey, yamlPaceKeyword)}
				return
			}

			// 'steps' describes the steps of the action
			stepsKey = w.rootKey + "." + yamlStepsKeyword
			steps = w.feature.Specs().GetStringMap(stepsKey)
			if len(steps) == 0 {
				chRes <- result{nil, fail.InvalidRequestError("nothing to do")}
				return
			}

			order = strings.Split(pace, ",")
		}

		// Applies reverseproxy rules and security to make Feature functional (Feature may need it during the installation)
		switch w.action {
		case installaction.Add:
			if !settings.SkipProxy {
				xerr := w.setReverseProxy(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{nil, fail.Wrap(xerr, "failed to set reverse proxy rules on Subnet")}
					return
				}
			}

			xerr := w.setSecurity(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, fail.Wrap(xerr, "failed to set security rules on Subnet")}
				return
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
			chRes <- result{nil, xerr}
			return
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
			k := k
			stepKey := stepsKey + "." + k
			stepMap, ok := steps[strings.ToLower(k)].(map[string]interface{})
			if !ok {
				msg := `syntax error in Feature '%s' specification file (%s): no key '%s' found`
				chRes <- result{outcomes, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(ctx), stepKey)}
				return
			}

			// Determine list of hosts concerned by the step
			var hostsList []resources.Host
			if w.target.TargetType() == featuretargettype.Host {
				var tmpList []resources.Host
				tmpList, xerr = w.identifyHosts(ctx, map[string]string{"hosts": "1"})
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{nil, xerr}
					return
				}
				for _, fl := range tmpList {
					if does, xerr := fl.Exists(ctx); xerr == nil {
						if does {
							hostsList = append(hostsList, fl)
						}
					}
				}

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
					chRes <- result{nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(ctx), stepKey, yamlTargetsKeyword)}
					return
				}

				var tmpList []resources.Host
				tmpList, xerr = w.identifyHosts(ctx, stepT)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{nil, xerr}
					return
				}
				for _, fl := range tmpList {
					if does, xerr := fl.Exists(ctx); xerr == nil {
						if does {
							hostsList = append(hostsList, fl)
						}
					}
				}
			}

			if len(hostsList) == 0 {
				continue
			}

			var ur resources.UnitResults
			ur, xerr = w.taskLaunchStep(ctx, taskLaunchStepParameters{
				stepName:  k,
				stepKey:   stepKey,
				stepMap:   stepMap,
				variables: params,
				hosts:     hostsList,
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
			}

			xerr = fail.ConvertError(outcomes.Add(k, ur))
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
			}
		}
		chRes <- result{outcomes, nil}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskLaunchStepParameters struct {
	stepName  string
	stepKey   string
	stepMap   map[string]interface{}
	variables data.Map
	hosts     []resources.Host
}

// taskLaunchStep starts the step
func (w *worker) taskLaunchStep(inctx context.Context, p taskLaunchStepParameters) (
	_ resources.UnitResults, ferr fail.Error,
) {
	if w == nil {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.UnitResults
		rErr fail.Error
	}

	defer fail.OnExitLogError(ctx, &ferr, fmt.Sprintf("executed step '%s::%s'", w.action.String(), p.stepName))
	defer temporal.NewStopwatch().OnExitLogWithLevel(ctx, fmt.Sprintf("Starting execution of step '%s::%s'...", w.action.String(), p.stepName), fmt.Sprintf("Ending execution of step '%s::%s' with error '%s'", w.action.String(), p.stepName, ferr), logrus.DebugLevel)

	chRes := make(chan result)
	go func() {
		defer close(chRes)

		if w.feature == nil {
			chRes <- result{nil, fail.InvalidInstanceContentError("w.Feature", "cannot be nil")}
			return
		}

		var (
			anon interface{}
			ok   bool
		)

		if p.stepName == "" {
			chRes <- result{nil, fail.InvalidParameterError("param.stepName", "cannot be empty string")}
			return
		}
		if p.stepKey == "" {
			chRes <- result{nil, fail.InvalidParameterError("param.stepKey", "cannot be empty string")}
			return
		}
		if p.stepMap == nil {
			chRes <- result{nil, fail.InvalidParameterCannotBeNilError("params.stepMap")}
			return
		}
		if p.variables == nil {
			chRes <- result{nil, fail.InvalidParameterCannotBeNilError("params[variables]")}
			return
		}
		if len(p.hosts) == 0 {
			chRes <- result{nil, fail.InvalidParameterError("p.hosts", "cannot be empty slice")}
			return
		}

		timings, xerr := w.service.Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		var (
			runContent string
			// stepT      = stepTargets{}
			// options    = map[string]string{}
		)

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
			chRes <- result{nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(ctx), p.stepKey, yamlRunKeyword)}
			return
		}

		wallTime := timings.HostLongOperationTimeout()
		if anon, ok = p.stepMap[yamlTimeoutKeyword]; ok {
			if _, ok = anon.(int); ok {
				wallTime = time.Duration(anon.(int)) * time.Minute
			} else {
				wallTimeConv, inner := strconv.Atoi(anon.(string))
				if inner != nil {
					logrus.WithContext(ctx).Warnf("Invalid value '%s' for '%s.%s', ignored.", anon.(string), w.rootKey, yamlTimeoutKeyword)
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
			chRes <- result{nil, xerr}
			return
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
		r, xerr := stepInstance.Run(ctx, p.hosts, p.variables, w.settings) // If an error occurred, do not execute the remaining steps, fail immediately
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		if !r.Successful() {
			// If there are some not complete steps, reports them and break
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
							logrus.WithContext(ctx).Warnf(msg.Error())
							errpack = append(errpack, msg)
						}
					}
				}

				if len(errpack) > 0 {
					chRes <- result{r, fail.NewErrorList(errpack)}
					return
				}
			}

			// not successful but complete, if action is check means the Feature is not installed, it's an information not a failure
			if w.action == installaction.Check {
				chRes <- result{r, nil}
				return
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
				chRes <- result{r, fail.NewErrorList(newerrpack)}
				return
			}
		}

		chRes <- result{r, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
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

func (w *worker) validateClusterSizing(inctx context.Context) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		clusterFlavor, xerr := w.cluster.unsafeGetFlavor(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		sizing, xerr := w.feature.ClusterSizingRequirementsForFlavor(strings.ToLower(clusterFlavor.String()))
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if sizing == nil {
			// No sizing requirement for the cluster flavor, so everything is ok
			chRes <- result{nil}
			return
		}

		if anon, ok := sizing["masters"]; ok {
			request, ok := anon.(string)
			if !ok {
				chRes <- result{fail.SyntaxError("invalid masters key")}
				return
			}

			count, _, _, xerr := w.parseClusterSizingRequest(request)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			masters, xerr := w.cluster.unsafeListMasterIDs(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			curMasters := len(masters)
			if curMasters < count {
				chRes <- result{fail.NotAvailableError("cluster does not meet the minimum number of masters (%d < %d)", curMasters, count)}
				return
			}
		}
		if anon, ok := sizing["nodes"]; ok {
			request, ok := anon.(string)
			if !ok {
				chRes <- result{fail.SyntaxError("invalid nodes key")}
				return
			}

			count, _, _, xerr := w.parseClusterSizingRequest(request)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			list, xerr := w.cluster.unsafeListNodeIDs(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			curNodes := len(list)
			if curNodes < count {
				chRes <- result{fail.NotAvailableError("cluster does not meet the minimum number of nodes (%d < %d)", curNodes, count)}
				return
			}
		}

		chRes <- result{nil}

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}

}

// parseClusterSizingRequest returns count, cpu and ram components of request
func (w *worker) parseClusterSizingRequest(request string) (int, int, float32, fail.Error) {
	return 0, 0, 0.0, fail.NotImplementedError("parseClusterSizingRequest() not yet implemented") // FIXME: Technical debt
}

// setReverseProxy applies the reverse proxy rules defined in specification file (if there are some)
func (w *worker) setReverseProxy(inctx context.Context) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		const yamlKey = "feature.proxy.rules"
		rules, ok := w.feature.Specs().Get(yamlKey).([]interface{})
		if !ok || len(rules) == 0 {
			chRes <- result{nil}
			return
		}

		// TODO: there are valid scenarios for reverse proxy settings when Feature applied to Host...
		if w.cluster == nil {
			chRes <- result{fail.InvalidParameterError("w.cluster", "nil cluster in setReverseProxy, cannot be nil")}
			return
		}

		rgw, xerr := w.identifyAvailableGateway(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		found, xerr := rgw.IsFeatureInstalled(ctx, "edgeproxy4subnet")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}
		if !found {
			chRes <- result{nil}
			return
		}

		netprops, xerr := w.cluster.GetNetworkConfig(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		subnetInstance, xerr := LoadSubnet(ctx, w.service, "", netprops.SubnetID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		primaryKongController, xerr := NewKongController(ctx, w.service, subnetInstance, true)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{fail.Wrap(xerr, "failed to apply reverse proxy rules")}
			return
		}

		var secondaryKongController *KongController
		if ok, _ := subnetInstance.HasVirtualIP(ctx); ok {
			secondaryKongController, xerr = NewKongController(ctx, w.service, subnetInstance, false)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{fail.Wrap(xerr, "failed to apply reverse proxy rules")}
				return
			}
		}

		// Now submits all the rules to reverse proxy
		primaryGatewayVariables, cerr := data.FromMap(w.variables)
		if cerr != nil {
			chRes <- result{fail.Wrap(cerr)}
			return
		}
		var secondaryGatewayVariables data.Map
		if secondaryKongController != nil {
			secondaryGatewayVariables, cerr = data.FromMap(w.variables)
			if cerr != nil {
				chRes <- result{fail.Wrap(cerr)}
				return
			}
		}
		for _, r := range rules {
			r := r
			if r == nil {
				continue
			}
			rule, ok := r.(map[interface{}]interface{})
			if !ok {
				chRes <- result{fail.InconsistentError("wrong r type %T, it should be a map[interface{}]interface{}", r)}
				return
			}
			targets := w.interpretRuleTargets(rule)
			hosts, xerr := w.identifyHosts(ctx, targets)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{fail.Wrap(xerr, "failed to apply proxy rules: %s")}
				return
			}

			for _, h := range hosts { // FIXME: make no mistake, this does NOT run in parallel, it's a HUGE bottleneck
				h := h
				primaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{xerr}
					return
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
					chRes <- result{xerr}
					return
				}

				primaryGatewayVariables["Hostname"] = h.GetName() + domain

				tg := new(errgroup.Group)

				tg.Go(func() error {
					_, err := taskApplyProxyRule(ctx, taskApplyProxyRuleParameters{
						controller: primaryKongController,
						rule:       r.(map[interface{}]interface{}),
						variables:  &primaryGatewayVariables,
					})
					return err
				})

				tg.Go(func() error {
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
						_, xerr = taskApplyProxyRule(ctx, taskApplyProxyRuleParameters{
							controller: secondaryKongController,
							rule:       rule,
							variables:  &secondaryGatewayVariables,
						})
						if xerr != nil {
							return xerr
						}
						return nil
					}
					return nil
				})

				xerr = fail.ConvertError(tg.Wait())
				if xerr != nil {
					chRes <- result{xerr}
					return
				}
			}
		}
		chRes <- result{nil}

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}

}

type taskApplyProxyRuleParameters struct {
	controller *KongController
	rule       map[interface{}]interface{}
	variables  *data.Map
}

func taskApplyProxyRule(inctx context.Context, params interface{}) (
	_ interface{}, ferr fail.Error,
) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		p, ok := params.(taskApplyProxyRuleParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "is not a taskApplyProxyRuleParameters")}
			return
		}
		hostName, ok := (*p.variables)["Hostname"].(string)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("variables['Hostname']", "is not a string")}
			return
		}

		ruleName, xerr := p.controller.Apply(ctx, p.rule, p.variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			msg := "failed to apply proxy rule"
			if ruleName != "" {
				msg += " '" + ruleName + "'"
			}
			msg += " for host '" + hostName
			chRes <- result{nil, fail.Wrap(xerr, msg)}
			return
		}
		chRes <- result{nil, nil}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// identifyHosts identifies hosts concerned based on 'targets' and returns a list of hosts
func (w *worker) identifyHosts(inctx context.Context, targets stepTargets) ([]resources.Host, fail.Error) {
	defer elapsed("identifyHosts")()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []resources.Host
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		hostT, masterT, nodeT, gwT, xerr := targets.parse()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		var (
			hostsList []resources.Host
			all       []resources.Host
		)

		if w.cluster == nil {
			if hostT != "" {
				hostsList = append(hostsList, w.host)
			}
			chRes <- result{hostsList, nil}
			return
		}

		switch masterT {
		case "1":
			hostInstance, xerr := w.identifyAvailableMaster(ctx) // nolint
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
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
				chRes <- result{nil, xerr}
				return
			}
			hostsList = append(hostsList, all...)
		}

		switch nodeT {
		case "1":
			hostInstance, xerr := w.identifyAvailableNode(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
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
				chRes <- result{nil, xerr}
				return
			}
			hostsList = append(hostsList, all...)
		}

		switch gwT {
		case "1":
			hostInstance, xerr := w.identifyAvailableGateway(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
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
				chRes <- result{nil, xerr}
				return
			}
			hostsList = append(hostsList, all...)
		}

		chRes <- result{hostsList, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

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

	// Templates are badly generated again...
	suspectContent := dataBuffer.String()
	fragments := strings.Split(suspectContent, "\n")
	if strings.Contains(fragments[len(fragments)-1], "!(EXTRA") {
		corrected := strings.Join(fragments[0:len(fragments)-2], "\n")
		return corrected, nil
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
func (w *worker) setNetworkingSecurity(inctx context.Context) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		const yamlKey = "feature.security.networking"
		if ok := w.feature.Specs().IsSet(yamlKey); !ok {
			chRes <- result{nil}
			return
		}

		rules, ok := w.feature.Specs().Get(yamlKey).([]interface{})
		if !ok || len(rules) == 0 {
			chRes <- result{nil}
			return
		}

		var rs resources.Subnet
		var xerr fail.Error
		if w.cluster != nil {
			if netprops, xerr := w.cluster.GetNetworkConfig(ctx); xerr != nil {
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{xerr}
					return
				}
			} else {
				rs, xerr = LoadSubnet(ctx, w.service, netprops.NetworkID, netprops.SubnetID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{xerr}
					return
				}
			}
		} else if w.host != nil {
			rs, xerr = w.host.GetDefaultSubnet(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
		}

		forFeature := " for Feature '" + w.feature.GetName() + "'"

		for k, rule := range rules {
			r, ok := rule.(map[interface{}]interface{})
			if !ok {
				chRes <- result{fail.InvalidParameterError("rule", "should be a map[interface{}][interface{}]")}
				return
			}
			targets := w.interpretRuleTargets(r)

			// If security rules concerns gateways, update subnet Security Group for gateways
			if _, ok := targets["gateways"]; ok {
				description, ok := r["name"].(string)
				if !ok {
					chRes <- result{fail.SyntaxError("missing field 'name' from rule '%s' in '%s'", k, yamlKey)}
					return
				}

				gwSG, xerr := rs.InspectGatewaySecurityGroup(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{xerr}
					return
				}

				gwID, err := gwSG.GetID()
				if err != nil {
					chRes <- result{fail.ConvertError(err)}
					return
				}

				sgRule := abstract.NewSecurityGroupRule()
				sgRule.Direction = securitygroupruledirection.Ingress // Implicit for gateways
				sgRule.EtherType = ipversion.IPv4
				sgRule.Protocol, _ = r["protocol"].(string) // nolint
				sgRule.Sources = []string{"0.0.0.0/0"}
				sgRule.Targets = []string{gwID}

				var commaSplitted []string
				if ports, ok := r["ports"].(int); ok {
					sgRule.Description = description + fmt.Sprintf(" (port %d)", ports) + forFeature
					if ports > 65535 {
						chRes <- result{fail.SyntaxError("invalid value '%s' for field 'ports'", ports)}
						return
					}
					sgRule.PortFrom = int32(ports)

					xerr = gwSG.AddRule(ctx, sgRule)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrDuplicate:
							// This rule already exists, considered as a success and continue
							debug.IgnoreError2(ctx, xerr)
						default:
							chRes <- result{xerr}
							return
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
									chRes <- result{fail.SyntaxError("invalid value '%s' for field 'ports'", ports)}
									return
								}
								if len(dashSplitted) == 2 {
									portTo, err = strconv.Atoi(dashSplitted[0])
									err = debug.InjectPlannedError(err)
									if err != nil {
										chRes <- result{fail.SyntaxError("invalid value '%s' for field 'ports'", ports)}
										return
									}
								}
								sgRule.Description += fmt.Sprintf(" (port%s %s)", strprocess.Plural(uint(dashCount)), dashSplitted)

								if portFrom > 65535 {
									chRes <- result{fail.SyntaxError("invalid value '%d' for field 'portFrom'", portFrom)}
									return
								}
								if portTo > 65535 {
									chRes <- result{fail.SyntaxError("invalid value '%d' for field 'portTo'", portTo)}
									return
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
									debug.IgnoreError2(ctx, xerr)
								default:
									chRes <- result{xerr}
									return
								}
							}
						}
					}
				} else {
					chRes <- result{fail.SyntaxError("invalid value for ports in rule '%s'")}
					return
				}
			}
		}

		chRes <- result{nil}

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}

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
