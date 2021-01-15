/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
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
	feature   *feature
	target    resources.Targetable
	method    installmethod.Enum
	action    installaction.Enum
	variables data.Map
	settings  resources.FeatureSettings
	startTime time.Time

	host resources.Host
	// node    bool
	cluster resources.Cluster

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
		feature:   f.(*feature),
		target:    t,
		method:    m,
		action:    a,
		commandCB: cb,
	}
	switch t.TargetType() {
	case featuretargettype.CLUSTER:
		w.cluster = t.(resources.Cluster)
	// case featuretargettype.NODE:
	// 	w.node = true
	// 	fallthrough
	case featuretargettype.HOST:
		w.host = t.(resources.Host)
	}

	w.rootKey = "feature.install." + strings.ToLower(m.String()) + "." + strings.ToLower(a.String())
	if !f.(*feature).Specs().IsSet(w.rootKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename(), w.rootKey)
	}

	return &w, nil
}

// ConcernsCluster returns true if the target of the worker is a cluster
func (w *worker) ConcernsCluster() bool {
	return w.cluster != nil
}

// CanProceed tells if the combination Feature/Target can work
func (w *worker) CanProceed(s resources.FeatureSettings) fail.Error {
	switch w.target.TargetType() {
	case featuretargettype.CLUSTER:
		xerr := w.validateContextForCluster()
		if xerr == nil && !s.SkipSizingRequirements {
			xerr = w.validateClusterSizing()
		}
		return xerr
	// case featuretargettype.NODE:
	// 	return nil
	case featuretargettype.HOST:
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
func (w *worker) identifyAvailableMaster() (resources.Host, fail.Error) {
	if w.cluster == nil {
		return nil, abstract.ResourceNotAvailableError("cluster", "")
	}
	if w.availableMaster == nil {
		var xerr fail.Error
		w.availableMaster, xerr = w.cluster.FindAvailableMaster(w.feature.task)
		if xerr != nil {
			return nil, xerr
		}
	}
	return w.availableMaster, nil
}

// identifyAvailableNode finds a node available and will use this one during all the install session
func (w *worker) identifyAvailableNode() (resources.Host, fail.Error) {
	if w.cluster == nil {
		return nil, abstract.ResourceNotAvailableError("cluster", "")
	}
	if w.availableNode == nil {
		var xerr fail.Error
		w.availableNode, xerr = w.cluster.FindAvailableNode(w.feature.task)
		if xerr != nil {
			return nil, xerr
		}
	}
	return w.availableNode, nil
}

// identifyConcernedMasters returns a list of all the hosts acting as masters and keep this list
// during all the install session
func (w *worker) identifyConcernedMasters() ([]resources.Host, fail.Error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.concernedMasters == nil {
		hosts, xerr := w.identifyAllMasters()
		if xerr != nil {
			return nil, xerr
		}
		concernedHosts, xerr := w.extractHostsFailingCheck(hosts)
		if xerr != nil {
			return nil, xerr
		}
		w.concernedMasters = concernedHosts
	}
	return w.concernedMasters, nil
}

// extractHostsFailingCheck identifies from the list passed as parameter which
// hosts fail feature check.
// The checks are done in parallel.
func (w *worker) extractHostsFailingCheck(hosts []resources.Host) ([]resources.Host, fail.Error) {
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
			r2, innerXErr := w.feature.Check(host, w.variables, settings)
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
func (w *worker) identifyAllMasters() ([]resources.Host, fail.Error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}
	if w.allMasters == nil || len(w.allMasters) == 0 {
		w.allMasters = []resources.Host{}
		masters, xerr := w.cluster.ListMasterIDs(w.feature.task)
		if xerr != nil {
			return nil, xerr
		}
		for _, i := range masters {
			host, xerr := LoadHost(w.feature.task, w.cluster.GetService(), i)
			if xerr != nil {
				return nil, xerr
			}
			w.allMasters = append(w.allMasters, host)
		}
	}
	return w.allMasters, nil
}

// identifyConcernedNodes returns a list of all the hosts acting nodes and keep this list
// during all the install session
func (w *worker) identifyConcernedNodes() ([]resources.Host, fail.Error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.concernedNodes == nil {
		hosts, xerr := w.identifyAllNodes()
		if xerr != nil {
			return nil, xerr
		}

		concernedHosts, xerr := w.extractHostsFailingCheck(hosts)
		if xerr != nil {
			return nil, xerr
		}

		w.concernedNodes = concernedHosts
	}
	return w.concernedNodes, nil
}

// identifyAllNodes returns a list of all the hosts acting as public of private nodes and keep this list
// during all the install session
func (w *worker) identifyAllNodes() ([]resources.Host, fail.Error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.allNodes == nil {
		var allHosts []resources.Host
		list, xerr := w.cluster.ListNodeIDs(w.feature.task)
		if xerr != nil {
			return nil, xerr
		}
		for _, i := range list {
			host, xerr := LoadHost(w.feature.task, w.cluster.GetService(), i)
			if xerr != nil {
				return nil, xerr
			}
			allHosts = append(allHosts, host)
		}
		w.allNodes = allHosts
	}
	return w.allNodes, nil
}

// identifyAvailableGateway finds a gateway available, and keep track of it
// for all the life of the action (prevent to request too often)
// For now, only one gateway is allowed, but in the future we may have 2 for High Availability
func (w *worker) identifyAvailableGateway() (resources.Host, fail.Error) {
	if w.availableGateway != nil {
		return w.availableGateway, nil
	}

	// Not in cluster context
	if w.cluster == nil {
		subnet, xerr := w.host.GetDefaultSubnet(w.feature.task)
		if xerr != nil {
			return nil, xerr
		}

		gw, xerr := subnet.GetGateway(w.feature.task, true)
		if xerr == nil {
			_, xerr = gw.WaitSSHReady(w.feature.task, temporal.GetConnectSSHTimeout())
		}

		if xerr != nil {
			if gw, xerr = subnet.GetGateway(w.feature.task, false); xerr == nil {
				_, xerr = gw.WaitSSHReady(w.feature.task, temporal.GetConnectSSHTimeout())
			}
		}

		if xerr != nil {
			return nil, fail.NotAvailableError("no gateway available")
		}

		w.availableGateway = gw
	} else {
		// FIXME: secondary gateway not tried if the primary doesn't respond in time
		// In cluster context
		netCfg, xerr := w.cluster.GetNetworkConfig(w.feature.task)
		if xerr == nil {
			w.availableGateway, xerr = LoadHost(w.feature.task, w.cluster.GetService(), netCfg.GatewayID)
		}
		if xerr != nil {
			return nil, xerr
		}
	}
	return w.availableGateway, nil
}

// identifyConcernedGateways returns a list of all the hosts acting as gateway that can accept the action
// and keep this list during all the install session
func (w *worker) identifyConcernedGateways() (_ []resources.Host, xerr fail.Error) {
	var hosts []resources.Host

	//if w.host != nil {
	//	host, xerr := gatewayFromHost(w.feature.task, w.host)
	//	if xerr != nil {
	//		return nil, xerr
	//	}
	//	hosts = []resources.IPAddress{host}
	//} else if w.cluster != nil {
	hosts, xerr = w.identifyAllGateways()
	if xerr != nil {
		return nil, xerr
	}
	//}

	concernedHosts, xerr := w.extractHostsFailingCheck(hosts)
	if xerr != nil {
		return nil, xerr
	}

	w.concernedGateways = concernedHosts
	return w.concernedGateways, nil
}

// identifyAllGateways returns a list of all the hosts acting as gateways and keep this list
// during all the install session
func (w *worker) identifyAllGateways() (_ []resources.Host, xerr fail.Error) {
	if w.allGateways != nil {
		return w.allGateways, nil
	}

	var (
		list []resources.Host
		rs   resources.Subnet
	)

	if w.cluster != nil {
		netCfg, xerr := w.cluster.GetNetworkConfig(w.feature.task)
		if xerr != nil {
			return nil, xerr
		}
		rs, xerr = LoadSubnet(w.feature.task, w.cluster.GetService(), "", netCfg.SubnetID)
		if xerr != nil {
			return nil, xerr
		}
	} else {
		rs, xerr = w.host.GetDefaultSubnet(w.feature.task)
		if xerr != nil {
			return nil, xerr
		}
	}

	gw, xerr := rs.GetGateway(w.feature.task, true)
	if xerr == nil {
		if _, xerr = gw.WaitSSHReady(w.feature.task, temporal.GetConnectSSHTimeout()); xerr == nil {
			list = append(list, gw)
		}
	}
	if gw, xerr = rs.GetGateway(w.feature.task, false); xerr == nil {
		if _, xerr = gw.WaitSSHReady(w.feature.task, temporal.GetConnectSSHTimeout()); xerr == nil {
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
func (w *worker) Proceed(v data.Map, s resources.FeatureSettings) (outcomes resources.Results, xerr fail.Error) {
	w.variables = v
	w.settings = s

	outcomes = &results{}

	// 'pace' tells the order of execution
	pace := w.feature.specs.GetString(w.rootKey + "." + yamlPaceKeyword)
	if pace == "" {
		return nil, fail.SyntaxError("missing or empty key %s.%s", w.rootKey, yamlPaceKeyword)
	}

	// 'steps' describes the steps of the action
	stepsKey := w.rootKey + "." + yamlStepsKeyword
	steps := w.feature.specs.GetStringMap(stepsKey)
	if len(steps) == 0 {
		return nil, fail.InvalidRequestError("nothing to do")
	}
	order := strings.Split(pace, ",")

	// Applies reverseproxy rules to make it functional (feature may need it during the install)
	if w.action == installaction.Add && !s.SkipProxy {
		if w.cluster != nil {
			if xerr := w.setReverseProxy(); xerr != nil {
				return nil, xerr
			}
		}
	}

	// Now enumerate steps and execute each of them
	for _, k := range order {
		stepKey := stepsKey + "." + k
		stepMap, ok := steps[strings.ToLower(k)].(map[string]interface{})
		if !ok {
			msg := `syntax error in feature '%s' specification file (%s): no key '%s' found`
			return outcomes, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(), stepKey)
		}
		params := data.Map{
			"stepName":  k,
			"stepKey":   stepKey,
			"stepMap":   stepMap,
			"variables": v,
		}

		subtask, xerr := w.feature.task.StartInSubtask(w.taskLaunchStep, params)
		if xerr != nil {
			return outcomes, xerr
		}

		tr, xerr := subtask.Wait()
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

// taskLaunchStep starts the step
func (w *worker) taskLaunchStep(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	if w == nil {
		return nil, fail.InvalidInstanceError()
	}
	if params == nil {
		return nil, fail.InvalidParameterError("params", "can't be nil")
	}
	if w.feature == nil {
		return nil, fail.InvalidInstanceContentError("w.feature", "cannot be nil")
	}

	var (
		anon              interface{}
		stepName, stepKey string
		stepMap           map[string]interface{}
		vars              data.Map
		ok                bool
	)
	p := params.(data.Map)

	if anon, ok = p["stepName"]; !ok {
		return nil, fail.InvalidParameterError("params[stepName]", "is missing")
	}
	if stepName, ok = anon.(string); !ok {
		return nil, fail.InvalidParameterError("param[stepName]", "must be a string")
	}
	if stepName == "" {
		return nil, fail.InvalidParameterError("param[stepName]", "cannot be an empty string")
	}
	if anon, ok = p["stepKey"]; !ok {
		return nil, fail.InvalidParameterError("params[stepKey]", "is missing")
	}
	if stepKey, ok = anon.(string); !ok {
		return nil, fail.InvalidParameterError("param[stepKey]", "must be a string")
	}
	if stepKey == "" {
		return nil, fail.InvalidParameterError("param[stepKey]", "cannot be an empty string")
	}
	if anon, ok = p["stepMap"]; !ok {
		return nil, fail.InvalidParameterError("params[stepMap]", "is missing")
	}
	if stepMap, ok = anon.(map[string]interface{}); !ok {
		return nil, fail.InvalidParameterError("params[stepMap]", "must be a map[string]interface{}")
	}
	if anon, ok = p["variables"]; !ok {
		return nil, fail.InvalidParameterError("params[variables]", "is missing")
	}
	if vars, ok = anon.(data.Map); !ok {
		return nil, fail.InvalidParameterError("params[variables]", "must be a data.Map")
	}
	if vars == nil {
		return nil, fail.InvalidParameterError("params[variables]", "cannot be nil")
	}

	defer fail.OnExitLogError(&xerr, fmt.Sprintf("executed step '%s::%s'", w.action.String(), stepName))
	defer temporal.NewStopwatch().OnExitLogWithLevel(
		fmt.Sprintf("Starting execution of step '%s::%s'...", w.action.String(), stepName),
		fmt.Sprintf("Ending execution of step '%s::%s'", w.action.String(), stepName),
		logrus.DebugLevel,
	)

	var (
		runContent string
		stepT      = stepTargets{}
		options    = map[string]string{}
	)

	// Determine list of hosts concerned by the step
	var hostsList []resources.Host
	if w.target.TargetType() == featuretargettype.HOST {
		hostsList, xerr = w.identifyHosts(map[string]string{"hosts": "1"})
	} else {
		anon, ok = stepMap[yamlTargetsKeyword]
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
			msg := `syntax error in feature '%s' specification file (%s): no key '%s.%s' found`
			return nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(), stepKey, yamlTargetsKeyword)
		}

		hostsList, xerr = w.identifyHosts(stepT)
	}
	if xerr != nil {
		return nil, xerr
	}
	if len(hostsList) == 0 {
		return nil, nil
	}

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
	anon, ok = stepMap[keyword]
	if ok {
		runContent = anon.(string)
		// If 'run' content has to be altered, do it
		if w.commandCB != nil {
			runContent = w.commandCB(runContent)
		}
	} else {
		msg := `syntax error in feature '%s' specification file (%s): no key '%s.%s' found`
		return nil, fail.SyntaxError(msg, w.feature.GetName(), w.feature.GetDisplayFilename(), stepKey, yamlRunKeyword)
	}

	// If there is an options file (for now specific to DCOS), upload it to the remote host
	optionsFileContent := ""
	anon, ok = stepMap[yamlOptionsKeyword]
	if ok {
		for i, j := range anon.(map[string]interface{}) {
			options[i] = j.(string)
		}
		var (
			avails  = map[string]interface{}{}
			ok      bool
			content interface{}
		)
		complexity, xerr := w.cluster.GetComplexity(w.feature.task)
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
			vars["options"] = fmt.Sprintf("--options=%s/options.json", utils.TempFolder)
		}
	} else {
		vars["options"] = ""
	}

	wallTime := temporal.GetLongOperationTimeout()
	anon, ok = stepMap[yamlTimeoutKeyword]
	if ok {
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
		"reserved_Step":    stepName,
	})
	if xerr != nil {
		return nil, xerr
	}

	// Checks if step can be performed in parallel on selected hosts
	serial := false
	anon, ok = stepMap[yamlSerialKeyword]
	if ok {
		value, ok := anon.(string)
		if ok {
			if strings.ToLower(value) == "yes" || strings.ToLower(value) != "true" {
				serial = true
			}
		}
	}

	stepInstance := step{
		Worker: w,
		Name:   stepName,
		Action: w.action,
		// Targets:            stepT,
		Script:             templateCommand,
		WallTime:           wallTime,
		OptionsFileContent: optionsFileContent,
		YamlKey:            stepKey,
		Serial:             serial,
	}
	r, xerr := stepInstance.Run(hostsList, vars, w.settings)
	// If an error occurred, don't do the remaining steps, fail immediately
	if xerr != nil {
		return nil, xerr
	}

	if !r.Successful() {
		// If there are some not completed steps, reports them and break
		if !r.Completed() {
			msg := fmt.Sprintf("execution of step '%s::%s' failed on: %v", w.action.String(), stepName, r.Uncompleted())
			logrus.Errorf(strprocess.Capitalize(msg))
			return &r, fail.NewError(msg)
		}
		// not successful but completed, if action is check means the feature is not installed, it's an information not a failure
		if w.action == installaction.Check {
			return &r, nil
		}

		// For any other situations, raise error and break
		msg := fmt.Sprintf("execution of step '%s::%s' failed on: %v", w.action.String(), stepName, r.ErrorMessages())
		logrus.Errorf(strprocess.Capitalize(msg))
		return &r, fail.NewError(msg)
	}

	return &r, nil
}

// validateContextForCluster checks if the flavor of the cluster is listed in feature specification
// 'feature.suitableFor.cluster'.
// If no flavors is listed, no flavors are authorized (but using 'cluster: no' is strongly recommended)
func (w *worker) validateContextForCluster() fail.Error {
	clusterFlavor, xerr := w.cluster.GetFlavor(w.feature.task)
	if xerr != nil {
		return xerr
	}

	yamlKey := "feature.suitableFor.cluster"
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
	msg := fmt.Sprintf("feature '%s' not suitable for flavor '%s' of the targeted cluster", w.feature.GetName(), clusterFlavor.String())
	return fail.NotAvailableError(msg)
}

// validateContextForHost ...
func (w *worker) validateContextForHost(settings resources.FeatureSettings) fail.Error {
	if settings.IgnoreSuitability /* || w.node*/ {
		return nil
	}

	ok := false
	yamlKey := "feature.suitableFor.host"
	if w.feature.specs.IsSet(yamlKey) {
		value := strings.ToLower(w.feature.specs.GetString(yamlKey))
		ok = value == "ok" || value == "yes" || value == "true" || value == "1"
	}
	if ok {
		return nil
	}

	return fail.NotAvailableError("feature '%s' not suitable for host", w.feature.GetName())
}

func (w *worker) validateClusterSizing() (xerr fail.Error) {
	clusterFlavor, xerr := w.cluster.GetFlavor(w.feature.task)
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
		if xerr != nil {
			return xerr
		}
		masters, xerr := w.cluster.ListMasterIDs(w.feature.task)
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
		if xerr != nil {
			return xerr
		}
		list, xerr := w.cluster.ListNodeIDs(w.feature.task)
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
func (w *worker) setReverseProxy() (xerr fail.Error) {
	rules, ok := w.feature.specs.Get("feature.proxy.rules").([]interface{})
	if !ok || len(rules) == 0 {
		return nil
	}

	if w.cluster == nil {
		return fail.InvalidParameterError("w.cluster", "nil cluster in setReverseProxy, cannot be nil")
	}

	if w.feature.task.IsNull() {
		return fail.InvalidParameterError("w.feature.task", "nil task in setReverseProxy, cannot be nil")
	}

	svc := w.cluster.GetService()
	netprops, xerr := w.cluster.GetNetworkConfig(w.feature.task)
	if xerr != nil {
		return xerr
	}
	subnet, xerr := LoadSubnet(w.feature.task, svc, "", netprops.SubnetID)
	if xerr != nil {
		return xerr
	}

	primaryKongController, xerr := NewKongController(svc, subnet, true)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to apply reverse proxy rules")
	}
	var secondaryKongController *KongController
	if subnet.HasVirtualIP(w.feature.task) {
		if secondaryKongController, xerr = NewKongController(svc, subnet, false); xerr != nil {
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
		targets := stepTargets{}
		rule, ok := r.(map[interface{}]interface{})
		if !ok {
			return fail.InvalidParameterError("r", "is not a rule (map)")
		}
		anon, ok := rule["targets"].(map[interface{}]interface{})
		if !ok {
			// If no 'targets' key found, applies on host only
			if w.cluster != nil {
				continue
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
		hosts, xerr := w.identifyHosts(targets)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to apply proxy rules: %s")
		}

		for _, h := range hosts {
			if primaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP(w.feature.task); xerr != nil {
				return xerr
			}
			primaryGatewayVariables["ShortHostname"] = h.GetName()
			domain := ""
			xerr = h.Inspect(w.feature.task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Inspect(w.feature.task, hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
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
			if xerr != nil {
				return xerr
			}

			primaryGatewayVariables["Hostname"] = h.GetName() + domain

			tP, xerr := w.feature.task.StartInSubtask(asyncApplyProxyRule, data.Map{
				"ctrl": primaryKongController,
				"rule": rule,
				"vars": &primaryGatewayVariables,
			})
			if xerr != nil {
				return fail.Wrap(xerr, "failed to apply proxy rules")
			}

			var errS fail.Error
			if secondaryKongController != nil {
				if secondaryGatewayVariables["HostIP"], xerr = h.GetPrivateIP(w.feature.task); xerr != nil {
					return xerr
				}
				secondaryGatewayVariables["ShortHostname"] = h.GetName()
				domain = ""
				xerr = h.Inspect(w.feature.task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Inspect(w.feature.task, hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
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
				if xerr != nil {
					return xerr
				}
				secondaryGatewayVariables["Hostname"] = h.GetName() + domain

				tS, errOp := w.feature.task.StartInSubtask(asyncApplyProxyRule, data.Map{
					"ctrl": secondaryKongController,
					"rule": rule,
					"vars": &secondaryGatewayVariables,
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

func asyncApplyProxyRule(task concurrency.Task, params concurrency.TaskParameters) (tr concurrency.TaskResult, xerr fail.Error) {
	ctrl, ok := params.(data.Map)["ctrl"].(*KongController)
	if !ok {
		return nil, fail.InvalidParameterError("ctrl", "is not a *KongController")
	}
	rule, ok := params.(data.Map)["rule"].(map[interface{}]interface{})
	if !ok {
		return nil, fail.InvalidParameterError("rule", "is not a map")
	}
	vars, ok := params.(data.Map)["vars"].(*data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("vars", "is not a '*data.Map'")
	}
	hostName, ok := (*vars)["Hostname"].(string)
	if !ok {
		return nil, fail.InvalidParameterError("Hostname", "is not a string")
	}

	ruleName, xerr := ctrl.Apply(rule, vars)
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
func (w *worker) identifyHosts(targets stepTargets) ([]resources.Host, fail.Error) {
	hostT, masterT, nodeT, gwT, xerr := targets.parse()
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
		host, xerr := w.identifyAvailableMaster()
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, host)
	case "*":
		if w.action == installaction.Add {
			all, xerr = w.identifyConcernedMasters()
		} else {
			all, xerr = w.identifyAllMasters()
		}
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, all...)
	}

	switch nodeT {
	case "1":
		host, xerr := w.identifyAvailableNode()
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, host)
	case "*":
		if w.action == installaction.Add {
			all, xerr = w.identifyConcernedNodes()
		} else {
			all, xerr = w.identifyAllNodes()
		}
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, all...)
	}

	switch gwT {
	case "1":
		host, xerr := w.identifyAvailableGateway()
		if xerr != nil {
			return nil, xerr
		}
		hostsList = append(hostsList, host)
	case "*":
		if w.action == installaction.Add {
			all, xerr = w.identifyConcernedGateways()
		} else {
			all, xerr = w.identifyAllGateways()
		}
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
		if xerr != nil {
			return "", fail.SyntaxError("error parsing bash template: %s", xerr.Error())
		}
		featureScriptTemplate.Store(r)
		anon = featureScriptTemplate.Load()
	}

	// Configures BashLibrary template var
	bashLibrary, xerr := system.GetBashLibrary()
	if xerr != nil {
		return "", xerr
	}
	params["reserved_BashLibrary"] = bashLibrary

	dataBuffer := bytes.NewBufferString("")
	err = anon.(*txttmpl.Template).Execute(dataBuffer, params)
	if err != nil {
		return "", fail.ToError(err)
	}

	return dataBuffer.String(), nil
}
