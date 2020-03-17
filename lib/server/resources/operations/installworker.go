/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"strconv"
	"strings"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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

	host    resources.Host
	node    bool
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
func newWorker(f resources.Feature, t resources.Targetable, m installmethod.Enum, a installaction.Enum, cb alterCommandCB) (*worker, error) {
	w := worker{
		feature:   f.(*feature),
		target:    t,
		method:    m,
		action:    a,
		commandCB: cb,
	}
	switch t.SafeGetTargetType() {
	case featuretargettype.CLUSTER:
		w.cluster = t.(resources.Cluster)
	case featuretargettype.NODE:
		w.node = true
		fallthrough
	case featuretargettype.HOST:
		w.host = t.(resources.Host)
	}

	w.rootKey = "feature.install." + strings.ToLower(m.String()) + "." + strings.ToLower(a.String())
	if !f.SafeGetSpecs().IsSet(w.rootKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, scerr.SyntaxError(msg, f.SafeGetName(), f.SafeGetDisplayFilename(), w.rootKey)
	}

	return &w, nil
}

// ConcernsCluster returns true if the target of the worker is a cluster
func (w *worker) ConcernsCluster() bool {
	return w.cluster != nil
}

// CanProceed tells if the combination Feature/Target can work
func (w *worker) CanProceed(s resources.FeatureSettings) error {
	switch w.target.SafeGetTargetType() {
	case featuretargettype.CLUSTER:
		err := w.validateContextForCluster()
		if err == nil && !s.SkipSizingRequirements {
			err = w.validateClusterSizing()
		}
		return err
	case featuretargettype.NODE:
		return nil
	case featuretargettype.HOST:
		return w.validateContextForHost()
	}
	return nil
}

// identifyAvailableMaster finds a master available, and keep track of it
// for all the life of the action (prevent to request too often)
func (w *worker) identifyAvailableMaster() (resources.Host, error) {
	if w.cluster == nil {
		return nil, abstract.ResourceNotAvailableError("cluster", "")
	}
	if w.availableMaster == nil {
		var err error
		w.availableMaster, err = w.cluster.FindAvailableMaster(w.feature.task)
		if err != nil {
			return nil, err
		}
	}
	return w.availableMaster, nil
}

// identifyAvailableNode finds a node available and will use this one during all the install session
func (w *worker) identifyAvailableNode() (resources.Host, error) {
	if w.cluster == nil {
		return nil, abstract.ResourceNotAvailableError("cluster", "")
	}
	if w.availableNode == nil {
		var err error
		w.availableNode, err = w.cluster.FindAvailableNode(w.feature.task)
		if err != nil {
			return nil, err
		}
	}
	return w.availableNode, nil
}

// identifyConcernedMasters returns a list of all the hosts acting as masters and keep this list
// during all the install session
func (w *worker) identifyConcernedMasters() ([]resources.Host, error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}
	if w.concernedMasters == nil {
		hosts, err := w.identifyAllMasters()
		if err != nil {
			return nil, err
		}
		concernedHosts, err := w.extractHostsFailingCheck(hosts)
		if err != nil {
			return nil, err
		}
		w.concernedMasters = concernedHosts
	}
	return w.concernedMasters, nil
}

// extractHostsFailingCheck identifies from the list passed as parameter which
// hosts fail feature check.
// The checks are done in parallel.
func (w *worker) extractHostsFailingCheck(hosts []resources.Host) ([]resources.Host, error) {
	var concernedHosts []resources.Host
	dones := map[resources.Host]chan error{}
	results := map[resources.Host]chan resources.Results{}
	for _, h := range hosts {
		d := make(chan error)
		r := make(chan resources.Results)
		dones[h] = d
		results[h] = r
		go func(host resources.Host, res chan resources.Results, done chan error) {
			results, err := w.feature.Check(host, w.variables, w.settings)
			if err != nil {
				res <- nil
				done <- err
				return
			}
			res <- results
			done <- nil
		}(h, r, d)
	}
	for h := range dones {
		r := <-results[h]
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
func (w *worker) identifyAllMasters() ([]resources.Host, error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}
	if w.allMasters == nil || len(w.allMasters) == 0 {
		w.allMasters = []resources.Host{}
		masters, err := w.cluster.ListMasterIDs(w.feature.task)
		if err != nil {
			return nil, err
		}
		for _, i := range masters {
			host, err := LoadHost(w.feature.task, w.cluster.SafeGetService(), i)
			if err != nil {
				return nil, err
			}
			w.allMasters = append(w.allMasters, host)
		}
	}
	return w.allMasters, nil
}

// identifyConcernedNodes returns a list of all the hosts acting nodes and keep this list
// during all the install session
func (w *worker) identifyConcernedNodes() ([]resources.Host, error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.concernedNodes == nil {
		hosts, err := w.identifyAllNodes()
		if err != nil {
			return nil, err
		}
		concernedHosts, err := w.extractHostsFailingCheck(hosts)
		if err != nil {
			return nil, err
		}
		w.concernedNodes = concernedHosts
	}
	return w.concernedNodes, nil
}

// identifyAllNodes returns a list of all the hosts acting as public of private nodes and keep this list
// during all the install session
func (w *worker) identifyAllNodes() ([]resources.Host, error) {
	if w.cluster == nil {
		return []resources.Host{}, nil
	}

	if w.allNodes == nil {
		var allHosts []resources.Host
		list, err := w.cluster.ListNodeIDs(w.feature.task)
		if err != nil {
			return nil, err
		}
		for _, i := range list {
			host, err := LoadHost(w.feature.task, w.cluster.SafeGetService(), i)
			if err != nil {
				return nil, err
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
func (w *worker) identifyAvailableGateway() (resources.Host, error) {
	if w.availableGateway != nil {
		return w.availableGateway, nil
	}

	// Not in cluster context
	if w.cluster == nil {
		network, err := w.host.GetDefaultNetwork(w.feature.task)
		if err != nil {
			return nil, err
		}

		gw, err := network.GetGateway(w.feature.task, true)
		if err == nil {
			_, err = gw.WaitSSHReady(w.feature.task, temporal.GetConnectSSHTimeout())
		}

		if err != nil {
			gw, err = network.GetGateway(w.feature.task, false)
			if err == nil {
				_, err = gw.WaitSSHReady(w.feature.task, temporal.GetConnectSSHTimeout())
			}
		}

		if err != nil {
			return nil, scerr.NotAvailableError("no gateway available")
		}

		w.availableGateway = gw
	} else {
		// FIXME: secondary gateway not tried if the primary doesn't respond in time
		// In cluster context
		netCfg, err := w.cluster.GetNetworkConfig(w.feature.task)
		if err == nil {
			w.availableGateway, err = LoadHost(w.feature.task, w.cluster.SafeGetService(), netCfg.GatewayID)
		}
		if err != nil {
			return nil, err
		}
	}
	return w.availableGateway, nil
}

// identifyConcernedGateways returns a list of all the hosts acting as gateway that can accept the action
// and keep this list during all the install session
func (w *worker) identifyConcernedGateways() ([]resources.Host, error) {
	var hosts []resources.Host

	if w.host != nil {
		host, err := gatewayFromHost(w.feature.task, w.host)
		if err != nil {
			return nil, err
		}
		hosts = []resources.Host{host}
	} else if w.cluster != nil {
		var err error
		hosts, err = w.identifyAllGateways()
		if err != nil {
			return nil, err
		}
	}

	concernedHosts, err := w.extractHostsFailingCheck(hosts)
	if err != nil {
		return nil, err
	}
	w.concernedGateways = concernedHosts
	return w.concernedGateways, nil
}

// identifyAllGateways returns a list of all the hosts acting as gateways and keep this list
// during all the install session
func (w *worker) identifyAllGateways() ([]resources.Host, error) {
	if w.allGateways != nil {
		return w.allGateways, nil
	}

	var (
		list    []resources.Host
		network resources.Network
		err     error
	)

	if w.cluster != nil {
		netCfg, err := w.cluster.GetNetworkConfig(w.feature.task)
		if err != nil {
			return nil, err
		}
		network, err = LoadNetwork(w.feature.task, w.cluster.SafeGetService(), netCfg.NetworkID)
		if err != nil {
			return nil, err
		}
	} else {
		network, err = w.host.GetDefaultNetwork(w.feature.task)
		if err != nil {
			return nil, err
		}
	}

	gw, err := network.GetGateway(w.feature.task, true)
	if err == nil {
		_, err = gw.WaitSSHReady(w.feature.task, temporal.GetConnectSSHTimeout())
		if err == nil {
			list = append(list, gw)
		}
	}
	gw, err = network.GetGateway(w.feature.task, false)
	if err == nil {
		_, err = gw.WaitSSHReady(w.feature.task, temporal.GetConnectSSHTimeout())
		if err == nil {
			list = append(list, gw)
		}
	}
	if len(list) == 0 {
		return nil, scerr.NotAvailableError("no gateways currently available")
	}
	w.allGateways = list
	return list, nil
}

// Proceed executes the action
func (w *worker) Proceed(v data.Map, s resources.FeatureSettings) (outcomes resources.Results, err error) {
	w.variables = v
	w.settings = s

	outcomes = &results{}

	// 'pace' tells the order of execution
	pace := w.feature.specs.GetString(w.rootKey + "." + yamlPaceKeyword)
	if pace == "" {
		return nil, scerr.SyntaxError("missing or empty key %s.%s", w.rootKey, yamlPaceKeyword)
	}

	// 'steps' describes the steps of the action
	stepsKey := w.rootKey + "." + yamlStepsKeyword
	steps := w.feature.specs.GetStringMap(stepsKey)
	if len(steps) == 0 {
		return nil, scerr.InvalidRequestError("nothing to do")
	}
	order := strings.Split(pace, ",")

	// Applies reverseproxy rules to make it functional (feature may need it during the install)
	if w.action == installaction.Add && !s.SkipProxy {
		if w.cluster != nil {
			err := w.setReverseProxy()
			if err != nil {
				return nil, err
			}
		}
	}

	// Now enumerate steps and execute each of them
	for _, k := range order {
		stepKey := stepsKey + "." + k
		stepMap, ok := steps[strings.ToLower(k)].(map[string]interface{})
		if !ok {
			msg := `syntax error in feature '%s' specification file (%s): no key '%s' found`
			return outcomes, scerr.SyntaxError(msg, w.feature.SafeGetName(), w.feature.SafeGetDisplayFilename(), stepKey)
		}
		params := data.Map{
			"stepName":  k,
			"stepKey":   stepKey,
			"stepMap":   stepMap,
			"variables": v,
		}

		subtask, err := w.feature.task.StartInSubtask(w.taskLaunchStep, params)
		if err != nil {
			return outcomes, err
		}

		tr, err := subtask.Wait()
		if tr != nil {
			outcome := tr.(resources.UnitResults)
			_ = outcomes.Add(k, outcome)
		}
		if err != nil {
			return outcomes, err
		}
	}
	return outcomes, nil
}

// taskLaunchStep starts the step
func (w *worker) taskLaunchStep(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, err error) {
	if w == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if params == nil {
		return nil, scerr.InvalidParameterError("params", "can't be nil")
	}
	if w.feature == nil {
		return nil, scerr.InvalidInstanceContentError("w.feature", "cannot be nil")
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
		return nil, scerr.InvalidParameterError("params[stepName]", "is missing")
	}
	if stepName, ok = anon.(string); !ok {
		return nil, scerr.InvalidParameterError("param[stepName]", "must be a string")
	}
	if stepName == "" {
		return nil, scerr.InvalidParameterError("param[stepName]", "cannot be an empty string")
	}
	if anon, ok = p["stepKey"]; !ok {
		return nil, scerr.InvalidParameterError("params[stepKey]", "is missing")
	}
	if stepKey, ok = anon.(string); !ok {
		return nil, scerr.InvalidParameterError("param[stepKey]", "must be a string")
	}
	if stepKey == "" {
		return nil, scerr.InvalidParameterError("param[stepKey]", "cannot be an empty string")
	}
	if anon, ok = p["stepMap"]; !ok {
		return nil, scerr.InvalidParameterError("params[stepMap]", "is missing")
	}
	if stepMap, ok = anon.(map[string]interface{}); !ok {
		return nil, scerr.InvalidParameterError("params[stepMap]", "must be a map[string]interface{}")
	}
	if anon, ok = p["variables"]; !ok {
		return nil, scerr.InvalidParameterError("params[variables]", "is missing")
	}
	if vars, ok = anon.(data.Map); !ok {
		return nil, scerr.InvalidParameterError("params[variables]", "must be a data.Map")
	}
	if vars == nil {
		return nil, scerr.InvalidParameterError("params[variables]", "cannot be nil")
	}

	defer scerr.OnExitLogError(fmt.Sprintf("executed step '%s::%s'", w.action.String(), stepName), &err)()
	defer temporal.NewStopwatch().OnExitLogWithLevel(
		fmt.Sprintf("Starting execution of step '%s::%s'...", w.action.String(), stepName),
		fmt.Sprintf("Ending execution of step '%s::%s'", w.action.String(), stepName),
		logrus.DebugLevel,
	)()

	var (
		runContent string
		stepT      = stepTargets{}
		options    = map[string]string{}
	)

	// Determine list of hosts concerned by the step
	var hostsList []resources.Host
	if w.target.SafeGetTargetType() == featuretargettype.NODE {
		hostsList, err = w.identifyHosts(map[string]string{"hosts": "1"})
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
			return nil, scerr.SyntaxError(msg, w.feature.SafeGetName(), w.feature.SafeGetDisplayFilename(), stepKey, yamlTargetsKeyword)
		}

		hostsList, err = w.identifyHosts(stepT)
	}
	if err != nil {
		return nil, err
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
		return nil, scerr.SyntaxError(msg, w.feature.SafeGetName(), w.feature.SafeGetDisplayFilename(), stepKey, yamlRunKeyword)
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
		complexity, err := w.cluster.GetComplexity(w.feature.task)
		if err != nil {
			return nil, err
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

	templateCommand, err := normalizeScript(data.Map{
		"reserved_Name":    w.feature.SafeGetName(),
		"reserved_Content": runContent,
		"reserved_Action":  strings.ToLower(w.action.String()),
		"reserved_Step":    stepName,
	})
	if err != nil {
		return nil, err
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
		Worker:             w,
		Name:               stepName,
		Action:             w.action,
		Targets:            stepT,
		Script:             templateCommand,
		WallTime:           wallTime,
		OptionsFileContent: optionsFileContent,
		YamlKey:            stepKey,
		Serial:             serial,
	}
	r, err := stepInstance.Run(hostsList, vars, w.settings)
	// If an error occurred, don't do the remaining steps, fail immediately
	if err != nil {
		return nil, err
	}

	if !r.Successful() {
		// If there are some not completed steps, reports them and break
		if !r.Completed() {
			logrus.Warnf("execution of step '%s::%s' failed on: %v", w.action.String(), stepName, r.Uncompleted())
			return &r, scerr.NewError(r.ErrorMessages())
		}
		// not successful but completed, if action is check means the feature is not install, it's an information not a failure
		if strings.Contains(w.action.String(), "Check") {
			return &r, nil
		}

		// For any other situations, raise error and break
		return &r, scerr.NewError(r.ErrorMessages())
	}

	return &r, nil
}

// validateContextForCluster checks if the flavor of the cluster is listed in feature specification
// 'feature.suitableFor.cluster'.
// If no flavors is listed, no flavors are authorized (but using 'cluster: no' is strongly recommended)
func (w *worker) validateContextForCluster() error {
	clusterFlavor, err := w.cluster.GetFlavor(w.feature.task)
	if err != nil {
		return err
	}

	yamlKey := "feature.suitableFor.cluster"
	if w.feature.specs.IsSet(yamlKey) {
		yamlFlavors := strings.Split(w.feature.specs.GetString(yamlKey), ",")
		for _, k := range yamlFlavors {
			k = strings.ToLower(k)
			e, err := clusterflavor.Parse(k)
			if (err == nil && clusterFlavor == e) || (err != nil && k == "all") {
				return nil
			}
		}
	}
	msg := fmt.Sprintf("feature '%s' not suitable for flavor '%s' of the targeted cluster", w.feature.SafeGetName(), clusterFlavor.String())
	return scerr.NotAvailableError(msg)
}

// validateContextForHost ...
func (w *worker) validateContextForHost() error {
	if w.node {
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
	msg := fmt.Sprintf("feature '%s' not suitable for host", w.feature.SafeGetName())
	// logrus.Println(msg)
	return scerr.NotAvailableError(msg)
}

func (w *worker) validateClusterSizing() error {
	clusterFlavor, err := w.cluster.GetFlavor(w.feature.task)
	if err != nil {
		return err
	}
	yamlKey := "feature.requirements.clusterSizing." + strings.ToLower(clusterFlavor.String())
	if !w.feature.specs.IsSet(yamlKey) {
		return nil
	}

	sizing := w.feature.specs.GetStringMap(yamlKey)
	if anon, ok := sizing["masters"]; ok {
		request, ok := anon.(string)
		if !ok {
			return scerr.SyntaxError("invalid masters key")
		}
		count, _, _, err := w.parseClusterSizingRequest(request)
		if err != nil {
			return err
		}
		masters, err := w.cluster.ListMasterIDs(w.feature.task)
		if err != nil {
			return err
		}
		curMasters := len(masters)
		if curMasters < count {
			return scerr.NotAvailableError("cluster does not meet the minimum number of masters (%d < %d)", curMasters, count)
		}
	}
	if anon, ok := sizing["nodes"]; ok {
		request, ok := anon.(string)
		if !ok {
			return scerr.SyntaxError("invalid nodes key")
		}
		count, _, _, err := w.parseClusterSizingRequest(request)
		if err != nil {
			return err
		}
		list, err := w.cluster.ListNodeIDs(w.feature.task)
		if err != nil {
			return err
		}
		curNodes := len(list)
		if curNodes < count {
			return scerr.NotAvailableError("cluster does not meet the minimum number of nodes (%d < %d)", curNodes, count)
		}
	}

	return nil
}

// parseClusterSizingRequest returns count, cpu and ram components of request
func (w *worker) parseClusterSizingRequest(request string) (int, int, float32, error) {

	return 0, 0, 0.0, scerr.NotImplementedError("parseClusterSizingRequest() not yet implemented")
}

// setReverseProxy applies the reverse proxy rules defined in specification file (if there are some)
func (w *worker) setReverseProxy() (err error) {
	rules, ok := w.feature.specs.Get("feature.proxy.rules").([]interface{})
	if !ok || len(rules) == 0 {
		return nil
	}

	if w.cluster == nil {
		return scerr.InvalidParameterError("w.cluster", "nil cluster in setReverseProxy, cannot be nil")
	}

	if w.feature.task == nil {
		return scerr.InvalidParameterError("w.feature.task", "nil task in setReverseProxy, cannot be nil")
	}

	svc := w.cluster.SafeGetService()
	netprops, err := w.cluster.GetNetworkConfig(w.feature.task)
	if err != nil {
		return err
	}
	network, err := LoadNetwork(w.feature.task, svc, netprops.NetworkID)
	if err != nil {
		return err
	}

	primaryKongController, err := NewKongController(svc, network, true)
	if err != nil {
		return scerr.Wrap(err, "failed to apply reverse proxy rules")
	}
	var secondaryKongController *KongController
	if network.HasVirtualIP() {
		secondaryKongController, err = NewKongController(svc, network, false)
		if err != nil {
			return scerr.Wrap(err, "failed to apply reverse proxy rules")
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
			return scerr.InvalidParameterError("r", "is not a rule (map)")
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
		hosts, err := w.identifyHosts(targets)
		if err != nil {
			return scerr.Wrap(err, "failed to apply proxy rules: %s")
		}

		for _, h := range hosts {
			if primaryGatewayVariables["HostIP"], err = h.GetPrivateIP(w.feature.task); err != nil {
				return err
			}
			primaryGatewayVariables["Hostname"] = h.SafeGetName()
			tP, err := w.feature.task.StartInSubtask(asyncApplyProxyRule, data.Map{
				"ctrl": primaryKongController,
				"rule": rule,
				"vars": &primaryGatewayVariables,
			})
			if err != nil {
				return scerr.Wrap(err, "failed to apply proxy rules")
			}

			var errS error
			if secondaryKongController != nil {
				if secondaryGatewayVariables["HostIP"], err = h.GetPrivateIP(w.feature.task); err != nil {
					return err
				}
				secondaryGatewayVariables["Hostname"] = h.SafeGetName()
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

func asyncApplyProxyRule(task concurrency.Task, params concurrency.TaskParameters) (tr concurrency.TaskResult, err error) {
	ctrl, ok := params.(data.Map)["ctrl"].(*KongController)
	if !ok {
		return nil, scerr.InvalidParameterError("ctrl", "is not a *KongController")
	}
	rule, ok := params.(data.Map)["rule"].(map[interface{}]interface{})
	if !ok {
		return nil, scerr.InvalidParameterError("rule", "is not a map")
	}
	vars, ok := params.(data.Map)["vars"].(*data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("vars", "is not a '*data.Map'")
	}
	hostName, ok := (*vars)["Hostname"].(string)
	if !ok {
		return nil, scerr.InvalidParameterError("Hostname", "is not a string")
	}

	ruleName, err := ctrl.Apply(rule, vars)

	if err != nil {
		msg := "failed to apply proxy rule"
		if ruleName != "" {
			msg += " '" + ruleName + "'"
		}
		msg += " for host '" + hostName
		logrus.Error(msg + "': " + err.Error())
		return nil, scerr.Wrap(err, msg)
	}
	logrus.Debugf("successfully applied proxy rule '%s' for host '%s'", ruleName, hostName)
	return nil, nil
}

// identifyHosts identifies hosts concerned based on 'targets' and returns a list of hosts
func (w *worker) identifyHosts(targets stepTargets) ([]resources.Host, error) {
	hostT, masterT, nodeT, gwT, err := targets.parse()
	if err != nil {
		return nil, err
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
		host, err := w.identifyAvailableMaster()
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, host)
	case "*":
		if w.action == installaction.Add {
			all, err = w.identifyConcernedMasters()
		} else {
			all, err = w.identifyAllMasters()
		}
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, all...)
	}

	switch nodeT {
	case "1":
		host, err := w.identifyAvailableNode()
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, host)
	case "*":
		if w.action == installaction.Add {
			all, err = w.identifyConcernedNodes()
		} else {
			all, err = w.identifyAllNodes()
		}
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, all...)
	}

	switch gwT {
	case "1":
		host, err := w.identifyAvailableGateway()
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, host)
	case "*":
		if w.action == installaction.Add {
			all, err = w.identifyConcernedGateways()
		} else {
			all, err = w.identifyAllGateways()
		}
		if err != nil {
			return nil, err
		}
		hostsList = append(hostsList, all...)
	}
	return hostsList, nil
}

// normalizeScript envelops the script with log redirection to /opt/safescale/var/log/feature.<name>.<action>.log
// and ensures BashLibrary are there
func normalizeScript(params map[string]interface{}) (string, error) {
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
		result, err := template.New("normalize_script").Parse(tmpl)
		if err != nil {
			return "", scerr.SyntaxError("error parsing bash template: %s", err.Error())
		}
		featureScriptTemplate.Store(result)
		anon = featureScriptTemplate.Load()
	}

	// Configures BashLibrary template var
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return "", err
	}
	params["reserved_BashLibrary"] = bashLibrary

	dataBuffer := bytes.NewBufferString("")
	err = anon.(*template.Template).Execute(dataBuffer, params)
	if err != nil {
		return "", err
	}

	return dataBuffer.String(), nil
}
