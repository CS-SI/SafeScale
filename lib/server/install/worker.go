/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package install

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	clusterapi "github.com/CS-SI/SafeScale/lib/server/cluster/api"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/install/enums/Action"
	"github.com/CS-SI/SafeScale/lib/server/install/enums/Method"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
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

type alterCommandCB func(string) string

type worker struct {
	feature   *Feature
	target    Target
	method    Method.Enum
	action    Action.Enum
	variables Variables
	settings  Settings
	startTime time.Time

	host    *pb.Host
	node    bool
	cluster clusterapi.Cluster

	availableMaster  *pb.Host
	availableNode    *pb.Host
	availableGateway *pb.Host

	allMasters  []*pb.Host
	allNodes    []*pb.Host
	allGateways []*pb.Host

	concernedMasters  []*pb.Host
	concernedNodes    []*pb.Host
	concernedGateways []*pb.Host

	rootKey string
	// function to alter the content of 'run' key of specification file
	commandCB alterCommandCB
}

// newWorker ...
// alterCmdCB is used to change the content of keys 'run' or 'package' before executing
// the requested action. If not used, must be nil
func newWorker(f *Feature, t Target, m Method.Enum, a Action.Enum, cb alterCommandCB) (*worker, error) {
	w := worker{
		feature:   f,
		target:    t,
		method:    m,
		action:    a,
		commandCB: cb,
	}
	hT, cT, nT := determineContext(t)
	if cT != nil {
		w.cluster = cT.cluster
	}
	if hT != nil {
		w.host = hT.host
	}
	if nT != nil {
		w.host = nT.host
		w.node = true
	}

	w.rootKey = "feature.install." + strings.ToLower(m.String()) + "." + strings.ToLower(a.String())
	if !f.specs.IsSet(w.rootKey) {
		msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, f.DisplayName(), f.DisplayFilename(), w.rootKey)
	}

	return &w, nil
}

// ConcernsCluster returns true if the target of the worker is a cluster
func (w *worker) ConcernsCluster() bool {
	return w.cluster != nil
}

// CanProceed tells if the combination Feature/Target can work
func (w *worker) CanProceed(s Settings) error {
	switch w.target.Type() {
	case "cluster":
		err := w.validateContextForCluster()
		if err == nil && !s.SkipSizingRequirements {
			err = w.validateClusterSizing()
		}
		return err
	case "node":
		return nil
	case "host":
		return w.validateContextForHost()
	}
	return nil
}

// identifyAvailableMaster finds a master available, and keep track of it
// for all the life of the action (prevent to request too often)
func (w *worker) identifyAvailableMaster() (*pb.Host, error) {
	if w.cluster == nil {
		return nil, resources.ResourceNotAvailableError("cluster", "")
	}
	if w.availableMaster == nil {
		hostID, err := w.cluster.FindAvailableMaster(w.feature.task)
		if err != nil {
			return nil, err
		}
		w.availableMaster, err = client.New().Host.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			return nil, err
		}
	}
	return w.availableMaster, nil
}

// identifyAvailableNode finds a node available and will use this one during all the install session
func (w *worker) identifyAvailableNode() (*pb.Host, error) {
	if w.cluster == nil {
		return nil, resources.ResourceNotAvailableError("cluster", "")
	}
	if w.availableNode == nil {
		hostID, err := w.cluster.FindAvailableNode(w.feature.task)
		if err != nil {
			return nil, err
		}
		host, err := client.New().Host.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			return nil, err
		}
		w.availableNode = host
	}
	return w.availableNode, nil
}

// identifyConcernedMasters returns a list of all the hosts acting as masters and keep this list
// during all the install session
func (w *worker) identifyConcernedMasters() ([]*pb.Host, error) {
	if w.cluster == nil {
		return []*pb.Host{}, nil
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
func (w *worker) extractHostsFailingCheck(hosts []*pb.Host) ([]*pb.Host, error) {
	concernedHosts := []*pb.Host{}
	dones := map[*pb.Host]chan error{}
	results := map[*pb.Host]chan Results{}
	for _, h := range hosts {
		d := make(chan error)
		r := make(chan Results)
		dones[h] = d
		results[h] = r
		go func(host *pb.Host, res chan Results, done chan error) {
			nodeTarget, err := NewNodeTarget(host)
			if err != nil {
				res <- nil
				done <- err
				return
			}
			results, err := w.feature.Check(nodeTarget, w.variables, w.settings)
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
func (w *worker) identifyAllMasters() ([]*pb.Host, error) {
	if w.cluster == nil {
		return []*pb.Host{}, nil
	}
	if w.allMasters == nil || len(w.allMasters) == 0 {
		w.allMasters = []*pb.Host{}
		safescale := client.New().Host
		for _, i := range w.cluster.ListMasterIDs(w.feature.task) {
			host, err := safescale.Inspect(i, temporal.GetExecutionTimeout())
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
func (w *worker) identifyConcernedNodes() ([]*pb.Host, error) {
	if w.cluster == nil {
		return []*pb.Host{}, nil
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
func (w *worker) identifyAllNodes() ([]*pb.Host, error) {
	if w.cluster == nil {
		return []*pb.Host{}, nil
	}

	if w.allNodes == nil {
		hostClt := client.New().Host
		allHosts := []*pb.Host{}
		for _, i := range w.cluster.ListNodeIDs(w.feature.task) {
			host, err := hostClt.Inspect(i, temporal.GetExecutionTimeout())
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
func (w *worker) identifyAvailableGateway() (*pb.Host, error) {
	if w.cluster == nil {
		return gatewayFromHost(w.host), nil
	}
	if w.availableGateway == nil {
		netCfg, err := w.cluster.GetNetworkConfig(w.feature.task)
		if err == nil {
			w.availableGateway, err = client.New().Host.Inspect(netCfg.GatewayID, temporal.GetExecutionTimeout())
		}
		if err != nil {
			return nil, err
		}
	}
	return w.availableGateway, nil
}

// identifyConcernedGateways returns a list of all the hosts acting as gateway that can accept the action
//  and keep this list during all the install session
func (w *worker) identifyConcernedGateways() ([]*pb.Host, error) {
	var hosts []*pb.Host

	if w.host != nil {
		host := gatewayFromHost(w.host)
		hosts = []*pb.Host{host}
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
func (w *worker) identifyAllGateways() ([]*pb.Host, error) {
	if w.allGateways != nil {
		return w.allGateways, nil
	}

	var (
		err     error
		results []*pb.Host
	)

	netCfg, err := w.cluster.GetNetworkConfig(w.feature.task)
	if err != nil {
		return nil, err
	}
	gw, err := client.New().Host.Inspect(netCfg.GatewayID, temporal.GetExecutionTimeout())
	if err != nil {
		return nil, err
	}

	results = append(results, w.allGateways...)
	results = append(results, gw)

	if netCfg.SecondaryGatewayID != "" {
		gw, err = client.New().Host.Inspect(netCfg.SecondaryGatewayID, temporal.GetExecutionTimeout())
		if err != nil {
			return nil, err
		}
		results = append(results, gw)
	}
	w.allGateways = results
	return results, nil
}

// Proceed executes the action
func (w *worker) Proceed(v Variables, s Settings) (results Results, err error) {
	w.variables = v
	w.settings = s

	results = Results{}

	// 'pace' tells the order of execution
	pace := w.feature.specs.GetString(w.rootKey + "." + yamlPaceKeyword)
	if pace == "" {
		return nil, fmt.Errorf("missing or empty key %s.%s", w.rootKey, yamlPaceKeyword)
	}

	// 'steps' describes the steps of the action
	stepsKey := w.rootKey + "." + yamlStepsKeyword
	steps := w.feature.specs.GetStringMap(stepsKey)
	if len(steps) == 0 {
		return nil, fmt.Errorf("nothing to do")
	}
	order := strings.Split(pace, ",")

	// Applies reverseproxy rules to make it functional (feature may need it during the install)
	if w.action == Action.Add && !s.SkipProxy {
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
			return results, fmt.Errorf(msg, w.feature.DisplayName(), w.feature.DisplayFilename(), stepKey)
		}
		params := data.Map{
			"stepName":  k,
			"stepKey":   stepKey,
			"stepMap":   stepMap,
			"variables": v,
		}

		subtask, err := w.feature.task.New()
		if err != nil {
			return results, err
		}

		subtask, err = subtask.Start(w.taskLaunchStep, params)
		if err != nil {
			return results, err
		}

		var result *StepResults
		tr, err := subtask.Wait()
		if tr != nil {
			result = tr.(*StepResults)
			results[k] = *result
		}
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

// taskLaunchStep starts the step
func (w *worker) taskLaunchStep(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, err error) {
	if w == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if params == nil {
		return nil, scerr.InvalidParameterError("params", "can't be nil")
	}

	var (
		anon              interface{}
		stepName, stepKey string
		stepMap           map[string]interface{}
		vars              Variables
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
	if vars, ok = p["variables"].(Variables); !ok {
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
	var hostsList []*pb.Host
	if w.target.Type() == "node" {
		hostsList, err = w.identifyHosts(map[string]string{"hosts": "1"})
	} else {
		anon, ok = stepMap[yamlTargetsKeyword]
		if ok {
			for i, j := range anon.(map[string]interface{}) {
				switch j.(type) {
				case bool:
					if j.(bool) {
						stepT[i] = "true"
					} else {
						stepT[i] = "false"
					}
				case string:
					stepT[i] = j.(string)
				}
			}
		} else {
			msg := `syntax error in feature '%s' specification file (%s): no key '%s.%s' found`
			return nil, fmt.Errorf(msg, w.feature.DisplayName(), w.feature.DisplayFilename(), stepKey, yamlTargetsKeyword)
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
	case Method.Apt:
		fallthrough
	case Method.Yum:
		fallthrough
	case Method.Dnf:
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
		return nil, fmt.Errorf(msg, w.feature.DisplayName(), w.feature.DisplayFilename(), stepKey, yamlRunKeyword)
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
		complexity := strings.ToLower(w.cluster.GetIdentity(w.feature.task).Complexity.String())
		for k, anon := range options {
			avails[strings.ToLower(k)] = anon
		}
		if content, ok = avails[complexity]; !ok {
			if complexity == strings.ToLower(Complexity.Large.String()) {
				complexity = Complexity.Normal.String()
			}
			if complexity == strings.ToLower(Complexity.Normal.String()) {
				if content, ok = avails[complexity]; !ok {
					content, ok = avails[Complexity.Small.String()]
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

	templateCommand, err := normalizeScript(Variables{
		"reserved_Name":    w.feature.DisplayName(),
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
			logrus.Warnf(fmt.Sprintf("execution of step '%s::%s' failed on: %v", w.action.String(), stepName, r.UncompletedEntries()))
			return &r, fmt.Errorf(r.ErrorMessages())
		}
		// not successful but completed, if action is check means the feature is not install, it's an information not a failure
		if strings.Contains(w.action.String(), "Check") {
			return &r, nil
		}

		// For any other situations, raise error and break
		return &r, fmt.Errorf(r.ErrorMessages())
	}

	return &r, nil
}

// validateContextForCluster checks if the flavor of the cluster is listed in feature specification
// 'feature.suitableFor.cluster'.
// If no flavors is listed, no flavors are authorized (but using 'cluster: no' is strongly recommended)
func (w *worker) validateContextForCluster() error {
	clusterFlavor := w.cluster.GetIdentity(w.feature.task).Flavor

	yamlKey := "feature.suitableFor.cluster"
	if w.feature.specs.IsSet(yamlKey) {
		flavors := strings.Split(w.feature.specs.GetString(yamlKey), ",")
		for _, k := range flavors {
			k = strings.ToLower(k)
			e, err := Flavor.Parse(k)
			if (err == nil && clusterFlavor == e) || (err != nil && k == "all") {
				return nil
			}
		}
	}
	msg := fmt.Sprintf("feature '%s' not suitable for flavor '%s' of the targeted cluster", w.feature.DisplayName(), clusterFlavor.String())
	return fmt.Errorf(msg)
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
	msg := fmt.Sprintf("feature '%s' not suitable for host", w.feature.DisplayName())
	// logrus.Println(msg)
	return fmt.Errorf(msg)
}

func (w *worker) validateClusterSizing() error {
	yamlKey := "feature.requirements.clusterSizing." + strings.ToLower(w.cluster.GetIdentity(w.feature.task).Flavor.String())
	if !w.feature.specs.IsSet(yamlKey) {
		return nil
	}

	sizing := w.feature.specs.GetStringMap(yamlKey)
	if anon, ok := sizing["masters"]; ok {
		request := anon.(string)
		count, _, _, err := w.parseClusterSizingRequest(request)
		if err != nil {
			return err
		}
		curMasters := len(w.cluster.ListMasterIDs(w.feature.task))
		if curMasters < count {
			return fmt.Errorf("cluster doesn't meet the minimum number of masters (%d < %d)", curMasters, count)
		}
	}
	if anon, ok := sizing["nodes"]; ok {
		request := anon.(string)
		count, _, _, err := w.parseClusterSizingRequest(request)
		if err != nil {
			return err
		}
		curNodes := len(w.cluster.ListNodeIDs(w.feature.task))
		if curNodes < count {
			return fmt.Errorf("cluster doesn't meet the minimum number of nodes (%d < %d)", curNodes, count)
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

	svc := w.cluster.GetService(w.feature.task)
	netprops, err := w.cluster.GetNetworkConfig(w.feature.task)
	if err != nil {
		return err
	}
	mn, err := metadata.LoadNetwork(svc, netprops.NetworkID)
	if err != nil {
		return err
	}

	network, err := mn.Get()
	if err != nil {
		return err
	}
	primaryKongController, err := NewKongController(svc, network, true)
	if err != nil {
		return fmt.Errorf("failed to apply reverse proxy rules: %s", err.Error())
	}
	var secondaryKongController *KongController
	if network.SecondaryGatewayID != "" {
		secondaryKongController, err = NewKongController(svc, network, false)
		if err != nil {
			return fmt.Errorf("failed to apply reverse proxy rules: %s", err.Error())
		}
	}

	// Now submits all the rules to reverse proxy
	primaryGatewayVariables := w.variables.Clone()
	var secondaryGatewayVariables Variables
	if secondaryKongController != nil {
		secondaryGatewayVariables = w.variables.Clone()
	}
	for _, r := range rules {
		targets := stepTargets{}
		rule := r.(map[interface{}]interface{})
		anon, ok := rule["targets"].(map[interface{}]interface{})
		if !ok {
			// If no 'targets' key found, applies on host only
			if w.cluster != nil {
				continue
			}
			targets[targetHosts] = "yes"
		} else {
			for i, j := range anon {
				switch j.(type) {
				case bool:
					if j.(bool) {
						targets[i.(string)] = "yes"
					} else {
						targets[i.(string)] = "no"
					}
				case string:
					targets[i.(string)] = j.(string)
				}
			}
		}
		hosts, err := w.identifyHosts(targets)
		if err != nil {
			return fmt.Errorf("failed to apply proxy rules: %s", err.Error())
		}

		for _, h := range hosts {
			tP, _ := w.feature.task.New() // FIXME Later
			primaryGatewayVariables["HostIP"] = h.PrivateIp
			primaryGatewayVariables["Hostname"] = h.Name
			_, _ = tP.Start(asyncApplyProxyRule, data.Map{ // FIXME Later
				"ctrl": primaryKongController,
				"rule": rule,
				"vars": &primaryGatewayVariables,
			})

			var errS error
			if secondaryKongController != nil {
				tS, _ := w.feature.task.New() // FIXME Later
				secondaryGatewayVariables["HostIP"] = h.PrivateIp
				secondaryGatewayVariables["Hostname"] = h.Name
				_, _ = tS.Start(asyncApplyProxyRule, data.Map{ // FIXME Later
					"ctrl": secondaryKongController,
					"rule": rule,
					"vars": &secondaryGatewayVariables,
				})
				_, errS = tS.Wait()
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

func asyncApplyProxyRule(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	ctrl := params.(data.Map)["ctrl"].(*KongController)
	rule := params.(data.Map)["rule"].(map[interface{}]interface{})
	vars := params.(data.Map)["vars"].(*Variables)

	hostName := (*vars)["Hostname"].(string)
	ruleName, err := ctrl.Apply(rule, vars)

	// FIXME Check this later
	if err != nil {
		msg := "failed to apply proxy rule"
		if ruleName != "" {
			msg += " '" + ruleName + "'"
		}
		msg += " for host '" + hostName + "': " + err.Error()
		logrus.Error(msg)
		return nil, fmt.Errorf(msg)
	}
	logrus.Debugf("successfully applied proxy rule '%s' for host '%s'", ruleName, hostName)
	return nil, nil
}

// identifyHosts identifies hosts concerned based on 'targets' and returns a list of hosts
func (w *worker) identifyHosts(targets stepTargets) ([]*pb.Host, error) {
	hostT, masterT, nodeT, gwT, err := targets.parse()
	if err != nil {
		return nil, err
	}

	var (
		hostsList = []*pb.Host{}
		all       []*pb.Host
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
		if w.action == Action.Add {
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
		if w.action == Action.Add {
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
		if w.action == Action.Add {
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
