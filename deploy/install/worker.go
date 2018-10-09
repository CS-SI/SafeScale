/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"log"
	"strconv"
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Flavor"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Action"
	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"
)

const (
	yamlPaceKeyword     = "pace"
	yamlStepsKeyword    = "steps"
	yamlTargetsKeyword  = "targets"
	yamlRunKeyword      = "run"
	yamlPackageKeyword  = "package"
	yamlOptionsKeyword  = "options"
	yamlWallTimeKeyword = "wallTime"
	yamlSerialKeyword   = "serialized"
)

type alterCommandCB func(string) string

type worker struct {
	component *Component
	target    Target
	method    Method.Enum
	action    Action.Enum

	host    *pb.Host
	node    bool
	cluster clusterapi.Cluster

	availableMaster      *pb.Host
	availablePrivateNode *pb.Host
	availablePublicNode  *pb.Host

	allMasters      []*pb.Host
	allPrivateNodes []*pb.Host
	allPublicNodes  []*pb.Host

	rootKey string
	// function to alter the content of 'run' key of specification file
	commandCB alterCommandCB
}

// newWorker ...
// alterCmdCB is used to change the content of keys 'run' or 'package' before executing
// the requested action. If not used, must be nil
func newWorker(c *Component, t Target, m Method.Enum, a Action.Enum, f alterCommandCB) (*worker, error) {
	w := worker{
		component: c,
		target:    t,
		method:    m,
		action:    a,
		commandCB: f,
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

	w.rootKey = "component.install." + strings.ToLower(m.String()) + "." + strings.ToLower(a.String())
	specs := w.component.Specs()
	if !specs.IsSet(w.rootKey) {
		msg := `syntax error in component '%s' specification file (%s):
				no key '%s' found`
		return nil, fmt.Errorf(msg, c.DisplayName(), c.DisplayFilename(), w.rootKey)
	}

	return &w, nil
}

// ConcernCluster returns true if the target of the worker is a cluster
func (w *worker) ConcernCluster() bool {
	return w.cluster != nil
}

// CanProceed tells if the combination Component/Target can work
func (w *worker) CanProceed(s Settings) error {
	if w.cluster != nil {
		err := w.validateContextForCluster()
		if err == nil && !s.SkipSizingRequirements {
			err = w.validateClusterSizing()
		}
		return err
	}
	return w.validateContextForHost()
}

func (w *worker) Host() (*pb.Host, error) {
	if w.host != nil {
		return w.host, nil
	}
	return nil, fmt.Errorf("target of worker isn't a host")
}

// AvailableMaster finds a master available, and keep track of it
// for all the life of the action (prevent to request too often)
func (w *worker) AvailableMaster() (*pb.Host, error) {
	if w.cluster == nil {
		return nil, nil
	}
	if w.availableMaster == nil {
		hostID, err := w.cluster.FindAvailableMaster()
		if err != nil {
			return nil, err
		}
		w.availableMaster, err = brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return nil, err
		}
	}
	return w.availableMaster, nil
}

// AvailableNode finds a node available and will use this one during all the install session
func (w *worker) AvailableNode(public bool) (*pb.Host, error) {
	if w.cluster == nil {
		return nil, nil
	}
	found := false
	if public {
		found = w.availablePublicNode != nil
	} else {
		found = w.availablePrivateNode != nil
	}
	if !found {
		hostID, err := w.cluster.FindAvailableNode(public)
		if err != nil {
			return nil, err
		}
		host, err := brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return nil, err
		}
		if public {
			w.availablePublicNode = host
		} else {
			w.availablePrivateNode = host
		}
	}
	if public {
		return w.availablePublicNode, nil
	}
	return w.availablePrivateNode, nil
}

// AllMasters returns a list of all the hosts acting as masters and keep this list
// during all the install session
func (w *worker) AllMasters() ([]*pb.Host, error) {
	if w.cluster == nil {
		return []*pb.Host{}, nil
	}
	if w.allMasters == nil || len(w.allMasters) == 0 {
		w.allMasters = []*pb.Host{}
		broker := brokerclient.New().Host
		for _, i := range w.cluster.ListMasterIDs() {
			host, err := broker.Inspect(i, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				return nil, err
			}
			w.allMasters = append(w.allMasters, host)
		}
	}
	return w.allMasters, nil
}

// AllNodes returns a list of all the hosts acting as public of private nodes and keep this list
// during all the install session
func (w *worker) AllNodes(public bool) ([]*pb.Host, error) {
	if w.cluster == nil {
		return []*pb.Host{}, nil
	}
	found := false
	if public {
		found = w.allPublicNodes != nil && len(w.allPublicNodes) > 0
	} else {
		found = w.allPrivateNodes != nil && len(w.allPrivateNodes) > 0
	}
	if !found {
		brokerhost := brokerclient.New().Host
		allHosts := []*pb.Host{}
		nodes := w.cluster.ListNodeIDs(public)
		for _, i := range nodes {
			host, err := brokerhost.Inspect(i, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				return nil, err
			}
			allHosts = append(allHosts, host)
		}
		if public {
			w.allPublicNodes = allHosts
		} else {
			w.allPrivateNodes = allHosts
		}
	}
	if public {
		return w.allPublicNodes, nil
	}
	return w.allPrivateNodes, nil

}

// Proceed executes the action
func (w *worker) Proceed(v Variables, s Settings) (Results, error) {
	results := Results{}
	specs := w.component.Specs()

	// 'pace' tells the order of execution
	pace := specs.GetString(w.rootKey + "." + yamlPaceKeyword)
	if pace == "" {
		return nil, fmt.Errorf("missing or empty key %s.%s", w.rootKey, yamlPaceKeyword)
	}

	// 'steps' describes the steps of the action
	stepsKey := w.rootKey + "." + yamlStepsKeyword
	steps := specs.GetStringMap(stepsKey)
	if len(steps) <= 0 {
		return nil, fmt.Errorf("nothing to do")
	}
	order := strings.Split(pace, ",")

	// Applies reverseproxy rules to make it functional (component may need it during the install)
	if w.action == Action.Add && !s.SkipProxy {
		err := w.setReverseProxy(v)
		if err != nil {
			return nil, err
		}
	}

	// Now enumerate steps and execute each of them
	var err error
	for _, k := range order {
		// log.Printf("executing step '%s::%s'...\n", w.action.String(), k)

		stepKey := stepsKey + "." + k
		var (
			runContent string
			stepT      = stepTargets{}
			options    = map[string]string{}
			ok         bool
			anon       interface{}
			err        error
		)
		stepMap, ok := steps[strings.ToLower(k)].(map[string]interface{})
		if !ok {
			msg := `syntax error in component '%s' specification file (%s): no key '%s' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey)
		}

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
			msg := `syntax error in component '%s' specification file (%s): no key '%s.%s' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey, yamlTargetsKeyword)
		}

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
			msg := `syntax error in component '%s' specification file (%s): no key '%s.%s' found`
			return nil, fmt.Errorf(msg, w.component.DisplayName(), w.component.DisplayFilename(), stepKey, yamlRunKeyword)
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
			complexity := strings.ToLower(w.cluster.GetConfig().Complexity.String())
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
				v["options"] = "--options=/var/tmp/options.json"
			}
		} else {
			v["options"] = ""
		}

		wallTime := 0
		anon, ok = stepMap[yamlWallTimeKeyword]
		if ok {
			wallTime, err = strconv.Atoi(anon.(string))
			if err != nil {
				log.Printf("Invalid value '%s' for '%s.%s', ignored.", anon.(string), w.rootKey, yamlWallTimeKeyword)
			}
		}
		if wallTime == 0 {
			wallTime = 5
		}

		templateCommand, err := normalizeScript(Variables{
			"reserved_Name":    w.component.BaseFilename(),
			"reserved_Content": runContent,
			"reserved_Action":  strings.ToLower(w.action.String()),
			"reserved_Step":    k,
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

		step := step{
			Worker:             w,
			Name:               k,
			Action:             w.action,
			Targets:            stepT,
			Script:             templateCommand,
			WallTime:           time.Duration(wallTime) * time.Minute,
			OptionsFileContent: optionsFileContent,
			YamlKey:            stepKey,
			Serial:             serial,
		}
		results[k], err = step.Run(v, s)
		// If an error occured, don't do the remaining steps, fail immediately
		if err != nil {
			break
		}
	}
	return results, err
}

// validateContextForCluster checks if the flavor of the cluster is listed in component specification
// 'component.suitableFor.cluster'.
// If no flavors is listed, no flavors are authorized (but using 'cluster: no' is strongly recommanded)
func (w *worker) validateContextForCluster() error {
	specs := w.component.Specs()
	config := w.cluster.GetConfig()
	clusterFlavor := config.Flavor
	yamlKey := "component.suitableFor.cluster"
	if specs.IsSet(yamlKey) {
		flavors := strings.Split(specs.GetString(yamlKey), ",")
		for _, k := range flavors {
			k = strings.ToLower(k)
			str, err := Flavor.Parse(k)
			if (err == nil && clusterFlavor == str) || (err != nil && k == "all") {
				return nil
			}
		}
	}
	msg := fmt.Sprintf("component '%s' not suitable for flavor '%s' of cluster", w.component.DisplayName(), config.Flavor.String())
	return fmt.Errorf(msg)
}

// validateContextForHost ...
func (w *worker) validateContextForHost() error {
	if w.node {
		return nil
	}
	specs := w.component.Specs()
	ok := false
	yamlKey := "component.suitableFor.host"
	if specs.IsSet(yamlKey) {
		value := strings.ToLower(specs.GetString(yamlKey))
		ok = value == "ok" || value == "yes" || value == "true" || value == "1"
	}
	if ok {
		return nil
	}
	msg := fmt.Sprintf("component '%s' not suitable for host", w.component.DisplayName())
	// log.Println(msg)
	return fmt.Errorf(msg)
}

func (w *worker) validateClusterSizing() error {
	specs := w.component.Specs()
	yamlKey := "component.requirements.clusterSizing." + strings.ToLower(w.cluster.GetConfig().Flavor.String())
	if !specs.IsSet(yamlKey) {
		return nil
	}
	sizing := specs.GetStringMap(yamlKey)
	if anon, ok := sizing["minMasters"]; ok {
		minMasters := anon.(int)
		curMasters := len(w.cluster.ListMasterIDs())
		if curMasters < minMasters {
			return fmt.Errorf("cluster doesn't meet the minimum number of masters (%d < %d)", curMasters, minMasters)
		}
	}
	if anon, ok := sizing["minPrivateNodes"]; ok {
		minNodes := anon.(int)
		curNodes := len(w.cluster.ListNodeIDs(false))
		if curNodes < minNodes {
			return fmt.Errorf("cluster doesn't meet the minimum number of private nodes (%d < %d)", curNodes, minNodes)
		}
	}
	if anon, ok := sizing["minPublicNodes"]; ok {
		minNodes := anon.(int)
		curNodes := len(w.cluster.ListNodeIDs(true))
		if curNodes < minNodes {
			return fmt.Errorf("cluster doesn't meet the minimum number of public nodes (%d < %d)", curNodes, minNodes)
		}
	}
	return nil
}

// setReverseProxy applies the reverse proxy rules defined in specification file (if there are some)
func (w *worker) setReverseProxy(v Variables) error {
	specs := w.component.Specs()
	rules, ok := specs.Get("component.proxy.rules").([]interface{})
	if !ok || len(rules) <= 0 {
		return nil
	}

	var (
		err error
		gw  *pb.Host
	)

	if w.cluster != nil {
		host, err := w.AvailableMaster()
		if err != nil {
			return fmt.Errorf("failed to set reverse proxy: %s", err.Error())
		}
		gw = gatewayFromHost(host)
	} else {
		gw = gatewayFromHost(w.host)
	}
	if gw == nil {
		return fmt.Errorf("failed to set reverse proxy, unable to determine gateway")
	}

	kc, err := NewKongController(gw)
	if err != nil {
		return fmt.Errorf("failed to apply reverse proxy rules: %s", err.Error())
	}

	// Sets the values useable in any cases
	v["GatewayIP"] = gw.PUBLIC_IP

	// Now submits all the rules to reverse proxy
	for _, r := range rules {
		targets := stepTargets{}
		rule := r.(map[interface{}]interface{})
		anon, ok := rule["targets"].(map[interface{}]interface{})
		if !ok {
			// If no 'targets' key found, applies on host only
			if w.cluster != nil {
				continue
			}
			targets[targetHosts] = "true"
		} else {
			for i, j := range anon {
				switch j.(type) {
				case bool:
					if j.(bool) {
						targets[i.(string)] = "true"
					} else {
						targets[i.(string)] = "false"
					}
				case string:
					targets[i.(string)] = j.(string)
				}
			}
		}
		hosts, err := identifyHosts(w, targets)
		if err != nil {
			return fmt.Errorf("failed to apply proxy rules: %s", err.Error())
		}
		for _, h := range hosts {
			v["HostIP"] = h.PRIVATE_IP
			v["Hostname"] = h.Name
			err := kc.Apply(rule, &v)
			if err != nil {
				return fmt.Errorf("failed to apply proxy rules: %s", err.Error())
			}
		}
	}
	return nil
}
