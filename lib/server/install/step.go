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
	"github.com/CS-SI/SafeScale/lib/utils"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/install/enums/Action"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

const (
	targetHosts    = "hosts"
	targetMasters  = "masters"
	targetNodes    = "nodes"
	targetGateways = "gateways"
)

type stepResult struct {
	success bool
	err     error
}

func (sr stepResult) Successful() bool {
	return sr.success
}

func (sr stepResult) Error() error {
	return sr.err
}

func (sr stepResult) ErrorMessage() string {
	if sr.err != nil {
		return sr.err.Error()
	}
	return ""
}

// stepResults contains the errors of the step for each host target
type stepResults map[string]stepResult

func (s stepResults) ErrorMessages() string {
	output := ""
	for h, k := range s {
		val := k.ErrorMessage()
		if val != "" {
			output += h + ": " + val + "\n"
		}
	}
	return output
}

func (s stepResults) Successful() bool {
	if len(s) == 0 {
		return false
	}
	for _, k := range s {
		if !k.Successful() {
			return false
		}
	}
	return true
}

type stepTargets map[string]string

// parse converts the content of specification file loaded inside struct to
// standardized values (0, 1 or *)
func (st stepTargets) parse() (string, string, string, string, error) {
	var (
		hostT, masterT, nodeT, gwT string
		ok                         bool
	)

	if hostT, ok = st[targetHosts]; ok {
		switch strings.ToLower(hostT) {
		case "":
			fallthrough
		case "false":
			fallthrough
		case "no":
			fallthrough
		case "none":
			fallthrough
		case "0":
			hostT = "0"
		case "yes":
			fallthrough
		case "true":
			fallthrough
		case "1":
			hostT = "1"
		default:
			return "", "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", hostT, targetHosts)
		}
	}

	if masterT, ok = st[targetMasters]; ok {
		switch strings.ToLower(masterT) {
		case "":
			fallthrough
		case "false":
			fallthrough
		case "no":
			fallthrough
		case "none":
			fallthrough
		case "0":
			masterT = "0"
		case "any":
			fallthrough
		case "one":
			fallthrough
		case "1":
			masterT = "1"
		case "all":
			fallthrough
		case "*":
			masterT = "*"
		default:
			return "", "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", masterT, targetMasters)
		}
	}

	if nodeT, ok = st[targetNodes]; ok {
		switch strings.ToLower(nodeT) {
		case "":
			fallthrough
		case "false":
			fallthrough
		case "no":
			fallthrough
		case "none":
			nodeT = "0"
		case "any":
			fallthrough
		case "one":
			fallthrough
		case "1":
			nodeT = "1"
		case "all":
			fallthrough
		case "*":
			nodeT = "*"
		default:
			return "", "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", nodeT, targetNodes)
		}
	}

	if gwT, ok = st[targetGateways]; ok {
		switch strings.ToLower(gwT) {
		case "":
			fallthrough
		case "false":
			fallthrough
		case "no":
			fallthrough
		case "none":
			fallthrough
		case "0":
			gwT = "0"
		case "any":
			fallthrough
		case "one":
			fallthrough
		case "1":
			gwT = "1"
		case "all":
			fallthrough
		case "*":
			gwT = "*"
		default:
			return "", "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", gwT, targetGateways)
		}
	}

	if hostT == "0" && masterT == "0" && nodeT == "0" && gwT == "0" {
		return "", "", "", "", fmt.Errorf("no targets identified")
	}
	return hostT, masterT, nodeT, gwT, nil
}

// step is a struct containing the needed information to apply the installation
// step on all selected host targets
type step struct {
	// Worker is a back pointer to the caller
	Worker *worker
	// Name is the name of the step
	Name string
	// Action is the action of the step (check, add, remove)
	Action Action.Enum
	// Targets contains the host targets to select
	Targets stepTargets
	// Script contains the script to execute
	Script string
	// WallTime contains the maximum time the step must run
	WallTime time.Duration
	// YamlKey contains the root yaml key on the specification file
	YamlKey string
	// OptionsFileContent contains the "options file" if it exists (for DCOS cluster for now)
	OptionsFileContent string
	// Serial tells if step can be performed in parallel on selected host or not
	Serial bool
}

// Run executes the step on all the concerned hosts
func (is *step) Run(hosts []*pb.Host, v Variables, s Settings) (results stepResults, err error) {
	results = stepResults{}
	defer utils.TimerErrWithLevel(fmt.Sprintf("running step '%s' on %d hosts...", is.Name, len(hosts)), &err, log.DebugLevel)

	if is.Serial || s.Serialize {
		subtask := concurrency.NewTask(is.Worker.feature.task)

		for _, h := range hosts {
			log.Debugf("%s(%s):step(%s)@%s: starting\n", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name)
			is.Worker.startTime = time.Now()

			cloneV := v.Clone()
			cloneV["HostIP"] = h.PrivateIp
			cloneV["Hostname"] = h.Name
			cloneV, err = realizeVariables(cloneV)
			if err != nil {
				return nil, err
			}
			result, _ := subtask.Run(is.taskRunOnHost, data.Map{"host": h, "variables": cloneV})
			results[h.Name] = result.(stepResult)
			subtask.Reset()

			if !results[h.Name].Successful() {
				if is.Worker.action == Action.Check { // Checks can fail and it's ok
					log.Debugf("%s(%s):step(%s)@%s finished in [%s]: fail: %s", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name, utils.FmtDuration(time.Since(is.Worker.startTime)), results.ErrorMessages())
				} else { // other steps are expected to succeed
					log.Errorf("%s(%s):step(%s)@%s finished in [%s]: fail: %s", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name, utils.FmtDuration(time.Since(is.Worker.startTime)), results.ErrorMessages())
				}
			} else {
				log.Debugf("%s(%s):step(%s)@%s finished in [%s]: done", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name, utils.FmtDuration(time.Since(is.Worker.startTime)))
			}
		}
	} else {
		subtasks := map[string]concurrency.Task{}
		for _, h := range hosts {
			log.Debugf("%s(%s):step(%s)@%s: starting", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name)
			is.Worker.startTime = time.Now()

			cloneV := v.Clone()
			cloneV["HostIP"] = h.PrivateIp
			cloneV["Hostname"] = h.Name
			cloneV, err = realizeVariables(cloneV)
			if err != nil {
				return nil, err
			}
			subtask := concurrency.NewTask(is.Worker.feature.task).Start(is.taskRunOnHost, data.Map{
				"host":      h,
				"variables": cloneV,
			})
			subtasks[h.Name] = subtask
		}
		for k, s := range subtasks {
			result, err := s.Wait()
			if err != nil {
				log.Warnf("%s(%s):step(%s)@%s finished in [%s]: fail to recover result", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, k, utils.FmtDuration(time.Since(is.Worker.startTime)))
				continue
			}
			results[k] = result.(stepResult)

			if !results[k].Successful() {
				if is.Worker.action == Action.Check { // Checks can fail and it's ok
					log.Debugf("%s(%s):step(%s)@%s finished in [%s]: fail: %s", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, k, utils.FmtDuration(time.Since(is.Worker.startTime)), results.ErrorMessages())
				} else { // other steps are expected to succeed
					log.Errorf("%s(%s):step(%s)@%s finished in [%s]: fail: %s", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, k, utils.FmtDuration(time.Since(is.Worker.startTime)), results.ErrorMessages())
				}
			} else {
				log.Debugf("%s(%s):step(%s)@%s finished in [%s]: done", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, k, utils.FmtDuration(time.Since(is.Worker.startTime)))
			}
		}
	}
	return results, nil
}

// taskRunOnHost ...
// Respects interface concurrency.TaskFunc
// func (is *step) runOnHost(host *pb.Host, v Variables) stepResult {
func (is *step) taskRunOnHost(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// Get parameters
	p := params.(data.Map)
	host := p["host"].(*pb.Host)
	variables := p["variables"].(Variables)

	// Updates variables in step script
	command, err := replaceVariablesInString(is.Script, variables)
	if err != nil {
		return stepResult{success: false, err: fmt.Errorf("failed to finalize installer script for step '%s': %s", is.Name, err.Error())}, nil
	}

	// If options file is defined, upload it to the remote host
	if is.OptionsFileContent != "" {
		err := UploadStringToRemoteFile(is.OptionsFileContent, host, srvutils.TempFolder+"/options.json", "cladm", "safescale", "ug+rw-x,o-rwx")
		if err != nil {
			return stepResult{success: false, err: err}, nil
		}
	}

	// Uploads then executes command
	filename := fmt.Sprintf("%s/feature.%s.%s_%s.sh", srvutils.TempFolder, is.Worker.feature.DisplayName(), strings.ToLower(is.Action.String()), is.Name)
	err = UploadStringToRemoteFile(command, host, filename, "", "", "")
	if err != nil {
		return stepResult{success: false, err: err}, nil
	}

	//command = fmt.Sprintf("sudo bash %s; rc=$?; if [[ rc -eq 0 ]]; then sudo rm -f %s %s/options.json; fi; exit $rc", filename, filename, srvutils.TempFolder)
	command = fmt.Sprintf("sudo bash %s; rc=$?; exit $rc", filename)

	// Executes the script on the remote host
	retcode, _, _, err := client.New().SSH.Run(host.Name, command, utils.GetConnectionTimeout(), is.WallTime)
	if err != nil {
		return stepResult{success: false, err: err}, nil
	}
	err = nil
	ok := retcode == 0
	if !ok {
		err = fmt.Errorf("step '%s' failed (retcode=%d)", is.Name, retcode)
	}
	return stepResult{success: ok, err: err}, nil
}
