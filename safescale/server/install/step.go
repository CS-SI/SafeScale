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
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/safescale"
	"github.com/CS-SI/SafeScale/safescale/client"
	"github.com/CS-SI/SafeScale/safescale/server/install/enums/Action"
)

const (
	targetHosts        = "hosts"
	targetMasters      = "masters"
	targetPublicNodes  = "publicnodes"
	targetPrivateNodes = "privatenodes"
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
		hostT, masterT, privnodeT, pubnodeT string
		ok                                  bool
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

	if privnodeT, ok = st[targetPrivateNodes]; ok {
		switch strings.ToLower(privnodeT) {
		case "":
			fallthrough
		case "false":
			fallthrough
		case "no":
			fallthrough
		case "none":
			privnodeT = "0"
		case "any":
			fallthrough
		case "one":
			fallthrough
		case "1":
			privnodeT = "1"
		case "all":
			fallthrough
		case "*":
			privnodeT = "*"
		default:
			return "", "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", privnodeT, targetPrivateNodes)
		}
	}

	if pubnodeT, ok = st[targetPublicNodes]; ok {
		switch strings.ToLower(pubnodeT) {
		case "":
			fallthrough
		case "false":
			fallthrough
		case "no":
			fallthrough
		case "none":
			fallthrough
		case "0":
			pubnodeT = "0"
		case "any":
			fallthrough
		case "one":
			fallthrough
		case "1":
			pubnodeT = "1"
		case "all":
			fallthrough
		case "*":
			pubnodeT = "*"
		default:
			return "", "", "", "", fmt.Errorf("invalid value '%s' for target '%s'", pubnodeT, targetPublicNodes)
		}
	}

	if hostT == "0" && masterT == "0" && privnodeT == "0" && pubnodeT == "0" {
		return "", "", "", "", fmt.Errorf("no targets identified")
	}
	return hostT, masterT, privnodeT, pubnodeT, nil
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
func (is *step) Run(hosts []*pb.Host, v Variables, s Settings) (stepResults, error) {
	//if debug
	if false {
		log.Printf("running step '%s' on %d hosts...", is.Name, len(hosts))
	}

	results := stepResults{}

	if is.Serial || s.Serialize {
		for _, h := range hosts {
			//if debug
			if false {
				log.Printf("%s(%s):step(%s)@%s: starting\n", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name)
			}
			v["HostIP"] = h.PrivateIP
			v["Hostname"] = h.Name
			results[h.Name] = is.runOnHost(h, v)
			//if debug {
			if false {
				if !results[h.Name].Successful() {
					log.Printf("%s(%s):step(%s)@%s: fail\n", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name)
				} else {
					log.Printf("%s(%s):step(%s)@%s: success\n", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name)
				}
			}
		}
	} else {
		dones := map[string]chan stepResult{}
		for _, h := range hosts {
			//if debug
			if false {
				log.Printf("%s(%s):step(%s)@%s: starting\n", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, h.Name)
			}
			v["HostIP"] = h.PrivateIP
			v["Hostname"] = h.Name
			d := make(chan stepResult)
			dones[h.Name] = d
			go func(host *pb.Host, done chan stepResult) {
				done <- is.runOnHost(host, v)
			}(h, d)
		}
		for k, d := range dones {
			results[k] = <-d
			//if debug {
			if false {
				if !results[k].Successful() {
					log.Printf("%s(%s):step(%s)@%s: fail\n", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, k)
				} else {
					log.Printf("%s(%s):step(%s)@%s: done\n", is.Worker.action.String(), is.Worker.feature.DisplayName(), is.Name, k)
				}
			}
		}
	}
	return results, nil
}

func (is *step) runOnHost(host *pb.Host, v Variables) stepResult {
	// Updates variables in step script
	command, err := replaceVariablesInString(is.Script, v)
	if err != nil {
		return stepResult{success: false, err: fmt.Errorf("failed to finalize installer script for step '%s': %s", is.Name, err.Error())}
	}

	// If options file is defined, upload it to the remote host
	if is.OptionsFileContent != "" {
		err := UploadStringToRemoteFile(is.OptionsFileContent, host, "/var/tmp/options.json", "cladm", "gpac", "ug+rw-x,o-rwx")
		if err != nil {
			return stepResult{success: false, err: err}
		}
	}

	// Uploads then executes command
	filename := fmt.Sprintf("/var/tmp/feature.%s.%s_%s.sh", is.Worker.feature.DisplayName(), strings.ToLower(is.Action.String()), is.Name)
	err = UploadStringToRemoteFile(command, host, filename, "", "", "")
	if err != nil {
		return stepResult{success: false, err: err}
	}
	//if debug {
	if true {
		command = fmt.Sprintf("sudo bash %s", filename)
	} else {
		command = fmt.Sprintf("sudo bash %s; rc=$?; sudo rm -f %s /var/tmp/options.json; exit $rc", filename, filename)
	}

	// Executes the script on the remote host
	retcode, _, _, err := client.New().Ssh.Run(host.Name, command, client.DefaultConnectionTimeout, is.WallTime)
	if err != nil {
		return stepResult{success: false, err: err}
	}
	err = nil
	ok := retcode == 0
	if !ok {
		err = fmt.Errorf("step '%s' failed (retcode=%d)", is.Name, retcode)
	}
	return stepResult{success: ok, err: err}
}
