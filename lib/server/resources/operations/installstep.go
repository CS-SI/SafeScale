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
	"strings"
	"text/template"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/remotefile"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	targetHosts    = "hosts"
	targetMasters  = "masters"
	targetNodes    = "nodes"
	targetGateways = "gateways"
)

type stepResult struct {
	completed bool // if true, the script has been run to completion
	output    string
	success   bool  // if true, the script has been run successfully and the result is a success
	err       error // if an error occurred, contains the err
}

func (sr stepResult) Successful() bool {
	return sr.success
}

func (sr stepResult) Completed() bool {
	return sr.completed
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

// // stepResults contains the errors of the step for each host target
// type stepResults map[string]stepResult

// // ErrorMessages returns a string containing all the errors registered
// func (s stepResults) ErrorMessages() string {
// 	output := ""
// 	for h, k := range s {
// 		val := k.ErrorMessage()
// 		if val != "" {
// 			output += h + ": " + val + "\n"
// 		}
// 	}
// 	return output
// }

// // UncompletedEntries returns an array of string of all keys where the script
// // to run action wasn't completed
// func (s stepResults) UncompletedEntries() []string {
// 	var output []string
// 	for k, v := range s {
// 		if !v.Completed() {
// 			output = append(output, k)
// 		}
// 	}
// 	return output
// }

// // Successful tells if all the steps have been successful
// func (s stepResults) Successful() bool {
// 	if len(s) == 0 {
// 		return false
// 	}
// 	for _, k := range s {
// 		if !k.Successful() {
// 			return false
// 		}
// 	}
// 	return true
// }

// // Completed tells if all the scripts corresponding to action have been completed.
// func (s stepResults) Completed() bool {
// 	if len(s) == 0 {
// 		return false
// 	}
// 	for _, k := range s {
// 		if !k.Completed() {
// 			return false
// 		}
// 	}
// 	return true
// }

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
			return "", "", "", "", scerr.SyntaxError("invalid value '%s' for target '%s'", hostT, targetHosts)
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
			return "", "", "", "", scerr.SyntaxError("invalid value '%s' for target '%s'", masterT, targetMasters)
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
			return "", "", "", "", scerr.SyntaxError("invalid value '%s' for target '%s'", nodeT, targetNodes)
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
			return "", "", "", "", scerr.SyntaxError("invalid value '%s' for target '%s'", gwT, targetGateways)
		}
	}

	if hostT == "0" && masterT == "0" && nodeT == "0" && gwT == "0" {
		return "", "", "", "", scerr.SyntaxError("no targets identified")
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
	Action installaction.Enum
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
func (is *step) Run(hosts []resources.Host, v data.Map, s resources.FeatureSettings) (outcomes resources.UnitResults, err error) {
	outcomes = unitResults{}

	tracer := concurrency.NewTracer(is.Worker.feature.task, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	nHosts := uint(len(hosts))
	defer temporal.NewStopwatch().OnExitLogWithLevel(
		fmt.Sprintf("Starting step '%s' on %d host%s...", is.Name, nHosts, strprocess.Plural(nHosts)),
		fmt.Sprintf("Ending step '%s' on %d host%s", is.Name, len(hosts), strprocess.Plural(nHosts)),
		logrus.DebugLevel,
	)()

	if is.Serial || s.Serialize {

		for _, h := range hosts {
			tracer.Trace("%s(%s):step(%s)@%s: starting", is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, h.SafeGetName())
			is.Worker.startTime = time.Now()

			cloneV := v.Clone()
			cloneV["HostIP"], err = h.GetPrivateIP(is.Worker.feature.task)
			if err != nil {
				return nil, err
			}
			cloneV["Hostname"] = h.SafeGetName()
			cloneV, err = realizeVariables(cloneV)
			if err != nil {
				return nil, err
			}
			subtask, err := concurrency.NewTaskWithParent(is.Worker.feature.task)
			if err != nil {
				return nil, err
			}
			outcome, err := subtask.Run(is.taskRunOnHost, data.Map{"host": h, "variables": cloneV})
			if err != nil {
				return nil, err
			}
			outcomes.AddSingle(h.SafeGetName(), outcome.(resources.UnitResult))
			subtask.Close()
			// err = subtask.Reset()
			// if err != nil {
			// 	return nil, err
			// }

			if !outcomes.Successful() {
				if is.Worker.action == installaction.Check { // Checks can fail and it's ok
					tracer.Trace("%s(%s):step(%s)@%s finished in %s: not present: %s",
						is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, h.SafeGetName(),
						temporal.FormatDuration(time.Since(is.Worker.startTime)), outcomes.ErrorMessages())
				} else { // other steps are expected to succeed
					tracer.Trace("%s(%s):step(%s)@%s failed in %s: %s",
						is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, h.SafeGetName(),
						temporal.FormatDuration(time.Since(is.Worker.startTime)), outcomes.ErrorMessages())
				}
			} else {
				tracer.Trace("%s(%s):step(%s)@%s succeeded in %s.",
					is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, h.SafeGetName(),
					temporal.FormatDuration(time.Since(is.Worker.startTime)))
			}
		}
	} else {
		subtasks := map[string]concurrency.Task{}
		for _, h := range hosts {
			tracer.Trace("%s(%s):step(%s)@%s: starting", is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, h.SafeGetName())
			is.Worker.startTime = time.Now()

			cloneV := v.Clone()
			cloneV["HostIP"], err = h.GetPrivateIP(is.Worker.feature.task)
			if err != nil {
				return nil, err
			}
			cloneV["Hostname"] = h.SafeGetName()
			cloneV, err = realizeVariables(cloneV)
			if err != nil {
				return nil, err
			}
			subtask, err := concurrency.NewTaskWithParent(is.Worker.feature.task)
			if err != nil {
				return nil, err
			}

			subtask, err = subtask.Start(is.taskRunOnHost, data.Map{
				"host":      h,
				"variables": cloneV,
			})
			if err != nil {
				return nil, err
			}

			subtasks[h.SafeGetName()] = subtask
		}
		for k, s := range subtasks {
			outcome, err := s.Wait()
			if err != nil {
				logrus.Warn(tracer.TraceMessage(": %s(%s):step(%s)@%s finished after %s, but failed to recover result",
					is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, k, temporal.FormatDuration(time.Since(is.Worker.startTime))))
				continue
			}
			outcomes.AddSingle(k, outcome.(resources.UnitResult))

			if !outcomes.Successful() {
				if is.Worker.action == installaction.Check { // Checks can fail and it's ok
					tracer.Trace(": %s(%s):step(%s)@%s finished in %s: not present: %s",
						is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, k,
						temporal.FormatDuration(time.Since(is.Worker.startTime)), outcomes.ErrorMessages())
				} else { // other steps are expected to succeed
					tracer.Trace(": %s(%s):step(%s)@%s failed in %s: %s",
						is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, k,
						temporal.FormatDuration(time.Since(is.Worker.startTime)), outcomes.ErrorMessages())
				}
			} else {
				tracer.Trace("%s(%s):step(%s)@%s succeeded in %s.",
					is.Worker.action.String(), is.Worker.feature.SafeGetName(), is.Name, k,
					temporal.FormatDuration(time.Since(is.Worker.startTime)))
			}
		}
	}
	return outcomes, nil
}

// taskRunOnHost ...
// Respects interface concurrency.TaskFunc
// func (is *step) runOnHost(host *protocol.Host, v Variables) Resources.UnitResult {
func (is *step) taskRunOnHost(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	var (
		p  = data.Map{}
		ok bool
	)
	if params != nil {
		if p, ok = params.(data.Map); !ok {
			return nil, scerr.InvalidParameterError("params", "must be a 'data.Map'")
		}
	}

	// Get parameters
	host, ok := p["host"].(resources.Host)
	if !ok {
		return nil, scerr.InvalidParameterError("params['host']", "must be a 'resources.Host'")
	}
	variables, ok := p["variables"].(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params['variables'", "must be a 'data.Map'")
	}

	// Updates variables in step script
	command, err := replaceVariablesInString(is.Script, variables)
	if err != nil {
		return stepResult{err: scerr.Wrap(err, "failed to finalize installer script for step '%s'", is.Name)}, nil
	}

	// If options file is defined, upload it to the remote host
	if is.OptionsFileContent != "" {
		// err := UploadStringToRemoteFile(is.OptionsFileContent, host, utils.TempFolder+"/options.json", "cladm:safescale", "ug+rw-x,o-rwx")
		rfcItem := remotefile.Item{
			Remote:       utils.TempFolder + "/options.json",
			RemoteOwner:  "cladm:safescale",
			RemoteRights: "ug+rw-x,o-rwx",
		}
		err = rfcItem.UploadString(task, is.OptionsFileContent, host)
		_ = os.Remove(rfcItem.Local)
		if err != nil {
			return stepResult{err: err}, nil
		}
	}

	hidesOutput := strings.Contains(command, "set +x\n")
	if hidesOutput {
		command = strings.Replace(command, "set +x\n", "\n", 1)
		if strings.Contains(command, "exec 2>&1\n") {
			command = strings.Replace(command, "exec 2>&1\n", "exec 2>&7\n", 1)
		}
	}

	// Uploads then executes command
	filename := fmt.Sprintf("%s/feature.%s.%s_%s.sh", utils.TempFolder, is.Worker.feature.SafeGetName(), strings.ToLower(is.Action.String()), is.Name)
	// err = UploadStringToRemoteFile(command, host, filename, "", "")
	rfcItem := remotefile.Item{
		Remote: filename,
	}
	err = rfcItem.UploadString(task, command, host)
	_ = os.Remove(rfcItem.Local)
	if err != nil {
		return stepResult{err: err}, nil
	}

	if !hidesOutput {
		command = fmt.Sprintf("sudo chmod u+rx %s;sudo bash %s;exit ${PIPESTATUS}", filename, filename)
	} else {
		command = fmt.Sprintf("sudo chmod u+rx %s;sudo bash -c \"BASH_XTRACEFD=7 %s 7> /tmp/captured 2>&7\";echo ${PIPESTATUS} > /tmp/errc;cat /tmp/captured; sudo rm /tmp/captured;exit `cat /tmp/errc`", filename, filename)
	}

	// Executes the script on the remote host
	retcode, outrun, _, err := host.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), is.WallTime)
	if err != nil {
		return stepResult{err: err, output: outrun}, nil
	}
	err = nil
	ok = retcode == 0
	if !ok {
		err = scerr.ReturnedValuesFromShellToError(retcode, outrun, "", err, "failure")
	}
	return stepResult{success: ok, completed: true, err: err, output: outrun}, nil
}

// func clitools.ReturnValuesFromShellToError(retcode int, stdout string, stderr string, err error, msg string) error {
// 	richErrc := fmt.Sprintf("%d", retcode)

// 	var collected []string
// 	if stdout != "" {
// 		errLines := strings.Split(stdout, "\n")
// 		for _, errline := range errLines {
// 			if strings.Contains(errline, "An error occurred") {
// 				collected = append(collected, errline)
// 			}
// 		}
// 	}
// 	if stderr != "" {
// 		errLines := strings.Split(stderr, "\n")
// 		for _, errline := range errLines {
// 			if strings.Contains(errline, "An error occurred") {
// 				collected = append(collected, errline)
// 			}
// 		}
// 	}

// 	if len(collected) > 0 {
// 		if err != nil {
// 			return scerr.Wrap(err, fmt.Sprintf("%s: failed with error code %s, std errors [%s]", msg, richErrc, strings.Join(collected, ";")))
// 		}
// 		return scerr.NewError("%s: failed with error code %s, std errors [%s]", msg, richErrc, strings.Join(collected, ";"))
// 	}

// 	if err != nil {
// 		return scerr.Wrap(err, fmt.Sprintf("%s: failed with error code %s", msg, richErrc))
// 	}
// 	if retcode != 0 {
// 		return scerr.NewError("%s: failed with error code %s", msg, richErrc)
// 	}

// 	return nil
// }

// realizeVariables replaces in every variable any template
func realizeVariables(variables data.Map) (data.Map, error) {
	cloneV := variables.Clone()

	for k, v := range cloneV {
		if variable, ok := v.(string); ok {
			varTemplate, err := template.New("realize_var").Parse(variable)
			if err != nil {
				return nil, scerr.SyntaxError("error parsing variable '%s': %s", k, err.Error())
			}
			buffer := bytes.NewBufferString("")
			err = varTemplate.Execute(buffer, variables)
			if err != nil {
				return nil, err
			}
			cloneV[k] = buffer.String()
		}
	}

	return cloneV, nil
}

func replaceVariablesInString(text string, v data.Map) (string, error) {
	tmpl, err := template.New("text").Parse(text)
	if err != nil {
		return "", scerr.SyntaxError("failed to parse: %s", err.Error())
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmpl.Execute(dataBuffer, v)
	if err != nil {
		return "", scerr.Wrap(err, "failed to replace variables")
	}
	return dataBuffer.String(), nil
}
