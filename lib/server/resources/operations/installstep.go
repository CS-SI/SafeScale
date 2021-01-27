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
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/remotefile"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/template"
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
	retcode   int
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
	var msg string
	if sr.err != nil {
		msg = sr.err.Error()
	}
	if msg == "" && sr.retcode != 0 {
		msg = fmt.Sprintf("exited with error %d", sr.retcode)
	}
	return msg
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
func (st stepTargets) parse() (string, string, string, string, fail.Error) {
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
			return "", "", "", "", fail.SyntaxError("invalid value '%s' for target '%s'", hostT, targetHosts)
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
			return "", "", "", "", fail.SyntaxError("invalid value '%s' for target '%s'", masterT, targetMasters)
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
			return "", "", "", "", fail.SyntaxError("invalid value '%s' for target '%s'", nodeT, targetNodes)
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
			return "", "", "", "", fail.SyntaxError("invalid value '%s' for target '%s'", gwT, targetGateways)
		}
	}

	if hostT == "0" && masterT == "0" && nodeT == "0" && gwT == "0" {
		return "", "", "", "", fail.SyntaxError("no targets identified")
	}
	return hostT, masterT, nodeT, gwT, nil
}

// step is a struct containing the needed information to apply the installation
// step on all selected host targets
type step struct {
	// Worker is a back pointer to the caller
	Worker *worker
	// GetName is the name of the step
	Name string
	// Action is the action of the step (check, add, remove)
	Action installaction.Enum
	// // Targets contains the host targets to select
	// Targets stepTargets
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
func (is *step) Run(hosts []resources.Host, v data.Map, s resources.FeatureSettings) (outcomes resources.UnitResults, xerr fail.Error) {
	outcomes = &unitResults{}

	tracer := debug.NewTracer(is.Worker.feature.task, true, "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// nHosts := uint(len(hosts))
	// defer temporal.NewStopwatch().OnExitLogWithLevel(
	// 	fmt.Sprintf("Starting step '%s' on %d host%s...", is.Name, nHosts, strprocess.Plural(nHosts)),
	// 	fmt.Sprintf("Ending step '%s' on %d host%s", is.Name, len(hosts), strprocess.Plural(nHosts)),
	// 	logrus.DebugLevel,
	// )()

	if is.Serial || s.Serialize {

		for _, h := range hosts {
			tracer.Trace("%s(%s):step(%s)@%s: starting", is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName())
			is.Worker.startTime = time.Now()

			cloneV := v.Clone()
			if cloneV["HostIP"], xerr = h.GetPrivateIP(is.Worker.feature.task); xerr != nil {
				return nil, xerr
			}

			cloneV["ShortHostname"] = h.GetName()
			domain := ""
			xerr = h.Inspect(is.Worker.feature.task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Inspect(is.Worker.feature.task, hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
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
			cloneV["Hostname"] = h.GetName() + domain

			if cloneV, xerr = realizeVariables(cloneV); xerr != nil {
				return nil, xerr
			}
			subtask, err := concurrency.NewTaskWithParent(is.Worker.feature.task)
			if err != nil {
				return nil, err
			}
			outcome, xerr := subtask.Run(is.taskRunOnHost, runOnHostParameters{Host: h, Variables: cloneV})
			if xerr != nil {
				return nil, xerr
			}

			outcomes.AddOne(h.GetName(), outcome.(resources.UnitResult))

			if !outcomes.Successful() {
				if is.Worker.action == installaction.Check { // Checks can fail and it's ok
					tracer.Trace("%s(%s):step(%s)@%s finished in %s: not present",
						is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName(),
						temporal.FormatDuration(time.Since(is.Worker.startTime)))
				} else { // other steps are expected to succeed
					tracer.Trace("%s(%s):step(%s)@%s failed in %s: %s",
						is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName(),
						temporal.FormatDuration(time.Since(is.Worker.startTime)), outcomes.ErrorMessages())
				}
			} else {
				tracer.Trace("%s(%s):step(%s)@%s succeeded in %s.",
					is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName(),
					temporal.FormatDuration(time.Since(is.Worker.startTime)))
			}
		}
	} else {
		subtasks := map[string]concurrency.Task{}
		for _, h := range hosts {
			tracer.Trace("%s(%s):step(%s)@%s: starting", is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName())
			is.Worker.startTime = time.Now()

			cloneV := v.Clone()
			if cloneV["HostIP"], xerr = h.GetPrivateIP(is.Worker.feature.task); xerr != nil {
				return nil, xerr
			}
			cloneV["ShortHostname"] = h.GetName()
			domain := ""
			xerr = h.Inspect(is.Worker.feature.task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Inspect(is.Worker.feature.task, hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
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
				return nil, xerr
			}

			cloneV["Hostname"] = h.GetName() + domain
			if cloneV, xerr = realizeVariables(cloneV); xerr != nil {
				return nil, xerr
			}
			subtask, xerr := concurrency.NewTaskWithParent(is.Worker.feature.task)
			if xerr != nil {
				return nil, xerr
			}

			subtask, xerr = subtask.Start(is.taskRunOnHost, runOnHostParameters{Host: h, Variables: cloneV})
			if xerr != nil {
				return nil, xerr
			}

			subtasks[h.GetName()] = subtask
		}
		for k, s := range subtasks {
			outcome, xerr := s.Wait()
			if xerr != nil {
				logrus.Warn(tracer.TraceMessage(": %s(%s):step(%s)@%s finished after %s, but failed to recover result",
					is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, k, temporal.FormatDuration(time.Since(is.Worker.startTime))))
				continue
			}
			outcomes.AddOne(k, outcome.(resources.UnitResult))

			if !outcomes.Successful() {
				if is.Worker.action == installaction.Check { // Checks can fail and it's ok
					tracer.Trace(": %s(%s):step(%s)@%s finished in %s: not present",
						is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, k,
						temporal.FormatDuration(time.Since(is.Worker.startTime)))
				} else { // other steps are expected to succeed
					tracer.Trace(": %s(%s):step(%s)@%s failed in %s: %s",
						is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, k,
						temporal.FormatDuration(time.Since(is.Worker.startTime)), outcomes.ErrorMessages())
				}
			} else {
				tracer.Trace("%s(%s):step(%s)@%s succeeded in %s.",
					is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, k,
					temporal.FormatDuration(time.Since(is.Worker.startTime)))
			}
		}
	}
	return outcomes, nil
}

type runOnHostParameters struct {
	Host      resources.Host
	Variables data.Map
}

// taskRunOnHost ...
// Respects interface concurrency.TaskFunc
// func (is *step) runOnHost(host *protocol.Host, v Variables) Resources.UnitResult {
func (is *step) taskRunOnHost(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	var ok bool
	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}
	p, ok := params.(runOnHostParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be of type 'runOnHostParameters'")
	}

	// Updates variables in step script
	command, xerr := replaceVariablesInString(is.Script, p.Variables)
	if xerr != nil {
		return stepResult{err: fail.Wrap(xerr, "failed to finalize installer script for step '%s'", is.Name)}, nil
	}

	// If options file is defined, upload it to the remote rh
	if is.OptionsFileContent != "" {
		rfcItem := remotefile.Item{
			Remote:       utils.TempFolder + "/options.json",
			RemoteOwner:  "cladm:safescale", // FIXME: group 'safescale' must be replaced with OperatorUsername here, and why cladm is being used ?
			RemoteRights: "ug+rw-x,o-rwx",
		}
		xerr = rfcItem.UploadString(task, is.OptionsFileContent, p.Host)
		_ = os.Remove(rfcItem.Local)
		if xerr != nil {
			return stepResult{err: xerr}, nil
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
	filename := fmt.Sprintf("%s/feature.%s.%s_%s.sh", utils.TempFolder, is.Worker.feature.GetName(), strings.ToLower(is.Action.String()), is.Name)
	rfcItem := remotefile.Item{
		Remote: filename,
	}
	xerr = rfcItem.UploadString(task, command, p.Host)
	_ = os.Remove(rfcItem.Local)
	if xerr != nil {
		return stepResult{err: xerr}, nil
	}

	if !hidesOutput {
		command = fmt.Sprintf("sudo -- bash -c 'chmod u+rx %s; bash -c %s; exit ${PIPESTATUS}'", filename, filename)
	} else {
		command = fmt.Sprintf("sudo -- bash -c 'chmod u+rx %s; captf=$(mktemp); bash -c \"BASH_XTRACEFD=7 %s 7>$captf 2>&7\"; rc=${PIPESTATUS};cat $captf; rm $captf; exit ${rc}'", filename, filename)
	}

	// Executes the script on the remote host
	retcode, outrun, _, xerr := p.Host.Run(task, command, outputs.COLLECT, temporal.GetConnectionTimeout(), is.WallTime)
	if xerr != nil {
		_ = xerr.Annotate("stdout", outrun)
		return stepResult{err: xerr, retcode: retcode, output: outrun}, nil
	}

	return stepResult{success: retcode == 0, completed: true, err: nil, retcode: retcode, output: outrun}, nil
}

// realizeVariables replaces any template occuring in every variable
func realizeVariables(variables data.Map) (data.Map, fail.Error) {
	cloneV := variables.Clone()

	for k, v := range cloneV {
		if variable, ok := v.(string); ok && variable != "" {
			varTemplate, xerr := template.Parse("realize_var", variable)
			if xerr != nil {
				return nil, fail.SyntaxError("error parsing variable '%s': %s", k, xerr.Error())
			}

			buffer := bytes.NewBufferString("")
			if err := varTemplate.Execute(buffer, variables); err != nil {
				return nil, fail.ToError(err)
			}

			cloneV[k] = buffer.String()
		}
	}

	return cloneV, nil
}

// replaceVariablesInString ...
func replaceVariablesInString(text string, v data.Map) (string, fail.Error) {
	tmpl, xerr := template.Parse("replaceVariablesInString", text)
	if xerr != nil {
		return "", fail.SyntaxError("failed to parse: %s", xerr.Error())
	}

	dataBuffer := bytes.NewBufferString("")
	if err := tmpl.Execute(dataBuffer, v); err != nil {
		return "", fail.Wrap(err, "failed to replace variables")
	}

	return dataBuffer.String(), nil
}
