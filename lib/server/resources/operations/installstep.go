/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"reflect"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installaction"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
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
	success   bool  // if true, the script has finished, and the result is a success
	err       error // if an error occurred, 'err' contains it
}

// Successful returns true if the script has finished AND its results is a success
func (sr stepResult) Successful() bool {
	return sr.success
}

// Completed returns true if the script has finished, false otherwise
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
		recoveredErr := ""
		if sr.output != "" {
			lastMsg := ""
			lines := strings.Split(sr.output, "\n")
			for _, line := range lines {
				if strings.Contains(line, "+ echo '") {
					lastMsg = line
				}
			}

			if len(lastMsg) > 0 {
				recoveredErr = lastMsg[8 : len(lastMsg)-1]
			}
		}

		if len(recoveredErr) > 0 {
			msg = fmt.Sprintf("exited with error code %d: %s", sr.retcode, recoveredErr)
		} else {
			msg = fmt.Sprintf("exited with error code %d", sr.retcode)
		}
	}
	return msg
}

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
	// Serial tells if step can be performed in parallel on selected host or not
	Serial bool
}

// Run executes the step on all the concerned hosts
func (is *step) Run(task concurrency.Task, hosts []resources.Host, v data.Map, s resources.FeatureSettings) (_ resources.UnitResults, ferr fail.Error) {
	outcomes := &unitResults{}

	select {
	case <-task.Context().Done():
		return outcomes, fail.AbortedError(task.Context().Err())
	default:
	}

	if is.Serial || s.Serialize {
		return is.loopSeriallyOnHosts(task.Context(), hosts, v)
	}

	return is.loopConcurrentlyOnHosts(task.Context(), hosts, v)
}

func (is *step) loopSeriallyOnHosts(ctx context.Context, hosts []resources.Host, v data.Map) (_ resources.UnitResults, ferr fail.Error) {
	tracer := debug.NewTracer(ctx, true, "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	outcomes := &unitResults{}

	var (
		subtask concurrency.Task
		outcome concurrency.TaskResult
		clonedV data.Map
	)

	for _, h := range hosts {
		select {
		case <-ctx.Done():
			return nil, fail.AbortedError(ctx.Err())
		default:
		}

		var xerr fail.Error
		tracer.Trace("%s(%s):step(%s)@%s: starting", is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName())
		clonedV, xerr = is.initLoopTurnForHost(ctx, h, v)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		subtask, xerr = concurrency.NewTaskWithContext(ctx, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s", h.GetName())))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		outcome, xerr = is.taskRunOnHost(subtask, runOnHostParameters{Host: h, Variables: clonedV})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		if outcome != nil {
			outcomes.AddOne(h.GetName(), outcome.(resources.UnitResult))
		}

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

	return outcomes, nil
}

func (is *step) loopConcurrentlyOnHosts(inctx context.Context, hosts []resources.Host, v data.Map) (_ resources.UnitResults, ferr fail.Error) {
	tracer := debug.NewTracer(inctx, true, "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	var (
		clonedV data.Map
		subtask concurrency.Task
	)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		ra   resources.UnitResults
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		tg, xerr := concurrency.NewTaskGroupWithContext(ctx)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		var taskErr fail.Error
		subtasks := map[string]concurrency.Task{}
		for _, h := range hosts {
			clonedV, taskErr = is.initLoopTurnForHost(ctx, h, v)
			taskErr = debug.InjectPlannedFail(taskErr)
			if taskErr != nil {
				abErr := tg.AbortWithCause(taskErr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}

			subtask, taskErr = tg.Start(is.taskRunOnHost, runOnHostParameters{Host: h, Variables: clonedV})
			taskErr = debug.InjectPlannedFail(taskErr)
			if taskErr != nil {
				abErr := tg.AbortWithCause(taskErr)
				if abErr != nil {
					logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
			subtasks[h.GetName()] = subtask
		}

		tgr, xerr := tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if len(subtasks) != len(hosts) {
				logrus.Warnf("Not all tasks were started, there should be one task per host, is not the case: %d tasks and %d hosts", len(subtasks), len(hosts))
			}
			logrus.Errorf("Critical error: [%s], also look at step outcomes below for more information", spew.Sdump(xerr))
			if taskErr != nil {
				_ = taskErr.AddConsequence(xerr)
			} else {
				taskErr = xerr
			}
		}

		wrongs, outcomes, cerr := is.collectOutcomes(subtasks, tgr)
		if cerr != nil {
			if wrongs == 0 && len(subtasks) == len(hosts) {
				inconsistency := fail.InconsistentError("CRITICAL problem: there is a discrepancy between WaitGroup and its individual results: %w", cerr)
				inconsistency.Annotate("wrongs", wrongs).Annotate("outcomes", outcomes)
				chRes <- result{nil, inconsistency}
				return
			}

			if taskErr != nil {
				_ = taskErr.AddConsequence(cerr)
				chRes <- result{nil, taskErr}
				return
			}
			chRes <- result{nil, cerr}
			return
		}

		chRes <- result{outcomes, taskErr}
		return // nolint
	}()
	select {
	case res := <-chRes:
		return res.ra, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// collectOutcomes collects results from subtasks
func (is *step) collectOutcomes(subtasks map[string]concurrency.Task, results concurrency.TaskGroupResult) (int, resources.UnitResults, fail.Error) {
	outcomes := &unitResults{}
	wrongs := 0
	for k, s := range subtasks {
		sid, err := s.ID()
		if err != nil {
			return 0, nil, err
		}
		outcome := results[sid]
		if outcome != nil {
			oko, ok := outcome.(stepResult)
			if !ok {
				return wrongs, nil, fail.InconsistentError("outcome should be a stepResult (implements resources.UnitResult)")
			}

			outcomes.AddOne(k, oko)
			if oko.err != nil || !strings.Contains(oko.output, "exit 0") {
				wrongs++
			}
		}
	}
	return wrongs, outcomes, nil
}

// initLoopTurnForHost inits the coming loop turn for a specific Host
func (is *step) initLoopTurnForHost(ctx context.Context, host resources.Host, v data.Map) (clonedV data.Map, ferr fail.Error) {
	is.Worker.startTime = time.Now()

	var xerr fail.Error
	var cerr error
	clonedV, cerr = data.FromMap(v)
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	clonedV["HostIP"], xerr = host.GetPrivateIP(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Errorf("aborting because of %s", xerr.Error())
		return nil, xerr
	}

	clonedV["ShortHostname"] = host.GetName()
	domain := ""
	xerr = host.Review(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		logrus.Errorf("aborting because of %s", xerr.Error())
		return nil, xerr
	}

	var sn resources.Subnet
	sn, xerr = host.GetDefaultSubnet(ctx)
	if xerr != nil {
		return nil, xerr
	}
	clonedV["CIDR"], xerr = sn.GetCIDR(ctx)
	if xerr != nil {
		return nil, xerr
	}

	clonedV["Hostname"] = host.GetName() + domain

	// FIXME: Another bug mitigation
	isgw, xerr := host.IsGateway(ctx)
	if xerr != nil {
		return nil, xerr
	}
	clonedV["HostIsGateway"] = isgw

	// logrus.Warningf("Checking variable substitution for: %s", spew.Sdump(clonedV))

	clonedV, xerr = realizeVariables(clonedV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to realize variables")
	}

	return clonedV, nil
}

type runOnHostParameters struct {
	Host      resources.Host
	Variables data.Map
}

// taskRunOnHost ...
// Respects interface concurrency.TaskFunc
// func (is *step) runOnHost(host *protocol.Host, v Variables) Resources.UnitResult {
func (is *step) taskRunOnHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var res concurrency.TaskResult

	defer func() {
		if res != nil {
			if sres, ok := res.(stepResult); ok {
				if !sres.Completed() || !sres.Successful() || sres.Error() != nil {
					dur := spew.Sdump(res)
					if !strings.Contains(dur, "check_") {
						logrus.Debugf("task result: %s", spew.Sdump(res))
					}
				}
			}
		}
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			logrus.Debugf("task error: %v", ferr)
		}
	}()

	var ok bool
	if params == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params")
	}
	p, ok := params.(runOnHostParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be of type 'runOnHostParameters'")
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		// Updates variables in step script
		command, xerr := replaceVariablesInString(is.Script, p.Variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			problem := fail.Wrap(xerr, "failed to finalize installer script for step '%s'", is.Name)
			chRes <- result{stepResult{err: problem}, problem}
			return
		}

		hidesOutput := strings.Contains(command, "set +x\n")
		if hidesOutput {
			command = strings.Replace(command, "set +x\n", "\n", 1)
			command = strings.Replace(command, "exec 2>&1\n", "exec 2>&7\n", 1)
		}

		// Uploads then executes command
		filename := fmt.Sprintf("%s/feature.%s.%s_%s.sh", utils.TempFolder, is.Worker.feature.GetName(), strings.ToLower(is.Action.String()), is.Name)
		rfcItem := Item{
			Remote: filename,
		}

		xerr = rfcItem.UploadString(ctx, command, p.Host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			problem := fail.Wrap(xerr, "failure uploading script")
			chRes <- result{stepResult{err: problem}, problem}
			return
		}

		if !hidesOutput {
			command = fmt.Sprintf("sudo -- bash -x -c 'sync; chmod u+rx %s; bash -x -c %s; exit ${PIPESTATUS}'", filename, filename)
		} else {
			command = fmt.Sprintf("sudo -- bash -x -c 'sync; chmod u+rx %s; captf=$(mktemp); bash -x -c \"BASH_XTRACEFD=7 %s 7>$captf 2>&7\"; rc=${PIPESTATUS};cat $captf; rm $captf; exit ${rc}'", filename, filename)
		}

		// If retcode is 126, iterate a few times...
		rounds := 10
		var (
			retcode int
			outrun  string
			outerr  string
		)
		svc := p.Host.Service()
		timings, xerr := svc.Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		connTimeout := timings.ConnectionTimeout()
		for {
			select {
			case <-ctx.Done():
				chRes <- result{nil, fail.ConvertError(ctx.Err())}
				return
			default:
			}

			retcode, outrun, outerr, xerr = p.Host.Run(ctx, command, outputs.COLLECT, connTimeout, is.WallTime)
			if retcode == 126 {
				logrus.Debugf("Text busy happened")
			}

			// Executes the script on the remote host
			if retcode != 126 || rounds == 0 {
				if retcode == 126 {
					logrus.Warnf("Text busy killed the script")
				}
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					xerr.Annotate("retcode", retcode)
					xerr.Annotate("stdout", outrun)
					xerr.Annotate("stderr", outerr)
					chRes <- result{stepResult{err: xerr, retcode: retcode, output: outrun}, xerr}
					return
				}
				break
			}

			if !(strings.Contains(outrun, "bad interpreter") || strings.Contains(outerr, "bad interpreter")) {
				if xerr != nil {
					if !strings.Contains(xerr.Error(), "bad interpreter") {
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							xerr.Annotate("retcode", retcode)
							xerr.Annotate("stdout", outrun)
							xerr.Annotate("stderr", outerr)
							chRes <- result{stepResult{err: xerr, retcode: retcode, output: outrun}, xerr}
							return
						}
						break
					}
				} else {
					break
				}
			}

			rounds--
			time.Sleep(timings.SmallDelay())
		}

		chRes <- result{stepResult{success: retcode == 0, completed: true, err: nil, retcode: retcode, output: outrun}, nil}
		return // nolint
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

// realizeVariables replaces any template occurring in every variable
func realizeVariables(variables data.Map) (data.Map, fail.Error) {
	cloneV, cerr := data.FromMap(variables)
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	for k, v := range cloneV {
		if variable, ok := v.(string); ok && variable != "" {
			varTemplate, xerr := template.Parse("realize_var", variable)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return cloneV, fail.SyntaxError("error parsing variable '%s': %s", k, xerr.Error())
			}

			buffer := bytes.NewBufferString("")
			err := varTemplate.Option("missingkey=error").Execute(buffer, variables)
			err = debug.InjectPlannedError(err)
			if err != nil {
				return cloneV, fail.ConvertError(err)
			}

			cloneV[k] = buffer.String()
		}
	}

	return cloneV, nil
}

// replaceVariablesInString ...
func replaceVariablesInString(text string, v data.Map) (string, fail.Error) {
	tmpl, xerr := template.Parse("replaceVariablesInString", text)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", fail.SyntaxError("failed to parse: %s", xerr.Error())
	}

	dataBuffer := bytes.NewBufferString("")
	err := tmpl.Option("missingkey=error").Execute(dataBuffer, v)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", fail.Wrap(err, "failed to replace variables")
	}

	return dataBuffer.String(), nil
}
