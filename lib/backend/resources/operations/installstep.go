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
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installaction"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
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
	complete bool // if true, the script has been run to completion
	retcode  int
	output   string
	success  bool  // if true, the script has finished, and the result is a success
	err      error // if an error occurred, 'err' contains it
}

// Successful returns true if the script has finished AND its results is a success
func (sr stepResult) Successful() bool {
	return sr.success
}

// Completed returns true if the script has finished, false otherwise
func (sr stepResult) Completed() bool {
	return sr.complete
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
func (is *step) Run(inctx context.Context, hosts []resources.Host, v data.Map, s resources.FeatureSettings) (_ resources.UnitResults, ferr fail.Error) {
	outcomes := &unitResults{}

	select {
	case <-inctx.Done():
		return outcomes, fail.AbortedError(inctx.Err())
	default:
	}

	if is.Serial || s.Serialize {
		return is.loopSeriallyOnHosts(inctx, hosts, v)
	}

	return is.loopConcurrentlyOnHosts(inctx, hosts, v)
}

func (is *step) loopSeriallyOnHosts(ctx context.Context, hosts []resources.Host, v data.Map) (_ resources.UnitResults, ferr fail.Error) {
	tracer := debug.NewTracer(ctx, true, "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	outcomes := &unitResults{}

	for _, h := range hosts {
		h := h

		select {
		case <-ctx.Done():
			return nil, fail.AbortedError(ctx.Err())
		default:
		}

		tracer.Trace("%s(%s):step(%s)@%s: starting", is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName())
		clonedV, xerr := is.initLoopTurnForHost(ctx, h, v)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		outcome, xerr := is.taskRunOnHost(ctx, runOnHostParameters{Host: h, Variables: clonedV})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		outcomes.AddOne(h.GetName(), outcome)

		if !outcomes.Successful() {
			if is.Worker.action == installaction.Check { // Checks can fail and it's ok
				tracer.Trace("%s(%s):step(%s)@%s finished in %s: not present",
					is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName(),
					temporal.FormatDuration(time.Since(is.Worker.GetStartTime())))
			} else { // other steps are expected to succeed
				tracer.Trace("%s(%s):step(%s)@%s failed in %s: %s",
					is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName(),
					temporal.FormatDuration(time.Since(is.Worker.GetStartTime())), outcomes.ErrorMessages())
			}
		} else {
			tracer.Trace("%s(%s):step(%s)@%s succeeded in %s.",
				is.Worker.action.String(), is.Worker.feature.GetName(), is.Name, h.GetName(),
				temporal.FormatDuration(time.Since(is.Worker.GetStartTime())))
		}
	}

	return outcomes, nil
}

func (is *step) loopConcurrentlyOnHosts(inctx context.Context, hosts []resources.Host, v data.Map) (_ resources.UnitResults, ferr fail.Error) {
	tracer := debug.NewTracer(inctx, true, "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(inctx, &ferr, tracer.TraceMessage())

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		ra   resources.UnitResults
		rErr fail.Error
	}

	type partResult struct {
		who  string
		what stepResult
		err  fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		blue := make(chan partResult, len(hosts))

		tg := new(errgroup.Group)
		for _, h := range hosts {
			h := h
			tg.Go(func() error {
				actx, loopCancel := context.WithCancel(ctx)
				defer loopCancel()
				tr, err := is.taskRunOnHostWithLoop(actx, runOnHostParameters{Host: h, Variables: v})
				hid, _ := h.GetID()
				blue <- partResult{who: hid, what: tr, err: err}
				if err != nil {
					return err
				}
				return nil
			})
		}

		xerr := fail.ConvertError(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		outcomes := &unitResults{}
		close(blue)
		for ur := range blue {
			outcomes.AddOne(ur.who, ur.what)
		}

		if xerr != nil {
			chRes <- result{outcomes, xerr}
			return
		}

		chRes <- result{outcomes, nil}
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

// initLoopTurnForHost inits the coming loop turn for a specific Host
func (is *step) initLoopTurnForHost(ctx context.Context, host resources.Host, v data.Map) (clonedV data.Map, ferr fail.Error) {
	is.Worker.SetStartTime(time.Now())

	var xerr fail.Error
	var cerr error
	clonedV, cerr = data.FromMap(v)
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	clonedV["HostIP"], xerr = host.GetPrivateIP(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.WithContext(ctx).Errorf("aborting because of %s", xerr.Error())
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
		logrus.WithContext(ctx).Errorf("aborting because of %s", xerr.Error())
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

func (is *step) taskRunOnHostWithLoop(inctx context.Context, params interface{}) (_ stepResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer elapsed("taskRunOnHostWithLoop")()

	if params == nil {
		return stepResult{}, fail.InvalidParameterCannotBeNilError("params")
	}
	p, ok := params.(runOnHostParameters)
	if !ok {
		return stepResult{}, fail.InvalidParameterError("params", "must be of type 'runOnHostParameters'")
	}

	cv, xerr := is.initLoopTurnForHost(inctx, p.Host, p.Variables)
	if xerr != nil {
		return stepResult{}, xerr
	}

	res, xerr := is.taskRunOnHost(inctx, runOnHostParameters{
		Host:      p.Host,
		Variables: cv,
	})

	if xerr != nil {
		return stepResult{}, xerr
	}
	return res, nil
}

// taskRunOnHost ...
func (is *step) taskRunOnHost(inctx context.Context, params interface{}) (_ stepResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer elapsed("taskRunOnHost")()

	if params == nil {
		return stepResult{}, fail.InvalidParameterCannotBeNilError("params")
	}
	p, ok := params.(runOnHostParameters)
	if !ok {
		return stepResult{}, fail.InvalidParameterError("params", "must be of type 'runOnHostParameters'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  stepResult
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

		var does bool
		does, xerr = p.Host.Exists(ctx)
		if xerr != nil {
			chRes <- result{stepResult{err: xerr}, xerr}
			return
		}
		if !does {
			logrus.WithContext(ctx).Errorf("Disaster: trying to install things on non-existing host")
			chRes <- result{stepResult{success: true, complete: true, err: nil, retcode: 0, output: ""}, nil}
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
			chRes <- result{stepResult{}, xerr}
			return
		}

		connTimeout := timings.ConnectionTimeout()
		for {
			select {
			case <-ctx.Done():
				chRes <- result{stepResult{}, fail.ConvertError(ctx.Err())}
				return
			default:
			}

			retcode, outrun, outerr, xerr = p.Host.Run(ctx, command, outputs.COLLECT, connTimeout, is.WallTime)
			if retcode == 126 {
				logrus.WithContext(ctx).Debugf("Text busy happened")
			}

			// Executes the script on the remote host
			if retcode != 126 || rounds == 0 {
				if retcode == 126 {
					logrus.WithContext(ctx).Warnf("Text busy killed the script")
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

		chRes <- result{stepResult{success: retcode == 0, complete: true, err: nil, retcode: retcode, output: outrun}, nil}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes
		return stepResult{}, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return stepResult{}, fail.ConvertError(inctx.Err())
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
