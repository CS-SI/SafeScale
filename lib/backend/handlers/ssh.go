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

package handlers

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const protocolSeparator = ":"

//go:generate minimock -o mocks/mock_sshhandler.go -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.SSHHandler

// NOTICE: At service level, we need to log before returning, because it's the last chance to track the real issue in server side, so we should catch panics here

// SSHHandler defines ssh management API
type SSHHandler interface {
	Run(hostname, cmd string) (int, string, string, fail.Error)
	Copy(from string, to string) (int, string, string, fail.Error)
	GetConfig(iaasapi.HostIdentifier) (sshapi.Connector, fail.Error)
}

// FIXME: ROBUSTNESS All functions MUST propagate context

// sshHandler SSH service
type sshHandler struct {
	job jobapi.Job
}

// NewSSHHandler ...
func NewSSHHandler(job jobapi.Job) SSHHandler {
	return &sshHandler{job: job}
}

// GetConfig creates Profile to connect to a host
func (handler *sshHandler) GetConfig(hostParam iaasapi.HostIdentifier) (_ sshapi.Connector, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	type Profile struct {
		Hostname               string   `json:"hostname"`
		IPAddress              string   `json:"ip_address"`
		Port                   int      `json:"port"`
		User                   string   `json:"user"`
		PrivateKey             string   `json:"private_key"`
		LocalPort              int      `json:"-"`
		LocalHost              string   `json:"local_host"`
		GatewayConfig          *Profile `json:"primary_gateway_config,omitempty"`
		SecondaryGatewayConfig *Profile `json:"secondary_gateway_config,omitempty"`
	}

	task := handler.job.Task()
	ctx := handler.job.Context()
	_, hostRef, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return nil, xerr
	}

	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.ssh"), "(%s)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	host, xerr := hostfactory.Load(ctx, hostRef)
	if xerr != nil {
		return nil, xerr
	}

	cfg, xerr := handler.job.Service().ConfigurationOptions()
	if xerr != nil {
		return nil, xerr
	}

	user := cfg.OperatorUsername
	if user == "" {
		logrus.Warnf("OperatorUsername is empty, check your tenants.toml file. Using default 'safescale' user instead.")
		user = abstract.DefaultUser
	}

	ip, xerr := host.GetAccessIP(task.Context())
	if xerr != nil {
		return nil, xerr
	}

	sshConfig := ssh.NewConfig(host.GetName(), ip, 22, user, "", 0, "", nil, nil)

	isSingle, xerr := host.IsSingle(ctx)
	if xerr != nil {
		return nil, xerr
	}

	isGateway, xerr := host.IsGateway(ctx)
	if xerr != nil {
		return nil, xerr
	}

	hostTrx, xerr := metadata.NewTransaction[*abstract.HostCore, *resources.Host](ctx, host)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	if isSingle || isGateway {
		xerr = metadata.InspectAbstract[*abstract.HostCore](ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
			sshConfig.PrivateKey = ahc.PrivateKey
			sshConfig.Port = int(ahc.SSHPort)
			return nil
		})
		if xerr != nil {
			return nil, xerr
		}
	} else {
		var subnetInstance *resources.Subnet
		xerr = metadata.Inspect[*abstract.HostCore](ctx, hostTrx, func(ahc *abstract.HostCore, props *serialize.JSONProperties) fail.Error {
			sshConfig.PrivateKey = ahc.PrivateKey
			sshConfig.Port = int(ahc.SSHPort)
			return props.Inspect(hostproperty.NetworkV2, func(p clonable.Clonable) fail.Error {
				hnV2, innerErr := clonable.Cast[*propertiesv2.HostNetworking](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				var subnetID string
				if hnV2.DefaultSubnetID != "" {
					subnetID = hnV2.DefaultSubnetID
				} else {
					for k := range hnV2.SubnetsByID {
						subnetID = k
						break
					}
				}
				if subnetID == "" {
					return fail.InconsistentError("no default Subnet found for Host '%s'", ahc.Name)
				}

				var innerXErr fail.Error
				subnetInstance, innerXErr = subnetfactory.Load(ctx, "", subnetID)
				return innerXErr
			})
		})
		if xerr != nil {
			return nil, xerr
		}
		if subnetInstance == nil {
			return nil, fail.NotFoundError("failed to find default Subnet of Host")
		}

		if isGateway {
			hs, err := host.GetState(ctx)
			if err != nil {
				return nil, fail.Wrap(err, "cannot retrieve host properties")
			}

			if hs != hoststate.Started {
				return nil, fail.NewError("cannot retrieve network properties when the gateway is not in 'started' state")
			}
		}

		// gets primary gateway information
		gw, xerr := subnetInstance.InspectGateway(handler.job.Context(), true)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Primary gateway not found ? let's try with the secondary one later...
				debug.IgnoreError(xerr)
			default:
				return nil, xerr
			}
		} else {
			ip, xerr = gw.GetAccessIP(task.Context())
			if xerr != nil {
				return nil, xerr
			}

			gwTrx, xerr := metadata.NewTransaction[*abstract.HostCore, *resources.Host](ctx, gw)
			if xerr != nil {
				return nil, xerr
			}
			defer gwTrx.TerminateFromError(ctx, &ferr)

			xerr = metadata.InspectAbstract[*abstract.HostCore](ctx, gwTrx, func(ahc *abstract.HostCore) fail.Error {
				sshConfig.GatewayConfig = ssh.NewConfig(ahc.Name, ip, int(ahc.SSHPort), user, ahc.PrivateKey, 0, "", nil, nil)
				return nil
			})
			if xerr != nil {
				return nil, xerr
			}
		}

		// gets secondary gateway information
		gw = nil
		gw, xerr = subnetInstance.InspectGateway(handler.job.Context(), false)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// If secondary gateway is not found, and previously failed to set primary gateway config, bail out
				if sshConfig.GatewayConfig == nil {
					return nil, fail.NotFoundError("failed to find a gateway to reach Host")
				}
			default:
				return nil, xerr
			}
		} else {
			ip, xerr = gw.GetAccessIP(task.Context())
			if xerr != nil {
				return nil, xerr
			}

			gwTrx, xerr := metadata.NewTransaction[*abstract.HostCore, *resources.Host](ctx, gw)
			if xerr != nil {
				return nil, xerr
			}
			defer gwTrx.TerminateFromError(ctx, &ferr)

			xerr = metadata.InspectAbstract[*abstract.HostCore](ctx, gwTrx, func(ahc *abstract.HostCore) fail.Error {
				sshConfig.SecondaryGatewayConfig = ssh.NewConfig(gw.GetName(), ip, int(ahc.SSHPort), user, ahc.PrivateKey, 0, "", nil, nil)
				return nil
			})
			if xerr != nil {
				return nil, xerr
			}

		}
	}

	return sshfactory.NewConnector(sshConfig)
}

// WaitServerReady waits for remote SSH server to be ready. After timeout, fails
func (handler *sshHandler) WaitServerReady(hostParam iaasapi.HostIdentifier, timeout time.Duration) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostParam == nil {
		return fail.InvalidParameterError("hostParam", "cannot be nil!")
	}

	ctx := handler.job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.ssh"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	sshCfg, xerr := handler.GetConfig(hostParam)
	if xerr != nil {
		return xerr
	}
	_, xerr = sshCfg.WaitServerReady(ctx, "ready", timeout)
	return xerr
}

// Run tries to execute command 'cmd' on the host
func (handler *sshHandler) Run(hostRef, cmd string) (_ int, _ string, _ string, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	const invalid = -1
	if handler == nil {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return invalid, "", "", fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if hostRef == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("hostRef")
	}
	if cmd == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("cmd")
	}

	retCode := invalid
	stdOut := ""
	stdErr := ""

	ctx := handler.job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.ssh"), "('%s', <command>)", hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	tracer.Trace(fmt.Sprintf("<command>=[%s]", cmd))

	host, xerr := hostfactory.Load(ctx, hostRef)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// retrieve sshCfg config to perform some commands
	sshConfig, xerr := host.GetSSHConfig(ctx)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	sshProfile, xerr := sshfactory.NewConnector(sshConfig)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	timings, xerr := handler.job.Service().Timings()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	retryErr := retry.WhileUnsuccessfulWithNotify(
		func() error {
			isAborted, err := handler.job.Aborted()
			if err != nil {
				return err
			}
			if isAborted {
				return retry.StopRetryError(nil, "operation aborted by user")
			}

			aretCode, astdOut, astdErr, xerr := handler.runWithTimeout(sshProfile, cmd, timings.HostOperationTimeout())
			if xerr != nil {
				return xerr
			}

			retCode, stdOut, stdErr = aretCode, astdOut, astdErr
			return nil
		},
		timings.SmallDelay(),
		timings.HostOperationTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				if t.Err != nil {
					logrus.WithContext(handler.job.Context()).Debugf("Remote SSH service on host '%s' isn't ready (%s), retrying...", host.GetName(), t.Err.Error())
				} else {
					logrus.WithContext(handler.job.Context()).Debugf("Remote SSH service on host '%s' isn't ready, retrying...", host.GetName())
				}
			}
		},
	)
	if retryErr != nil {
		return invalid, "", "", retryErr
	}

	return retCode, stdOut, stdErr, nil
}

// run executes command on the host
func (handler *sshHandler) runWithTimeout(ssh sshapi.Connector, cmd string, duration time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	const invalid = -1

	var sshCmd sshapi.Command
	var xerr fail.Error
	defer func() {
		if sshCmd != nil {
			_ = sshCmd.Close()
		}
	}()

	// Create the command
	sshCmd, xerr = ssh.NewCommand(handler.job.Task().Context(), cmd)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	defer func() {
		if sshCmd != nil {
			derr := sshCmd.Close()
			if derr != nil {
				if xerr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "failed to close SSH tunnel"))
					return
				}
				xerr = derr
			}
		}
	}()

	defer func() {
		if sshCmd != nil {
			_ = sshCmd.Close()
		}
	}()
	rc, stdout, stderr, xerr := sshCmd.RunWithTimeout(handler.job.Task().Context(), outputs.DISPLAY, duration) // FIXME: What if this never returns ?
	return rc, stdout, stderr, xerr
}

func extracthostName(in string) (string, fail.Error) {
	parts := strings.Split(in, protocolSeparator)
	if len(parts) == 1 {
		return "", nil
	}

	if len(parts) > 2 {
		return "", fail.InvalidRequestError("too many parts in path")
	}

	hostName := strings.TrimSpace(parts[0])
	for _, protocol := range []string{"file", "http", "https", "ftp"} {
		if strings.ToLower(hostName) == protocol {
			return "", fail.SyntaxError("no protocol expected. Only host name")
		}
	}

	return hostName, nil
}

func extractPath(in string) (string, fail.Error) {
	parts := strings.Split(in, protocolSeparator)
	if len(parts) == 1 {
		return in, nil
	}
	if len(parts) > 2 {
		return "", fail.InvalidRequestError("too many parts in path")
	}
	_, err := extracthostName(in)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(parts[1]), nil
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	_, err := hasher.Write([]byte(text))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// Copy copies file/directory from/to remote host
func (handler *sshHandler) Copy(from, to string) (retCode int, stdOut string, stdErr string, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if handler == nil {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return invalid, "", "", fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if from == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("from")
	}
	if to == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("to")
	}

	ctx := handler.job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.ssh"), "('%s', '%s')", from, to).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	hostName := ""
	var upload bool
	var localPath, remotePath string
	// Try extract host
	hostFrom, xerr := extracthostName(from)
	if xerr != nil {
		return invalid, "", "", xerr
	}
	hostTo, xerr := extracthostName(to)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	// IPAddress checks
	if hostFrom != "" && hostTo != "" {
		return invalid, "", "", fail.NotImplementedError("copy between 2 hosts is not supported yet") // FIXME: Technical debt
	}
	if hostFrom == "" && hostTo == "" {
		return invalid, "", "", fail.InvalidRequestError("no host name specified neither in from nor to")
	}

	fromPath, xerr := extractPath(from)
	if xerr != nil {
		return invalid, "", "", xerr
	}
	toPath, xerr := extractPath(to)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if hostFrom != "" {
		hostName = hostFrom
		remotePath = fromPath
		localPath = toPath
		upload = false
	} else {
		hostName = hostTo
		remotePath = toPath
		localPath = fromPath
		upload = true
	}

	host, xerr := hostfactory.Load(handler.job.Context(), hostName)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	hid, err := host.GetID()
	if err != nil {
		return invalid, "", "", fail.Wrap(err)
	}

	// retrieve ssh config to perform some commands
	sshCfg, xerr := handler.GetConfig(hid)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	var (
		stdout, stderr string
	)
	retcode := -1
	timings, xerr := handler.job.Service().Timings()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	xerr = retry.WhileUnsuccessful(
		func() error {
			theTime := timings.HostLongOperationTimeout()
			if upload {
				fi, err := os.Stat(localPath)
				if err != nil {
					return err
				}
				// get the size
				size := fi.Size()
				theTime = time.Duration(size)*time.Second/(64*1024) + 30*time.Second
			}

			iretcode, istdout, istderr, innerXErr := sshCfg.CopyWithTimeout(ctx, remotePath, localPath, upload, theTime)
			if innerXErr != nil {
				return innerXErr
			}
			if iretcode != 0 {
				problem := fail.NewError("copy failed")
				problem.Annotate("stdout", istdout)
				problem.Annotate("stderr", istderr)
				problem.Annotate("retcode", iretcode)
				return problem
			}

			logrus.WithContext(handler.job.Context()).Debugf("Checking MD5 of remote file...")
			crcCheck := func() fail.Error {
				// take local md5...
				md5hash := ""
				if localPath != "" {
					content, err := os.ReadFile(localPath)
					if err != nil {
						return fail.WarningError(err, "couldn't open local file")
					}
					md5hash = getMD5Hash(string(content))
				}

				crcCtx := handler.job.Task().Context()

				var crcCmd sshapi.Command
				var finnerXerr fail.Error
				defer func() {
					if crcCmd != nil {
						_ = crcCmd.Close()
					}
				}()

				crcCmd, finnerXerr = sshCfg.NewCommand(crcCtx, fmt.Sprintf("/usr/bin/md5sum %s", remotePath))
				if finnerXerr != nil {
					return fail.WarningError(finnerXerr, "cannot create md5 command")
				}

				fretcode, fstdout, fstderr, finnerXerr := crcCmd.RunWithTimeout(crcCtx, outputs.COLLECT, timings.HostLongOperationTimeout())
				finnerXerr = debug.InjectPlannedFail(finnerXerr)
				if finnerXerr != nil {
					finnerXerr.Annotate("retcode", fretcode)
					finnerXerr.Annotate("stdout", fstdout)
					finnerXerr.Annotate("stderr", fstderr)
					return fail.WarningError(finnerXerr, "error running md5 command")
				}
				if fretcode != 0 {
					finnerXerr = fail.NewError("failed to check md5")
					finnerXerr.Annotate("retcode", fretcode)
					finnerXerr.Annotate("stdout", fstdout)
					finnerXerr.Annotate("stderr", fstderr)
					return fail.WarningError(finnerXerr, "unexpected return code of md5 command")
				}
				if !strings.Contains(fstdout, md5hash) {
					logrus.Warnf("WRONG MD5, Tried 'md5sum %s' We got '%s' and '%s', the original was '%s'", remotePath, fstdout, fstderr, md5hash)
					return fail.NewError("wrong md5 of '%s'", remotePath)
				}
				return nil
			}
			checksumErr := crcCheck()
			if checksumErr != nil {
				if _, ok := checksumErr.(*fail.ErrWarning); !ok || valid.IsNil(checksumErr) {
					return checksumErr
				}
				logrus.Warnf(checksumErr.Error())
			}

			retcode = iretcode
			stdout = istdout
			stderr = istderr

			return nil
		},
		timings.NormalDelay(),
		2*timings.HostLongOperationTimeout(),
	)
	return retcode, stdout, stderr, xerr
}

/*
 * VPL: new Copy implementation... Why commented?

// Copy copies file/directory from/to remote host
func (handler *sshHandler) Copy(from, to, owner, mode string) (_ int, _ string, _ string, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if handler == nil {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return invalid, "", "", fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if from == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("from")
	}
	if to == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("to")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.ssh"), "('%s', '%s')", from, to).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	var (
		pull                bool
		hostRef             string
		hostPath, localPath string
		retcode             int
		stdout, stderr      string
	)

	// If source contains remote host, we pull
	parts := strings.Split(from, ":")
	if len(parts) > 1 {
		pull = true
		hostRef = parts[0]
		hostPath = strings.Join(parts[1:], ":")
	} else {
		localPath = from
	}

	// if destination contains remote host, we push (= !pull)
	parts = strings.Split(to, ":")
	if len(parts) > 1 {
		if pull {
			return invalid, "", "", fail.InvalidRequestError("file copy from one remote host to another one is not supported")
		}
		hostRef = parts[0]
		hostPath = strings.Join(parts[1:], ":")
	} else {
		if !pull {
			return invalid, "", "", fail.InvalidRequestError("failed to find a remote host in the request")
		}
		localPath = to
	}

	timings, xerr := handler.job.Scope().Timings()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Scope(), hostRef)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if pull {
		retcode, stdout, stderr, xerr = hostInstance.Pull(handler.job.Context(), hostPath, localPath, timings.HostLongOperationTimeout())
	} else {
		retcode, stdout, stderr, xerr = hostInstance.Push(handler.job.Context(), localPath, hostPath, owner, mode, timings.HostLongOperationTimeout())
	}
	if xerr != nil {
		return invalid, "", "", xerr
	}
	if retcode != 0 {
		return retcode, stdout, stderr, fail.NewError("copy failed: retcode=%d: %s", retcode, stderr)
	}

	return retcode, stdout, stderr, nil
}

*/
