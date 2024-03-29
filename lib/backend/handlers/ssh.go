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
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry/enums/verdict"
)

const protocolSeparator = ":"

//go:generate minimock -o mocks/mock_sshhandler.go -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.SSHHandler

// NOTICE: At service level, we need to log before returning, because it's the last chance to track the real issue in server side, so we should catch panics here

// SSHHandler defines ssh management API
type SSHHandler interface {
	Run(hostname, cmd string) (int, string, string, fail.Error)
	Copy(from string, to string) (int, string, string, fail.Error)
	GetConfig(stacks.HostParameter) (api.Connector, fail.Error)
}

// FIXME: ROBUSTNESS All functions MUST propagate context

// sshHandler SSH service
type sshHandler struct {
	job backend.Job
}

// NewSSHHandler ...
func NewSSHHandler(job backend.Job) SSHHandler {
	return &sshHandler{job: job}
}

// GetConfig creates Profile to connect to a host
func (handler *sshHandler) GetConfig(hostParam stacks.HostParameter) (_ api.Connector, ferr fail.Error) {
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

	svc := handler.job.Service()
	ctx := handler.job.Context()

	_, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	host, xerr := hostfactory.Load(ctx, svc, hostRef, isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	if !isTerraform {
		cfg, xerr := svc.GetConfigurationOptions(ctx)
		if xerr != nil {
			return nil, xerr
		}
		var user string
		if anon, ok := cfg.Get("OperatorUsername"); ok {
			user, ok = anon.(string)
			if !ok {
				logrus.WithContext(ctx).Warnf("OperatorUsername is not a string, check your tenants.toml file. Using 'safescale' user instead.")
			} else if user == "" {
				logrus.WithContext(ctx).Warnf("OperatorUsername is empty, check your tenants.toml file. Using 'safescale' user instead.")
			}
		}
		if user == "" {
			user = abstract.DefaultUser
		}

		ip, xerr := host.GetAccessIP(handler.job.Context())
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

		if isSingle || isGateway {
			xerr = host.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				ahc, ok := clonable.(*abstract.HostCore)
				if !ok {
					return fail.InconsistentError("")
				}

				sshConfig.PrivateKey = ahc.PrivateKey
				sshConfig.Port = int(ahc.SSHPort)
				return nil
			})
			if xerr != nil {
				return nil, xerr
			}
		} else {
			var subnetInstance resources.Subnet
			xerr = host.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				ahc, ok := clonable.(*abstract.HostCore)
				if !ok {
					return fail.InconsistentError("")
				}

				sshConfig.PrivateKey = ahc.PrivateKey
				sshConfig.Port = int(ahc.SSHPort)
				return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
					hnV2, ok := clonable.(*propertiesv2.HostNetworking)
					if !ok {
						return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
					subnetInstance, innerXErr = subnetfactory.Load(ctx, svc, "", subnetID, false)
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
				hs, err := host.ForceGetState(ctx)
				if err != nil {
					return nil, fail.Wrap(err, "cannot retrieve host properties")
				}
				if hs != hoststate.Started {
					return nil, fail.NewError("cannot retrieve network properties when the gateway is not in 'started' state")
				}
			}

			var (
				gwahc *abstract.HostCore
				ok    bool
			)

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
				xerr = gw.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					if gwahc, ok = clonable.(*abstract.HostCore); !ok {
						return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					return nil
				})
				if xerr != nil {
					return nil, xerr
				}

				if ip, xerr = gw.GetAccessIP(handler.job.Context()); xerr != nil {
					return nil, xerr
				}

				gwConfig, xerr := gw.GetSSHConfig(handler.job.Context())
				if xerr != nil {
					return nil, xerr
				}

				thePort, _ := gwConfig.GetPort()

				GatewayConfig := ssh.NewConfig(gw.GetName(), ip, int(thePort), user, gwahc.PrivateKey, 0, "", nil, nil)
				sshConfig.GatewayConfig = GatewayConfig
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
				xerr = gw.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					gwahc, ok = clonable.(*abstract.HostCore)
					if !ok {
						return fail.InconsistentError("'*abstract.HostFull' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					return nil
				})
				if xerr != nil {
					return nil, xerr
				}

				if ip, xerr = gw.GetAccessIP(handler.job.Context()); xerr != nil {
					return nil, xerr
				}

				gwConfig, xerr := gw.GetSSHConfig(handler.job.Context())
				if xerr != nil {
					return nil, xerr
				}

				thePort, _ := gwConfig.GetPort()

				GatewayConfig := ssh.NewConfig(gw.GetName(), ip, int(thePort), user, gwahc.PrivateKey, 0, "", nil, nil)
				sshConfig.SecondaryGatewayConfig = GatewayConfig
			}
		}

		return sshfactory.NewConnector(sshConfig)
	}

	aCfg, xerr := host.GetSSHConfig(ctx)
	if xerr != nil {
		return nil, xerr
	}

	// if it's terraform, use the terraform ssh config
	return sshfactory.NewConnector(aCfg)
}

// WaitServerReady waits for remote SSH server to be ready. After timeout, fails
func (handler *sshHandler) WaitServerReady(hostParam stacks.HostParameter, timeout time.Duration) (ferr fail.Error) {
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
	logrus.WithContext(ctx).Tracef(fmt.Sprintf("<command>=[%s]", cmd))

	timings, xerr := handler.job.Service().Timings()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return invalid, "", "", xerr
	}
	isTerraform = pn == "terraform"

	retryErr := retry.WhileUnsuccessfulWithNotify(
		func() error {
			host, xerr := hostfactory.Load(ctx, handler.job.Service(), hostRef, isTerraform)
			if xerr != nil {
				return xerr
			}

			// retrieve sshCfg config to perform some commands
			sshConfig, xerr := host.GetSSHConfig(ctx)
			if xerr != nil {
				return xerr
			}

			sshProfile, xerr := sshfactory.NewConnector(sshConfig)
			if xerr != nil {
				return xerr
			}

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
					logrus.WithContext(handler.job.Context()).Debugf("Remote SSH service on host '%s' isn't ready (%s), retrying...", hostRef, t.Err.Error())
				} else {
					logrus.WithContext(handler.job.Context()).Debugf("Remote SSH service on host '%s' isn't ready, retrying...", hostRef)
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
func (handler *sshHandler) runWithTimeout(ssh api.Connector, cmd string, duration time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	const invalid = -1

	var sshCmd api.Command
	var xerr fail.Error
	defer func() {
		if sshCmd != nil {
			_ = sshCmd.Close()
		}
	}()

	// Create the command
	sshCmd, xerr = ssh.NewCommand(handler.job.Context(), cmd)
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
	rc, stdout, stderr, xerr := sshCmd.RunWithTimeout(handler.job.Context(), outputs.DISPLAY, duration) // FIXME: What if this never returns ?
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

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return invalid, "", "", xerr
	}
	isTerraform = pn == "terraform"

	host, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), hostName, isTerraform)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	hid, err := host.GetID()
	if err != nil {
		return invalid, "", "", fail.ConvertError(err)
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
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

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

				crcCtx := handler.job.Context()

				var crcCmd api.Command
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
					logrus.WithContext(ctx).Warnf("WRONG MD5, Tried 'md5sum %s' We got '%s' and '%s', the original was '%s'", remotePath, fstdout, fstderr, md5hash)
					return fail.NewError("wrong md5 of '%s'", remotePath)
				}
				return nil
			}
			checksumErr := crcCheck()
			if checksumErr != nil {
				if _, ok := checksumErr.(*fail.ErrWarning); !ok || valid.IsNil(checksumErr) {
					return checksumErr
				}
				logrus.WithContext(ctx).Warnf(checksumErr.Error())
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
