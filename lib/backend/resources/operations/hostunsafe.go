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
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// unsafeRun is the non goroutine-safe version of Run, with less parameter validation, that does the real work
func (instance *Host) unsafeRun(ctx context.Context, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if cmd == "" {
		return invalid, "", "", fail.InvalidParameterError("cmd", "cannot be empty string")
	}

	state, xerr := instance.ForceGetState(ctx)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if state != hoststate.Started {
		return invalid, "", "", fail.NewError("the machine is not started: %s", state.String())
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	connTimeout := temporal.MaxTimeout(connectionTimeout, timings.SSHConnectionTimeout())
	execTimeout := temporal.MaxTimeout(executionTimeout, timings.ExecutionTimeout())

	var (
		stdOut, stdErr string
		retCode        int
	)

	hostName := instance.GetName()
	sshCfg, xerr := instance.GetSSHConfig(ctx)
	if xerr != nil {
		return retCode, stdOut, stdErr, xerr
	}

	sshProfile, xerr := sshfactory.NewConnector(sshCfg)
	if xerr != nil {
		return retCode, stdOut, stdErr, xerr
	}

	retCode, stdOut, stdErr, xerr = run(ctx, sshProfile, cmd, outs, connTimeout+execTimeout)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // == *fail.ErrAborted
			xerr = fail.ConvertError(fail.Cause(xerr))
		case *fail.ErrTimeout:
			if cerr := fail.Cause(xerr); cerr != nil {
				switch cerr.(type) {
				case *fail.ErrTimeout:
					xerr = fail.Wrap(cerr, "failed to execute command on Host '%s' in %s", hostName, temporal.FormatDuration(connTimeout+execTimeout))
				default:
					xerr = fail.Wrap(cerr, "failed to connect by SSH to Host '%s' after %s", hostName, temporal.FormatDuration(connTimeout+execTimeout))
				}
			}
		}
	}

	return retCode, stdOut, stdErr, xerr
}

// run executes command on the host
// If run fails to connect to remote host, returns *fail.ErrNotAvailable
// In case of error, can return:
// - *fail.ErrExecution: problem detected running the script
// - *fail.ErrNotAvailable: execution with 409 or 404 errors
// - *fail.ErrTimeout: execution has timed out
// - *fail.ErrAborted: execution has been aborted by context
func run(ctx context.Context, sshProfile2 api.Connector, cmd string, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	// no timeout is unsafe, we set an upper limit
	if timeout == 0 {
		timeout = temporal.HostLongOperationTimeout()
	}

	cfg, xerr := sshProfile2.Config()
	if xerr != nil {
		return 0, "", "", xerr
	}
	hn, xerr := cfg.GetHostname()
	if xerr != nil {
		return 0, "", "", xerr
	}

	var (
		iterations, retcode int
		stdout, stderr      string
	)
	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			// recreate the profile every retry
			sshProfile, xerr := sshfactory.NewConnector(cfg)
			if xerr != nil {
				return xerr
			}

			iterations++
			// Create the command
			var sshCmd api.Command
			var innerXErr fail.Error
			defer func() {
				var ignored error
				defer fail.IgnoreProblems(&ignored)

				if sshCmd != nil {
					_ = sshCmd.Close()
				}
			}()

			sshCmd, innerXErr = sshProfile.NewCommand(ctx, cmd)
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}
			retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outs, timeout)
			if innerXErr != nil {
				innerXErr.Annotate("retcode", retcode)
				innerXErr.Annotate("stdout", stdout)
				innerXErr.Annotate("stderr", stderr)
				innerXErr.Annotate("operation", cmd)
				innerXErr.Annotate("iterations", iterations)
				return innerXErr
			}

			if retcode == 255 { // ssh connection drop
				return fail.NotAvailableError("failed to execute command '%s': failed to connect", cmd)
			}
			return nil
		},
		temporal.DefaultDelay(),
		timeout+time.Minute,
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return retcode, stdout, stderr, fail.Wrap(fail.Cause(xerr), "failed to execute command on Host '%s' after %s", hn, temporal.FormatDuration(timeout))
		case *retry.ErrStopRetry:
			return retcode, stdout, stderr, fail.ConvertError(fail.Cause(xerr))
		default:
			return retcode, stdout, stderr, xerr
		}
	}
	return retcode, stdout, stderr, nil
}

func getMD5Hash(text string) string {
	hasher := md5.New()
	_, err := hasher.Write([]byte(text))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// unsafePush is the non goroutine-safe version of Push, with less parameter validation, that do the real work
// Note: must be used with wisdom
func (instance *Host) unsafePush(ctx context.Context, source, target, owner, mode string, timeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if source == "" {
		return invalid, "", "", fail.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return invalid, "", "", fail.InvalidParameterError("target", "cannot be empty string")
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	state, xerr := instance.ForceGetState(ctx)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if state != hoststate.Started {
		return invalid, "", "", fail.NewError("the machine is not started: %s", state.String())
	}

	md5hash := ""
	uploadSize := 0
	if source != "" {
		content, err := os.ReadFile(source)
		if err != nil {
			return invalid, "", "", fail.AbortedError(err, "aborted")
		}
		uploadSize = len(content)
		md5hash = getMD5Hash(string(content))
	}

	var (
		stdout, stderr string
	)

	var finalProfile api.Connector

	retcode := -1
	timeout = temporal.MaxTimeout(4*(time.Duration(uploadSize)*time.Second/(64*1024)+30*time.Second), timeout)

	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			sshCfg, xerr := instance.GetSSHConfig(ctx)
			if xerr != nil {
				return xerr
			}

			sshProfile, xerr := sshfactory.NewConnector(sshCfg)
			if xerr != nil {
				return xerr
			}

			finalProfile = sshProfile
			uploadTime := time.Duration(uploadSize)*time.Second/(64*1024) + 30*time.Second

			copyCtx, cancel := context.WithTimeout(ctx, uploadTime)
			defer cancel()

			iretcode, istdout, istderr, innerXErr := sshProfile.CopyWithTimeout(copyCtx, target, source, true, uploadTime)
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
			if retcode == 1 && (strings.Contains(stderr, "lost connection") || strings.Contains(stdout, "lost connection")) {
				problem := fail.NewError(stderr)
				problem.Annotate("retcode", retcode)
				return problem
			}

			crcCheck := func() fail.Error {
				crcCtx, cancelCrc := context.WithTimeout(ctx, uploadTime)
				defer cancelCrc()

				fretcode, fstdout, fstderr, finnerXerr := run(crcCtx, sshProfile, fmt.Sprintf("/usr/bin/md5sum %s", target), outputs.COLLECT, uploadTime)
				finnerXerr = debug.InjectPlannedFail(finnerXerr)
				if finnerXerr != nil {
					finnerXerr.Annotate("retcode", fretcode)
					finnerXerr.Annotate("stdout", fstdout)
					finnerXerr.Annotate("stderr", fstderr)

					switch finnerXerr.(type) {
					case *fail.ErrTimeout:
						return fail.Wrap(fail.Cause(finnerXerr), "failed to check md5 in %v delay", uploadTime)
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.Cause(finnerXerr), "stopping retries")
					default:
						return finnerXerr
					}
				}
				if fretcode != 0 {
					finnerXerr = fail.NewError("failed to check md5")
					finnerXerr.Annotate("retcode", fretcode)
					finnerXerr.Annotate("stdout", fstdout)
					finnerXerr.Annotate("stderr", fstderr)
				}
				if finnerXerr != nil {
					return finnerXerr
				}
				if !strings.Contains(fstdout, md5hash) {
					logrus.WithContext(ctx).Warnf("WRONG MD5, Tried 'md5sum %s' We got '%s' and '%s', the original was '%s'", target, fstdout, fstderr, md5hash)
					return fail.NewError("wrong md5 of '%s'", target)
				}
				return nil
			}

			if innerXErr = crcCheck(); innerXErr != nil {
				return innerXErr
			}

			retcode = iretcode
			stdout = istdout
			stderr = istderr

			return nil
		},
		timings.NormalDelay(),
		timeout,
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return retcode, stdout, stderr, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout:
			return retcode, stdout, stderr, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return retcode, stdout, stderr, xerr
		}
	}
	if retcode != 0 {
		return retcode, stdout, stderr, nil
	}

	// Changing rights
	cmd := ""
	if owner != "" {
		cmd += "sudo chown " + owner + ` '` + target + `' ;`
	}
	if mode != "" {
		cmd += "sudo chmod " + mode + ` '` + target + `'`
	}
	if cmd != "" {
		iretcode, istdout, istderr, innerXerr := run(ctx, finalProfile, cmd, outputs.COLLECT, timeout)
		innerXerr = debug.InjectPlannedFail(innerXerr)
		if innerXerr != nil {
			innerXerr.Annotate("retcode", iretcode)
			innerXerr.Annotate("stdout", istdout)
			innerXerr.Annotate("stderr", istderr)

			switch innerXerr.(type) {
			case *fail.ErrTimeout:
				return iretcode, istdout, istderr, fail.Wrap(fail.Cause(innerXerr), "failed to update access rights in %v delay", timeout)
			case *retry.ErrStopRetry:
				return iretcode, istdout, istderr, fail.Wrap(fail.Cause(innerXerr), "stopping retries")
			default:
				return iretcode, istdout, istderr, innerXerr
			}
		}
		if retcode != 0 {
			innerXerr = fail.NewError("failed to update access rights")
			innerXerr.Annotate("retcode", iretcode)
			innerXerr.Annotate("stdout", istdout)
			innerXerr.Annotate("stderr", istderr)
		}
		if innerXerr != nil {
			return iretcode, istdout, istderr, innerXerr
		}
	}

	return retcode, stdout, stderr, xerr
}

// unsafeGetVolumes is the not goroutine-safe version of GetVolumes, without parameter validation, that does the real work
// Note: must be used with wisdom
func (instance *Host) unsafeGetVolumes(ctx context.Context) (*propertiesv1.HostVolumes, fail.Error) {
	var hvV1 *propertiesv1.HostVolumes
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			hvV1, ok = clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.unsafeGetVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return hvV1, nil
}

// unsafeGetMounts returns the information about the mounts of the host
// Intended to be used when instance is notoriously not nil (because previously checked)
func (instance *Host) unsafeGetMounts(ctx context.Context) (mounts *propertiesv1.HostMounts, ferr fail.Error) {
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			clone, _ := hostMountsV1.Clone()
			mounts, ok = clone.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("clone should be a *propertiesv1.HostMounts")
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	return mounts, nil
}

// unsafePushStringToFileWithOwnership is the non goroutine-safe version of PushStringToFIleWithOwnership, that does the real work
func (instance *Host) unsafePushStringToFileWithOwnership(ctx context.Context, content string, filename string, owner, mode string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if content == "" {
		return fail.InvalidParameterError("content", "cannot be empty string")
	}
	if filename == "" {
		return fail.InvalidParameterError("filename", "cannot be empty string")
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	state, xerr := instance.ForceGetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.NewError("the machine is not started: %s", state.String())
	}

	hostName := instance.GetName()
	f, xerr := utils.CreateTempFileFromString(content, 0666) // nolint
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create temporary file")
	}

	defer func() {
		rerr := utils.LazyRemove(f.Name())
		if rerr != nil {
			logrus.WithContext(ctx).Debugf(rerr.Error())
		}
	}()

	to := fmt.Sprintf("%s:%s", hostName, filename)
	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			retcode, stdout, stderr, innerXErr := instance.unsafePush(ctx, f.Name(), filename, owner, mode, timings.ExecutionTimeout())
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 && (stdout != "" || stderr != "") {
				logrus.WithContext(ctx).Debugf("Ignoring '%s' and '%s'", stdout, stderr)
			}
			if retcode == 1 && (strings.Contains(stderr, "lost connection") || strings.Contains(stdout, "lost connection")) {
				problem := fail.NewError(stderr)
				problem.Annotate("retcode", retcode)
				return problem
			}
			if retcode != 0 {
				return fail.NewError("failed to copy temporary file to '%s' (retcode: %d)", to, retcode)
			}
			return nil
		},
		timings.SmallDelay(),
		2*temporal.MaxTimeout(timings.ConnectionTimeout(), timings.ExecutionTimeout()),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(retryErr))
		case *retry.ErrTimeout:
			return fail.Wrap(retryErr, "timeout trying to copy temporary file to '%s'", to)
		default:
			return xerr
		}
	}

	return nil
}

// unsafeGetDefaultSubnet returns the Networking instance corresponding to host default subnet
func (instance *Host) unsafeGetDefaultSubnet(ctx context.Context) (subnetInstance resources.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	svc := instance.Service()
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(hostproperty.NetworkV2) {
			return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				networkV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				var inErr fail.Error
				subnetInstance, inErr = LoadSubnet(ctx, svc, "", networkV2.DefaultSubnetID)
				if inErr != nil {
					return inErr
				}
				return nil
			})
		}
		return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			var inErr fail.Error
			subnetInstance, inErr = LoadSubnet(ctx, svc, "", hostNetworkV2.DefaultSubnetID)
			if inErr != nil {
				return inErr
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return subnetInstance, nil
}
