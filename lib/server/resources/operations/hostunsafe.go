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
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// UnsafeRun is the non goroutine-safe version of Run, with less parameter validation, that does the real work
func (instance *Host) UnsafeRun(ctx context.Context, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	const invalid = -1

	if cmd == "" {
		return invalid, "", "", fail.InvalidParameterError("cmd", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return invalid, "", "", xerr
			}
		default:
			return invalid, "", "", xerr
		}
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	if connectionTimeout < temporal.GetConnectSSHTimeout() {
		connectionTimeout = temporal.GetConnectSSHTimeout()
	}

	var (
		stdOut, stdErr string
		retCode        int
	)

	hostName := instance.GetName()
	retCode, stdOut, stdErr, xerr = run(ctx, instance.sshProfile, cmd, outs, executionTimeout)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // == *fail.ErrAborted
			xerr = fail.ConvertError(fail.Cause(xerr))
		case *fail.ErrTimeout:
			if cerr := fail.Cause(xerr); cerr != nil {
				switch cerr.(type) {
				case *fail.ErrTimeout:
					xerr = fail.Wrap(cerr, "failed to execute command on Host '%s' in %s", hostName, temporal.FormatDuration(executionTimeout))
				default:
					xerr = fail.Wrap(cerr, "failed to connect by SSH to Host '%s' after %s", hostName, temporal.FormatDuration(connectionTimeout))
				}
			}
		}
	}

	return retCode, stdOut, stdErr, xerr
}

// run executes command on the host
// If run fails to connect to remote host, returns *fail.ErrNotAvailable
// In case of error, can return:
// - *fail.ErrExecution: // FIXME: complete comment
// - *fail.ErrNotAvailable: // FIXME: complete comment
// - *fail.ErrTimeout: execution has timed out
// - *fail.ErrAborted: execution has been aborted by context
func run(ctx context.Context, ssh *system.SSHConfig, cmd string, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	// no timeout is unsafe, we set an upper limit
	if timeout == 0 {
		timeout = temporal.GetLongOperationTimeout()
	}

	var (
		iterations, retcode int
		stdout, stderr      string
	)
	xerr := retry.WhileUnsuccessful(
		func() error {
			iterations++
			// Create the command
			sshCmd, innerXErr := ssh.NewCommand(ctx, cmd)
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			// Do not forget to close the command (allowing to close SSH tunnels and free process)
			defer func(cmd *system.SSHCommand) {
				derr := cmd.Close()
				if derr != nil {
					if innerXErr == nil {
						innerXErr = derr
					} else {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "failed to close SSH tunnel"))
					}
				}
			}(sshCmd)

			retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outs, timeout)
			if innerXErr != nil {
				// Adds stdout and stderr as annotations to innerXErr
				_ = innerXErr.Annotate("retcode", retcode)
				_ = innerXErr.Annotate("stdout", stdout)
				_ = innerXErr.Annotate("stderr", stderr)
				_ = innerXErr.Annotate("operation", cmd)
				_ = innerXErr.Annotate("iterations", iterations)
				return innerXErr
			}
			// If retcode == 255, ssh connection failed
			if retcode == 255 {
				return fail.NotAvailableError("failed to execute command '%s': failed to connect", cmd)
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		timeout+time.Minute,
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return retcode, stdout, stderr, fail.Wrap(fail.Cause(xerr), "failed to execute command on Host '%s' after %s", ssh.Hostname, temporal.FormatDuration(timeout))
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

// UnsafePush is the non goroutine-safe version of Push, with less parameter validation, that do the real work
// Note: must be used with wisdom
func (instance *Host) UnsafePush(ctx context.Context, source, target, owner, mode string, timeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)
	const invalid = -1

	if source == "" {
		return invalid, "", "", fail.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return invalid, "", "", fail.InvalidParameterError("target", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return invalid, "", "", xerr
			}
		default:
			return invalid, "", "", xerr
		}
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	if timeout < temporal.GetHostTimeout() {
		timeout = temporal.GetHostTimeout()
	}

	md5hash := ""
	if source != "" {
		if content, err := ioutil.ReadFile(source); err == nil {
			md5hash = getMD5Hash(string(content))
		}
	}

	var (
		stdout, stderr string
	)
	retcode := -1
	xerr = retry.WhileUnsuccessful(
		func() error {
			copyCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			iretcode, istdout, istderr, innerXErr := instance.sshProfile.CopyWithTimeout(copyCtx, target, source, true, timeout)
			if innerXErr != nil {
				return innerXErr
			}
			if iretcode != 0 {
				problem := fail.NewError("copy failed")
				_ = problem.Annotate("stdout", istdout)
				_ = problem.Annotate("stderr", istderr)
				_ = problem.Annotate("retcode", iretcode)
				return problem
			}

			crcCheck := func() fail.Error {
				crcCtx, cancelCrc := context.WithTimeout(ctx, timeout)
				defer cancelCrc()

				fretcode, fstdout, fstderr, finnerXerr := run(crcCtx, instance.sshProfile, fmt.Sprintf("/usr/bin/md5sum %s", target), outputs.COLLECT, timeout)
				finnerXerr = debug.InjectPlannedFail(finnerXerr)
				if finnerXerr != nil {
					_ = finnerXerr.Annotate("retcode", fretcode)
					_ = finnerXerr.Annotate("stdout", fstdout)
					_ = finnerXerr.Annotate("stderr", fstderr)

					switch finnerXerr.(type) {
					case *fail.ErrTimeout:
						return fail.Wrap(fail.Cause(finnerXerr), "failed to check md5 in %v delay", timeout)
					case *retry.ErrStopRetry:
						return fail.Wrap(fail.Cause(finnerXerr), "stopping retries")
					default:
						return finnerXerr
					}
				}
				if fretcode != 0 {
					finnerXerr = fail.NewError("failed to check md5")
					_ = finnerXerr.Annotate("retcode", fretcode)
					_ = finnerXerr.Annotate("stdout", fstdout)
					_ = finnerXerr.Annotate("stderr", fstderr)
				}
				if finnerXerr != nil {
					return finnerXerr
				}
				if !strings.Contains(fstdout, md5hash) {
					logrus.Warnf("TBR: WRONG MD5, Tried 'md5sum %s' We got '%s' and '%s', the original was '%s'", target, fstdout, fstderr, md5hash)
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
		temporal.GetDefaultDelay(),
		2*timeout,
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
		logrus.Warnf("TBR: extra changing rights")
		iretcode, istdout, istderr, innerXerr := run(ctx, instance.sshProfile, cmd, outputs.COLLECT, timeout)
		innerXerr = debug.InjectPlannedFail(innerXerr)
		if innerXerr != nil {
			_ = innerXerr.Annotate("retcode", iretcode)
			_ = innerXerr.Annotate("stdout", istdout)
			_ = innerXerr.Annotate("stderr", istderr)

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
			_ = innerXerr.Annotate("retcode", iretcode)
			_ = innerXerr.Annotate("stdout", istdout)
			_ = innerXerr.Annotate("stderr", istderr)
		}
		if innerXerr != nil {
			return iretcode, istdout, istderr, innerXerr
		}
	}

	return retcode, stdout, stderr, xerr
}

// UnsafeGetVolumes is the not goroutine-safe version of GetVolumes, without parameter validation, that does the real work
// Note: must be used with wisdom
func (instance *Host) UnsafeGetVolumes() (*propertiesv1.HostVolumes, fail.Error) {
	var hvV1 *propertiesv1.HostVolumes
	xerr := instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			hvV1, ok = clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.UnsafeGetVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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

// UnsafeGetMounts returns the information about the mounts of the host
// Intended to be used when objh is notoriously not nil (because previously checked)
func (instance *Host) UnsafeGetMounts() (mounts *propertiesv1.HostMounts, xerr fail.Error) {
	xerr = instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			mounts = hostMountsV1.Clone().(*propertiesv1.HostMounts)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	return mounts, nil
}

func (instance *Host) unsafePushStringToFile(ctx context.Context, content string, filename string) (xerr fail.Error) {
	return instance.unsafePushStringToFileWithOwnership(ctx, content, filename, "", "")
}

// unsafePushStringToFileWithOwnership is the non goroutine-safe version of PushStringToFIleWithOwnership, that does the real work
func (instance *Host) unsafePushStringToFileWithOwnership(ctx context.Context, content string, filename string, owner, mode string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if content == "" {
		return fail.InvalidParameterError("content", "cannot be empty string")
	}
	if filename == "" {
		return fail.InvalidParameterError("filename", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	hostName := instance.GetName()
	f, xerr := system.CreateTempFileFromString(content, 0600)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create temporary file")
	}

	to := fmt.Sprintf("%s:%s", hostName, filename)
	retryErr := retry.WhileUnsuccessful(
		func() error {
			retcode, stdout, stderr, innerXErr := instance.UnsafePush(ctx, f.Name(), filename, owner, mode, temporal.GetExecutionTimeout())
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 && (stdout != "" || stderr != "") {
				logrus.Debugf("Ignoring '%s' and '%s'", stdout, stderr)
			}
			if retcode == 1 && (strings.Contains(stderr, "lost connection") || strings.Contains(stdout, "lost connection")) {
				problem := fail.NewError(stderr)
				_ = problem.Annotate("retcode", retcode)
				return problem
			}
			if retcode != 0 {
				return fail.NewError("failed to copy temporary file to '%s' (retcode: %d=%s)", to, retcode, system.SCPErrorString(retcode))
			}
			return nil
		},
		temporal.GetMinDelay(),
		2*temporal.MaxTimeout(temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout()),
	)
	_ = os.Remove(f.Name())
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

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	cmd := ""
	if owner != "" {
		cmd += `sudo chown ` + owner + ` '` + filename + `' ;`
	}
	if mode != "" {
		cmd += `sudo chmod ` + mode + ` '` + filename + `'`
	}
	if cmd != "" {
		retryErr = retry.WhileUnsuccessful(
			func() error {
				retcode, stdout, stderr, innerXErr := instance.UnsafeRun(ctx, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrAborted:
						return innerXErr
					default:
						_ = innerXErr.Annotate("retcode", retcode)
						_ = innerXErr.Annotate("stdout", stdout)
						_ = innerXErr.Annotate("stderr", stderr)
						return innerXErr
					}
				}
				if retcode != 0 {
					return fail.NewError("failed to change rights of file '%s' (retcode=%d)", to, retcode)
				}
				return nil
			},
			temporal.GetMinDelay(),
			2*temporal.MaxTimeout(temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout()),
		)
		if retryErr != nil {
			switch retryErr.(type) {
			case *retry.ErrStopRetry:
				return fail.Wrap(fail.Cause(retryErr), "stopping retries")
			case *retry.ErrTimeout:
				return fail.Wrap(fail.Cause(retryErr), "timeout")
			default:
				return retryErr
			}
		}
	}
	return nil
}

// unsafeGetDefaultSubnet returns the Networking instance corresponding to host default subnet
func (instance *Host) unsafeGetDefaultSubnet() (rs resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(hostproperty.NetworkV2) {
			return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				networkV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				rs, innerXErr = LoadSubnet(instance.GetService(), "", networkV2.DefaultSubnetID)
				if innerXErr != nil {
					return innerXErr
				}
				return nil
			})
		}
		return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			rs, innerXErr = LoadSubnet(instance.GetService(), "", hostNetworkV2.DefaultSubnetID)
			if innerXErr != nil {
				return innerXErr
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return NullSubnet(), xerr
	}

	return rs, nil
}
