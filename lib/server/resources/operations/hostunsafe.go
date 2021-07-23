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
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"golang.org/x/net/context"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
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
		default:
		}
	}
	if xerr != nil {
		return invalid, "", "", xerr
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
			if cerr := xerr.Cause(); cerr != nil {
				xerr = fail.ConvertError(cerr)
			}
		case *fail.ErrTimeout:
			if cerr := xerr.Cause(); cerr != nil {
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
		retcode        int
		stdout, stderr string
	)
	xerr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
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

			retcode = -1
			if retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(ctx, outs, timeout); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrExecution:
					// Adds stdout and stderr as annotations to innerXErr
					_ = innerXErr.Annotate("stdout", stdout)
					_ = innerXErr.Annotate("stderr", stderr)
				default:
				}
				return innerXErr
			}
			// If retcode == 255, ssh connection failed
			if retcode == 255 {
				return fail.NotAvailableError("failed to execute command '%s': failed to connect", cmd)
			}
			return nil
		},
		timeout+time.Minute,
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			xerr = fail.Wrap(xerr.Cause(), "failed to execute command '%s' after '%s'", cmd, temporal.FormatDuration(timeout))
		case *retry.ErrStopRetry:
			if xerr.Cause() != nil {
				xerr = fail.ConvertError(xerr.Cause())
			}
		}
	}
	return retcode, stdout, stderr, xerr
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
		default:
		}
	}
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if task.Aborted() {
		return invalid, "", "", fail.AbortedError(nil, "aborted")
	}

	if timeout < temporal.GetHostTimeout() {
		timeout = temporal.GetHostTimeout()
	}

	var (
		retcode        int
		stdout, stderr string
	)
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var innerXErr fail.Error
			if retcode, stdout, stderr, innerXErr = instance.sshProfile.Copy(ctx, target, source, true); innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 {
				if retcode == 1 && strings.Contains(stdout, "lost connection") {
					return fail.NewError("lost connection, retrying...")
				}
			}
			return nil
		},
		2*timeout,
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return retcode, stdout, stderr, xerr
	}
	if retcode != 0 {
		return retcode, stdout, stderr, nil
	}

	cmd := ""
	if owner != "" {
		cmd += "sudo chown " + owner + ` '` + target + `' ;`
	}
	if mode != "" {
		cmd += "sudo chmod " + mode + ` '` + target + `'`
	}
	if cmd != "" {
		retcode, stdout, stderr, xerr = run(ctx, instance.sshProfile, cmd, outputs.DISPLAY, timeout)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrTimeout:
				xerr = fail.Wrap(xerr.Cause(), "failed to update access rights in %v delay", timeout)
			default:
			}
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
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
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
		default:
		}
	}
	if xerr != nil {
		return xerr
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
	deleted := false
	retryErr := retry.WhileUnsuccessful(
		func() error {
			retcode, _, _, innerXErr := instance.UnsafePush(ctx, f.Name(), filename, owner, mode, temporal.GetExecutionTimeout())
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 {
				// If retcode == 1 (general copy error), retry. It may be a temporary network incident
				if retcode == 1 && !deleted {
					// File may exist on target, try to remove it
					if _, _, _, innerXErr = instance.UnsafeRun(ctx, "sudo rm -f "+filename, outputs.COLLECT, temporal.GetConnectSSHTimeout(), temporal.GetExecutionTimeout()); innerXErr == nil {
						deleted = true
					}
					switch innerXErr.(type) {
					case *fail.ErrAborted:
						return innerXErr
					default:
						return fail.NewError("file may exist on remote with inappropriate access rights, deleted it and now retrying")
					}
				}
				if system.IsSCPRetryable(retcode) {
					xerr = fail.NewError("failed to copy temporary file to '%s' (retcode: %d=%s)", to, retcode, system.SCPErrorString(retcode))
				}
			}
			return nil
		},
		temporal.GetMinDelay(),
		2*temporal.MaxTimeout(temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout()),
	)
	_ = os.Remove(f.Name())
	if retryErr != nil {
		switch retryErr.(type) {
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
				retcode, stdout, _, innerXErr := instance.UnsafeRun(ctx, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrAborted:
						return innerXErr
					default:
						// on error, innerXErr already has annotations "retcode" and "stderr", we need to add stdout
						_ = innerXErr.Annotate("stdout", stdout)
						return innerXErr
					}
				}
				if retcode != 0 {
					xerr = fail.NewError("failed to change rights of file '%s' (retcode=%d)", to, retcode)
				}
				return nil
			},
			temporal.GetMinDelay(),
			2*temporal.MaxTimeout(temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout()),
		)
		if retryErr != nil {
			switch retryErr.(type) {
			case *fail.ErrAborted:
				if cerr := retryErr.Cause(); cerr != nil {
					retryErr = fail.ConvertError(cerr)
				}
			case *retry.ErrTimeout:
				return xerr
			}
		}
		if retryErr != nil {
			return fail.Wrap(retryErr, "failed to change rights of file '%s' on host '%s'", filename, hostName)
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
