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
	"github.com/CS-SI/SafeScale/lib/server/resources"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"os"
	"reflect"
	"strings"
	"time"

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

// unsafeRun is the non goroutine-safe version of Run, with less parameter validation, that does the real work
func (instance *host) unsafeRun(task concurrency.Task, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if cmd == "" {
		return 0, "", "", fail.InvalidParameterError("cmd", "cannot be empty string")
	}

	if task.Aborted() {
		return 0, "", "", fail.AbortedError(nil, "aborted")
	}

	if connectionTimeout < temporal.GetConnectSSHTimeout() {
		connectionTimeout = temporal.GetConnectSSHTimeout()
	}

	var (
		stdOut, stdErr string
		retCode        int
	)

	hostName := instance.GetName()
	retCode, stdOut, stdErr, xerr = run(task, instance.sshProfile, cmd, outs, executionTimeout)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // == *fail.ErrAborted
			if cerr := xerr.Cause(); cerr != nil {
				xerr = fail.ConvertError(cerr)
			}
		case *fail.ErrTimeout:
			switch xerr.Cause().(type) {
			case *fail.ErrTimeout:
				xerr = fail.Wrap(xerr.Cause(), "failed to execute command on Host '%s' in %s", hostName, temporal.FormatDuration(executionTimeout))
			default:
				xerr = fail.Wrap(xerr.Cause(), "failed to connect by SSH to Host '%s' after %s", hostName, temporal.FormatDuration(connectionTimeout))
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
// - *fail.ErrTimeout: // FIXME: complete comment
// - *fail.ErrAborted: // FIXME: complete comment
func run(task concurrency.Task, ssh *system.SSHConfig, cmd string, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	// Create the command
	sshCmd, xerr := ssh.NewCommand(task, cmd)
	if xerr != nil {
		return 0, "", "", xerr
	}

	defer func() {
		if derr := sshCmd.Close(); derr != nil {
			if xerr == nil {
				xerr = derr
			} else {
				_ = xerr.AddConsequence(fail.Wrap(derr, "failed to close SSHCommand"))
			}
		}
	}()

	var (
		retcode        int
		stdout, stderr string
	)
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var innerXErr fail.Error
			retcode = -1
			if retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(task, outs, timeout); innerXErr != nil {
				switch innerXErr.(type) { //nolint
				case *fail.ErrExecution:
					// Adds stdout annotation to xerr
					_ = innerXErr.Annotate("stdout", stdout)
					_ = innerXErr.Annotate("stderr", stderr)
				}
				return innerXErr
			}
			// If retcode == 255, ssh connection failed
			if retcode == 255 {
				return fail.NotAvailableError("failed to connect")
			}
			return nil
		},
		timeout+time.Minute,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			xerr = fail.Wrap(xerr.Cause(), "failed to execute command after %s", temporal.FormatDuration(timeout))
		case *retry.ErrStopRetry:
			if xerr.Cause() != nil {
				xerr = fail.ConvertError(xerr.Cause())
			}
		}
	}
	return retcode, stdout, stderr, xerr
}

// unsafePush is the non goroutine-safe version of Push, with less parameter validation, that do the real work
// Note: must be used with wisdom
func (instance *host) unsafePush(task concurrency.Task, source, target, owner, mode string, timeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if source == "" {
		return 0, "", "", fail.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return 0, "", "", fail.InvalidParameterError("target", "cannot be empty string")
	}

	if task.Aborted() {
		return 0, "", "", fail.AbortedError(nil, "aborted")
	}

	// // retrieve ssh config to perform some commands
	// ssh, xerr := instance.GetSSHConfig(task)
	// if xerr != nil {
	// 	return 0, "", "", xerr
	// }

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
			if retcode, stdout, stderr, innerXErr = instance.sshProfile.Copy(task, target, source, true); innerXErr != nil {
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
		retcode, stdout, stderr, xerr = run(task, instance.sshProfile, cmd, outputs.DISPLAY, timeout)
		if xerr != nil {
			switch xerr.(type) { //nolint
			case *fail.ErrTimeout:
				xerr = fail.Wrap(xerr.Cause(), "failed to update access rights in %v delay", timeout)
			}
		}
	}
	return retcode, stdout, stderr, xerr
}

// unsafeGetVolumes is the not goroutine-safe version of GetVolumes, without parameter validation, that does the real work
// Note: must be used with wisdom
func (instance *host) unsafeGetVolumes(task concurrency.Task) (*propertiesv1.HostVolumes, fail.Error) {
	var hvV1 *propertiesv1.HostVolumes
	err := instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			hvV1, ok = clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.unsafeGetVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return hvV1, nil
}

// unsafeGetMounts returns the information about the mounts of the host
// Intended to be used when objh is notoriously not nil (because previously checked)
func (instance *host) unsafeGetMounts(task concurrency.Task) (mounts *propertiesv1.HostMounts, xerr fail.Error) {
	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			mounts = hostMountsV1.Clone().(*propertiesv1.HostMounts)
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}
	return mounts, nil
}

func (instance *host) unsafePushStringToFile(task concurrency.Task, content string, filename string) (xerr fail.Error) {
	return instance.unsafePushStringToFileWithOwnership(task, content, filename, "", "")
}

// unsafePushStringToFileWithOwnership is the non goroutine-safe version of PushStringToFIleWithOwnership, that does the real work
func (instance *host) unsafePushStringToFileWithOwnership(task concurrency.Task, content string, filename string, owner, mode string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if content == "" {
		return fail.InvalidParameterError("content", "cannot be empty string")
	}
	if filename == "" {
		return fail.InvalidParameterError("filename", "cannot be empty string")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	hostName := instance.GetName()
	f, xerr := system.CreateTempFileFromString(content, 0600)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create temporary file")
	}

	to := fmt.Sprintf("%s:%s", hostName, filename)
	deleted := false
	retryErr := retry.WhileUnsuccessful(
		func() error {
			retcode, _, _, innerXErr := instance.unsafePush(task, f.Name(), filename, owner, mode, temporal.GetExecutionTimeout())
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 {
				// If retcode == 1 (general copy error), retry. It may be a temporary network incident
				if retcode == 1 && !deleted {
					// File may exist on target, try to remove it
					if _, _, _, innerXErr = instance.unsafeRun(task, "sudo rm -f "+filename, outputs.COLLECT, temporal.GetConnectSSHTimeout(), temporal.GetExecutionTimeout()); innerXErr == nil {
						deleted = true
					}
					switch innerXErr.(type) {
					case *fail.ErrAborted:
						return innerXErr
					default:
						return fail.NewError("file may have existing on remote with inappropriate access rights, deleted it and now retrying")
					}
				}
				if system.IsSCPRetryable(retcode) {
					xerr = fail.NewError("failed to copy temporary file to '%s' (retcode: %d=%s)", to, retcode, system.SCPErrorString(retcode))
				}
			}
			return nil
		},
		1*time.Second,
		2*time.Minute,
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
				retcode, stdout, _, innerXErr := instance.unsafeRun(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
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
			2*time.Second,
			1*time.Minute,
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
func (instance *host) unsafeGetDefaultSubnet(task concurrency.Task) (rs resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task.Aborted() {
		return nullSubnet(), fail.AbortedError(nil, "aborted")
	}

	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(hostproperty.NetworkV2) {
			return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				networkV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				rs, innerXErr = LoadSubnet(task, instance.GetService(), "", networkV2.DefaultSubnetID)
				if innerXErr != nil {
					return innerXErr
				}
				return nil
			})
		}
		return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			rs, innerXErr = LoadSubnet(task, instance.GetService(), "", hostNetworkV2.DefaultSubnetID)
			if innerXErr != nil {
				return innerXErr
			}
			return nil
		})
	})
	if xerr != nil {
		return nullSubnet(), xerr
	}

	return rs, nil
}
