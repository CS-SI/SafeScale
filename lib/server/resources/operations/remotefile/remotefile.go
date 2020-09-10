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

package remotefile

import (
    "fmt"

    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/server/resources"
    "github.com/CS-SI/SafeScale/lib/system"
    "github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/debug"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    "github.com/CS-SI/SafeScale/lib/utils/retry"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Item is a helper struct to ease the copy of local files to remote
type Item struct {
    Local        string
    Remote       string
    RemoteOwner  string
    RemoteRights string
}

// Upload transfers the local file to the hostname
func (rfc Item) Upload(task concurrency.Task, host resources.Host) (xerr fail.Error) {
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }
    if host == nil {
        return fail.InvalidParameterError("host", "cannot be nil")
    }
    if rfc.Local == "" {
        return fail.InvalidInstanceContentError("rfc.Local", "cannot be empty string")
    }
    if rfc.Remote == "" {
        return fail.InvalidInstanceContentError("rfc.Remote", "cannot be empty string")

    }

    tracer := debug.NewTracer(task, true, "").WithStopwatch().Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

    retryErr := retry.WhileUnsuccessful(
        func() error {
            retcode, _, _, err := host.Push(task, rfc.Local, rfc.Remote, rfc.RemoteOwner, rfc.RemoteRights, temporal.GetExecutionTimeout())
            if err != nil {
                return err
            }
            if retcode != 0 {
                // If retcode == 1 (general copy error), retry. It may be a temporary network incident
                if retcode == 1 {
                    // File may exist on target, try to remote it
                    _, _, _, err = host.Run(task, fmt.Sprintf("sudo rm -f %s", rfc.Remote), outputs.COLLECT, temporal.GetLongOperationTimeout(), temporal.GetExecutionTimeout())
                    if err == nil {
                        return fail.NewError("file may exist on remote with inappropriate access rights, deleted it and retrying")
                    }
                    // If submission of removal of remote file fails, stop the retry and consider this as an unrecoverable network error
                    return retry.StopRetryError(err, "an unrecoverable network error has occurred")
                }
                if system.IsSCPRetryable(retcode) {
                    err = fail.NewError("failed to copy file '%s' to '%s:%s' (retcode: %d=%s)", rfc.Local, host.GetName(), rfc.Remote, retcode, system.SCPErrorString(retcode))
                    return err
                }
                return nil
            }
            return nil
        },
        temporal.GetDefaultDelay(),
        temporal.GetLongOperationTimeout(),
    )
    if retryErr != nil {
        switch realErr := retryErr.(type) { // nolint
        case *retry.ErrStopRetry:
            return fail.Prepend(realErr.Cause(), "failed to copy file to remote host '%s'", host.GetName())
        case *retry.ErrTimeout:
            return fail.Wrap(realErr, "timeout trying to copy file to '%s:%s'", host.GetName(), rfc.Remote)
        }
        return retryErr
    }

    // Updates owner and access rights if asked for
    cmd := ""
    if rfc.RemoteOwner != "" {
        cmd += "chown " + rfc.RemoteOwner + " " + rfc.Remote
    }
    if rfc.RemoteRights != "" {
        if cmd != "" {
            cmd += " && "
        }
        cmd += "chmod " + rfc.RemoteRights + " " + rfc.Remote
    }
    retcode, _, _, err := host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
    if err != nil {
        return err
    }
    if retcode != 0 {
        return fail.NewError("failed to update owner and/or access rights of the remote file")
    }

    return nil
}

// UploadString transfers the local file to the hostname
func (rfc Item) UploadString(task concurrency.Task, content string, host resources.Host) fail.Error {
    if rfc.Remote == "" {
        return fail.InvalidInstanceContentError("rfc.Remote", "cannot be empty string")

    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }

    f, xerr := system.CreateTempFileFromString(content, 0600)
    if xerr != nil {
        return fail.Wrap(xerr, "failed to create temporary file")
    }
    rfc.Local = f.Name()
    return rfc.Upload(task, host)
}

// RemoveRemote deletes the remote file from host
func (rfc Item) RemoveRemote(task concurrency.Task, host resources.Host) fail.Error {
    cmd := "rm -rf " + rfc.Remote
    retcode, _, _, xerr := host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
    if xerr != nil || retcode != 0 {
        return fail.NewError("failed to remove file '%s:%s'", host.GetName(), rfc.Remote)
    }
    return nil
}

// RemoteFilesHandler handles the copy of files and cleanup
type RemoteFilesHandler struct {
    items []*Item
}

// Add adds an Item in the handler
func (rfh *RemoteFilesHandler) Add(file *Item) {
    rfh.items = append(rfh.items, file)
}

// Count returns the number of files in the handler
func (rfh *RemoteFilesHandler) Count() uint {
    return uint(len(rfh.items))
}

// Upload executes the copy of files
// TODO: allow to upload to many hosts
func (rfh *RemoteFilesHandler) Upload(task concurrency.Task, host resources.Host) fail.Error {
    for _, v := range rfh.items {
        xerr := v.Upload(task, host)
        if xerr != nil {
            return xerr
        }
    }
    return nil
}

// Cleanup executes the removal of remote files.
// NOTE: Removal of local files is the responsability of the caller, not the RemoteFilesHandler.
// TODO: allow to cleanup on many hosts
func (rfh *RemoteFilesHandler) Cleanup(task concurrency.Task, host resources.Host) {
    for _, v := range rfh.items {
        xerr := v.RemoveRemote(task, host)
        if xerr != nil {
            logrus.Warnf(xerr.Error())
        }
    }
}
