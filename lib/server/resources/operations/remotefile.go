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
	"context"
	"errors"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/system"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/retry"
)

// Item is a helper struct to ease the copy of local files to remote
type Item struct {
	Local        string
	Remote       string
	RemoteOwner  string
	RemoteRights string
}

// Upload transfers the local file to the hostname
func (rfc Item) Upload(ctx context.Context, host resources.Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}
	if rfc.Local == "" {
		return fail.InvalidInstanceContentError("rfc.Local", "cannot be empty string")
	}
	if rfc.Remote == "" {
		return fail.InvalidInstanceContentError("rfc.Remote", "cannot be empty string")
	}

	timings, xerr := host.Service().Timings()
	if xerr != nil {
		return xerr
	}

	// Check the local file exists first
	if _, err := os.Stat(rfc.Local); errors.Is(err, os.ErrNotExist) {
		return fail.InvalidInstanceContentError("rfc.Local", "MUST be an already existing file")
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

	tracer := debug.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()

	iterations := 0
	retryErr := retry.WhileUnsuccessful(
		func() error {
			iterations++
			retcode, iout, ierr, xerr := host.Push(ctx, rfc.Local, rfc.Remote, rfc.RemoteOwner, rfc.RemoteRights, timings.ExecutionTimeout())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr.Annotate("iterations", iterations)
				return xerr
			}

			if retcode != 0 && (iout != "" || ierr != "") {
				logrus.Debugf("Ignoring '%s' and '%s'", iout, ierr)
			}
			if retcode == 1 && (strings.Contains(ierr, "lost connection") || strings.Contains(iout, "lost connection")) {
				problem := fail.NewError(ierr)
				problem.Annotate("retcode", retcode)
				problem.Annotate("iterations", iterations)
				return problem
			}

			if retcode != 0 {
				problem := fail.NewError("failed to copy file '%s' to '%s:%s' (retcode: %d)", rfc.Local, host.GetName(), rfc.Remote, retcode)
				problem.Annotate("iterations", iterations)
				return problem
			}
			return nil
		},
		timings.NormalDelay(),
		timings.ConnectionTimeout()+2*timings.ExecutionTimeout(),
	)
	if retryErr != nil {
		switch realErr := retryErr.(type) { // nolint
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(realErr), "failed to copy file to remote host '%s'", host.GetName())
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(realErr), "timeout trying to copy file to '%s:%s'", host.GetName(), rfc.Remote)
		}
		return retryErr
	}

	return nil
}

// UploadString transfers the local file to the hostname
func (rfc Item) UploadString(ctx context.Context, content string, host resources.Host) fail.Error {
	if rfc.Remote == "" {
		return fail.InvalidInstanceContentError("rfc.Remote", "cannot be empty string")

	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	f, xerr := system.CreateTempFileFromString(content, 0666) // nolint
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create temporary file")
	}

	rfc.Local = f.Name()
	return rfc.Upload(ctx, host)
}

// RemoveRemote deletes the remote file from host
func (rfc Item) RemoveRemote(ctx context.Context, host resources.Host) fail.Error {
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	timings, xerr := host.Service().Timings()
	if xerr != nil {
		return xerr
	}

	cmd := "rm -rf " + rfc.Remote
	retcode, _, _, xerr := host.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
	xerr = debug.InjectPlannedFail(xerr)
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
func (rfh *RemoteFilesHandler) Upload(ctx context.Context, host resources.Host) fail.Error {
	for _, v := range rfh.items {
		xerr := v.Upload(ctx, host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// Cleanup executes the removal of remote files.
// NOTE: Removal of local files is the responsibility of the caller, not the RemoteFilesHandler.
// TODO: allow to cleanup on many hosts
func (rfh *RemoteFilesHandler) Cleanup(ctx context.Context, host resources.Host) fail.Error {
	for _, v := range rfh.items {
		xerr := v.RemoveRemote(ctx, host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.Warnf(xerr.Error())
		}
	}

	return nil
}
