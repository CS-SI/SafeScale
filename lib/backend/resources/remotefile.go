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

package resources

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
)

// Item is a helper struct to ease the copy of local files to remote
type Item struct {
	Local        string
	Remote       string
	RemoteOwner  string
	RemoteRights string
}

// Upload transfers the local file to the hostname
func (rfc Item) Upload(ctx context.Context, host *Host) (ferr fail.Error) { // FIXME: This function should NOT exist
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

	if does, xerr := host.Exists(ctx); xerr != nil {
		return xerr
	} else if !does {
		return fail.InvalidParameterError("host", "must exist")
	}

	svc, xerr := host.Service()
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	// Check the local file exists first
	uploadSize := int64(0)
	info, err := os.Stat(rfc.Local)
	if errors.Is(err, os.ErrNotExist) {
		return fail.InvalidInstanceContentError("rfc.Local", "MUST be an already existing file")
	}

	uploadSize = info.Size()

	uploadTime := time.Duration(uploadSize)*time.Second/(64*1024) + 30*time.Second
	timeout := 4 * 8 * uploadTime

	tracer := debug.NewTracerFromCtx(ctx, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()

	iterations := 0
	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			iterations++
			retcode, iout, ierr, xerr := host.Push(ctx, rfc.Local, rfc.Remote, rfc.RemoteOwner, rfc.RemoteRights, uploadTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr.Annotate("iterations", iterations)
				return xerr
			}

			if retcode != 0 && (iout != "" || ierr != "") {
				logrus.WithContext(ctx).Debugf("Ignoring '%s' and '%s'", iout, ierr)
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
		timings.SmallDelay(),
		timeout,
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
func (rfc Item) UploadString(ctx context.Context, content string, host *Host) fail.Error {
	if rfc.Remote == "" {
		return fail.InvalidInstanceContentError("rfc.Remote", "cannot be empty string")

	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	f, xerr := utils.CreateTempFileFromString(content, 0666) // nolint
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create temporary file")
	}

	defer func() {
		if derr := utils.LazyRemove(f.Name()); derr != nil {
			logrus.WithContext(ctx).Debugf("Error deleting file: %v", derr)
		}
	}()

	rfc.Local = f.Name()
	xerr = rfc.Upload(ctx, host)
	if xerr != nil {
		return xerr
	}

	return nil
}

// RemoveRemote deletes the remote file from host
func (rfc Item) RemoveRemote(ctx context.Context, host *Host) fail.Error {
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	svc, xerr := host.Service()
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
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
func (rfh *RemoteFilesHandler) Upload(ctx context.Context, host *Host) fail.Error {
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
func (rfh *RemoteFilesHandler) Cleanup(ctx context.Context, host *Host) fail.Error {
	for _, v := range rfh.items {
		xerr := v.RemoveRemote(ctx, host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.WithContext(ctx).Warnf(xerr.Error())
		}
	}

	return nil
}
