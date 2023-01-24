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
	"path"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	sharefactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/share"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.ShareHandler -o mocks/mock_share.go

// NOTICE: At service level, we need to log before returning, because it's the last chance to track the real issue in server side, so we should catch panics here

// ShareHandler defines API to manipulate Shares
type ShareHandler interface {
	Create(string, string, string, string /*[]string, bool, bool, bool, bool, bool, bool, bool*/) (*resources.Share, fail.Error)
	Inspect(string) (*resources.Share, fail.Error)
	Delete(string) fail.Error
	List() (map[string]map[string]*propertiesv1.HostShare, fail.Error)
	Mount(string, string, string, bool) (*propertiesv1.HostRemoteMount, fail.Error)
	Unmount(string, string) fail.Error
}

// shareHandler nas service
type shareHandler struct {
	job jobapi.Job
}

// NewShareHandler creates a ShareHandler
func NewShareHandler(job jobapi.Job) ShareHandler {
	return &shareHandler{job: job}
}

func sanitize(in string) (string, fail.Error) { // nolint
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fail.InvalidRequestError("exposed path must be absolute")
	}
	return sanitized, nil
}

// Create a share on host
func (handler *shareHandler) Create(
	shareName, hostName, apath string, options string, /*securityModes []string,
	readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool,*/
) (share *resources.Share, ferr fail.Error) {
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
	if shareName == "" {
		return nil, fail.InvalidParameterError("shareName", "cannot be empty")
	}
	if hostName == "" {
		return nil, fail.InvalidParameterError("hostName", "cannot be empty")
	}
	if apath == "" {
		return nil, fail.InvalidParameterError("path", "cannot be empty")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.share"), "(%s)", shareName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	shareInstance, xerr := sharefactory.New(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), hostName)
	if xerr != nil {
		return nil, xerr
	}

	return shareInstance, shareInstance.Create(task.Context(), shareName, hostInstance, apath, options /*securityModes, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck*/)
}

// Delete a share from host
func (handler *shareHandler) Delete(name string) (ferr fail.Error) {
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
	if name == "" {
		return fail.InvalidParameterError("name", "cannot be empty!")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.share"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	shareInstance, xerr := sharefactory.Load(handler.job.Context(), name)
	if xerr != nil {
		return xerr
	}

	return shareInstance.Delete(task.Context())
}

// List return the list of all shares from all servers
func (handler *shareHandler) List() (shares map[string]map[string]*propertiesv1.HostShare, ferr fail.Error) {
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

	ctx := handler.job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.share"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	objs, xerr := sharefactory.New(ctx)
	if xerr != nil {
		return nil, xerr
	}
	var servers []string
	xerr = objs.Browse(ctx, func(hostName string, shareID string) fail.Error {
		servers = append(servers, hostName)
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	// Now walks through the hosts acting as NAS
	shares = map[string]map[string]*propertiesv1.HostShare{}
	if len(servers) == 0 {
		return shares, nil
	}

	for _, serverID := range servers {
		host, xerr := hostfactory.Load(ctx, serverID)
		if xerr != nil {
			return nil, xerr
		}

		hostTrx, xerr := metadata.NewTransaction[*abstract.HostCore, *resources.Host](ctx, host)
		if xerr != nil {
			return nil, xerr
		}
		defer func(trx metadata.Transaction[*abstract.HostCore, *resources.Host]) {
			trx.TerminateBasedOnError(ctx, &ferr)
		}(hostTrx)

		xerr = metadata.InspectProperty[*abstract.HostCore](ctx, hostTrx, hostproperty.SharesV1, func(hostSharesV1 *propertiesv1.HostShares) fail.Error {
			shares[serverID] = hostSharesV1.ByID
			return nil
		})
		if xerr != nil {
			return nil, xerr
		}
	}
	return shares, nil
}

// Mount a share on a local directory of a host
func (handler *shareHandler) Mount(shareName, hostRef, path string, withCache bool) (mount *propertiesv1.HostRemoteMount, ferr fail.Error) {
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
	if shareName == "" {
		return nil, fail.InvalidParameterError("shareName", "cannot be empty string")
	}
	if hostRef == "" {
		return nil, fail.InvalidParameterError("hostRef", "cannot be empty string")
	}
	if path == "" {
		return nil, fail.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.share"), "('%s', '%s')", shareName, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	// Retrieve info about the share
	ctx := handler.job.Context()
	shareInstance, xerr := sharefactory.Load(ctx, shareName)
	if xerr != nil {
		return nil, xerr
	}

	target, xerr := hostfactory.Load(ctx, hostRef)
	if xerr != nil {
		return nil, xerr
	}

	return shareInstance.Mount(ctx, target, path, withCache)
}

// Unmount a share from local directory of a host
func (handler *shareHandler) Unmount(shareRef, hostRef string) (ferr fail.Error) {
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
	if shareRef == "" {
		return fail.InvalidParameterError("shareRef", "cannot be empty string")
	}
	if hostRef == "" {
		return fail.InvalidParameterError("hostRef", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.share"), "('%s', '%s')", shareRef, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	ctx := handler.job.Context()
	objs, xerr := sharefactory.Load(ctx, shareRef)
	if xerr != nil {
		return xerr
	}

	target, xerr := hostfactory.Load(ctx, hostRef)
	if xerr != nil {
		return xerr
	}

	return objs.Unmount(ctx, target)
}

// Inspect returns the host and share corresponding to 'shareName'
// If share isn't found, return (nil, nil, nil, utils.ErrNotFound)
func (handler *shareHandler) Inspect(shareRef string) (_ *resources.Share, ferr fail.Error) {
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
	if shareRef == "" {
		return nil, fail.InvalidParameterError("shareName", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task.Context(), tracing.ShouldTrace("handlers.share"), "(%s)", shareRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage(""))

	return sharefactory.Load(handler.job.Context(), shareRef)
}
