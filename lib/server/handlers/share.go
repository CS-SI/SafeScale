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

package handlers

import (
	"path"
	"reflect"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	sharefactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/share"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

//go:generate minimock -o ../mocks/mock_nasapi.go -i github.com/CS-SI/SafeScale/lib/server/handlers.ShareHandler

// TODO: At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// ShareHandler defines API to manipulate Shares
type ShareHandler interface {
	Create(string, string, string, string /*[]string, bool, bool, bool, bool, bool, bool, bool*/) (resources.Share, fail.Error)
	Inspect(string) (resources.Share, fail.Error)
	Delete(string) fail.Error
	List() (map[string]map[string]*propertiesv1.HostShare, fail.Error)
	Mount(string, string, string, bool) (*propertiesv1.HostRemoteMount, fail.Error)
	Unmount(string, string) fail.Error
}

// shareHandler nas service
type shareHandler struct {
	job server.Job
}

// NewShareHandler creates a ShareHandler
func NewShareHandler(job server.Job) ShareHandler {
	return &shareHandler{job: job}
}

func sanitize(in string) (string, fail.Error) { //nolint
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fail.InvalidRequestError("exposed path must be absolute")
	}
	return sanitized, nil
}

// Create a share on host
func (handler *shareHandler) Create(
	shareName, hostName, path string, options string, /*securityModes []string,
	readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool,*/
) (share resources.Share, xerr fail.Error) {
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
	if path == "" {
		return nil, fail.InvalidParameterError("path", "cannot be empty")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "(%s)", shareName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	objs, xerr := sharefactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}

	objh, xerr := hostfactory.Load(handler.job.Service(), hostName)
	if xerr != nil {
		return nil, xerr
	}

	return objs, objs.Create(task.Context(), shareName, objh, path, options /*securityModes, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck*/)
}

// Delete a share from host
func (handler *shareHandler) Delete(name string) (xerr fail.Error) {
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
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	objs, xerr := sharefactory.Load(handler.job.Service(), name)
	if xerr != nil {
		return xerr
	}
	return objs.Delete(task.Context())
}

// List return the list of all shares from all servers
func (handler *shareHandler) List() (shares map[string]map[string]*propertiesv1.HostShare, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	svc := handler.job.Service()
	objs, xerr := sharefactory.New(svc)
	if xerr != nil {
		return nil, xerr
	}
	var servers []string
	xerr = objs.Browse(task.Context(), func(hostName string, shareID string) fail.Error {
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
		host, xerr := hostfactory.Load(svc, serverID)
		if xerr != nil {
			return nil, xerr
		}

		xerr = host.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
				hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				shares[serverID] = hostSharesV1.ByID
				return nil
			})
		})
		if xerr != nil {
			return nil, xerr
		}
	}
	return shares, nil
}

// Mount a share on a local directory of an host
func (handler *shareHandler) Mount(shareName, hostRef, path string, withCache bool) (mount *propertiesv1.HostRemoteMount, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

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
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "('%s', '%s')", shareName, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	// Retrieve info about the share
	svc := handler.job.Service()
	shareInstance, xerr := sharefactory.Load(svc, shareName)
	if xerr != nil {
		return nil, xerr
	}

	target, xerr := hostfactory.Load(svc, hostRef)
	if xerr != nil {
		return nil, xerr
	}

	return shareInstance.Mount(task.Context(), target, path, withCache)
}

// Unmount a share from local directory of an host
func (handler *shareHandler) Unmount(shareRef, hostRef string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

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
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "('%s', '%s')", shareRef, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	svc := handler.job.Service()
	objs, xerr := sharefactory.Load(svc, shareRef)
	if xerr != nil {
		return xerr
	}

	target, xerr := hostfactory.Load(svc, hostRef)
	if xerr != nil {
		return xerr
	}

	return objs.Unmount(task.Context(), target)
}

// Inspect returns the host and share corresponding to 'shareName'
// If share isn't found, return (nil, nil, nil, utils.ErrNotFound)
func (handler *shareHandler) Inspect(shareRef string) (share resources.Share, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

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
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "(%s)", shareRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	return sharefactory.Load(handler.job.Service(), shareRef)
}
