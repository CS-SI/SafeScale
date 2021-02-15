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

//go:generate mockgen -destination=../mocks/mock_nasapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers ShareHandler

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

func sanitize(in string) (string, fail.Error) {
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

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "(%s)", shareName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	objs, xerr := sharefactory.New(handler.job.GetService())
	if xerr != nil {
		return nil, xerr
	}

	objh, xerr := hostfactory.Load(task, handler.job.GetService(), hostName)
	if xerr != nil {
		return nil, xerr
	}

	return objs, objs.Create(task, shareName, objh, path, options /*securityModes, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck*/)
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

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	objs, xerr := sharefactory.Load(task, handler.job.GetService(), name)
	if xerr != nil {
		return xerr
	}
	return objs.Delete(task)
}

// List return the list of all shares from all servers
func (handler *shareHandler) List() (shares map[string]map[string]*propertiesv1.HostShare, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	svc := handler.job.GetService()
	objs, xerr := sharefactory.New(svc)
	if xerr != nil {
		return nil, xerr
	}
	var servers []string
	xerr = objs.Browse(task, func(hostName string, shareID string) fail.Error {
		servers = append(servers, hostName)
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	// Now walks through the hosts acting as Nas
	shares = map[string]map[string]*propertiesv1.HostShare{}
	if len(servers) == 0 {
		return shares, nil
	}

	for _, serverID := range servers {
		host, xerr := hostfactory.Load(task, svc, serverID)
		if xerr != nil {
			return nil, xerr
		}

		xerr = host.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
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

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "('%s', '%s')", shareName, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	// Retrieve info about the share
	objs, xerr := sharefactory.Load(task, handler.job.GetService(), shareName)
	if xerr != nil {
		return nil, xerr
	}
	server, xerr := objs.GetServer(task)
	if xerr != nil {
		return nil, xerr
	}

	return objs.Mount(task, server, path, withCache)
	// // Sanitize path
	// mountPath, xerr := sanitize(path)
	// if xerr != nil {
	// 	return nil, fail.InvalidRequestError("invalid mount path '%s': '%s'", path, xerr)
	// }
	//
	// var target resources.IPAddress
	// if server.GetName() == hostRef || server.GetID() == hostRef {
	// 	target = server
	// } else {
	// 	if target, xerr = hostfactory.Load(task, handler.job.GetService(), hostRef); xerr != nil {
	// 		return nil, xerr
	// 	}
	// }
	//
	// // Check if share is already mounted
	// // Check if there is already volume mounted in the path (or in subpath)
	// var targetNetwork *propertiesv1.HostNetwork
	// xerr = target.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	innerXErr := props.Inspect(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
	// 		targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.HostsMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		if s, ok := targetMountsV1.RemoteMountsByShareID[objs.GetID()]; ok {
	// 			return fail.DuplicateError("already mounted in '%s:%s'", target.GetName(), targetMountsV1.RemoteMountsByPath[s].Path)
	// 		}
	// 		for _, i := range targetMountsV1.LocalMountsByPath {
	// 			if i.Path == path {
	// 				// Can't mount a share in place of a volume (by convention, nothing technically preventing it)
	// 				return fail.DuplicateError("there is already a volume in path '%s:%s'", target.GetName(), path)
	// 			}
	// 		}
	// 		for _, i := range targetMountsV1.RemoteMountsByPath {
	// 			if strings.Index(path, i.Path) == 0 {
	// 				// Can't mount a share inside another share (at least by convention, if not technically)
	// 				return fail.DuplicateError("there is already a share mounted in '%s:%s'", target.GetName(), i.Path)
	// 			}
	// 		}
	// 		return nil
	// 	})
	// 	if innerXErr != nil {
	// 		return innerXErr
	// 	}
	//
	// 	return props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
	// 		var ok bool
	// 		targetNetwork, ok = clonable.(*propertiesv1.HostNetwork)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		return nil
	// 	})
	// })
	//
	// var export, sharePath string
	// shareID := objs.GetID()
	// xerr = server.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	var ip string
	// 	innerXErr := props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
	// 		serverNetwork, ok := clonable.(*propertiesv1.HostNetwork)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	//
	// 		if netID, ok := serverNetwork.SubnetsByID[targetNetwork.DefaultSubnetID]; ok {
	// 			ip = serverNetwork.IPv4Addresses[netID]
	// 		} else {
	// 			for _, v := range targetNetwork.SubnetsByID {
	// 				if _, ok := serverNetwork.SubnetsByID[v]; ok {
	// 					ip = serverNetwork.IPv4Addresses[v]
	// 					break
	// 				}
	// 			}
	// 			if ip == "" {
	// 				ip = serverNetwork.IPv4Addresses[serverNetwork.DefaultSubnetID]
	// 			}
	// 		}
	// 		if ip == "" {
	// 			return fail.NotFoundError("no IP address found on server '%s' to serve the share to host '%s'", server.GetName(), target.GetName())
	// 		}
	// 		return nil
	// 	})
	// 	if innerXErr != nil {
	// 		return innerXErr
	// 	}
	//
	// 	return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
	// 		hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	//
	// 		sharePath = hostSharesV1.ByID[objs.GetID()].Path
	// 		export = ip + ":" + sharePath
	// 		return nil
	// 	})
	// })
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// sshConfig, xerr := target.GetSSHConfig(task)
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// // Mount the share on host
	// xerr = server.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
	// 		serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.HostShare' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		_, found := serverSharesV1.ByID[serverSharesV1.ByName[shareName]]
	// 		if !found {
	// 			return fail.NotFoundError("failed to find metadata about share '%s'", shareName)
	// 		}
	// 		shareID = serverSharesV1.ByName[shareName]
	// 		sharePath = serverSharesV1.ByID[shareID].Path
	//
	// 		nfsClient, innerXErr := nfs.NewNFSClient(sshConfig)
	// 		if innerXErr != nil {
	// 			return innerXErr
	// 		}
	// 		innerXErr = nfsClient.Install(task)
	// 		if innerXErr != nil {
	// 			return innerXErr
	// 		}
	//
	// 		innerXErr = nfsClient.Mount(task, export, mountPath, withCache)
	// 		if innerXErr != nil {
	// 			return innerXErr
	// 		}
	//
	// 		serverSharesV1.ByID[shareID].ClientsByName[target.GetName()] = target.GetID()
	// 		serverSharesV1.ByID[shareID].ClientsByID[target.GetID()] = target.GetName()
	// 		return nil
	// 	})
	// })
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// defer func() {
	// 	if xerr != nil {
	// 		sshConfig, derr := target.GetSSHConfig(task)
	// 		if derr != nil {
	// 			logrus.Warn(derr)
	// 			_ = xerr.AddConsequence(derr)
	// 		}
	//
	// 		nfsClient, derr := nfs.NewNFSClient(sshConfig)
	// 		if derr != nil {
	// 			logrus.Warn(derr)
	// 			_ = xerr.AddConsequence(derr)
	// 		}
	//
	// 		derr = nfsClient.Install(handler.job.GetTask())
	// 		if derr != nil {
	// 			logrus.Warn(derr)
	// 			_ = xerr.AddConsequence(derr)
	// 		}
	//
	// 		derr = nfsClient.Unmount(handler.job.GetTask(), export)
	// 		if derr != nil {
	// 			logrus.Warn(derr)
	// 			_ = xerr.AddConsequence(derr)
	// 		}
	//
	// 		derr = server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 			return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
	// 				serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
	// 				if !ok {
	// 					return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 				}
	// 				delete(serverSharesV1.ByID[shareID].ClientsByName, target.GetName())
	// 				delete(serverSharesV1.ByID[shareID].ClientsByID, target.GetID())
	// 				return nil
	// 			})
	// 		})
	// 		if derr != nil {
	// 			logrus.Warnf("failed to remove mounted share %s from host '%s' metadata", shareName, server.GetName())
	// 			_ = xerr.AddConsequence(derr)
	// 		}
	// 	}
	// }()
	//
	// xerr = target.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
	// 		targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		// Make sure the HostMounts is correctly init if there are no mount yet
	// 		if !props.Lookup(hostproperty.MountsV1) {
	// 			targetMountsV1.Reset()
	// 		}
	// 		mount = propertiesv1.NewHostRemoteMount()
	// 		mount.ShareID = objs.GetID()
	// 		mount.Export = export
	// 		mount.Path = mountPath
	// 		mount.FileSystem = "nfs"
	// 		targetMountsV1.RemoteMountsByPath[mount.Path] = mount
	// 		targetMountsV1.RemoteMountsByShareID[mount.ShareID] = mount.Path
	// 		targetMountsV1.RemoteMountsByExport[mount.Export] = mount.Path
	// 		return nil
	// 	})
	// })
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// return mount, nil
}

// Unmount a share from local directory of an host
func (handler *shareHandler) Unmount(shareRef, hostRef string) (xerr fail.Error) {
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

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "('%s', '%s')", shareRef, hostRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	objs, xerr := sharefactory.Load(task, handler.job.GetService(), shareRef)
	if xerr != nil {
		return xerr
	}

	// Note: as soon as factory implements instance caching, server won't be necessary
	server, xerr := objs.GetServer(task)
	if xerr != nil {
		return xerr
	}

	// Note: for the same reason, comparing target to server won't be necessary, hostfactory.Load() would return
	//       the same instance
	var target resources.Host
	if server.GetName() == hostRef || server.GetID() == hostRef {
		target = server
	} else {
		if target, xerr = hostfactory.Load(task, handler.job.GetService(), hostRef); xerr != nil {
			return xerr
		}
	}
	return objs.Unmount(task, target)
	//
	// var shareID, sharePath string
	// xerr = server.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
	// 		serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		var found bool
	// 		shareID, found = serverSharesV1.ByName[shareRef]
	// 		if !found {
	// 			var share *propertiesv1.HostShare
	// 			share, found = serverSharesV1.ByID[shareRef]
	// 			if !found {
	// 				return fail.NotFoundError("failed to find data about share '%s'", shareRef)
	// 			}
	// 			shareID = share.GetID
	// 			sharePath = share.Path
	// 		}
	// 		return nil
	// 	})
	// })
	// if xerr != nil {
	// 	return xerr
	// }
	//
	// var target resources.IPAddress
	// if server.GetName() == hostRef || server.GetID() == hostRef {
	// 	target = server
	// } else {
	// 	if target, xerr = hostfactory.Load(task, handler.job.GetService(), hostRef); xerr != nil {
	// 		return xerr
	// 	}
	// }
	//
	// xerr = target.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
	// 		targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		mount, found := targetMountsV1.RemoteMountsByPath[targetMountsV1.RemoteMountsByShareID[shareID]]
	// 		if !found {
	// 			return fail.NotFoundError("not mounted on host '%s'", target.GetName())
	// 		}
	//
	// 		serverIP, innerXErr := server.GetAccessIP(task)
	// 		if innerXErr != nil {
	// 			return innerXErr
	// 		}
	//
	// 		// Unmount share from client
	// 		sshConfig, innerXErr := target.GetSSHConfig(task)
	// 		if innerXErr != nil {
	// 			return innerXErr
	// 		}
	// 		nfsClient, innerXErr := nfs.NewNFSClient(sshConfig)
	// 		if innerXErr != nil {
	// 			return innerXErr
	// 		}
	// 		innerXErr = nfsClient.Unmount(task, serverIP+":"+sharePath)
	// 		if innerXErr != nil {
	// 			return innerXErr
	// 		}
	//
	// 		// Remove mount from mount list
	// 		mountPath := mount.Path
	// 		delete(targetMountsV1.RemoteMountsByShareID, mount.ShareID)
	// 		delete(targetMountsV1.RemoteMountsByPath, mountPath)
	// 		return nil
	// 	})
	// })
	// if xerr != nil {
	// 	return xerr
	// }
	//
	// // Remove host from client lists of the share
	// xerr = server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
	// 	return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
	// 		serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
	// 		if !ok {
	// 			return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
	// 		}
	// 		delete(serverSharesV1.ByID[shareID].ClientsByName, target.GetName())
	// 		delete(serverSharesV1.ByID[shareID].ClientsByID, target.GetID())
	// 		return nil
	// 	})
	// })
	// if xerr != nil {
	// 	return xerr
	// }
	//
	// return nil
}

// Inspect returns the host and share corresponding to 'shareName'
// If share isn't found, return (nil, nil, nil, utils.ErrNotFound)
func (handler *shareHandler) Inspect(shareRef string) (share resources.Share, xerr fail.Error) {
	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if shareRef == "" {
		return nil, fail.InvalidParameterError("shareName", "cannot be empty string")
	}

	task := handler.job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.share"), "(%s)", shareRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	return sharefactory.Load(task, handler.job.GetService(), shareRef)
}
