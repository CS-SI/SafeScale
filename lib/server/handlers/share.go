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

package handlers

import (
	"context"
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	sharefactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/share"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system/nfs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

//go:generate mockgen -destination=../mocks/mock_nasapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers ShareAPI

// TODO: At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// ShareHandler defines API to manipulate Shares
type ShareHandler interface {
	Create(string, string, string, []string, bool, bool, bool, bool, bool, bool, bool) (resources.Share, error)
	Inspect(string) (resources.Share, error)
	Delete(string) error
	List() (map[string]map[string]*propertiesv1.HostShare, error)
	Mount(string, string, string, bool) (*propertiesv1.HostRemoteMount, error)
	Unmount(string, string) error
}

// shareHandler nas service
type shareHandler struct {
	job server.Job
}

// NewShareHandler creates a ShareHandler
func NewShareHandler(job server.Job) ShareHandler {
	return &shareHandler{job: job}
}

func sanitize(in string) (string, error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fmt.Errorf("exposed path must be absolute")
	}
	return sanitized, nil
}

// Create a share on host
func (handler *shareHandler) Create(
	shareName, hostName, path string, securityModes []string,
	readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool,
) (share resources.Share, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if shareName == "" {
		return nil, scerr.InvalidParameterError("shareName", "cannot be empty")
	}
	if hostName == "" {
		return nil, scerr.InvalidParameterError("hostName", "cannot be empty")
	}
	if path == "" {
		return nil, scerr.InvalidParameterError("path", "cannot be empty")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%s)", shareName), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objs, err := sharefactory.New(handler.service)
	if err != nil {
		return nil, err
	}
	objh, err := hostfactory.Load(task, handler.service, hostName)
	if err != nil {
		return nil, err
	}
	return objs, objs.Create(task, shareName, objh, path, securityModes, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck)
}

// Delete a share from host
func (handler *ShareHandler) Delete(name string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if name == "" {
		return scerr.InvalidParameterError("name", "cannot be empty!")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%s)", name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objs, err := sharefactory.Load(task, handler.service, name)
	if err != nil {
		return err
	}
	return objs.Delete(task)
}

// List return the list of all shares from all servers
func (handler *ShareHandler) List() (shares map[string]map[string]*propertiesv1.HostShare, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objs, err := sharefactory.New(handler.service)
	if err != nil {
		return nil, err
	}
	var servers []string
	err = objs.Browse(task, func(hostName string, shareID string) error {
		servers = append(servers, hostName)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Now walks through the hosts acting as Nas
	shares = map[string]map[string]*propertiesv1.HostShare{}
	if len(servers) == 0 {
		return shares, nil
	}

	for _, serverID := range servers {
		host, err := hostfactory.Load(task, handler.service, serverID)
		if err != nil {
			return nil, err
		}

		err = host.Inspect(task, func(_ data.Clonable) error {
			props, inErr := host.Properties(task)
			if inErr != nil {
				return inErr
			}
			return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
				hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				shares[serverID] = hostSharesV1.ByID
				return nil
			})
		})
		if err != nil {
			return nil, err
		}
	}
	return shares, nil
}

// Mount a share on a local directory of an host
func (handler *shareHandler) Mount(shareName, hostRef, path string,	withCache bool) (mount *propertiesv1.HostRemoteMount, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if shareName == "" {
		return nil, scerr.InvalidParameterError("shareName", "cannot be empty string")
	}
	if hostRef == "" {
		return nil, scerr.InvalidParameterError("hostRef", "cannot be empty string")
	}
	if path == "" {
		return nil, scerr.InvalidParameterError("hostName", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s', '%s')", shareName, hostRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	// Retrieve info about the share
	objs, err := sharefactory.Load(task, handler.service, shareName)
	if err != nil {
		return nil, err
	}
	server, err := objs.Server(task)
	if err != nil {
		return nil, err
	}

	// Sanitize path
	mountPath, err := sanitize(path)
	if err != nil {
		return nil, fmt.Errorf("invalid mount path '%s': '%s'", path, err)
	}

	var target resources.Host
	if server.Name() == hostRef || server.ID() == hostRef {
		target = server
	} else {
		target, err = hostfactory.Load(task, handler.service, hostRef)
		if err != nil {
			return nil, err
		}
	}

	// Check if share is already mounted
	// Check if there is already volume mounted in the path (or in subpath)
	var targetNetwork *propertiesv1.HostNetwork
	err = target.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		inErr = props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostsMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if s, ok := targetMountsV1.RemoteMountsByShareID[objs.ID()]; ok {
				return scerr.DuplicateError("already mounted in '%s:%s'", target.Name, targetMountsV1.RemoteMountsByPath[s].Path)
			}
			for _, i := range targetMountsV1.LocalMountsByPath {
				if i.Path == path {
					// Can't mount a share in place of a volume (by convention, nothing technically preventing it)
					return fmt.Errorf("there is already a volume in path '%s:%s'", target.Name(), path)
				}
			}
			for _, i := range targetMountsV1.RemoteMountsByPath {
				if strings.Index(path, i.Path) == 0 {
					// Can't mount a share inside another share (at least by convention, if not technically)
					return fmt.Errorf("there is already a share mounted in '%s:%s'", target.Name(), i.Path)
				}
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		return props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			var ok bool
			targetNetwork, ok = clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})

	var export, sharePath string
	shareID := objs.ID()
	err = server.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		var ip string
		inErr = props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			serverNetwork, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if netID, ok := serverNetwork.NetworksByID[targetNetwork.DefaultNetworkID]; ok {
				ip = serverNetwork.IPv4Addresses[netID]
			} else {
				for _, v := range targetNetwork.NetworksByID {
					if _, ok := serverNetwork.NetworksByID[v]; ok {
						ip = serverNetwork.IPv4Addresses[v]
						break
					}
				}
				if ip == "" {
					ip = serverNetwork.IPv4Addresses[serverNetwork.DefaultNetworkID]
				}
			}
			if ip == "" {
				return scerr.NotFoundError("no IP address found on server '%s' to serve the share to host '%s'", server.Name(), target.Name())
			}
			return nil
		})
		if inErr != nil {
			return inErr
		}

		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sharePath = hostSharesV1.ByID[objs.ID()].Path
			export = ip + ":" + sharePath
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	sshConfig, err := target.SSHConfig(task)
	if err != nil {
		return nil, err
	}

	// Mount the share on host
	err = server.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShare' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, found := serverSharesV1.ByID[serverSharesV1.ByName[shareName]]
			if !found {
				return fmt.Errorf("failed to find metadata about share '%s'", shareName)
			}
			shareID = serverSharesV1.ByName[shareName]
			sharePath = serverSharesV1.ByID[shareID].Path

			nfsClient, err := nfs.NewNFSClient(sshConfig)
			if err != nil {
				return err
			}
			err = nfsClient.Install(ctx)
			if err != nil {
				return err
			}

			err = nfsClient.Mount(ctx, export, mountPath, withCache)
			if err != nil {
				return err
			}

			serverSharesV1.ByID[shareID].ClientsByName[target.Name()] = target.ID()
			serverSharesV1.ByID[shareID].ClientsByID[target.ID()] = target.Name()
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			sshConfig, derr := target.SSHConfig(task)
			if derr != nil {
				logrus.Warn(derr)
				err = scerr.AddConsequence(err, derr)
			}

			nfsClient, derr := nfs.NewNFSClient(sshConfig)
			if derr != nil {
				logrus.Warn(derr)
				err = scerr.AddConsequence(err, derr)
			}

			derr = nfsClient.Install(handler.job.Task())
			if derr != nil {
				logrus.Warn(derr)
				err = scerr.AddConsequence(err, derr)
			}

			derr = nfsClient.Unmount(handler.job.Task(), export)
			if derr != nil {
				logrus.Warn(derr)
				err = scerr.AddConsequence(err, derr)
			}

			derr = server.Alter(task, func(_ data.Clonable) error {
				props, inErr := server.Properties(task)
				if inErr != nil {
					return inErr
				}
				return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
					serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(serverSharesV1.ByID[shareID].ClientsByName, target.Name())
					delete(serverSharesV1.ByID[shareID].ClientsByID, target.ID())
					return nil
				})
			})
			if derr != nil {
				logrus.Warnf("failed to remove mounted share %s from host '%s' metadata", shareName, server.Name())
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	err = target.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// Make sure the HostMounts is correctly init if there are no mount yet
			if !props.Lookup(hostproperty.MountsV1) {
				targetMountsV1.Reset()
			}
			mount = propertiesv1.NewHostRemoteMount()
			mount.ShareID = objs.ID()
			mount.Export = export
			mount.Path = mountPath
			mount.FileSystem = "nfs"
			targetMountsV1.RemoteMountsByPath[mount.Path] = mount
			targetMountsV1.RemoteMountsByShareID[mount.ShareID] = mount.Path
			targetMountsV1.RemoteMountsByExport[mount.Export] = mount.Path
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return mount, nil
}

// Unmount a share from local directory of an host
func (handler *shareHandler) Unmount(shareRef, hostRef string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if shareRef == "" {
		return scerr.InvalidParameterError("shareRef", "cannot be empty string")
	}
	if hostRef == "" {
		return scerr.InvalidParameterError("hostRef", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s', '%s')", shareRef, hostRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objs, err := sharefactory.Load(task, handler.service, shareRef)
	if err != nil {
		return err
	}
	server, err := objs.Server(task)
	if err != nil {
		return err
	}

	var shareID, sharePath string
	err = server.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			var found bool
			shareID, found = serverSharesV1.ByName[shareRef]
			if !found {
				var share *propertiesv1.HostShare
				share, found = serverSharesV1.ByID[shareRef]
				if !found {
					return fmt.Errorf("failed to find data about share '%s'", shareRef)
				}
				shareID = share.ID
				sharePath = share.Path
			}
			return nil
		})
	})
	if err != nil {
		return err
	}

	var target resources.Host
	if server.Name() == hostRef || server.ID() == hostRef {
		target = server
	} else {
		target, err = hostfactory.Load(task, handler.service, hostRef)
		if err != nil {
			return err
		}
	}

	var mountPath string
	err = target.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			mount, found := targetMountsV1.RemoteMountsByPath[targetMountsV1.RemoteMountsByShareID[shareID]]
			if !found {
				return fmt.Errorf("not mounted on host '%s'", target.Name())
			}

			serverIP, inErr := server.AccessIP(task)
			if inErr != nil {
				return inErr
			}

			// Unmount share from client
			sshConfig, inErr := target.SSHConfig(task)
			if inErr != nil {
				return inErr
			}
			nfsClient, inErr := nfs.NewNFSClient(sshConfig)
			if inErr != nil {
				return inErr
			}
			inErr = nfsClient.Unmount(ctx, serverIP+":"+sharePath)
			if inErr != nil {
				return inErr
			}

			// Remove mount from mount list
			mountPath = mount.Path
			delete(targetMountsV1.RemoteMountsByShareID, mount.ShareID)
			delete(targetMountsV1.RemoteMountsByPath, mountPath)
			return nil
		})
	})
	if err != nil {
		return err
	}

	// Remove host from client lists of the share
	err = server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			delete(serverSharesV1.ByID[shareID].ClientsByName, target.Name())
			delete(serverSharesV1.ByID[shareID].ClientsByID, target.ID())
			return nil
		})
	})
	if err != nil {
		return err
	}

	return nil
}

// Inspect returns the host and share corresponding to 'shareName'
// If share isn't found, return (nil, nil, nil, utils.ErrNotFound)
func (handler *ShareHandler) Inspect(shareRef string) (share resources.Share, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if shareRef == "" {
		return nil, scerr.InvalidParameterError("shareName", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%s)", shareRef), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	return sharefactory.Load(task, handler.service, shareRef)
}
