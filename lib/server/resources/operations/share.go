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

package operations

import (
	"fmt"
	"path"
	"reflect"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system/nfs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

const (
	// nasFolderName is the technical name of the container used to store nas info
	sharesFolderName = "shares"
)

// ShareIdentity contains information about a share
type ShareIdentity struct {
	HostID    string `json:"host_id"`    // contains the ID of the host serving the share
	HostName  string `json:"host_name"`  // contains the Name of the host serving the share
	ShareID   string `json:"share_id"`   // contains the ID of the share
	ShareName string `json:"share_name"` // contains the name of the share
}

// ID returns the ID of the share
//
// satisfies interface data.Identifyable
func (si *ShareIdentity) ID() string {
	return si.ShareID
}

// Name returns the name of the share
//
// satisfies interface data.Identifyable
func (si *ShareIdentity) Name() string {
	return si.ShareName
}

// Serialize ...
func (si *ShareIdentity) Serialize() ([]byte, error) {
	return serialize.ToJSON(si)
}

// Deserialize ...
func (si *ShareIdentity) Deserialize(buf []byte) error {
	return serialize.FromJSON(buf, si)
}

// Clone ...
// satisfies interface data.Clonable
func (si *ShareIdentity) Clone() data.Clonable {
	newShareItem := *si
	return &newShareItem
}

// Replace ...
// satisfies interface data.Clonable
func (si *ShareIdentity) Replace(src data.Clonable) data.Clonable {
	srcSi := src.(*ShareIdentity)
	*si = *srcSi
	return si
}

// share contains information to maintain in Object Storage a list of shared folders
type share struct {
	*Core
}

// NewShare creates an instance of Share
func NewShare(svc iaas.Service) (*share, error) {
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}

	core, err := NewCore(svc, "share", sharesFolderName)
	if err != nil {
		return nil, err
	}
	return &share{Core: core}, nil
}

// LoadShare returns the name of the host owing the share 'ref', read from Object Storage
// logic: try to read until success.
//        If error is scerr.ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return scerr.ErrTimeout
func LoadShare(task concurrency.Task, svc iaas.Service, ref string) (*share, error) {
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	share, err := NewShare(svc)
	if err != nil {
		return nil, err
	}

	err = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return share.Read(task, ref)
		},
		10*time.Second,
	)
	if err != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := err.(retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of share '%s'", ref)
			err = scerr.NotFoundError("failed to load metadata of share '%s': timeout", ref)
		}
		return nil, err
	}
	return share, nil
}

// Browse walks through shares folder and executes a callback for each entry
func (objs *share) Browse(task concurrency.Task, callback func(string, string) error) error {
	if objs == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}
	return objs.Core.BrowseFolder(task, func(buf []byte) error {
		si := ShareIdentity{}
		err := (&si).Deserialize(buf)
		if err != nil {
			return err
		}
		return callback(si.HostName, si.ShareID)
	})
}

// // AddClient adds a client to the Nas definition in Object Storage
// func (m *Nas) AddClient(nas *resources.Nas) error {
// 	return NewNas(m.item.Service().Carry(nas).item.WriteInto(*m.id, nas.ID)
// 	// return m.item.WriteInto(m.id, nas.ID)
// }

// // RemoveClient removes a client to the Nas definition in Object Storage
// func (m *Nas) RemoveClient(nas *resources.Nas) error {
// 	return m.item.DeleteFrom(*m.id, nas.ID)
// }

// // Listclients returns the list of ID of hosts clients of the NAS server
// func (m *Nas) Listclients() ([]*resources.Nas, error) {
// 	var list []*resources.Nas
// 	err := m.item.BrowseInto(*m.id, func(buf []byte) error {
// 		nas := resources.Nas{}
// 		err := (&nas).Deserialize(buf)
// 		if err != nil {
// 			return err
// 		}
// 		list = append(list, &nas)
// 		return nil
// 	})
// 	return list, err
// }

// // FindClient returns the client hosted by the Host whose name is given
// func (m *Nas) FindClient(hostName string) (*resources.Nas, error) {
// 	var client *resources.Nas
// 	err := m.item.BrowseInto(*m.id, func(buf []byte) error {
// 		nas := resources.Nas{}
// 		err := (&nas).Deserialize(buf)
// 		if err != nil {
// 			return err
// 		}
// 		if nas.Host == hostName {
// 			client = &nas
// 			return nil
// 		}
// 		return nil
// 	})
// 	if err != nil {
// 		return nil, err
// 	}
// 	if client == nil {
// 		return nil, fmt.Errorf("no client found for nas '%s' on host '%s'", *m.name, hostName)
// 	}
// 	return client, nil
// }

// // MountNas add the client nas to the Nas definition from Object Storage
// func MountNas(svc *providers.Service, client *resources.Nas, server *resources.Nas) error {
// 	return NewNas(svc).Carry(server).AddClient(client)
// }

// // UmountNas remove the client nas to the Nas definition from Object Storage
// func UmountNas(svc *providers.Service, client *resources.Nas, server *resources.Nas) error {
// 	return NewNas(svc).Carry(server).RemoveClient(client)
// }

// Create creates a share on host
// FIXME: add task aborption handling
func (objs *share) Create(
	task concurrency.Task,
	shareName string,
	server resources.Host, path string,
	securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool,
) (err error) {

	if objs == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if shareName == "" {
		return scerr.InvalidParameterError("shareName", "cannot be empty string")
	}
	if server == nil {
		return scerr.InvalidParameterError("server", "cannot be nil")
	}

	// Check if a share already exists with the same name
	_, err = server.GetShare(task, shareName)
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); !ok {
			return err
		}
	}

	// Sanitize path
	sharePath, err := sanitize(path)
	if err != nil {
		return err
	}

	// -- make some validations --
	err = server.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		// Check if the path to share isn't a remote mount or contains a remote mount
		return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) error {
			serverMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if _, found := serverMountsV1.RemoteMountsByPath[path]; found {
				return scerr.InvalidRequestError(fmt.Sprintf("path to export '%s' is a mounted share", sharePath))
			}
			for k := range serverMountsV1.RemoteMountsByPath {
				if strings.Index(sharePath, k) == 0 {
					return scerr.InvalidRequestError("export path '%s' contains a share mounted in '%s'", sharePath, k)
				}
			}
			return nil
		})
	})
	if err != nil {
		return err
	}

	// Installs NFS Server software if needed
	sshConfig, err := server.SSHConfig(task)
	if err != nil {
		return err
	}
	nfsServer, err := nfs.NewServer(sshConfig)
	if err != nil {
		return err
	}

	// Nothing will be changed in object, but we don't want more than 1 goroutine to install NFS if needed (yes, this will cost a useless metadata update)
	err = server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if len(serverSharesV1.ByID) == 0 {
				// Host doesn't have shares yet, so install NFS
				err = nfsServer.Install(task)
				if err != nil {
					return err
				}
			}
			return nil
		})
	})
	if err != nil {
		return err
	}
	err = nfsServer.AddShare(task, sharePath, securityModes, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck)
	if err != nil {
		return err
	}

	// Starting from here, remove share from host if exiting with error
	defer func() {
		if err != nil {
			derr := nfsServer.RemoveShare(task, sharePath)
			if derr != nil {
				logrus.Errorf("After failure, cleanup failed to remove share '%s' on host", sharePath)
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Updates Host Property propertiesv1.HostShares
	var hostShare *propertiesv1.HostShare
	err = server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hostShare := propertiesv1.NewHostShare()
			hostShare.Name = shareName
			shareID, err := uuid.NewV4()
			if err != nil {
				return scerr.Wrap(err, "Error creating UUID for share")
			}
			hostShare.ID = shareID.String()
			hostShare.Path = sharePath
			hostShare.Type = "nfs"

			serverSharesV1.ByID[hostShare.ID] = hostShare
			serverSharesV1.ByName[hostShare.Name] = hostShare.ID

			return nil
		})
	})
	if err != nil {
		return err
	}

	// Starting from here, delete share reference in server if exiting with error
	defer func() {
		if err != nil {
			derr := server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
				return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
					serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(serverSharesV1.ByID, hostShare.ID)
					delete(serverSharesV1.ByName, hostShare.Name)
					return nil
				})
			})
			if derr != nil {
				logrus.Errorf("After failure, cleanup failed to update metadata of host '%s'", server.SafeGetName())
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Uses err to possibly trigger defer calls
	si := ShareIdentity{
		HostID:    server.SafeGetID(),
		HostName:  server.SafeGetName(),
		ShareID:   hostShare.ID,
		ShareName: hostShare.Name,
	}
	err = objs.Carry(task, &si)
	return err
}

// GetServer returns the *Host acting as share server, with error handling
func (objs *share) GetServer(task concurrency.Task) (resources.Host, error) {
	if objs == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	var hostID, hostName string
	err := objs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		share, ok := clonable.(*ShareIdentity)
		if !ok {
			return scerr.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		hostID = share.HostID
		hostName = share.HostName
		return nil
	})
	if err != nil {
		return nil, err
	}
	svc := objs.SafeGetService()
	server, err := LoadHost(task, svc, hostID)
	if err != nil {
		server, err = LoadHost(task, svc, hostName)
	}
	if err != nil {
		return nil, err
	}
	return server, nil
}

// SafeGetServer returns the *Host acting as share server, with no error handling
// if server cannot be found, returns NullHost
func (objs *share) SafeGetServer(task concurrency.Task) (host resources.Host) {
	host = NullHost
	if !objs.IsNull() {
		host, _ = objs.GetServer(task)
	}
	return host
}

// Mount mounts a share on a local directory of an host
// returns a clone of the propertiesv1.HostRemoteMount created on success
func (objs *share) Mount(task concurrency.Task, hostName, path string, withCache bool) (*propertiesv1.HostRemoteMount, error) {
	if objs == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostName == "" {
		return nil, scerr.InvalidParameterError("hostName", "cannot be empty string")
	}
	if path == "" {
		return nil, scerr.InvalidParameterError("path", "cannot be empty string")
	}
	var (
		serverName, serverID            string
		serverPrivateIP, serverAccessIP string
		export                          string
		objtarget                       resources.Host
		targetName, targetID            string
		hostShare                       *propertiesv1.HostShare
		shareName                       string
	)

	// Retrieve info about the share
	err := objs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return scerr.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		shareName = si.ShareName
		return nil
	})

	objserver, err := objs.GetServer(task)
	if err != nil {
		return nil, err
	}
	serverID = objserver.SafeGetID()
	serverName = objserver.SafeGetName()
	ip, err := objserver.GetPrivateIP(task)
	if err != nil {
		return nil, err
	}
	serverPrivateIP = ip
	ip, err = objserver.GetAccessIP(task)
	if err != nil {
		return nil, err
	}
	serverAccessIP = ip

	err = objserver.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostShare = sharesV1.ByID[sharesV1.ByName[shareName]].Clone().(*propertiesv1.HostShare)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// Sanitize path
	mountPath, err := sanitize(path)
	if err != nil {
		return nil, scerr.Wrap(err, "invalid mount path '%s'", path)
	}

	svc := objs.SafeGetService()
	if serverName == hostName || serverID == hostName {
		objtarget = objserver
	} else {
		objtarget, err = LoadHost(task, svc, hostName)
		if err != nil {
			return nil, err
		}
	}

	// Lock for read, won't change data other than properties, which are protected by their own way
	targetID = objtarget.SafeGetID()
	targetName = objtarget.SafeGetName()
	err = objtarget.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		// Check if share is already mounted
		// Check if there is already volume mounted in the path (or in subpath)
		innerErr := props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if s, ok := targetMountsV1.RemoteMountsByShareID[hostShare.ID]; ok {
				return scerr.DuplicateError(fmt.Sprintf("already mounted in '%s:%s'", targetName, targetMountsV1.RemoteMountsByPath[s].Path))
			}
			for _, i := range targetMountsV1.LocalMountsByPath {
				if i.Path == path {
					// cannot mount a share in place of a volume (by convention, nothing technically preventing it)
					return scerr.InvalidRequestError(fmt.Sprintf("there is already a volume in path '%s:%s'", targetName, path))
				}
			}
			for _, i := range targetMountsV1.RemoteMountsByPath {
				if strings.Index(path, i.Path) == 0 {
					// cannot mount a share inside another share (at least by convention, if not technically)
					return scerr.InvalidRequestError("there is already a share mounted in '%s:%s'", targetName, i.Path)
				}
			}

			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		return props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostNetworkV1.DefaultGatewayPrivateIP == serverPrivateIP {
				export = serverPrivateIP + ":" + hostShare.Path
			} else {
				export = serverAccessIP + ":" + hostShare.Path
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	targetSSHConfig, err := objtarget.SSHConfig(task)
	if err != nil {
		return nil, err
	}

	// -- Mount the share on host --
	// Lock for read, won't change data other than properties, which are protected by their own way
	err = objserver.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, found := serverSharesV1.ByID[serverSharesV1.ByName[shareName]]
			if !found {
				return scerr.NotFoundError(fmt.Sprintf("failed to find metadata about share '%s'", shareName))
			}
			shareID := serverSharesV1.ByName[shareName]

			nfsClient, err := nfs.NewNFSClient(targetSSHConfig)
			if err != nil {
				return err
			}
			err = nfsClient.Install(task)
			if err != nil {
				return err
			}
			err = nfsClient.Mount(task, export, mountPath, withCache)
			if err != nil {
				return err
			}

			serverSharesV1.ByID[shareID].ClientsByName[targetName] = targetID
			serverSharesV1.ByID[shareID].ClientsByID[targetID] = targetName
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	// Starting from here, remove share mount from server share when exiting with error
	defer func() {
		if err != nil {
			derr := objserver.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
				return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
					serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(serverSharesV1.ByID[serverSharesV1.ByName[shareName]].ClientsByName, targetName)
					delete(serverSharesV1.ByID[serverSharesV1.ByName[shareName]].ClientsByID, targetID)
					return nil
				})
			})
			if derr == nil {
				var nfsClient *nfs.Client
				if nfsClient, derr = nfs.NewNFSClient(targetSSHConfig); derr == nil {
					if derr = nfsClient.Install(task); derr == nil {
						derr = nfsClient.Unmount(task, export)
					}
				}
			}
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
				logrus.Error(derr)
			}
		}
	}()

	var mount *propertiesv1.HostRemoteMount
	err = objtarget.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
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
			mount.ShareID = hostShare.ID
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

	// Starting from here, removes share mount from target if exiting with error
	defer func() {
		if err != nil {
			derr := objtarget.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
				return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
					targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(targetMountsV1.RemoteMountsByShareID, mount.ShareID)
					delete(targetMountsV1.RemoteMountsByPath, mount.Path)
					delete(targetMountsV1.RemoteMountsByExport, mount.Export)
					return nil
				})
			})
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
				logrus.Warnf("Failed to remove mounted share '%s' from host '%s' metadata", shareName, hostName)
			}
		}
	}()

	return mount.Clone().(*propertiesv1.HostRemoteMount), nil
}

// Unmount unmounts a share from local directory of an host
func (objs *share) Unmount(task concurrency.Task, targetName string) error {
	if objs == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if targetName == "" {
		return scerr.InvalidParameterError("targetName", "cannot be empty string")
	}

	var (
		shareName, shareID   string
		serverID, serverName string
		serverAccessIP       string
		targetID             string
		objtarget            resources.Host
		hostShare            *propertiesv1.HostShare
	)

	// -- get data from share --
	err := objs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return scerr.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		shareName = si.ShareName
		return nil
	})

	objserver, err := objs.GetServer(task)
	if err != nil {
		return err
	}
	err = objserver.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		serverName = objserver.SafeGetName()
		serverID = objserver.SafeGetID()
		serverAccessIP = objserver.SafeGetAccessIP(task)

		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1 := clonable.(*propertiesv1.HostShares)
			var found bool
			shareID, found = serverSharesV1.ByName[shareName]
			if !found {
				return scerr.NotFoundError("failed to find data about share '%s' on host '%s'", shareName, serverName)
			}
			hostShare = serverSharesV1.ByID[shareID]
			// remotePath := h.AccessIP() + ":" + hostShare.Path
			return nil
		})
	})
	if err != nil {
		return err
	}

	svc := objs.SafeGetService()
	if serverName == targetName || serverID == targetName {
		objtarget = objserver
	} else {
		objtarget, err = LoadHost(task, svc, targetName)
		if err != nil {
			return err
		}
	}

	var mountPath string
	err = objtarget.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		targetName = objtarget.SafeGetName()
		targetID = objtarget.SafeGetID()
		return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			mount, found := targetMountsV1.RemoteMountsByPath[targetMountsV1.RemoteMountsByShareID[shareID]]
			if !found {
				return scerr.NotFoundError("not mounted on host '%s'", targetName)
			}

			// Unmount share from client
			sshConfig, inErr := objtarget.SSHConfig(task)
			if inErr != nil {
				return inErr
			}
			nfsClient, inErr := nfs.NewNFSClient(sshConfig)
			if inErr != nil {
				return inErr
			}
			inErr = nfsClient.Unmount(task, serverAccessIP+":"+hostShare.Path)
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
	return objserver.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1 := clonable.(*propertiesv1.HostShares)
			delete(serverSharesV1.ByID[shareID].ClientsByName, targetName)
			delete(serverSharesV1.ByID[shareID].ClientsByID, targetID)
			return nil
		})
	})
}

// Delete deletes a share from server
func (objs *share) Delete(task concurrency.Task) error {
	if objs == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	var (
		shareID, shareName string
		hostShare          *propertiesv1.HostShare
	)

	// -- Retrieve info about the share --
	err := objs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return scerr.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		shareID = si.ShareID
		shareName = si.ShareName
		return nil
	})

	objserver, err := objs.GetServer(task)
	if err != nil {
		return err
	}
	err = objserver.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if _, ok := serverSharesV1.ByID[shareName]; !ok {
				return scerr.NotFoundError("failed to find data about share '%s' in host '%s'", shareName, objserver.SafeGetName())
			}

			hostShare = serverSharesV1.ByID[shareID].Clone().(*propertiesv1.HostShare)
			// remotePath := h.AccessIP() + ":" + hostShare.Path

			if len(hostShare.ClientsByName) > 0 {
				var list []string
				for k := range hostShare.ClientsByName {
					list = append(list, "'"+k+"'")
				}
				return scerr.InvalidRequestError("still used by: %s", strings.Join(list, ","))
			}

			sshConfig, err := objserver.SSHConfig(task)
			if err != nil {
				return err
			}
			nfsServer, err := nfs.NewServer(sshConfig)
			if err != nil {
				return err
			}
			err = nfsServer.RemoveShare(task, hostShare.Path)
			if err != nil {
				return err
			}

			delete(serverSharesV1.ByID, shareID)
			delete(serverSharesV1.ByName, shareName)
			return nil
		})
	})
	if err != nil {
		return err
	}

	// Remove share metadata
	return objs.Core.Delete(task)
}

func sanitize(in string) (string, error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", scerr.InvalidParameterError("in", "must be a string containing an absolute path")
	}
	return sanitized, nil
}
