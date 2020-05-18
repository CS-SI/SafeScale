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
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"
	"time"

	"github.com/google/martian/log"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system/nfs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
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

// SafeGetID returns the ID of the share
//
// satisfies interface data.Identifiable
func (si *ShareIdentity) SafeGetID() string {
	return si.ShareID
}

// SafeGetName returns the name of the share
//
// satisfies interface data.Identifiable
func (si *ShareIdentity) SafeGetName() string {
	return si.ShareName
}

// Serialize ...
// satisfies interface data.Serializable
func (si *ShareIdentity) Serialize() ([]byte, fail.Error) {
	r, err := json.Marshal(si)
	return r, fail.ToError(err)
}

// Deserialize ...
// satisfies interface data.Serializable
func (si *ShareIdentity) Deserialize(buf []byte) (xerr fail.Error) {
	defer fail.OnPanic(&xerr) // json.Unmarshal may panic
	return fail.ToError(json.Unmarshal(buf, si))
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
	*core
}

func nullShare() *share {
	return &share{core: nullCore()}
}

// NewShare creates an instance of Share
func NewShare(svc iaas.Service) (resources.Share, fail.Error) {
	if svc == nil {
		return nullShare(), fail.InvalidParameterError("svc", "cannot be nil")
	}

	c, xerr := NewCore(svc, "share", sharesFolderName, &ShareIdentity{})
	if xerr != nil {
		return nullShare(), xerr
	}
	return &share{core: c}, nil
}

// LoadShare returns the name of the host owing the share 'ref', read from Object Storage
// logic: try to read until success.
//        If error is fail.ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return fail.ErrTimeout
func LoadShare(task concurrency.Task, svc iaas.Service, ref string) (resources.Share, fail.Error) {
	if task == nil {
		return nullShare(), fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullShare(), fail.InvalidParameterError("svc", "cannot be nil")
	}
	if ref == "" {
		return nullShare(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	rs, xerr := NewShare(svc)
	if xerr != nil {
		return rs, xerr
	}

	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return rs.Read(task, ref)
		},
		10*time.Second,
	)
	if xerr != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := xerr.(retry.ErrTimeout); ok {
			logrus.Debugf("timeout reading metadata of rs '%s'", ref)
			xerr = fail.NotFoundError("failed to load metadata of rs '%s': timeout", ref)
		}
		return nullShare(), xerr
	}
	return rs, nil
}

func (objs *share) IsNull() bool {
	return objs == nil || objs.core.IsNull()
}

// Browse walks through shares folder and executes a callback for each entry
func (objs *share) Browse(task concurrency.Task, callback func(string, string) fail.Error) fail.Error {
	if objs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}
	return objs.core.BrowseFolder(task, func(buf []byte) fail.Error {
		si := &ShareIdentity{}
		if xerr := si.Deserialize(buf); xerr != nil {
			return xerr
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
// 		return nil, fail.NotFoundError("no client found for nas '%s' on host '%s'", *m.name, hostName)
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
	options string,
	/*securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool,*/
) (xerr fail.Error) {

	if objs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if shareName == "" {
		return fail.InvalidParameterError("shareName", "cannot be empty string")
	}
	if server == nil {
		return fail.InvalidParameterError("server", "cannot be nil")
	}

	// Check if a share already exists with the same name
	if _, xerr = server.GetShare(task, shareName); xerr != nil {
		if _, ok := xerr.(fail.ErrNotFound); !ok {
			return xerr
		}
	}

	// Sanitize path
	sharePath, xerr := sanitize(path)
	if xerr != nil {
		return xerr
	}

	// -- make some validations --
	xerr = server.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Check if the path to share isn't a remote mount or contains a remote mount
		return props.Inspect(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			serverMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if _, found := serverMountsV1.RemoteMountsByPath[path]; found {
				return fail.InvalidRequestError(fmt.Sprintf("path to export '%s' is a mounted share", sharePath))
			}
			for k := range serverMountsV1.RemoteMountsByPath {
				if strings.Index(sharePath, k) == 0 {
					return fail.InvalidRequestError("export path '%s' contains a share mounted in '%s'", sharePath, k)
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// Installs NFS Server software if needed
	sshConfig, xerr := server.GetSSHConfig(task)
	if xerr != nil {
		return xerr
	}
	nfsServer, xerr := nfs.NewServer(sshConfig)
	if xerr != nil {
		return xerr
	}

	// Nothing will be changed in object, but we don't want more than 1 goroutine to install NFS if needed (yes, this will cost a useless metadata update)
	xerr = server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if len(serverSharesV1.ByID) == 0 {
				// Host doesn't have shares yet, so install NFS
				if xerr = nfsServer.Install(task); xerr != nil {
					return xerr
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}
	if xerr = nfsServer.AddShare(task, sharePath, options /*securityModes, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck*/); xerr != nil {
		return xerr
	}

	// Starting from here, remove share from host if exiting with error
	defer func() {
		if xerr != nil {
			derr := nfsServer.RemoveShare(task, sharePath)
			if derr != nil {
				logrus.Errorf("After failure, cleanup failed to remove share '%s' on host", sharePath)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	// Updates Host Property propertiesv1.HostShares
	var hostShare *propertiesv1.HostShare
	xerr = server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hostShare := propertiesv1.NewHostShare()
			hostShare.Name = shareName
			shareID, err := uuid.NewV4()
			if err != nil {
				return fail.Wrap(err, "Error creating UUID for share")
			}
			hostShare.ID = shareID.String()
			hostShare.Path = sharePath
			hostShare.Type = "nfs"

			serverSharesV1.ByID[hostShare.ID] = hostShare
			serverSharesV1.ByName[hostShare.Name] = hostShare.ID

			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// Starting from here, delete share reference in server if exiting with error
	defer func() {
		if xerr != nil {
			derr := server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
					serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(serverSharesV1.ByID, hostShare.ID)
					delete(serverSharesV1.ByName, hostShare.Name)
					return nil
				})
			})
			if derr != nil {
				logrus.Errorf("After failure, cleanup failed to update metadata of host '%s'", server.SafeGetName())
				_ = xerr.AddConsequence(derr)
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
	return objs.Carry(task, &si)
}

// GetServer returns the *Host acting as share server, with error handling
func (objs *share) GetServer(task concurrency.Task) (resources.Host, fail.Error) {
	if objs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	var hostID, hostName string
	xerr := objs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		share, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		hostID = share.HostID
		hostName = share.HostName
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	svc := objs.SafeGetService()
	server, xerr := LoadHost(task, svc, hostID)
	if xerr != nil {
		server, xerr = LoadHost(task, svc, hostName)
	}
	if xerr != nil {
		return nil, xerr
	}
	return server, nil
}

// SafeGetServer returns the *Host acting as share server, with no error handling
func (objs *share) SafeGetServer(task concurrency.Task) (rh resources.Host) {
	rh, _ = objs.GetServer(task)
	return rh
}

// Mount mounts a share on a local directory of an host
// returns a clone of the propertiesv1.HostRemoteMount created on success
func (objs *share) Mount(task concurrency.Task, target resources.Host, path string, withCache bool) (*propertiesv1.HostRemoteMount, fail.Error) {
	if objs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if target == nil {
		return nil, fail.InvalidParameterError("target", "cannot be nil")
	}
	if path == "" {
		return nil, fail.InvalidParameterError("path", "cannot be empty string")
	}

	var (
		// serverName, serverID            string
		serverPrivateIP, serverAccessIP string
		export                          string
		targetName, targetID            string
		hostShare                       *propertiesv1.HostShare
		shareName                       string
	)

	// Retrieve info about the share
	xerr := objs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		shareName = si.ShareName
		return nil
	})

	objserver, xerr := objs.GetServer(task)
	if xerr != nil {
		return nil, xerr
	}
	// serverID = objserver.SafeGetID()
	// serverName = objserver.SafeGetName()
	ip, xerr := objserver.GetPrivateIP(task)
	if xerr != nil {
		return nil, xerr
	}
	serverPrivateIP = ip
	if ip, xerr = objserver.GetAccessIP(task); xerr != nil {
		return nil, xerr
	}
	serverAccessIP = ip

	xerr = objserver.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostShare = sharesV1.ByID[sharesV1.ByName[shareName]].Clone().(*propertiesv1.HostShare)
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	// Sanitize path
	mountPath, xerr := sanitize(path)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "invalid mount path '%s'", path)
	}

	// Lock for read, won't change data other than properties, which are protected by their own way
	targetID = target.SafeGetID()
	targetName = target.SafeGetName()
	xerr = target.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Check if share is already mounted
		// Check if there is already volume mounted in the path (or in subpath)
		innerXErr := props.Inspect(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if s, ok := targetMountsV1.RemoteMountsByShareID[hostShare.ID]; ok {
				return fail.DuplicateError(fmt.Sprintf("already mounted in '%s:%s'", targetName, targetMountsV1.RemoteMountsByPath[s].Path))
			}
			for _, i := range targetMountsV1.LocalMountsByPath {
				if i.Path == path {
					// cannot mount a share in place of a volume (by convention, nothing technically preventing it)
					return fail.InvalidRequestError(fmt.Sprintf("there is already a volume in path '%s:%s'", targetName, path))
				}
			}
			for _, i := range targetMountsV1.RemoteMountsByPath {
				if strings.Index(path, i.Path) == 0 {
					// cannot mount a share inside another share (at least by convention, if not technically)
					return fail.InvalidRequestError("there is already a share mounted in '%s:%s'", targetName, i.Path)
				}
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(task, hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
			hostNetworkV1, ok := clonable.(*propertiesv1.HostNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostNetworkV1.DefaultGatewayPrivateIP == serverPrivateIP {
				export = serverPrivateIP + ":" + hostShare.Path
			} else {
				export = serverAccessIP + ":" + hostShare.Path
			}
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	targetSSHConfig, xerr := target.GetSSHConfig(task)
	if xerr != nil {
		return nil, xerr
	}

	// -- Mount the share on host --
	// Lock for read, won't change data other than properties, which are protected by their own way
	xerr = objserver.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, found := serverSharesV1.ByID[serverSharesV1.ByName[shareName]]
			if !found {
				return fail.NotFoundError(fmt.Sprintf("failed to find metadata about share '%s'", shareName))
			}
			shareID := serverSharesV1.ByName[shareName]

			nfsClient, xerr := nfs.NewNFSClient(targetSSHConfig)
			if xerr != nil {
				return xerr
			}
			xerr = nfsClient.Install(task)
			if xerr != nil {
				return xerr
			}
			xerr = nfsClient.Mount(task, export, mountPath, withCache)
			if xerr != nil {
				return xerr
			}

			serverSharesV1.ByID[shareID].ClientsByName[targetName] = targetID
			serverSharesV1.ByID[shareID].ClientsByID[targetID] = targetName
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	// Starting from here, remove share mount from server share when exiting with error
	defer func() {
		if xerr != nil {
			derr := objserver.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
					serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
				_ = xerr.AddConsequence(derr)
				logrus.Error(derr)
			}
		}
	}()

	var mount *propertiesv1.HostRemoteMount
	xerr = target.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
	if xerr != nil {
		return nil, xerr
	}

	// Starting from here, removes share mount from target if exiting with error
	defer func() {
		if xerr != nil {
			derr := target.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
					targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(targetMountsV1.RemoteMountsByShareID, mount.ShareID)
					delete(targetMountsV1.RemoteMountsByPath, mount.Path)
					delete(targetMountsV1.RemoteMountsByExport, mount.Export)
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(derr)
				logrus.Warnf("Failed to remove mounted share '%s' from host '%s' metadata", shareName, targetName)
			}
		}
	}()

	return mount.Clone().(*propertiesv1.HostRemoteMount), nil
}

// Unmount unmounts a share from local directory of an host
func (objs *share) Unmount(task concurrency.Task, target resources.Host) fail.Error {
	if objs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if target == nil {
		return fail.InvalidParameterError("target", "cannot be nil")
	}

	var (
		shareName, shareID string
		/*serverID,*/ serverName string
		serverAccessIP           string
		hostShare                *propertiesv1.HostShare
	)

	// -- get data from share --
	xerr := objs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		shareName = si.ShareName
		return nil
	})
	if xerr != nil {
		return xerr
	}

	objserver, xerr := objs.GetServer(task)
	if xerr != nil {
		return xerr
	}
	xerr = objserver.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		serverName = objserver.SafeGetName()
		// serverID = objserver.SafeGetID()
		serverAccessIP = objserver.SafeGetAccessIP(task)

		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1 := clonable.(*propertiesv1.HostShares)
			var found bool
			shareID, found = serverSharesV1.ByName[shareName]
			if !found {
				return fail.NotFoundError("failed to find data about share '%s' on host '%s'", shareName, serverName)
			}
			hostShare = serverSharesV1.ByID[shareID]
			// remotePath := h.AccessIP() + ":" + hostShare.Path
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	var mountPath string
	targetName := target.SafeGetName()
	targetID := target.SafeGetID()
	xerr = target.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			mount, found := targetMountsV1.RemoteMountsByPath[targetMountsV1.RemoteMountsByShareID[shareID]]
			if !found {
				return fail.NotFoundError("not mounted on host '%s'", targetName)
			}

			// Unmount share from client
			sshConfig, inErr := target.GetSSHConfig(task)
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
	if xerr != nil {
		return xerr
	}

	// Remove host from client lists of the share
	return objserver.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1 := clonable.(*propertiesv1.HostShares)
			delete(serverSharesV1.ByID[shareID].ClientsByName, targetName)
			delete(serverSharesV1.ByID[shareID].ClientsByID, targetID)
			return nil
		})
	})
}

// Delete deletes a share from server
func (objs *share) Delete(task concurrency.Task) fail.Error {
	if objs.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	var (
		shareID, shareName string
		hostShare          *propertiesv1.HostShare
	)

	// -- Retrieve info about the share --
	xerr := objs.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		shareID = si.ShareID
		shareName = si.ShareName
		return nil
	})
	if xerr != nil {
		return xerr
	}

	objserver, xerr := objs.GetServer(task)
	if xerr != nil {
		return xerr
	}
	xerr = objserver.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if _, ok := serverSharesV1.ByID[shareName]; !ok {
				return fail.NotFoundError("failed to find data about share '%s' in host '%s'", shareName, objserver.SafeGetName())
			}

			hostShare = serverSharesV1.ByID[shareID].Clone().(*propertiesv1.HostShare)
			// remotePath := h.AccessIP() + ":" + hostShare.Path

			if len(hostShare.ClientsByName) > 0 {
				var list []string
				for k := range hostShare.ClientsByName {
					list = append(list, "'"+k+"'")
				}
				return fail.InvalidRequestError("still used by: %s", strings.Join(list, ","))
			}

			sshConfig, xerr := objserver.GetSSHConfig(task)
			if xerr != nil {
				return xerr
			}
			nfsServer, xerr := nfs.NewServer(sshConfig)
			if xerr != nil {
				return xerr
			}
			if xerr = nfsServer.RemoveShare(task, hostShare.Path); xerr != nil {
				return xerr
			}

			delete(serverSharesV1.ByID, shareID)
			delete(serverSharesV1.ByName, shareName)
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// Remove share metadata
	return objs.core.Delete(task)
}

func sanitize(in string) (string, fail.Error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fail.InvalidParameterError("in", "must be a string containing an absolute path")
	}
	return sanitized, nil
}

func (objs *share) ToProtocol(task concurrency.Task) (*protocol.ShareMountList, fail.Error) {
	if objs.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	shareID := objs.SafeGetID()
	shareName := objs.SafeGetName()
	server := objs.SafeGetServer(task)
	share, xerr := server.GetShare(task, shareID)
	if xerr != nil {
		return nil, xerr
	}

	psml := &protocol.ShareMountList{
		Share: &protocol.ShareDefinition{
			Id:              shareID,
			Name:            shareName,
			Host:            &protocol.Reference{Name: server.SafeGetName()},
			Path:            share.Path,
			Type:            share.Type,
			OptionsAsString: share.ShareOptions,
			// SecurityModes: share.ShareAcls,
		},
	}
	for k := range share.ClientsByName {
		h, xerr := LoadHost(task, objs.SafeGetService(), k)
		if xerr != nil {
			log.Errorf(xerr.Error())
			continue
		}
		mounts, xerr := h.GetMounts(task)
		if xerr != nil {
			log.Errorf(xerr.Error())
			continue
		}
		path, ok := mounts.RemoteMountsByShareID[shareID]
		if !ok {
			logrus.Error(fail.InconsistentError("failed to find the path on host '%s' where share '%s' is mounted", h.SafeGetName(), shareName).Error())
			continue
		}
		mount, ok := mounts.RemoteMountsByPath[path]
		if !ok {
			logrus.Error(fail.InconsistentError("failed to find a mount associated to share path '%s' for host '%s'", path, h.SafeGetName()).Error())
			continue
		}
		psmd := &protocol.ShareMountDefinition{
			Host:    &protocol.Reference{Name: k},
			Share:   &protocol.Reference{Name: shareName, Id: shareID},
			Path:    mount.Path,
			Type:    mount.FileSystem,
			Options: mount.Options,
		}
		psml.MountList = append(psml.MountList, psmd)
	}

	return psml, nil
}
