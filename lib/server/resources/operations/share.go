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
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"strings"
	"sync"

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
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

const (
	shareKind = "share"
	// nasFolderName is the technical name of the container used to store nas info
	sharesFolderName = "shares"
)

// ShareIdentity contains information about a share
type ShareIdentity struct {
	HostID    string `json:"host_id"`    // contains the ID of the host serving the share
	HostName  string `json:"host_name"`  // contains the name of the host serving the share
	ShareID   string `json:"share_id"`   // contains the ID of the share
	ShareName string `json:"share_name"` // contains the name of the share
}

// GetID returns the ID of the share
// satisfies interface data.Identifiable
func (si ShareIdentity) GetID() string {
	return si.ShareID
}

// GetName returns the name of the share
// satisfies interface data.Identifiable
func (si ShareIdentity) GetName() string {
	return si.ShareName
}

// Serialize ...
// satisfies interface data.Serializable
func (si ShareIdentity) Serialize() ([]byte, fail.Error) {
	r, err := json.Marshal(&si)
	return r, fail.ConvertError(err)
}

// Deserialize ...
// satisfies interface data.Serializable
func (si *ShareIdentity) Deserialize(buf []byte) (xerr fail.Error) {
	defer fail.OnPanic(&xerr) // json.Unmarshal may panic
	return fail.ConvertError(json.Unmarshal(buf, si))
}

// Clone ...
// satisfies interface data.Clonable
func (si ShareIdentity) Clone() data.Clonable {
	newShareItem := si
	return &newShareItem
}

// Replace ...
// satisfies interface data.Clonable
func (si *ShareIdentity) Replace(src data.Clonable) data.Clonable {
	// Do not test with IsNull(), it's allowed to clone a null value...
	if si == nil || src == nil {
		return si
	}

	srcSi := src.(*ShareIdentity)
	*si = *srcSi
	return si
}

// share contains information to maintain in Object Storage a list of shared folders
type share struct {
	*core

	lock sync.RWMutex
}

func nullShare() *share {
	return &share{core: nullCore()}
}

// NewShare creates an instance of Share
func NewShare(svc iaas.Service) (resources.Share, fail.Error) {
	if svc == nil {
		return nullShare(), fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := newCore(svc, shareKind, sharesFolderName, &ShareIdentity{})
	if xerr != nil {
		return nullShare(), xerr
	}

	instance := &share{
		core: coreInstance,
	}
	return instance, nil
}

// LoadShare returns the name of the host owing the share 'ref', read from Object Storage
// logic: try to read until success.
//        If error is fail.ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return fail.ErrTimeout
func LoadShare(task concurrency.Task, svc iaas.Service, ref string) (rs resources.Share, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task == nil {
		return nullShare(), fail.InvalidParameterCannotBeNilError("task")
	}
	if svc == nil {
		return nullShare(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref == "" {
		return nullShare(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	if task.Aborted() {
		return nullShare(), fail.AbortedError(nil, "aborted")
	}

	shareCache, xerr := svc.GetCache(shareKind)
	if xerr != nil {
		return nil, xerr
	}

	options := []data.ImmutableKeyValue{
		data.NewImmutableKeyValue("onMiss", func() (cache.Cacheable, fail.Error) {
			rs, innerXErr := NewShare(svc)
			if innerXErr != nil {
				return nil, innerXErr
			}

			// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
			if innerXErr = rs.Read(task, ref); innerXErr != nil {
				return nil, innerXErr
			}

			return rs, nil
		}),
	}
	cacheEntry, xerr := shareCache.Get(task, ref, options...)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nullShare(), fail.NotFoundError("failed to find a Share '%s'", ref)
		default:
			return nullShare(), xerr
		}
	}

	if rs = cacheEntry.Content().(resources.Share); rs == nil {
		return nullShare(), fail.InconsistentError("nil value found in Share cache for key '%s'", ref)
	}
	_ = cacheEntry.LockContent()
	defer func() {
		if xerr != nil {
			_ = cacheEntry.UnlockContent()
		}
	}()

	return rs, nil
}

// isNull tells if the instance should be considered as a null value
func (instance *share) isNull() bool {
	return instance == nil || instance.core.isNull()
}

// Carry overloads rv.core.Carry() to add Volume to service cache
func (instance *share) carry(task concurrency.Task, clonable data.Clonable) (xerr fail.Error) {
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.core.kind)
	if xerr != nil {
		return xerr
	}

	if xerr := kindCache.ReserveEntry(task, identifiable.GetID()); xerr != nil {
		return xerr
	}
	defer func() {
		if xerr != nil {
			if derr := kindCache.FreeEntry(task, identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.core.kind, identifiable.GetID()))
			}

		}
	}()

	// Note: do not validate parameters, this call will do it
	if xerr := instance.core.Carry(task, clonable); xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(task, identifiable.GetID(), instance)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()

	return nil
}

// Browse walks through shares folder and executes a callback for each entry
func (instance *share) Browse(task concurrency.Task, callback func(string, string) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value, so do not validate instance
	// if instance.isNull() {
	// 	return fail.InvalidInstanceError()
	// }
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.core.BrowseFolder(task, func(buf []byte) fail.Error {
		si := &ShareIdentity{}
		if xerr := si.Deserialize(buf); xerr != nil {
			return xerr
		}

		return callback(si.HostName, si.ShareID)
	})
}

// Create creates a share on host
func (instance *share) Create(
	task concurrency.Task,
	shareName string,
	server resources.Host, path string,
	options string,
	/*securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool,*/
) (xerr fail.Error) {

	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if shareName == "" {
		return fail.InvalidParameterError("shareName", "cannot be empty string")
	}
	if server == nil {
		return fail.InvalidParameterCannotBeNilError("server")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if a share already exists with the same name
	if _, xerr = server.GetShare(task, shareName); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
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
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

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

	// Installs NFS getServer software if needed
	sshConfig, xerr := server.GetSSHConfig(task)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	nfsServer, xerr := nfs.NewServer(sshConfig)
	if xerr != nil {
		return xerr
	}

	// Nothing will be changed in instance, but we do not want more than 1 goroutine to install NFS if needed
	xerr = server.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if len(serverSharesV1.ByID) == 0 {
				// IPAddress doesn't have shares yet, so install NFS
				if xerr = nfsServer.Install(task); xerr != nil {
					return xerr
				}
			}
			// using fail.AlteredNothingError(), this will not cost a metadata update
			return fail.AlteredNothingError()
		})
	})
	if xerr != nil {
		return xerr
	}

	if xerr = nfsServer.AddShare(task, sharePath, options); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrExecution:
			var retcode int
			if annotation, ok := xerr.Annotation("retcode"); ok {
				retcode = annotation.(int)
			}
			var msg string
			if stdout, ok := xerr.Annotation("stdout"); ok {
				msg = stdout.(string)
			} else if stderr, ok := xerr.Annotation("stderr"); ok {
				msg = stderr.(string)
			}

			switch retcode {
			case 192: // export with exact same parameters already exist
				return fail.DuplicateError(msg)
			default:
				return xerr
			}
		default:
			return xerr
		}
	}

	// Starting from here, remove share from host if exiting with error
	defer func() {
		if xerr != nil {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := nfsServer.RemoveShare(task, sharePath); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove share '%s' from Host", sharePath))
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

			hostShare = propertiesv1.NewHostShare()
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
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

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
				logrus.Errorf("After failure, cleanup failed to update metadata of host '%s'", server.GetName())
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	si := ShareIdentity{
		HostID:    server.GetID(),
		HostName:  server.GetName(),
		ShareID:   hostShare.ID,
		ShareName: hostShare.Name,
	}
	return instance.carry(task, &si)
}

// GetServer returns the Host acting as share server, with error handling
// Note: do not forget to call .Released() on returned host when you do not use it anymore
func (instance *share) GetServer(task concurrency.Task) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be il")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var hostID, hostName string
	xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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

	svc := instance.GetService()
	server, xerr := LoadHost(task, svc, hostID)
	if xerr != nil {
		server, xerr = LoadHost(task, svc, hostName)
	}
	if xerr != nil {
		return nil, xerr
	}

	return server, nil
}

// Mount mounts a share on a local directory of an host
// returns a clone of the propertiesv1.HostRemoteMount created on success
func (instance *share) Mount(task concurrency.Task, target resources.Host, path string, withCache bool) (_ *propertiesv1.HostRemoteMount, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}
	if path == "" {
		return nil, fail.InvalidParameterError("path", "cannot be empty string")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	var (
		export               string
		targetName, targetID string
		hostShare            *propertiesv1.HostShare
		shareName, shareID   string
	)

	// Retrieve info about the share
	xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		shareName = si.ShareName
		shareID = si.ShareID
		return nil
	})

	rhServer, xerr := instance.GetServer(task)
	if xerr != nil {
		return nil, xerr
	}

	// serverID = rhServer.GetID()
	// serverName = rhServer.GetName()
	serverPrivateIP := rhServer.(*host).privateIP
	//serverAccessIP := rhServer.(*host).unsafeGetAccessIP(task)

	xerr = rhServer.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hostShare = hostSharesV1.ByID[shareID].Clone().(*propertiesv1.HostShare)
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Sanitize path
	mountPath, xerr := sanitize(path)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "invalid mount path '%s'", path)
	}

	// Lock for read, won't change data other than properties, which are protected by their own way
	targetID = target.GetID()
	targetName = target.GetName()
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
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if i.Path == path {
					// cannot mount a share in place of a volume (by convention, nothing technically preventing it)
					return fail.InvalidRequestError(fmt.Sprintf("there is already a volume in path '%s:%s'", targetName, path))
				}
			}
			for _, i := range targetMountsV1.RemoteMountsByPath {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

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

		// VPL: why this ?
		//return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
		//	hostNetworkV2, ok := clonable.(*propertiesv2.HostNetwork)
		//	if !ok {
		//		return fail.InconsistentError("'*propertiesv2.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
		//	}
		//	if hostNetworkV2.DefaultGatewayPrivateIP == serverPrivateIP {
		//		export = serverPrivateIP + ":" + hostShare.Path
		//	} else {
		//		export = serverAccessIP + ":" + hostShare.Path
		//	}
		//	return nil
		//})

		export = serverPrivateIP + ":" + hostShare.Path
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	targetSSHConfig, xerr := target.GetSSHConfig(task)
	if xerr != nil {
		return nil, xerr
	}

	// -- Mount the share on host --
	xerr = rhServer.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found := hostSharesV1.ByID[hostSharesV1.ByName[shareName]]
			if !found {
				return fail.NotFoundError(fmt.Sprintf("failed to find metadata about share '%s'", shareName))
			}

			shareID := hostSharesV1.ByName[shareName]

			nfsClient, xerr := nfs.NewNFSClient(targetSSHConfig)
			if xerr != nil {
				return xerr
			}

			if xerr = nfsClient.Install(task); xerr != nil {
				return xerr
			}

			if xerr = nfsClient.Mount(task, export, mountPath, withCache); xerr != nil {
				return xerr
			}

			hostSharesV1.ByName[shareName] = shareID
			if hostSharesV1.ByID[shareID].ClientsByName == nil {
				hostSharesV1.ByID[shareID].ClientsByName = map[string]string{}
			}
			hostSharesV1.ByID[shareID].ClientsByName[targetName] = targetID

			if hostSharesV1.ByID[shareID].ClientsByID == nil {
				hostSharesV1.ByID[shareID].ClientsByID = map[string]string{}
			}
			hostSharesV1.ByID[shareID].ClientsByID[targetID] = targetName
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	// Starting from here, remove share mount from server share when exiting with error
	defer func() {
		if xerr != nil {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			derr := rhServer.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
					hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					delete(hostSharesV1.ByID[shareID].ClientsByName, targetName)
					delete(hostSharesV1.ByID[shareID].ClientsByID, targetID)
					return nil
				})
			})
			if derr == nil {
				var nfsClient *nfs.Client
				if nfsClient, derr = nfs.NewNFSClient(targetSSHConfig); derr == nil {
					derr = nfsClient.Unmount(task, export)
				}
			}
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Share"))
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

			mount = propertiesv1.NewHostRemoteMount()
			mount.ShareID = hostShare.ID
			mount.Export = export
			mount.Path = mountPath
			mount.FileSystem = "nfs"

			if targetMountsV1.RemoteMountsByPath == nil {
				targetMountsV1.RemoteMountsByPath = map[string]*propertiesv1.HostRemoteMount{}
			}
			targetMountsV1.RemoteMountsByPath[mount.Path] = mount
			if targetMountsV1.RemoteMountsByShareID == nil {
				targetMountsV1.RemoteMountsByShareID = map[string]string{}
			}
			targetMountsV1.RemoteMountsByShareID[mount.ShareID] = mount.Path
			if targetMountsV1.RemoteMountsByExport == nil {
				targetMountsV1.RemoteMountsByExport = map[string]string{}
			}
			targetMountsV1.RemoteMountsByExport[mount.Export] = mount.Path
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	return mount.Clone().(*propertiesv1.HostRemoteMount), nil
}

// Unmount unmounts a share from local directory of an host
func (instance *share) Unmount(task concurrency.Task, target resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if target == nil {
		return fail.InvalidParameterCannotBeNilError("target")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	var (
		shareName, shareID string
		// /*serverID,*/ serverName string
		// serverPrivateIP          string
		hostShare *propertiesv1.HostShare
	)

	// Retrieve info about the share
	xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		shareName = si.ShareName
		shareID = si.ShareID
		return nil
	})

	rhServer, xerr := instance.GetServer(task)
	if xerr != nil {
		return xerr
	}

	serverName := rhServer.GetName()
	serverPrivateIP, xerr := rhServer.GetPrivateIP(task)
	if xerr != nil {
		return xerr
	}

	xerr = rhServer.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			rhServer, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HotShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var found bool
			if hostShare, found = rhServer.ByID[shareID]; !found {
				return fail.NotFoundError("failed to find Share '%s' in Host '%s' metadata", shareName, serverName)
			}

			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	var mountPath string
	remotePath := serverPrivateIP + ":" + hostShare.Path
	targetName := target.GetName()
	targetID := target.GetID()
	xerr = target.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

			inErr = nfsClient.Unmount(task, serverPrivateIP+":"+hostShare.Path)
			if inErr != nil {
				return inErr
			}

			// Remove mount from mount list
			mountPath = mount.Path
			delete(targetMountsV1.RemoteMountsByShareID, mount.ShareID)
			delete(targetMountsV1.RemoteMountsByPath, mountPath)
			delete(targetMountsV1.RemoteMountsByExport, remotePath)
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// Remove host from client lists of the share
	xerr = rhServer.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(hostSharesV1.ByID[shareID].ClientsByName, targetName)
			delete(hostSharesV1.ByID[shareID].ClientsByID, targetID)
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	return nil
}

// Delete deletes a share from server
func (instance *share) Delete(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	var (
		shareID, shareName string
		hostShare          *propertiesv1.HostShare
	)

	// -- Retrieve info about the share --
	// Note: we do not use GetName() and GetID() to avoid 2 consecutive instance.Inspect()
	xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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

	objserver, xerr := instance.GetServer(task)
	if xerr != nil {
		return xerr
	}

	xerr = objserver.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if _, ok := hostSharesV1.ByID[shareID]; !ok {
				return fail.NotFoundError("failed to find Share '%s' in Host '%s' metadata", shareName, objserver.GetName())
			}

			hostShare = hostSharesV1.ByID[shareID].Clone().(*propertiesv1.HostShare)

			if len(hostShare.ClientsByName) > 0 {
				var list []string
				for k := range hostShare.ClientsByName {
					if task.Aborted() {
						return fail.AbortedError(nil, "aborted")
					}

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

			defer task.DisarmAbortSignal()()

			if xerr = nfsServer.RemoveShare(task, hostShare.Path); xerr != nil {
				return xerr
			}

			delete(hostSharesV1.ByID, shareID)
			delete(hostSharesV1.ByName, shareName)
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// FIXME: we should have a defer statement to restore share in case of failure...

	defer task.DisarmAbortSignal()()

	// Remove share metadata
	return instance.core.Delete(task)
}

func sanitize(in string) (string, fail.Error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fail.InvalidParameterError("in", "must be a string containing an absolute path")
	}

	return sanitized, nil
}

func (instance *share) ToProtocol(task concurrency.Task) (_ *protocol.ShareMountList, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	shareID := instance.GetID()
	shareName := instance.GetName()
	server, xerr := instance.GetServer(task)
	if xerr != nil {
		return nil, xerr
	}

	share, xerr := server.GetShare(task, shareID)
	if xerr != nil {
		return nil, xerr
	}

	psml := &protocol.ShareMountList{
		Share: &protocol.ShareDefinition{
			Id:              shareID,
			Name:            shareName,
			Host:            &protocol.Reference{Name: server.GetName()},
			Path:            share.Path,
			Type:            share.Type,
			OptionsAsString: share.ShareOptions,
			// SecurityModes: share.ShareAcls,
		},
	}
	for k := range share.ClientsByName {
		h, xerr := LoadHost(task, instance.GetService(), k)
		if xerr != nil {
			logrus.Errorf(xerr.Error())
			continue
		}
		defer func(hostInstance resources.Host) {
			hostInstance.Released(task)
		}(h)

		mounts, xerr := h.GetMounts(task)
		if xerr != nil {
			logrus.Errorf(xerr.Error())
			continue
		}
		sharePath, ok := mounts.RemoteMountsByShareID[shareID]
		if !ok {
			logrus.Error(fail.InconsistentError("failed to find the sharePath on host '%s' where share '%s' is mounted", h.GetName(), shareName).Error())
			continue
		}
		mount, ok := mounts.RemoteMountsByPath[sharePath]
		if !ok {
			logrus.Error(fail.InconsistentError("failed to find a mount associated to share path '%s' for host '%s'", sharePath, h.GetName()).Error())
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
