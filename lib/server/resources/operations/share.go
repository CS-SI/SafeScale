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
	"golang.org/x/net/context"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

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

// ShareIdentity contains information about a Share
type ShareIdentity struct {
	HostID    string `json:"host_id"`    // contains the ID of the host serving the Share
	HostName  string `json:"host_name"`  // contains the name of the host serving the Share
	ShareID   string `json:"share_id"`   // contains the ID of the Share
	ShareName string `json:"share_name"` // contains the name of the Share
}

// GetID returns the ID of the Share
// satisfies interface data.Identifiable
func (si ShareIdentity) GetID() string {
	return si.ShareID
}

// GetName returns the name of the Share
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
	// Do not test with isNull(), it's allowed to clone a null value...
	if si == nil || src == nil {
		return si
	}

	srcSi := src.(*ShareIdentity)
	*si = *srcSi
	return si
}

// Share contains information to maintain in Object Storage a list of shared folders
type Share struct {
	*MetadataCore

	lock sync.RWMutex
}

// ShareNullValue returns a *Share representing a null value
func ShareNullValue() *Share {
	return &Share{MetadataCore: NullCore()}
}

// NewShare creates an instance of Share
func NewShare(svc iaas.Service) (resources.Share, fail.Error) {
	if svc == nil {
		return ShareNullValue(), fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, shareKind, sharesFolderName, &ShareIdentity{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return ShareNullValue(), xerr
	}

	instance := &Share{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// LoadShare returns the name of the host owing the Share 'ref', read from Object Storage
// logic: try to read until success.
//        If error is fail.ErrNotFound return this error
//        In case of any other error, abort the retry to propagate the error
//        If retry times out, return fail.ErrTimeout
func LoadShare(svc iaas.Service, ref string) (rs resources.Share, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return ShareNullValue(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref == "" {
		return ShareNullValue(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	shareCache, xerr := svc.GetCache(shareKind)
	xerr = debug.InjectPlannedFail(xerr)
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
			if innerXErr = rs.Read(ref); innerXErr != nil {
				return nil, innerXErr
			}

			return rs, nil
		}),
	}
	cacheEntry, xerr := shareCache.Get(ref, options...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return ShareNullValue(), fail.NotFoundError("failed to find a Share '%s'", ref)
		default:
			return ShareNullValue(), xerr
		}
	}

	if rs = cacheEntry.Content().(resources.Share); rs == nil {
		return ShareNullValue(), fail.InconsistentError("nil value found in Share cache for key '%s'", ref)
	}
	_ = cacheEntry.LockContent()
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			_ = cacheEntry.UnlockContent()
		}
	}()

	return rs, nil
}

// IsNull tells if the instance should be considered as a null value
func (instance *Share) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || instance.MetadataCore.IsNull()
}

// carry creates metadata and add Volume to service cache
func (instance *Share) carry(clonable data.Clonable) (xerr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.MetadataCore.GetKind())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = kindCache.ReserveEntry(identifiable.GetID())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.MetadataCore.GetKind(), identifiable.GetID()))
			}

		}
	}()

	// Note: do not validate parameters, this call will do it
	xerr = instance.MetadataCore.Carry(clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(identifiable.GetID(), instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()

	return nil
}

// Browse walks through shares MetadataFolder and executes a callback for each entry
func (instance *Share) Browse(ctx context.Context, callback func(string, string) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value, so do not validate instance with .IsNull()
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.MetadataCore.BrowseFolder(func(buf []byte) fail.Error {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		si := &ShareIdentity{}
		xerr = si.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		return callback(si.HostName, si.ShareID)
	})
}

// Create creates a Share on host
func (instance *Share) Create(
	ctx context.Context,
	shareName string,
	server resources.Host, path string,
	options string,
	/*securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool,*/
) (xerr fail.Error) {

	defer fail.OnPanic(&xerr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		shareName := instance.GetName()
		if shareName != "" {
			return fail.NotAvailableError("already carrying Share '%s'", shareName)
		}
		return fail.InvalidInstanceContentError("instance", "is not null value")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if shareName == "" {
		return fail.InvalidParameterError("shareName", "cannot be empty string")
	}
	if server == nil {
		return fail.InvalidParameterCannotBeNilError("server")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if a Share already exists with the same name
	_, xerr = server.GetShare(shareName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	// Sanitize path
	sharePath, xerr := sanitize(path)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- make some validations --
	xerr = server.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Check if the path to Share isn't a remote mount or contains a remote mount
		return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			serverMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if _, found := serverMountsV1.RemoteMountsByPath[path]; found {
				return fail.InvalidRequestError(fmt.Sprintf("path to export '%s' is a mounted Share", sharePath))
			}

			for k := range serverMountsV1.RemoteMountsByPath {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if strings.Index(sharePath, k) == 0 {
					return fail.InvalidRequestError("export path '%s' contains a Share mounted in '%s'", sharePath, k)
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Installs NFS getServer software if needed
	sshConfig, xerr := server.GetSSHConfig()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	nfsServer, xerr := nfs.NewServer(sshConfig)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Nothing will be changed in instance, but we do not want more than 1 goroutine to install NFS if needed
	xerr = server.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(serverSharesV1.ByID) == 0 {
				// Host doesn't have shares yet, so install NFS
				xerr = nfsServer.Install(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}
			// using fail.AlteredNothingError(), this will not cost a metadata update
			return fail.AlteredNothingError()
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			// continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	xerr = nfsServer.AddShare(ctx, sharePath, options)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
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

	// Starting from here, remove Share from host if exiting with error
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := nfsServer.RemoveShare(ctx, sharePath); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove Share '%s' from Host", sharePath))
			}
		}
	}()

	// Updates Host Property propertiesv1.HostShares
	var hostShare *propertiesv1.HostShare
	xerr = server.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hostShare = propertiesv1.NewHostShare()
			hostShare.Name = shareName
			shareID, err := uuid.NewV4()
			err = debug.InjectPlannedError(err)
			if err != nil {
				return fail.Wrap(err, "Error creating UUID for Share")
			}

			hostShare.ID = shareID.String()
			hostShare.Path = sharePath
			hostShare.Type = "nfs"

			serverSharesV1.ByID[hostShare.ID] = hostShare
			serverSharesV1.ByName[hostShare.Name] = hostShare.ID
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, delete Share reference in server if exiting with error
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			derr := server.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
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
	return instance.carry(&si)
}

// GetServer returns the Host acting as Share server, with error handling
// Note: do not forget to call .Released() on returned host when you do not use it anymore
func (instance *Share) GetServer() (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var hostID, hostName string
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		share, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		hostID = share.HostID
		hostName = share.HostName
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	svc := instance.GetService()
	server, xerr := LoadHost(svc, hostID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		server, xerr = LoadHost(svc, hostName)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return server, nil
}

// Mount mounts a Share on a local directory of an host
// returns a clone of the propertiesv1.HostRemoteMount created on success
func (instance *Share) Mount(ctx context.Context, target resources.Host, path string, withCache bool) (_ *propertiesv1.HostRemoteMount, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}
	if path == "" {
		return nil, fail.InvalidParameterError("path", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return nil, xerr
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

	// Retrieve info about the Share
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		shareName = si.ShareName
		shareID = si.ShareID
		return nil
	})

	rhServer, xerr := instance.GetServer()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// serverID = rhServer.ID()
	// serverName = rhServer.GetName()
	serverPrivateIP, xerr := rhServer.GetPrivateIP()
	if xerr != nil {
		return nil, xerr
	}

	xerr = rhServer.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hostShare = hostSharesV1.ByID[shareID].Clone().(*propertiesv1.HostShare)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Sanitize path
	mountPath, xerr := sanitize(path)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "invalid mount path '%s'", path)
	}

	// Lock for read, won't change data other than properties, which are protected by their own way
	targetID = target.GetID()
	targetName = target.GetName()
	xerr = target.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Check if Share is already mounted
		// Check if there is already volume mounted in the path (or in subpath)
		innerXErr := props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
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
					// cannot mount a Share in place of a volume (by convention, nothing technically preventing it)
					return fail.InvalidRequestError(fmt.Sprintf("there is already a volume in path '%s:%s'", targetName, path))
				}
			}
			for _, i := range targetMountsV1.RemoteMountsByPath {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if strings.Index(path, i.Path) == 0 {
					// cannot mount a Share inside another Share (at least by convention, if not technically)
					return fail.InvalidRequestError("there is already a Share mounted in '%s:%s'", targetName, i.Path)
				}
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		export = serverPrivateIP + ":" + hostShare.Path
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	targetSSHConfig, xerr := target.GetSSHConfig()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// -- Mount the Share on host --
	xerr = rhServer.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found := hostSharesV1.ByID[hostSharesV1.ByName[shareName]]
			if !found {
				return fail.NotFoundError(fmt.Sprintf("failed to find metadata about Share '%s'", shareName))
			}

			shareID := hostSharesV1.ByName[shareName]

			nfsClient, xerr := nfs.NewNFSClient(targetSSHConfig)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = nfsClient.Install(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = nfsClient.Mount(ctx, export, mountPath, withCache)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Starting from here, remove Share mount from server Share when exiting with error
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			derr := rhServer.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
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
					derr = nfsClient.Unmount(ctx, export)
				}
			}
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Share"))
			}
		}
	}()

	var mount *propertiesv1.HostRemoteMount
	xerr = target.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return mount.Clone().(*propertiesv1.HostRemoteMount), nil
}

// Unmount unmounts a Share from local directory of an host
func (instance *Share) Unmount(ctx context.Context, target resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return fail.InvalidParameterCannotBeNilError("target")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
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

	// Retrieve info about the Share
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		shareName = si.ShareName
		shareID = si.ShareID
		return nil
	})

	rhServer, xerr := instance.GetServer()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	serverName := rhServer.GetName()
	serverPrivateIP, xerr := rhServer.GetPrivateIP()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = rhServer.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var mountPath string
	remotePath := serverPrivateIP + ":" + hostShare.Path
	targetName := target.GetName()
	targetID := target.GetID()
	xerr = target.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			targetMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			mount, found := targetMountsV1.RemoteMountsByPath[targetMountsV1.RemoteMountsByShareID[shareID]]
			if !found {
				return fail.NotFoundError("not mounted on host '%s'", targetName)
			}

			// Unmount Share from client
			sshConfig, inErr := target.GetSSHConfig()
			if inErr != nil {
				return inErr
			}

			nfsClient, inErr := nfs.NewNFSClient(sshConfig)
			if inErr != nil {
				return inErr
			}

			inErr = nfsClient.Unmount(ctx, serverPrivateIP+":"+hostShare.Path)
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Remove host from client lists of the Share
	xerr = rhServer.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(hostSharesV1.ByID[shareID].ClientsByName, targetName)
			delete(hostSharesV1.ByID[shareID].ClientsByID, targetID)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Delete deletes a Share from server
func (instance *Share) Delete(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
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

	// -- Retrieve info about the Share --
	// Note: we do not use GetName() and ID() to avoid 2 consecutive instance.Inspect()
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		shareID = si.ShareID
		shareName = si.ShareName
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	objserver, xerr := instance.GetServer()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = objserver.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
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

			sshConfig, xerr := objserver.GetSSHConfig()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			nfsServer, xerr := nfs.NewServer(sshConfig)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			defer task.DisarmAbortSignal()()

			xerr = nfsServer.RemoveShare(ctx, hostShare.Path)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			delete(hostSharesV1.ByID, shareID)
			delete(hostSharesV1.ByName, shareName)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// FIXME: we should have a defer statement to restore Share in case of failure...

	defer task.DisarmAbortSignal()()

	// Remove Share metadata
	return instance.MetadataCore.Delete()
}

func sanitize(in string) (string, fail.Error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fail.InvalidParameterError("in", "must be a string containing an absolute path")
	}

	return sanitized, nil
}

func (instance *Share) ToProtocol() (_ *protocol.ShareMountList, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	shareID := instance.GetID()
	shareName := instance.GetName()
	server, xerr := instance.GetServer()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	share, xerr := server.GetShare(shareID)
	xerr = debug.InjectPlannedFail(xerr)
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
			// SecurityModes: Share.ShareAcls,
		},
	}
	for k := range share.ClientsByName {
		h, xerr := LoadHost(instance.GetService(), k)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.Errorf(xerr.Error())
			continue
		}
		//goland:noinspection ALL
		defer func(hostInstance resources.Host) {
			hostInstance.Released()
		}(h)

		mounts, xerr := h.GetMounts()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.Errorf(xerr.Error())
			continue
		}
		sharePath, ok := mounts.RemoteMountsByShareID[shareID]
		if !ok {
			logrus.Error(fail.InconsistentError("failed to find the sharePath on host '%s' where Share '%s' is mounted", h.GetName(), shareName).Error())
			continue
		}
		mount, ok := mounts.RemoteMountsByPath[sharePath]
		if !ok {
			logrus.Error(fail.InconsistentError("failed to find a mount associated to Share path '%s' for host '%s'", sharePath, h.GetName()).Error())
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
