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
	"fmt"
	"path"
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	uuid "github.com/gofrs/uuid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/system/nfs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
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
func (si *ShareIdentity) Deserialize(buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr) // json.Unmarshal may panic
	return fail.ConvertError(json.Unmarshal(buf, si))
}

// IsNull ...
// satisfies interface data.Clonable
func (si *ShareIdentity) IsNull() bool {
	return si == nil || (si.HostID == "" && si.ShareID == "")
}

// Clone ...
// satisfies interface data.Clonable
func (si ShareIdentity) Clone() (data.Clonable, error) {
	newShareItem := si
	return &newShareItem, nil
}

// Replace ...
// satisfies interface data.Clonable
// may panic
func (si *ShareIdentity) Replace(p data.Clonable) (data.Clonable, error) {
	if si == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*ShareIdentity)
	if !ok {
		return nil, fmt.Errorf("p is not a *ShareIdentity")
	}

	*si = *src
	return si, nil
}

// Share contains information to maintain in Object Storage a list of shared folders
type Share struct {
	*MetadataCore
}

// NewShare creates an instance of Share
func NewShare(svc iaas.Service) (resources.Share, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, shareKind, sharesFolderName, &ShareIdentity{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
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
func LoadShare(ctx context.Context, svc iaas.Service, ref string, options ...data.ImmutableKeyValue) (_ resources.Share, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	cacheMissLoader := func() (data.Identifiable, fail.Error) { return onShareCacheMiss(ctx, svc, ref) }
	anon, xerr := cacheMissLoader()
	if xerr != nil {
		return nil, xerr
	}

	var ok bool
	var shareInstance resources.Share
	if shareInstance, ok = anon.(resources.Share); !ok {
		return nil, fail.InconsistentError("cache content should be a resources.Share", ref)
	}
	if shareInstance == nil {
		return nil, fail.InconsistentError("nil value found in Share cache for key '%s'", ref)
	}

	return shareInstance, nil
}

// onShareCacheMiss is called when there is no instance in cache of Share 'ref'
func onShareCacheMiss(ctx context.Context, svc iaas.Service, ref string) (data.Identifiable, fail.Error) {
	shareInstance, innerXErr := NewShare(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewShare(svc)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if innerXErr = shareInstance.Read(ctx, ref); innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(shareInstance.Sdump(ctx)).(string), fail.IgnoreError(blank.Sdump(ctx)).(string)) == 0 {
		return nil, fail.NotFoundError("share with ref '%s' does NOT exist", ref)
	}

	return shareInstance, nil
}

// IsNull tells if the instance should be considered as a null value
func (instance *Share) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

func (instance *Share) Exists(ctx context.Context) (bool, fail.Error) {
	// FIXME: There is no InspectShare
	return true, nil
}

// carry creates metadata and add Volume to service cache
func (instance *Share) carry(ctx context.Context, clonable data.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.MetadataCore.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.MetadataCore.Carry(ctx, clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through shares MetadataFolder and executes a callback for each entry
func (instance *Share) Browse(ctx context.Context, callback func(string, string) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: Do not test with Isnull here, as Browse may be used from null value
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
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.MetadataCore.BrowseFolder(ctx, func(buf []byte) fail.Error {
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
	server resources.Host, spath string,
	options string,
	/*securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool,*/
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return fail.InconsistentError("already carrying information")
		}
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
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	targetName := server.GetName()

	var state hoststate.Enum
	state, xerr = server.GetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.InvalidRequestError(fmt.Sprintf("cannot create share on '%s', '%s' is NOT started", targetName, targetName))
	}

	// Check if a Share already exists with the same name
	_, xerr = server.GetShare(ctx, shareName)
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
	sharePath, xerr := sanitize(spath)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- make some validations --
	xerr = server.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Check if the path to Share isn't a remote mount or contains a remote mount
		return props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			serverMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if _, found := serverMountsV1.RemoteMountsByPath[spath]; found {
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
	sshConfig, xerr := server.GetSSHConfig(task.Context())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	nfsServer, xerr := nfs.NewServer(instance.Service(), sshConfig)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Nothing will be changed in instance, but we do not want more than 1 goroutine to install NFS if needed
	xerr = server.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			serverSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(serverSharesV1.ByID) == 0 {
				// Host doesn't have shares yet, so install NFS
				xerr = nfsServer.Install(task.Context())
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
				if v, ok := annotation.(int); ok {
					retcode = v
				}
			}
			var msg string
			if stdout, ok := xerr.Annotation("stdout"); ok {
				if m, ok := stdout.(string); ok {
					msg = m
				}
			} else if stderr, ok := xerr.Annotation("stderr"); ok {
				if m, ok := stderr.(string); ok {
					msg = m
				}
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
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			// Disable abort signal during clean up
			defer task.DisarmAbortSignal()()

			if derr := nfsServer.RemoveShare(context.Background(), sharePath); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove Share '%s' from Host", sharePath))
			}
		}
	}()

	// Updates Host Property propertiesv1.HostShares
	var hostShare *propertiesv1.HostShare
	xerr = server.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := server.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	si := ShareIdentity{
		HostID:    server.GetID(),
		HostName:  server.GetName(),
		ShareID:   hostShare.ID,
		ShareName: hostShare.Name,
	}
	return instance.carry(ctx, &si)
}

// unsafeGetServer returns the Host acting as Share server, with error handling
// Note: do not forget to call .Released() on returned host when you do not use it anymore
func (instance *Share) unsafeGetServer(ctx context.Context) (_ resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var hostID, hostName string
	xerr := instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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

	svc := instance.Service()
	server, xerr := LoadHost(ctx, svc, hostID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		server, xerr = LoadHost(ctx, svc, hostName)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return server, nil
}

// GetServer returns the Host acting as Share server, with error handling
// Note: do not forget to call .Released() on returned host when you do not use it anymore
func (instance *Share) GetServer(ctx context.Context) (_ resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	var hostID, hostName string
	xerr := instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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

	svc := instance.Service()
	server, xerr := LoadHost(ctx, svc, hostID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		server, xerr = LoadHost(ctx, svc, hostName)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return server, nil
}

// Mount mounts a Share on a local directory of a host
// returns a clone of the propertiesv1.HostRemoteMount created on success
func (instance *Share) Mount(ctx context.Context, target resources.Host, spath string, withCache bool) (_ *propertiesv1.HostRemoteMount, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}
	if spath == "" {
		return nil, fail.InvalidParameterError("path", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	var (
		export               string
		targetName, targetID string
		hostShare            *propertiesv1.HostShare
		shareName, shareID   string
	)

	targetName = target.GetName()

	var state hoststate.Enum
	state, xerr = target.GetState(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if state != hoststate.Started {
		return nil, fail.InvalidRequestError(fmt.Sprintf("cannot mount share on '%s', '%s' is NOT started", targetName, targetName))
	}

	// Retrieve info about the Share
	xerr = instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		shareName = si.ShareName
		shareID = si.ShareID
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	rhServer, xerr := instance.unsafeGetServer(task.Context())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// serverID = rhServer.ID()
	// serverName = rhServer.GetName()
	serverPrivateIP, xerr := rhServer.GetPrivateIP(task.Context())
	if xerr != nil {
		return nil, xerr
	}

	xerr = rhServer.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			cloned, cerr := hostSharesV1.ByID[shareID].Clone()
			if cerr != nil {
				return fail.Wrap(cerr)
			}
			hostShare, ok = cloned.(*propertiesv1.HostShare)
			if !ok {
				return fail.InconsistentError("clone should be a *propertiesv1.HostShare")
			}
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
	mountPath, xerr := sanitize(spath)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "invalid mount path '%s'", spath)
	}

	// Lock for read, won't change data other than properties, which are protected by their own way
	targetID = target.GetID()
	xerr = target.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

				if i.Path == spath {
					// cannot mount a Share in place of a volume (by convention, nothing technically preventing it)
					return fail.InvalidRequestError(fmt.Sprintf("there is already a volume in path '%s:%s'", targetName, spath))
				}
			}
			for _, i := range targetMountsV1.RemoteMountsByPath {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if strings.Index(spath, i.Path) == 0 {
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

	targetSSHConfig, xerr := target.GetSSHConfig(task.Context())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// -- Mount the Share on host --
	xerr = rhServer.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found := hostSharesV1.ByID[hostSharesV1.ByName[shareName]]
			if !found {
				return fail.NotFoundError(fmt.Sprintf("failed to find metadata about Share '%s'", shareName))
			}

			ashareID := hostSharesV1.ByName[shareName]

			nfsClient, xerr := nfs.NewNFSClient(targetSSHConfig)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = nfsClient.Install(ctx, instance.Service())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = nfsClient.Mount(ctx, instance.Service(), export, mountPath, withCache)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			hostSharesV1.ByName[shareName] = ashareID
			if hostSharesV1.ByID[ashareID].ClientsByName == nil {
				hostSharesV1.ByID[ashareID].ClientsByName = map[string]string{}
			}
			hostSharesV1.ByID[ashareID].ClientsByName[targetName] = targetID

			if hostSharesV1.ByID[ashareID].ClientsByID == nil {
				hostSharesV1.ByID[ashareID].ClientsByID = map[string]string{}
			}
			hostSharesV1.ByID[ashareID].ClientsByID[targetID] = targetName
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Starting from here, remove Share mount from server Share when exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := rhServer.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to alter metadata trying to delete Share"))
				return
			}

			var nfsClient *nfs.Client
			if nfsClient, derr = nfs.NewNFSClient(targetSSHConfig); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to get nfs client trying to delete Share"))
				return
			}

			derr = nfsClient.Unmount(ctx, instance.Service(), export)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unmount trying to delete Share"))
				return
			}
		}
	}()

	var mount *propertiesv1.HostRemoteMount
	xerr = target.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

	cloned, cerr := mount.Clone()
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	casted, ok := cloned.(*propertiesv1.HostRemoteMount)
	if !ok {
		return nil, fail.InconsistentError("cloned is not a *propertiesv1.HostRemoteMount")
	}

	return casted, nil
}

// Unmount unmounts a Share from local directory of a host
func (instance *Share) Unmount(ctx context.Context, target resources.Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return fail.InvalidParameterCannotBeNilError("target")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	var (
		shareName, shareID string
		// /*serverID,*/ serverName string
		// serverPrivateIP          string
		hostShare *propertiesv1.HostShare
	)

	targetName := target.GetName()

	var state hoststate.Enum
	state, xerr = target.GetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.InvalidRequestError(fmt.Sprintf("cannot unmount share on '%s', '%s' is NOT started", targetName, targetName))
	}

	// Retrieve info about the Share
	xerr = instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		si, ok := clonable.(*ShareIdentity)
		if !ok {
			return fail.InconsistentError("'*shareItem' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		shareName = si.ShareName
		shareID = si.ShareID
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	rhServer, xerr := instance.unsafeGetServer(task.Context())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	serverName := rhServer.GetName()
	serverPrivateIP, xerr := rhServer.GetPrivateIP(task.Context())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = rhServer.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	targetID := target.GetID()
	xerr = target.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
			sshConfig, inErr := target.GetSSHConfig(task.Context())
			if inErr != nil {
				return inErr
			}

			nfsClient, inErr := nfs.NewNFSClient(sshConfig)
			if inErr != nil {
				return inErr
			}

			inErr = nfsClient.Unmount(task.Context(), instance.Service(), serverPrivateIP+":"+hostShare.Path)
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
	xerr = rhServer.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (instance *Share) Delete(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	var (
		shareID, shareName string
		hostShare          *propertiesv1.HostShare
	)

	// -- Retrieve info about the Share --
	// Note: we do not use GetName() and ID() to avoid 2 consecutive instance.Inspect()
	xerr = instance.Review(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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

	objserver, xerr := instance.unsafeGetServer(task.Context())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	targetName := objserver.GetName()

	var state hoststate.Enum
	state, xerr = objserver.GetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.InvalidRequestError(fmt.Sprintf("cannot delete share on '%s', '%s' is NOT started", targetName, targetName))
	}

	xerr = objserver.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if _, ok = hostSharesV1.ByID[shareID]; !ok {
				return fail.NotFoundError("failed to find Share '%s' in Host '%s' metadata", shareName, objserver.GetName())
			}

			cloned, cerr := hostSharesV1.ByID[shareID].Clone()
			if cerr != nil {
				return fail.Wrap(cerr)
			}

			hostShare, ok = cloned.(*propertiesv1.HostShare)
			if !ok {
				return fail.InconsistentError("clone should be a *propertiesv1.HostShare")
			}

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

			sshConfig, xerr := objserver.GetSSHConfig(task.Context())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			nfsServer, xerr := nfs.NewServer(instance.Service(), sshConfig)
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

	defer task.DisarmAbortSignal()()

	// Remove Share metadata
	return instance.MetadataCore.Delete(ctx)
}

func sanitize(in string) (string, fail.Error) {
	sanitized := path.Clean(in)
	if !path.IsAbs(sanitized) {
		return "", fail.InvalidParameterError("in", "must be a string containing an absolute path")
	}

	return sanitized, nil
}

// ToProtocol transforms a Share into its protobuf representation
func (instance *Share) ToProtocol(ctx context.Context) (_ *protocol.ShareMountList, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	shareID := instance.GetID()
	shareName := instance.GetName()
	server, xerr := instance.unsafeGetServer(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	share, xerr := server.GetShare(ctx, shareID)
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
	svc := instance.Service()
	for k := range share.ClientsByName {
		h, xerr := LoadHost(ctx, svc, k)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.Errorf(xerr.Error())
			continue
		}

		mounts, xerr := h.GetMounts(ctx)
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
