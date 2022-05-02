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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/observer"
	serializer "github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/shielded"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	// byIDFolderName tells in what MetadataFolder to put 'byID' information
	byIDFolderName = "byID"
	// byNameFolderName tells in what MetadataFolder to store 'byName' information
	byNameFolderName = "byName"

	NullMetadataKind = "nil"
)

// MetadataCore contains the core functions of a persistent object
type MetadataCore struct {
	id    atomic.Value
	name  atomic.Value
	taken atomic.Value

	shielded   *shielded.Shielded
	properties *serializer.JSONProperties
	observers  map[string]observer.Observer
	sync.RWMutex

	kind              string
	folder            MetadataFolder
	loaded            bool
	committed         bool
	kindSplittedStore bool // tells if data read/write is done directly from/to folder (when false) or from/to subfolders (when true)
}

// NewCore creates an instance of MetadataCore
func NewCore(svc iaas.Service, kind string, path string, instance data.Clonable) (_ *MetadataCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if kind == "" {
		return nil, fail.InvalidParameterError("kind", "cannot be empty string")
	}
	if path == "" {
		return nil, fail.InvalidParameterError("path", "cannot be empty string")
	}

	fld, xerr := NewMetadataFolder(svc, path)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	props, err := serializer.NewJSONProperties("resources." + kind)
	err = debug.InjectPlannedFail(err)
	if err != nil {
		return nil, err
	}

	protected, cerr := shielded.NewShielded(instance)
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	c := MetadataCore{
		kind:       kind,
		folder:     fld,
		properties: props,
		shielded:   protected,
		observers:  map[string]observer.Observer{},
	}
	switch kind {
	case clusterKind:
		c.kindSplittedStore = false
	default:
		c.kindSplittedStore = true
	}
	c.taken.Store(false)

	return &c, nil
}

// IsNull returns true if the MetadataCore instance represents the null value for MetadataCore
func (myself *MetadataCore) IsNull() bool {
	return myself == nil || myself.kind == "" || myself.kind == NullMetadataKind
}

// Service returns the iaas.Service used to create/load the persistent object
func (myself *MetadataCore) Service() iaas.Service {
	return myself.folder.Service()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (myself *MetadataCore) GetID() string {
	return myself.getID()
}

func (myself *MetadataCore) getID() string {
	id := myself.id.Load().(string) // nolint, better panic than error-hiding
	return id
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (myself *MetadataCore) GetName() string {
	return myself.getName()
}

func (myself *MetadataCore) getName() string {
	name := myself.name.Load().(string) // nolint, better panic than error-hiding
	return name
}

func (myself *MetadataCore) IsTaken() bool {
	taken, ok := myself.taken.Load().(bool)
	if !ok {
		return false
	}
	return taken
}

// GetKind returns the kind of object served
func (myself *MetadataCore) GetKind() string {
	return myself.kind
}

// Inspect protects the data for shared read
func (myself *MetadataCore) Inspect(callback resources.Callback) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if myself.properties == nil {
		return fail.InvalidInstanceContentError("myself.properties", "cannot be nil")
	}

	timings, xerr := myself.Service().Timings()
	if xerr != nil {
		return xerr
	}

	// Reload reloads data from Object Storage to be sure to have the last revision
	xerr = retry.WhileUnsuccessfulWithLimitedRetries(func() error {
		myself.Lock()
		xerr = myself.unsafeReload()
		myself.Unlock() // nolint
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to unsafeReload metadata")
		}
		return nil
	},
		timings.SmallDelay(),
		timings.ContextTimeout(),
		6)
	if xerr != nil {
		return fail.ConvertError(xerr.Cause())
	}

	myself.RLock()
	defer myself.RUnlock()

	xerr = retry.WhileUnsuccessfulWithLimitedRetries(func() error {
		return myself.shielded.Inspect(func(clonable data.Clonable) fail.Error {
			return callback(clonable, myself.properties)
		})
	},
		timings.SmallDelay(),
		timings.ConnectionTimeout(),
		6)
	if xerr != nil {
		return fail.ConvertError(xerr.Cause())
	}
	return nil
}

// Review allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// change through time).
func (myself *MetadataCore) Review(callback resources.Callback) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if myself.properties == nil {
		return fail.InvalidInstanceContentError("myself.properties", "cannot be nil")
	}

	myself.RLock()
	defer myself.RUnlock()

	return myself.shielded.Inspect(func(clonable data.Clonable) fail.Error {
		return callback(clonable, myself.properties)
	})
}

// Alter protects the data for exclusive write
// Valid keyvalues for options are :
// - "Reload": bool = allow disabling reloading from Object Storage if set to false (default is true)
func (myself *MetadataCore) Alter(ctx context.Context, callback resources.Callback, options ...data.ImmutableKeyValue) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if myself.shielded == nil {
		return fail.InvalidInstanceContentError("myself.shielded", "cannot be nil")
	}

	myself.Lock()
	defer myself.Unlock()

	if myself.getName() == "" || myself.getID() == "" {
		return fail.InconsistentError("uninitalized metadata should not be altered")
	}

	// Make sure myself.properties is populated
	if myself.properties == nil {
		myself.properties, xerr = serializer.NewJSONProperties("resources." + myself.kind)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	doReload := true
	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() {
			case "Reload":
				if bv, ok := v.Value().(bool); ok {
					doReload = bv
				}
			default:
			}
		}
	}
	// Reload reloads data from object storage to be sure to have the last revision
	if doReload {
		xerr = myself.unsafeReload()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to unsafeReload metadata")
		}
	}

	xerr = myself.shielded.Alter(func(clonable data.Clonable) fail.Error {
		return callback(clonable, myself.properties)
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			return nil
		default:
			return xerr
		}
	}

	myself.committed = false

	xerr = myself.write()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// notify observers there has been changed in the instance
	return fail.ConvertError(myself.unsafeNotifyObservers())
}

// Carry links metadata with real data
// If c is already carrying a shielded data, returns fail.NotAvailableError
//
// errors returned :
// - fail.ErrInvalidInstance
// - fail.ErrInvalidParameter
// - fail.ErrNotAvailable if the MetadataCore instance already carries a data
func (myself *MetadataCore) Carry(clonable data.Clonable) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	// Note: do not test with IsNull() here, it MUST be null value on call
	if myself == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(myself) {
		if myself.IsTaken() {
			return fail.InvalidRequestError("cannot carry, already carries something")
		}
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	if myself.shielded == nil {
		return fail.InvalidInstanceContentError("myself.shielded", "cannot be nil")
	}
	if myself.loaded {
		return fail.NotAvailableError("already carrying a value")
	}

	myself.Lock()
	defer myself.Unlock()

	var cerr error
	myself.shielded, cerr = shielded.NewShielded(clonable)
	if cerr != nil {
		return fail.Wrap(cerr)
	}
	myself.loaded = true

	xerr = myself.updateIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	myself.committed = false

	xerr = myself.write()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// updateIdentity updates instance cached identity
func (myself *MetadataCore) updateIdentity() fail.Error {
	if myself.loaded {
		issue := myself.shielded.Alter(func(clonable data.Clonable) fail.Error {
			ident, ok := clonable.(data.Identifiable)
			if !ok {
				return fail.InconsistentError("'data.Identifiable' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if myself.kindSplittedStore {
				myself.id.Store(ident.GetID())
			} else {
				myself.id.Store(ident.GetName())
			}
			myself.name.Store(ident.GetName())
			myself.taken.Store(true)

			return nil
		})
		if issue != nil {
			return issue
		}

		// notify observers there has been changed in the instance
		err := myself.unsafeNotifyObservers()
		err = debug.InjectPlannedError(err)
		if err != nil {
			return fail.ConvertError(err)
		}
		return nil
	}

	return fail.InconsistentError("uninitialized data should NOT be updated")
}

// Read gets the data from Object Storage
func (myself *MetadataCore) Read(ref string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	// Note: do not test with .IsNull() here, it may be null value on first read
	if myself == nil {
		return fail.InvalidInstanceError()
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if myself.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	myself.Lock()
	defer myself.Unlock()

	bu, xerr := myself.folder.getBucket()
	if xerr != nil {
		return xerr
	}

	if !myself.kindSplittedStore {
		isName, xerr := myself.Service().HasObject(bu.GetName(), myself.folder.absolutePath("", ref))
		if xerr != nil {
			return xerr
		}

		if isName {
			xerr := myself.readByName(ref)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			myself.loaded = true
			myself.committed = true

			return myself.updateIdentity()
		}

		return fail.NotFoundError("%s was NOT found in the bucket", myself.folder.absolutePath("", ref))
	}

	isName, xerr := myself.Service().HasObject(bu.GetName(), myself.folder.absolutePath(byNameFolderName, ref))
	if xerr != nil {
		return xerr
	}

	if isName {
		xerr := myself.readByName(ref)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	isID, xerr := myself.Service().HasObject(bu.GetName(), myself.folder.absolutePath(byIDFolderName, ref))
	if xerr != nil {
		return xerr
	}

	if isID {
		xerr := myself.readByID(ref)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	if !isID && !isName {
		return fail.NotFoundError("nor %s nor %s were found in the bucket", myself.folder.absolutePath(byNameFolderName, ref), myself.folder.absolutePath(byIDFolderName, ref))
	}

	myself.loaded = true
	myself.committed = true

	return myself.updateIdentity()
}

// ReadByID reads a metadata identified by ID from Object Storage
func (myself *MetadataCore) ReadByID(id string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: do not test with .IsNull() here, it may be null value on first read
	if myself == nil {
		return fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}
	if myself.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	timings, xerr := myself.Service().Timings()
	if xerr != nil {
		return xerr
	}

	myself.Lock()
	defer myself.Unlock()

	if myself.kindSplittedStore {
		xerr = retry.WhileUnsuccessful(
			func() error {
				if innerXErr := myself.readByID(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			timings.SmallDelay(),
			timings.ContextTimeout(),
		)
	} else {
		xerr = retry.WhileUnsuccessful(
			func() error {
				if innerXErr := myself.readByName(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			timings.SmallDelay(),
			timings.ContextTimeout(),
		)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", myself.kind, id)
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", myself.kind, id)
		default:
			return fail.Wrap(xerr, "failed to read %s by id %s", myself.kind, id)
		}
	}

	myself.loaded = true
	myself.committed = true

	return myself.updateIdentity()
}

// readByID reads a metadata identified by ID from Object Storage
func (myself *MetadataCore) readByID(id string) fail.Error {
	var path string
	if myself.kindSplittedStore {
		path = byIDFolderName
	}

	timings, xerr := myself.Service().Timings()
	if xerr != nil {
		return xerr
	}

	rerr := retry.WhileUnsuccessful(func() error {
		werr := myself.folder.Read(path, id, func(buf []byte) fail.Error {
			if innerXErr := myself.unsafeDeserialize(buf); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotAvailable:
					return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", myself.kind)
				case *fail.ErrSyntax:
					return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", myself.kind)
				case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
					return retry.StopRetryError(innerXErr)
				default:
					return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s resource", myself.kind)
				}
			}
			return nil
		})
		if werr != nil {
			switch werr.Cause().(type) {
			case *fail.ErrNotFound:
				return retry.StopRetryError(werr, "quit trying")
			default:
				return werr
			}
		}
		return nil
	},
		timings.SmallDelay(),
		timings.ContextTimeout())

	if rerr != nil {
		return fail.ConvertError(rerr.Cause())
	}

	return nil

}

// readByName reads a metadata identified by name
func (myself *MetadataCore) readByName(name string) fail.Error {
	var path string
	if myself.kindSplittedStore {
		path = byNameFolderName
	}

	timings, xerr := myself.Service().Timings()
	if xerr != nil {
		return xerr
	}

	rerr := retry.WhileUnsuccessful(func() error {
		werr := myself.folder.Read(path, name, func(buf []byte) fail.Error {
			if innerXErr := myself.unsafeDeserialize(buf); innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to unsafeDeserialize %s '%s'", myself.kind, name)
			}
			return nil
		})
		if werr != nil {
			switch werr.Cause().(type) {
			case *fail.ErrNotFound:
				return retry.StopRetryError(werr, "quit trying")
			default:
				return werr
			}
		}
		return nil
	},
		timings.SmallDelay(),
		timings.ContextTimeout())

	if rerr != nil {
		return fail.ConvertError(rerr.Cause())
	}

	return nil
}

// write updates the metadata corresponding to the host in the Object Storage
func (myself *MetadataCore) write() fail.Error {
	if !myself.committed {
		jsoned, xerr := myself.unsafeSerialize()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		name, ok := myself.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}

		if myself.kindSplittedStore {
			xerr = myself.folder.Write(byNameFolderName, name, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			id, ok := myself.id.Load().(string)
			if !ok {
				return fail.InconsistentError("field 'id' is not set with string")
			}

			xerr = myself.folder.Write(byIDFolderName, id, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		} else {
			xerr = myself.folder.Write("", name, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}

		myself.loaded = true
		myself.committed = true
	}
	return nil
}

// Reload reloads the content from the Object Storage
func (myself *MetadataCore) Reload(context.Context) (ferr fail.Error) {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.Lock()
	defer myself.Unlock()

	return myself.unsafeReload()
}

// unsafeReload loads the content from the Object Storage
// Note: must be called after locking the instance
func (myself *MetadataCore) unsafeReload() (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	timings, xerr := myself.Service().Timings()
	if xerr != nil {
		return xerr
	}

	if myself.loaded && !myself.committed {
		return fail.InconsistentError("cannot unsafeReload a not committed data")
	}

	if myself.kindSplittedStore {
		id, ok := myself.id.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'id' is not set with string")
		}

		xerr = retry.WhileUnsuccessful(
			func() error {
				if innerXErr := myself.readByID(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			timings.SmallDelay(),
			2*timings.MetadataTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", myself.kind, id)
			case *retry.ErrStopRetry:
				return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", myself.kind, id)
			default:
				return fail.Wrap(xerr, "failed to read %s by id %s", myself.kind, myself.id)
			}
		}
	} else {
		name, ok := myself.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}
		if name == "" {
			return fail.InconsistentError("field 'name' cannot be empty")
		}

		xerr = retry.WhileUnsuccessful(
			func() error {
				if innerXErr := myself.readByName(name); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					case *fail.ErrInconsistent, *fail.ErrInvalidParameter, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent:
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			timings.SmallDelay(),
			timings.ContextTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				return fail.Wrap(fail.RootCause(xerr), "failed (timeout) to read %s '%s'", myself.kind, name)
			case *retry.ErrStopRetry:
				return fail.Wrap(fail.RootCause(xerr), "failed to read %s '%s'", myself.kind, name)
			default:
				return fail.Wrap(xerr, "failed to read %s '%s'", myself.kind, name)
			}
		}
	}

	myself.loaded = true
	myself.committed = true

	return fail.ConvertError(myself.unsafeNotifyObservers())
}

// BrowseFolder walks through MetadataFolder and executes a callback for each entry
func (myself *MetadataCore) BrowseFolder(callback func(buf []byte) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	myself.RLock()
	defer myself.RUnlock()

	if myself.kindSplittedStore {
		return myself.folder.Browse(byIDFolderName, func(buf []byte) fail.Error {
			return callback(buf)
		})
	}
	return myself.folder.Browse("", func(buf []byte) fail.Error {
		return callback(buf)
	})
}

// Delete deletes the metadata
func (myself *MetadataCore) Delete() (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.Lock()
	defer myself.Unlock()

	var (
		idFound, nameFound bool
		errors             []error
	)

	// Checks entries exist in Object Storage
	if myself.kindSplittedStore {
		id, ok := myself.id.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'id' is not set with string")
		}

		var xerr fail.Error
		xerr = myself.folder.Lookup(byIDFolderName, id)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// If entry not found, consider operation not an error
				logrus.Tracef("MetadataFolder not found by id, maybe not an error")
			default:
				errors = append(errors, xerr)
			}
		} else {
			idFound = true
		}

		name, ok := myself.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}
		if name == "" {
			return fail.InconsistentError("field 'name' cannot be empty")
		}

		xerr = myself.folder.Lookup(byNameFolderName, name)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// If entry not found, consider operation not an error
				logrus.Tracef("MetadataFolder not found by name, maybe not an error")
			default:
				errors = append(errors, xerr)
			}
		} else {
			nameFound = true
		}

		// Deletes entries found
		if idFound {
			xerr = myself.folder.Delete(byIDFolderName, id)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
		if nameFound {
			xerr = myself.folder.Delete(byNameFolderName, name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
	} else {
		name, ok := myself.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}

		var xerr fail.Error
		xerr = myself.folder.Lookup("", name)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// If entry not found, consider operation not an error
				logrus.Tracef("MetadataFolder not found by name, maybe not an error")
			default:
				errors = append(errors, xerr)
			}
		} else {
			nameFound = true
		}
		if nameFound {
			xerr = myself.folder.Delete("", name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
	}

	myself.loaded = false
	myself.committed = false

	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}

	myself.unsafeDestroyed() // notifies cache that the instance has been deleted
	return nil
}

func (myself *MetadataCore) Sdump(context.Context) (_ string, ferr fail.Error) {
	if valid.IsNil(myself) {
		return "", fail.InvalidInstanceError()
	}

	myself.RLock()
	defer myself.RUnlock()

	dumped, _ := myself.shielded.Sdump()
	return dumped, nil
}

// unsafeSerialize serializes instance into bytes (output json code)
// Note: must be called after locking the instance
func (myself *MetadataCore) unsafeSerialize() (_ []byte, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var (
		shieldedJSONed []byte
		shieldedMapped = map[string]interface{}{}
		propsMapped    = map[string]string{}
	)

	var xerr fail.Error
	shieldedJSONed, xerr = myself.shielded.Serialize()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	err := json.Unmarshal(shieldedJSONed, &shieldedMapped)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return nil, fail.NewErrorWithCause(err, "*MetadataCore.Serialize(): Unmarshalling JSONed shielded into map failed!")
	}

	if myself.properties.Count() > 0 {
		propsJSONed, xerr := myself.properties.Serialize()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		if len(propsJSONed) > 0 && string(propsJSONed) != `"{}"` {
			if jserr := json.Unmarshal(propsJSONed, &propsMapped); jserr != nil {
				// logrus.Tracef("*MetadataCore.Serialize(): Unmarshalling JSONed properties into map failed!")
				return nil, fail.ConvertError(jserr)
			}
		}
	}

	shieldedMapped["properties"] = propsMapped

	r, err := json.Marshal(shieldedMapped)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	return r, nil
}

// Deserialize reads json code and reinstantiates
func (myself *MetadataCore) Deserialize(buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.Lock()
	defer myself.Unlock()

	return myself.unsafeDeserialize(buf)
}

// unsafeDeserialize reads json code and instantiates a MetadataCore
// Note: must be called after locking the instance
func (myself *MetadataCore) unsafeDeserialize(buf []byte) (ferr fail.Error) {
	if myself.properties == nil {
		var xerr fail.Error
		myself.properties, xerr = serializer.NewJSONProperties("resources." + myself.kind)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	var (
		mapped, props map[string]interface{}
		ok            bool
		jsoned        []byte
	)

	if buf != nil {
		err := json.Unmarshal(buf, &mapped)
		err = debug.InjectPlannedError(err)
		if err != nil {
			if strings.Contains(err.Error(), "unexpected end of input") {
				return fail.NotAvailableErrorWithCause(err, nil, "server returned incomplete data")
			}
			return fail.SyntaxErrorWithCause(err, nil, "unmarshalling JSON to map failed")
		}
		if props, ok = mapped["properties"].(map[string]interface{}); ok {
			delete(mapped, "properties")
		}
	}

	jsoned, err := json.Marshal(mapped)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return fail.SyntaxErrorWithCause(err, nil, "failed to marshal MetadataCore to JSON")
	}

	xerr := myself.shielded.Deserialize(jsoned)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "deserializing MetadataCore failed")
	}

	if len(props) > 0 {
		jsoned, err = json.Marshal(props)
		err = debug.InjectPlannedError(err)
		if err != nil {
			return fail.SyntaxErrorWithCause(err, nil, "failed to marshal properties to JSON")
		}

		xerr = myself.properties.Deserialize(jsoned)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to unsafeDeserialize properties")
		}
	}
	return nil
}

// Released is used to tell cache that the instance has been used and will not be anymore.
// Helps the cache handler to know when a cached item can be removed from cache (if needed)
// satisfies interface data.Cacheable
func (myself *MetadataCore) Released() error {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.RLock()
	defer myself.RUnlock()

	return myself.unsafeReleased()
}

// unsafeReleased is used to tell cache that the instance has been used and will not be anymore.
// Helps the cache handler to know when a cached item can be removed from cache (if needed)
// Note: must be called after locking the instance
func (myself *MetadataCore) unsafeReleased() error {
	id, ok := myself.id.Load().(string)
	if !ok {
		return fail.InconsistentError("field 'id' is not set with string")
	}

	for _, v := range myself.observers {
		v.MarkAsFreed(id)
	}
	return nil
}

// Destroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// satisfies interface data.Cacheable
func (myself *MetadataCore) Destroyed() error {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.RLock()
	defer myself.RUnlock()

	myself.unsafeDestroyed()
	return nil
}

// unsafeDestroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// Note: Does nothing for now, prepared for future use
func (myself *MetadataCore) unsafeDestroyed() {
	id, ok := myself.id.Load().(string)
	if !ok {
		logrus.Error(fail.InconsistentError("field 'id' is not set with string").Error())
		return
	}

	for _, v := range myself.observers {
		v.MarkAsDeleted(id)
	}
}

// AddObserver ...
// satisfies interface data.Observable
func (myself *MetadataCore) AddObserver(o observer.Observer) error {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}
	if o == nil {
		return fail.InvalidParameterError("o", "cannot be nil")
	}

	myself.Lock()
	defer myself.Unlock()

	if pre, ok := myself.observers[o.GetID()]; ok {
		if pre == o {
			return fail.DuplicateError("there is already an Observer identified by '%s'", o.GetID())
		}
		return nil
	}
	myself.observers[o.GetID()] = o
	return nil
}

// NotifyObservers sends a signal to all registered Observers to notify change
// Satisfies interface data.Observable
func (myself *MetadataCore) NotifyObservers() error {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}

	myself.RLock()
	defer myself.RUnlock()

	return myself.unsafeNotifyObservers()
}

// unsafeNotifyObservers sends a signal to all registered Observers to notify change
// Note: must be called after locking the instance
func (myself *MetadataCore) unsafeNotifyObservers() error {
	id, ok := myself.id.Load().(string)
	if !ok {
		return fail.InconsistentError("field 'id' is not set with string")
	}

	for _, v := range myself.observers {
		v.SignalChange(id)
	}
	return nil
}

// RemoveObserver ...
func (myself *MetadataCore) RemoveObserver(name string) error {
	if valid.IsNil(myself) {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	myself.Lock()
	defer myself.Unlock()

	delete(myself.observers, name)
	return nil
}
