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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	serializer "github.com/CS-SI/SafeScale/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/data/shielded"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// byIDFolderName tells in what MetadataFolder to put 'byID' information
	byIDFolderName = "byID"
	// byNameFolderName tells in what MetadataFolder to store 'byName' information
	byNameFolderName = "byName"

	NullMetadataKind = "nil"
	NullMetadataName = "<NullCore>"
	NullMetadataID   = NullMetadataName
)

// MetadataCore contains the core functions of a persistent object
type MetadataCore struct {
	id   atomic.Value
	name atomic.Value

	lock       sync.RWMutex
	shielded   *shielded.Shielded
	properties *serializer.JSONProperties
	observers  map[string]observer.Observer

	kind              string
	folder            MetadataFolder
	loaded            bool
	committed         bool
	kindSplittedStore bool // tells if data read/write is done directly from/to folder (when false) or from/to subfolders (when true)
}

func NullCore() *MetadataCore {
	return &MetadataCore{kind: NullMetadataKind}
}

// NewCore creates an instance of MetadataCore
func NewCore(svc iaas.Service, kind string, path string, instance data.Clonable) (_ *MetadataCore, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return NullCore(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if kind == "" {
		return NullCore(), fail.InvalidParameterError("kind", "cannot be empty string")
	}
	if path == "" {
		return NullCore(), fail.InvalidParameterError("path", "cannot be empty string")
	}

	fld, xerr := NewMetadataFolder(svc, path)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return NullCore(), xerr
	}

	props, err := serializer.NewJSONProperties("resources." + kind)
	err = debug.InjectPlannedFail(err)
	if err != nil {
		return NullCore(), err
	}

	c := MetadataCore{
		kind:       kind,
		folder:     fld,
		properties: props,
		shielded:   shielded.NewShielded(instance),
		observers:  map[string]observer.Observer{},
	}
	switch kind {
	case clusterKind:
		c.kindSplittedStore = false
	default:
		c.kindSplittedStore = true
	}
	return &c, nil
}

// IsNull returns true if the MetadataCore instance represents the null value for MetadataCore
func (self *MetadataCore) IsNull() bool {
	return self == nil || (self.kind == "" || self.kind == NullMetadataKind || self.folder.IsNull() || (self.getID() == NullMetadataID && self.getName() == NullMetadataName))
}

// Service returns the iaas.Service used to create/load the persistent object
func (self *MetadataCore) Service() iaas.Service {
	if self == nil {
		return nil
	}

	return self.folder.Service()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (self *MetadataCore) GetID() string {
	if self == nil || self.IsNull() {
		return NullMetadataID
	}

	return self.getID()
}

func (self *MetadataCore) getID() string {
	id, ok := self.id.Load().(string)
	if !ok {
		return NullMetadataID
	}

	return id
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (self *MetadataCore) GetName() string {
	if self == nil || self.IsNull() {
		return NullMetadataName
	}

	return self.getName()
}

func (self *MetadataCore) getName() string {
	name, ok := self.name.Load().(string)
	if !ok {
		return NullMetadataName
	}

	return name
}

// GetKind returns the kind of object served
func (self *MetadataCore) GetKind() string {
	if self == nil {
		return NullMetadataKind
	}
	return self.kind
}

// Inspect protects the data for shared read
func (self *MetadataCore) Inspect(callback resources.Callback) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if self.properties == nil {
		return fail.InvalidInstanceContentError("self.properties", "cannot be nil")
	}

	// Reload reloads data from Object Storage to be sure to have the last revision
	self.lock.Lock()
	xerr = self.reload()
	self.lock.Unlock() // nolint
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to reload metadata")
	}

	self.lock.RLock()
	defer self.lock.RUnlock()

	return self.shielded.Inspect(func(clonable data.Clonable) fail.Error {
		return callback(clonable, self.properties)
	})
}

// Review allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// change thru time).
func (self *MetadataCore) Review(callback resources.Callback) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if self.properties == nil {
		return fail.InvalidInstanceContentError("self.properties", "cannot be nil")
	}

	self.lock.RLock()
	defer self.lock.RUnlock()

	return self.shielded.Inspect(func(clonable data.Clonable) fail.Error {
		return callback(clonable, self.properties)
	})
}

// Alter protects the data for exclusive write
// Valid keyvalues for options are :
// - "Reload": bool = allow to disable reloading from Object Storage if set to false (default is true)
func (self *MetadataCore) Alter(callback resources.Callback, options ...data.ImmutableKeyValue) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if self.shielded == nil {
		return fail.InvalidInstanceContentError("self.shielded", "cannot be nil")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	// Make sure self.properties is populated
	if self.properties == nil {
		self.properties, xerr = serializer.NewJSONProperties("resources." + self.kind)
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
	// Reload reloads data from objectstorage to be sure to have the last revision
	if doReload {
		xerr = self.reload()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to reload metadata")
		}
	}

	xerr = self.shielded.Alter(func(clonable data.Clonable) fail.Error {
		return callback(clonable, self.properties)
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

	self.committed = false

	xerr = self.write()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// notify observers there has been changed in the instance
	return fail.ConvertError(self.notifyObservers())
}

// Carry links metadata with real data
// If c is already carrying a shielded data, returns fail.NotAvailableError
//
// errors returned :
// - fail.ErrInvalidInstance
// - fail.ErrInvalidParameter
// - fail.ErrNotAvailable if the MetadataCore instance already carries a data
func (self *MetadataCore) Carry(clonable data.Clonable) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: do not test with IsNull() here, it MUST be null value on call
	if self == nil {
		return fail.InvalidInstanceError()
	}
	if !self.IsNull() {
		return fail.InvalidRequestError("cannot carry, already carries something")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	if self.shielded == nil {
		return fail.InvalidInstanceContentError("self.shielded", "cannot be nil")
	}
	if self.loaded {
		return fail.NotAvailableError("already carrying a value")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	self.shielded = shielded.NewShielded(clonable)
	self.loaded = true

	xerr = self.updateIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	self.committed = false

	xerr = self.write()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// updateIdentity updates instance cached identity
func (self *MetadataCore) updateIdentity() fail.Error {
	if self.loaded {
		return self.shielded.Inspect(func(clonable data.Clonable) fail.Error {
			ident, ok := clonable.(data.Identifiable)
			if !ok {
				return fail.InconsistentError("'data.Identifiable' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if self.kindSplittedStore {
				self.id.Store(ident.GetID())
			} else {
				self.id.Store(ident.GetName())
			}
			self.name.Store(ident.GetName())

			return nil
		})
	}

	self.name.Store(NullMetadataName)
	self.id.Store(NullMetadataID)

	// notify observers there has been changed in the instance
	err := self.notifyObservers()
	err = debug.InjectPlannedError(err)
	if err != nil {
		return fail.ConvertError(err)
	}

	return nil
}

// Read gets the data from Object Storage
func (self *MetadataCore) Read(ref string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: do not test with .IsNull() here, it may be null value on first read
	if self == nil {
		return fail.InvalidInstanceError()
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if self.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	xerr = self.readByReference(ref)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	self.loaded = true
	self.committed = true

	return self.updateIdentity()
}

// ReadByID reads a metadata identified by ID from Object Storage
func (self *MetadataCore) ReadByID(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: do not test with .IsNull() here, it may be null value on first read
	if self == nil {
		return fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}
	if self.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	if self.kindSplittedStore {
		xerr = retry.WhileUnsuccessful(
			func() error {
				if innerXErr := self.readByID(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			self.Service().Timings().SmallDelay(),
			self.Service().Timings().ContextTimeout(),
		)
	} else {
		xerr = retry.WhileUnsuccessful(
			func() error {
				if innerXErr := self.readByName(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			self.Service().Timings().SmallDelay(),
			self.Service().Timings().ContextTimeout(),
		)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", self.kind, id)
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", self.kind, id)
		default:
			return fail.Wrap(xerr, "failed to read %s by id %s", self.kind, id)
		}
	}

	self.loaded = true
	self.committed = true

	return self.updateIdentity()
}

// readByID reads a metadata identified by ID from Object Storage
func (self *MetadataCore) readByID(id string) fail.Error {
	var path string
	if self.kindSplittedStore {
		path = byIDFolderName
	}
	return self.folder.Read(path, id, func(buf []byte) fail.Error {
		if innerXErr := self.deserialize(buf); innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrSyntax:
				return fail.Wrap(innerXErr, "failed to deserialize %s resource", self.kind)
			default:
				return fail.Wrap(innerXErr, "failed to deserialize %s resource", self.kind)
			}
		}
		return nil
	})
}

// readByReference gets the data from Object Storage
// First read using 'ref' as an ID; if *fail.ErrNotFound occurs, read using 'ref' as a name
func (self *MetadataCore) readByReference(ref string) (xerr fail.Error) {
	timeout := self.Service().Timings().CommunicationTimeout()
	delay := self.Service().Timings().SmallDelay()
	xerr = retry.WhileUnsuccessful(
		func() error {
			if innerXErr := self.readByID(ref); innerXErr != nil {
				innerXErr = debug.InjectPlannedFail(innerXErr)
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					if self.kindSplittedStore {
						// Try to read by name
						innerXErr = self.readByName(ref)
						innerXErr = debug.InjectPlannedFail(innerXErr)
					}
					if innerXErr != nil {
						switch innerXErr.(type) {
						case *fail.ErrNotFound:
							return retry.StopRetryError(innerXErr)
						default:
							return innerXErr
						}
					}
				default:
					return innerXErr
				}
			}
			return nil
		},
		delay,
		timeout,
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(fail.RootCause(xerr), "failed to read metadata of %s '%s' after %s", self.kind, ref, temporal.FormatDuration(timeout))
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.RootCause(xerr), "failed to read metadata of %s '%s'", self.kind, ref)
		case *fail.ErrNotFound:
			return fail.Wrap(xerr, "failed to find metadata of %s '%s'", self.kind, ref)
		default:
			return fail.Wrap(xerr, "something failed reading metadata of %s '%s'", self.kind, ref)
		}
	}
	return nil
}

// readByName reads a metadata identified by name
func (self *MetadataCore) readByName(name string) fail.Error {
	var path string
	if self.kindSplittedStore {
		path = byNameFolderName
	}
	return self.folder.Read(path, name, func(buf []byte) fail.Error {
		if innerXErr := self.deserialize(buf); innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to deserialize %s '%s'", self.kind, name)
		}
		return nil
	})
}

// write updates the metadata corresponding to the host in the Object Storage
func (self *MetadataCore) write() fail.Error {
	if !self.committed {
		jsoned, xerr := self.serialize()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		name, ok := self.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}

		if self.kindSplittedStore {
			xerr = self.folder.Write(byNameFolderName, name, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			id, ok := self.id.Load().(string)
			if !ok {
				return fail.InconsistentError("field 'id' is not set with string")
			}

			xerr = self.folder.Write(byIDFolderName, id, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		} else {
			xerr = self.folder.Write("", name, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}

		self.loaded = true
		self.committed = true
	}
	return nil
}

// Reload reloads the content from the Object Storage
func (self *MetadataCore) Reload() (xerr fail.Error) {
	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	return self.reload()
}

// reload reloads the content from the Object Storage
// Note: must be called after locking the instance
func (self *MetadataCore) reload() (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if self.loaded && !self.committed {
		return fail.InconsistentError("cannot reload a not committed data")
	}

	if self.kindSplittedStore {
		id, ok := self.id.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'id' is not set with string")
		}

		xerr = retry.WhileUnsuccessful(
			func() error {
				if innerXErr := self.readByID(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			self.Service().Timings().SmallDelay(),
			2*self.Service().Timings().MetadataTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", self.kind, id)
			case *retry.ErrStopRetry:
				return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", self.kind, id)
			default:
				return fail.Wrap(xerr, "failed to read %s by id %s", self.kind, self.id)
			}
		}
	} else {
		name, ok := self.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}
		if name == "" {
			return fail.InconsistentError("field 'name' cannot be empty")
		}

		xerr = retry.WhileUnsuccessful(
			func() error {
				if innerXErr := self.readByName(name); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			self.Service().Timings().SmallDelay(),
			self.Service().Timings().ContextTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				return fail.Wrap(fail.RootCause(xerr), "failed (timeout) to read %s '%s'", self.kind, name)
			case *retry.ErrStopRetry:
				return fail.Wrap(fail.RootCause(xerr), "failed to read %s '%s'", self.kind, name)
			default:
				return fail.Wrap(xerr, "failed to read %s '%s'", self.kind, name)
			}
		}
	}

	self.loaded = true
	self.committed = true

	return fail.ConvertError(self.notifyObservers())
}

// BrowseFolder walks through MetadataFolder and executes a callback for each entry
func (self *MetadataCore) BrowseFolder(callback func(buf []byte) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if self == nil {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	self.lock.RLock()
	defer self.lock.RUnlock()

	if self.kindSplittedStore {
		return self.folder.Browse(byIDFolderName, func(buf []byte) fail.Error {
			return callback(buf)
		})
	}
	return self.folder.Browse("", func(buf []byte) fail.Error {
		return callback(buf)
	})
}

// Delete deletes the metadata
func (self *MetadataCore) Delete() (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	var (
		idFound, nameFound bool
		errors             []error
	)

	// Checks entries exist in Object Storage
	if self.kindSplittedStore {
		id, ok := self.id.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'id' is not set with string")
		}

		xerr = self.folder.Lookup(byIDFolderName, id)
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

		name, ok := self.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}
		if name == "" {
			return fail.InconsistentError("field 'name' cannot be empty")
		}

		xerr = self.folder.Lookup(byNameFolderName, name)
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
			xerr = self.folder.Delete(byIDFolderName, id)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
		if nameFound {
			xerr = self.folder.Delete(byNameFolderName, name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
	} else {
		name, ok := self.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}

		xerr = self.folder.Lookup("", name)
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
			xerr = self.folder.Delete("", name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
	}

	self.loaded = false
	self.committed = false

	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}

	self.destroyed() // notifies cache that the instance has been deleted
	return nil
}

// Serialize serializes instance into bytes (output json code)
func (self *MetadataCore) Serialize() (_ []byte, xerr fail.Error) {
	if self == nil || self.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	self.lock.RLock()
	defer self.lock.RUnlock()

	return self.serialize()
}

// serialize serializes instance into bytes (output json code)
// Note: must be called after locking the instance
func (self *MetadataCore) serialize() (_ []byte, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var (
		shieldedJSONed []byte
		shieldedMapped = map[string]interface{}{}
		propsMapped    = map[string]string{}
	)

	shieldedJSONed, xerr = self.shielded.Serialize()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	err := json.Unmarshal(shieldedJSONed, &shieldedMapped)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return nil, fail.NewErrorWithCause(err, "*MetadataCore.Serialize(): Unmarshalling JSONed shielded into map failed!")
	}

	if self.properties.Count() > 0 {
		propsJSONed, xerr := self.properties.Serialize()
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
	// logrus.Tracef("everything mapped:\n%s\n", spew.Sdump(shieldedMapped))

	r, err := json.Marshal(shieldedMapped)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	return r, nil
}

// Deserialize reads json code and reinstantiates
func (self *MetadataCore) Deserialize(buf []byte) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	return self.deserialize(buf)
}

// deserialize reads json code and reinstantiates
// Note: must be called after locking the instance
func (self *MetadataCore) deserialize(buf []byte) (xerr fail.Error) {
	if self.properties == nil {
		self.properties, xerr = serializer.NewJSONProperties("resources." + self.kind)
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
			return fail.SyntaxErrorWithCause(err, "unmarshalling JSON to map failed")
		}
		if props, ok = mapped["properties"].(map[string]interface{}); ok {
			delete(mapped, "properties")
		}
	}

	jsoned, err := json.Marshal(mapped)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return fail.SyntaxErrorWithCause(err, "failed to marshal MetadataCore to JSON")
	}

	xerr = self.shielded.Deserialize(jsoned)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "deserializing MetadataCore failed")
	}

	if len(props) > 0 {
		jsoned, err = json.Marshal(props)
		err = debug.InjectPlannedError(err)
		if err != nil {
			return fail.SyntaxErrorWithCause(err, "failed to marshal properties to JSON")
		}

		xerr = self.properties.Deserialize(jsoned)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to deserialize properties")
		}
	}
	return nil
}

// Released is used to tell cache that the instance has been used and will not be anymore.
// Helps the cache handler to know when a cached item can be removed from cache (if needed)
// Note: Does nothing for now, prepared for future use
// satisfies interface data.Cacheable
func (self *MetadataCore) Released() {
	if self == nil || self.IsNull() {
		logrus.Errorf(callstack.DecorateWith("", "Released called on an invalid instance", "cannot be nil or null value", 0))
		return
	}

	self.lock.RLock()
	defer self.lock.RUnlock()

	self.released()
}

// released is used to tell cache that the instance has been used and will not be anymore.
// Helps the cache handler to know when a cached item can be removed from cache (if needed)
// Note: must be called after locking the instance
func (self *MetadataCore) released() {
	id, ok := self.id.Load().(string)
	if !ok {
		logrus.Error(fail.InconsistentError("field 'id' is not set with string").Error())
		return
	}

	for _, v := range self.observers {
		v.MarkAsFreed(id)
	}
}

// Destroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// Note: Does nothing for now, prepared for future use
// satisfies interface data.Cacheable
func (self *MetadataCore) Destroyed() {
	if self == nil || self.IsNull() {
		logrus.Warnf("Destroyed called on an invalid instance")
		return
	}

	self.lock.RLock()
	defer self.lock.RUnlock()

	self.destroyed()
}

// destroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// Note: Does nothing for now, prepared for future use
// Note: must be called after locking the instance
func (self *MetadataCore) destroyed() {
	id, ok := self.id.Load().(string)
	if !ok {
		logrus.Error(fail.InconsistentError("field 'id' is not set with string").Error())
		return
	}

	for _, v := range self.observers {
		v.MarkAsDeleted(id)
	}
}

// AddObserver ...
// satisfies interface data.Observable
func (self *MetadataCore) AddObserver(o observer.Observer) error {
	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}
	if o == nil {
		return fail.InvalidParameterError("o", "cannot be nil")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	if pre, ok := self.observers[o.GetID()]; ok {
		if pre == o {
			return fail.DuplicateError("there is already an Observer identified by '%s'", o.GetID())
		}
		return nil
	}
	self.observers[o.GetID()] = o
	return nil
}

// NotifyObservers sends a signal to all registered Observers to notify change
// Satisfies interface data.Observable
func (self *MetadataCore) NotifyObservers() error {
	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}

	self.lock.RLock()
	defer self.lock.RUnlock()

	return self.notifyObservers()
}

// notifyObservers sends a signal to all registered Observers to notify change
// Note: must be called after locking the instance
func (self *MetadataCore) notifyObservers() error {
	id, ok := self.id.Load().(string)
	if !ok {
		return fail.InconsistentError("field 'id' is not set with string")
	}

	for _, v := range self.observers {
		v.SignalChange(id)
	}
	return nil
}

// RemoveObserver ...
func (self *MetadataCore) RemoveObserver(name string) error {
	if self == nil || self.IsNull() {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	self.lock.Lock()
	defer self.lock.Unlock()

	delete(self.observers, name)
	return nil
}
