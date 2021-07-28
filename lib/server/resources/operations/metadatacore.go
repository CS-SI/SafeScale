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
	"reflect"
	"strings"
	"sync"
	"sync/atomic"

	shielded2 "github.com/CS-SI/SafeScale/lib/utils/data/shielded"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// byIDFolderName tells in what MetadataFolder to put 'byID' information
	byIDFolderName = "byID"
	// byNameFolderName tells in what MetadataFolder to store 'byName' information
	byNameFolderName = "byName"

	NullMetadataKind = "nil"
	NullMetadataName = "<NullCore>"
	NullMetadataID = NullMetadataName
)

// MetadataCore contains the core functions of a persistent object
type MetadataCore struct {
	id   atomic.Value
	name atomic.Value

	//	concurrency.TaskedLock `json:"-"`

	lock       sync.RWMutex
	shielded   *shielded2.Shielded
	properties *serialize.JSONProperties
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

	props, err := serialize.NewJSONProperties("resources." + kind)
	err = debug.InjectPlannedFail(err)
	if err != nil {
		return NullCore(), err
	}

	c := MetadataCore{
		kind:       kind,
		folder:     fld,
		properties: props,
		shielded:   shielded2.NewShielded(instance),
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
func (c *MetadataCore) IsNull() bool {
	return c == nil || (c.kind == "" || c.kind == NullMetadataKind || c.folder.IsNull() || (c.getID() == NullMetadataID && c.getName() == NullMetadataName))
}

// GetService returns the iaas.GetService used to create/load the persistent object
func (c *MetadataCore) GetService() iaas.Service {
	if c == nil {
		return nil
	}

	return c.folder.GetService()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (c *MetadataCore) GetID() string {
	if c == nil || c.IsNull() {
		return NullMetadataID
	}

	return c.getID()
}

func (c *MetadataCore) getID() string {
	id, ok := c.id.Load().(string)
	if !ok {
		return NullMetadataID
	}

	return id
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (c *MetadataCore) GetName() string {
	if c == nil || c.IsNull() {
		return NullMetadataName
	}

	return c.getName()
}

func (c *MetadataCore) getName() string {
	name, ok := c.name.Load().(string)
	if !ok {
		return NullMetadataName
	}

	return name
}

// GetKind returns the kind of object served
func (c *MetadataCore) GetKind() string {
	if c == nil {
		return NullMetadataKind
	}
	return c.kind
}

// Inspect protects the data for shared read
func (c *MetadataCore) Inspect(callback resources.Callback) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if c.properties == nil {
		return fail.InvalidInstanceContentError("c.properties", "cannot be nil")
	}

	// Reload reloads data from Object Storage to be sure to have the last revision
	c.lock.Lock()
	xerr = c.reload()
	c.lock.Unlock()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to reload metadata")
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.shielded.Inspect(func(clonable data.Clonable) fail.Error {
		return callback(clonable, c.properties)
	})
}

// Review allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// change thru time).
func (c *MetadataCore) Review(callback resources.Callback) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if c.properties == nil {
		return fail.InvalidInstanceContentError("c.properties", "cannot be nil")
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.shielded.Inspect(func(clonable data.Clonable) fail.Error {
		return callback(clonable, c.properties)
	})
}

// Alter protects the data for exclusive write
// Valid keyvalues for options are :
// - "Reload": bool = allow to disable reloading from Object Storage if set to false (default is true)
func (c *MetadataCore) Alter(callback resources.Callback, options ...data.ImmutableKeyValue) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}
	if c.shielded == nil {
		return fail.InvalidInstanceContentError("c.shielded", "cannot be nil")
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	// Make sure c.properties is populated
	if c.properties == nil {
		c.properties, xerr = serialize.NewJSONProperties("resources." + c.kind)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			c.lock.Unlock()
			return xerr
		}
	}

	doReload := true
	if len(options) > 0 {
		for _, v := range options {
			switch v.Key() {
			case "Reload":
				doReload = v.Value().(bool)
			default:
			}
		}
	}
	// Reload reloads data from objectstorage to be sure to have the last revision
	if doReload {
		xerr = c.reload()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to reload metadata")
		}
	}

	xerr = c.shielded.Alter(func(clonable data.Clonable) fail.Error {
		return callback(clonable, c.properties)
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

	c.committed = false

	xerr = c.write()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// notify observers there has been changed in the instance
	return fail.ConvertError(c.notifyObservers())
}

// Carry links metadata with real data
// If c is already carrying a shielded data, returns fail.NotAvailableError
//
// errors returned :
// - fail.ErrInvalidInstance
// - fail.ErrInvalidParameter
// - fail.ErrNotAvailable if the MetadataCore instance already carries a data
func (c *MetadataCore) Carry(clonable data.Clonable) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: do not test with IsNull() here, it MUST be null value on call
	if c == nil {
		return fail.InvalidInstanceError()
	}
	if !c.IsNull() {
		return fail.InvalidRequestError("cannot carry, already carries something")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	if c.shielded == nil {
		return fail.InvalidInstanceContentError("c.shielded", "cannot be nil")
	}
	if c.loaded {
		return fail.NotAvailableError("already carrying a value")
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	c.shielded = shielded2.NewShielded(clonable)
	c.loaded = true

	xerr = c.updateIdentity()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	c.committed = false

	xerr = c.write()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// updateIdentity updates instance cached identity
func (c *MetadataCore) updateIdentity() fail.Error {
	if c.loaded {
		return c.shielded.Inspect(func(clonable data.Clonable) fail.Error {
			ident, ok := clonable.(data.Identifiable)
			if !ok {
				return fail.InconsistentError("'data.Identifiable' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if c.kindSplittedStore {
				c.id.Store(ident.GetID())
			} else {
				c.id.Store(ident.GetName())
			}
			c.name.Store(ident.GetName())

			return nil
		})
	}

	c.name.Store(NullMetadataName)
	c.id.Store(NullMetadataID)

	// notify observers there has been changed in the instance
	err := c.notifyObservers()
	err = debug.InjectPlannedError(err)
	if err != nil {
		return fail.ConvertError(err)
	}

	return nil
}

// Read gets the data from Object Storage
func (c *MetadataCore) Read(ref string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: do not test with .IsNull() here, it may be null value on first read
	if c == nil {
		return fail.InvalidInstanceError()
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if c.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	xerr = c.readByReference(ref)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	c.loaded = true
	c.committed = true

	return c.updateIdentity()
}

// ReadByID reads a metadata identified by ID from Object Storage
func (c *MetadataCore) ReadByID(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: do not test with .IsNull() here, it may be null value on first read
	if c == nil {
		return fail.InvalidInstanceError()
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}
	if c.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if c.kindSplittedStore {
		xerr = retry.WhileUnsuccessfulDelay1Second(
			func() error {
				if innerXErr := c.readByID(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			temporal.GetContextTimeout(),
		)
	} else {
		xerr = retry.WhileUnsuccessfulDelay1Second(
			func() error {
				if innerXErr := c.readByName(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			temporal.GetContextTimeout(),
		)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", c.kind, id)
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", c.kind, id)
		default:
			return fail.Wrap(xerr, "failed to read %s by id %s", c.kind, id)
		}
	}

	c.loaded = true
	c.committed = true

	return c.updateIdentity()
}

// readByID reads a metadata identified by ID from Object Storage
func (c *MetadataCore) readByID(id string) fail.Error {
	var path string
	if c.kindSplittedStore {
		path = byIDFolderName
	}
	return c.folder.Read(path, id, func(buf []byte) fail.Error {
		if innerXErr := c.deserialize(buf); innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrSyntax:
				return fail.Wrap(innerXErr, "failed to deserialize %s resource", c.kind)
			default:
				return fail.Wrap(innerXErr, "failed to deserialize %s resource", c.kind)
			}
		}
		return nil
	})
}

// readByReference gets the data from Object Storage
// First read using 'ref' as an ID; if *fail.ErrNotFound occurs, read using 'ref' as a name
func (c *MetadataCore) readByReference(ref string) (xerr fail.Error) {
	timeout := temporal.GetCommunicationTimeout()

	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			if innerXErr := c.readByID(ref); innerXErr != nil {
				innerXErr = debug.InjectPlannedFail(innerXErr)
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					if c.kindSplittedStore {
						// Try to read by name
						innerXErr = c.readByName(ref)
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
		timeout,
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			xerr = fail.Wrap(fail.RootCause(xerr), "failed to read metadata of %s '%s' after %s", c.kind, ref, temporal.FormatDuration(timeout))
		case *retry.ErrStopRetry:
			xerr = fail.Wrap(fail.RootCause(xerr), "failed to read metadata of %s '%s'", c.kind, ref)
		case *fail.ErrNotFound:
			xerr = fail.Wrap(xerr, "failed to find metadata of %s '%s'", c.kind, ref)
		default:
			xerr = fail.Wrap(xerr, "failed to read metadata of %s '%s'", c.kind, ref)
		}
	}
	return xerr
}

// readByName reads a metadata identified by name
func (c *MetadataCore) readByName(name string) fail.Error {
	var path string
	if c.kindSplittedStore {
		path = byNameFolderName
	}
	return c.folder.Read(path, name, func(buf []byte) fail.Error {
		if innerXErr := c.deserialize(buf); innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to deserialize %s '%s'", c.kind, name)
		}
		return nil
	})
}

// write updates the metadata corresponding to the host in the Object Storage
func (c *MetadataCore) write() fail.Error {
	if !c.committed {
		jsoned, xerr := c.serialize()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		name, ok := c.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}

		if c.kindSplittedStore {
			xerr = c.folder.Write(byNameFolderName, name, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			id, ok := c.id.Load().(string)
			if !ok {
				return fail.InconsistentError("field 'id' is not set with string")
			}

			xerr = c.folder.Write(byIDFolderName, id, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		} else {
			xerr = c.folder.Write("", name, jsoned)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}

		c.loaded = true
		c.committed = true
	}
	return nil
}

// Reload reloads the content from the Object Storage
func (c *MetadataCore) Reload() (xerr fail.Error) {
	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	return c.reload()
}

// reload reloads the content from the Object Storage
// Note: must be called after locking the instance
func (c *MetadataCore) reload() (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.loaded && !c.committed {
		return fail.InconsistentError("cannot reload a not committed data")
	}

	if c.kindSplittedStore {
		id, ok := c.id.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'id' is not set with string")
		}

		xerr = retry.WhileUnsuccessfulDelay1Second(
			func() error {
				if innerXErr := c.readByID(id); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			2*temporal.GetMetadataTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout, *retry.ErrStopRetry:
				return fail.Wrap(fail.RootCause(xerr), "failed to read %s by id %s", c.kind, id)
			default:
				return fail.Wrap(xerr, "failed to read %s by id %s", c.kind, c.id)
			}
		}
	} else {
		name, ok := c.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}

		xerr = retry.WhileUnsuccessfulDelay1Second(
			func() error {
				if innerXErr := c.readByName(name); innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound: // If not found, stop immediately
						return retry.StopRetryError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			temporal.GetContextTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout, *retry.ErrStopRetry:
				return fail.Wrap(fail.RootCause(xerr), "failed to read %s '%s'", c.kind, name)
			default:
				return fail.Wrap(xerr, "failed to read %s '%s'", c.kind, name)
			}
		}
	}

	c.loaded = true
	c.committed = true

	return fail.ConvertError(c.notifyObservers())
}

// BrowseFolder walks through MetadataFolder and executes a callback for each entries
func (c *MetadataCore) BrowseFolder(callback func(buf []byte) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c == nil {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	if c.kindSplittedStore {
		return c.folder.Browse(byIDFolderName, func(buf []byte) fail.Error {
			return callback(buf)
		})
	}
	return c.folder.Browse("", func(buf []byte) fail.Error {
		return callback(buf)
	})
}

// Delete deletes the metadata
func (c *MetadataCore) Delete() (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	var (
		idFound, nameFound bool
		errors             []error
	)

	// Checks entries exist in Object Storage
	if c.kindSplittedStore {
		id, ok := c.id.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'id' is not set with string")
		}

		xerr = c.folder.Lookup(byIDFolderName, id)
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

		name, ok := c.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}

		xerr = c.folder.Lookup(byNameFolderName, name)
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
			xerr = c.folder.Delete(byIDFolderName, id)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
		if nameFound {
			xerr = c.folder.Delete(byNameFolderName, name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
	} else {
		name, ok := c.name.Load().(string)
		if !ok {
			return fail.InconsistentError("field 'name' is not set with string")
		}

		xerr = c.folder.Lookup("", name)
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
			xerr = c.folder.Delete("", name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				errors = append(errors, xerr)
			}
		}
	}

	c.loaded = false
	c.committed = false

	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}

	c.destroyed() // notifies cache that the instance has been deleted
	return nil
}

// Serialize serializes instance into bytes (output json code)
func (c *MetadataCore) Serialize() (_ []byte, xerr fail.Error) {
	if c == nil || c.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.serialize()
}

// serialize serializes instance into bytes (output json code)
// Note: must be called after locking the instance
func (c *MetadataCore) serialize() (_ []byte, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var (
		shieldedJSONed []byte
		shieldedMapped = map[string]interface{}{}
		propsMapped    = map[string]string{}
	)

	shieldedJSONed, xerr = c.shielded.Serialize()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	err := json.Unmarshal(shieldedJSONed, &shieldedMapped)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return nil, fail.NewErrorWithCause(err, "*MetadataCore.Serialize(): Unmarshalling JSONed shielded into map failed!")
	}

	if c.properties.Count() > 0 {
		propsJSONed, xerr := c.properties.Serialize()
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
func (c *MetadataCore) Deserialize(buf []byte) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	return c.deserialize(buf)
}

// deserialize reads json code and reinstantiates
// Note: must be called after locking the instance
func (c *MetadataCore) deserialize(buf []byte) (xerr fail.Error) {
	if c.properties == nil {
		c.properties, xerr = serialize.NewJSONProperties("resources." + c.kind)
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

	xerr = c.shielded.Deserialize(jsoned)
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

		xerr = c.properties.Deserialize(jsoned)
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
func (c *MetadataCore) Released() {
	if c == nil || c.IsNull() {
		return // FIXME: Missing log?
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	c.released()
}

// released is used to tell cache that the instance has been used and will not be anymore.
// Helps the cache handler to know when a cached item can be removed from cache (if needed)
// Note: must be called after locking the instance
func (c *MetadataCore) released() {
	id, ok := c.id.Load().(string)
	if !ok {
		logrus.Error(fail.InconsistentError("field 'id' is not set with string").Error())
		return
	}

	for _, v := range c.observers {
		v.MarkAsFreed(id)
	}
}

// Destroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// Note: Does nothing for now, prepared for future use
// satisfies interface data.Cacheable
func (c *MetadataCore) Destroyed() {
	if c == nil || c.IsNull() {
		return // FIXME: Missing log ?
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	c.destroyed()
}

// destroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// Note: Does nothing for now, prepared for future use
// Note: must be called after locking the instance
func (c *MetadataCore) destroyed() {
	id, ok := c.id.Load().(string)
	if !ok {
		logrus.Error(fail.InconsistentError("field 'id' is not set with string").Error())
		return
	}

	for _, v := range c.observers {
		v.MarkAsDeleted(id)
	}
}

// AddObserver ...
// satisfies interface data.Observable
func (c *MetadataCore) AddObserver(o observer.Observer) error {
	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if o == nil {
		return fail.InvalidParameterError("o", "cannot be nil")
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if pre, ok := c.observers[o.GetID()]; ok {
		if pre == o {
			return fail.DuplicateError("there is already an Observer identified by '%s'", o.GetID())
		}
		return nil
	}
	c.observers[o.GetID()] = o
	return nil
}

// NotifyObservers sends a signal to all registered Observers to notify change
// Satisfies interface data.Observable
func (c *MetadataCore) NotifyObservers() error {
	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.notifyObservers()
}

// notifyObservers sends a signal to all registered Observers to notify change
// Note: must be called after locking the instance
func (c *MetadataCore) notifyObservers() error {
	id, ok := c.id.Load().(string)
	if !ok {
		return fail.InconsistentError("field 'id' is not set with string")
	}

	for _, v := range c.observers {
		v.SignalChange(id)
	}
	return nil
}

// RemoveObserver ...
func (c *MetadataCore) RemoveObserver(name string) error {
	if c == nil || c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.observers, name)
	return nil
}
