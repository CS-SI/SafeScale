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

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// byIDFolderName tells in what folder to put 'byID' information
	byIDFolderName = "byID"
	// byNameFolderName tells in what folder to store 'byName' information
	byNameFolderName = "byName"
)

// core contains the core functions of a persistent object
type core struct {
	id   atomic.Value
	name atomic.Value

	//	concurrency.TaskedLock `json:"-"`

	lock       sync.RWMutex
	shielded   *concurrency.Shielded
	properties *serialize.JSONProperties
	observers  map[string]observer.Observer

	kind      string
	folder    folder
	loaded    bool
	committed bool
}

func nullCore() *core {
	return &core{kind: "nil"}
}

// newCore creates an instance of core
func newCore(svc iaas.Service, kind string, path string, instance data.Clonable) (_ *core, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nullCore(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if kind == "" {
		return nullCore(), fail.InvalidParameterError("kind", "cannot be empty string")
	}
	if path == "" {
		return nullCore(), fail.InvalidParameterError("path", "cannot be empty string")
	}

	fld, xerr := newFolder(svc, path)
	if xerr != nil {
		return nullCore(), xerr
	}

	props, err := serialize.NewJSONProperties("resources." + kind)
	if err != nil {
		return nullCore(), err
	}

	c := core{
		kind:       kind,
		folder:     fld,
		properties: props,
		//TaskedLock: concurrency.NewTaskedLock(),
		shielded:  concurrency.NewShielded(instance),
		observers: map[string]observer.Observer{},
	}
	return &c, nil
}

// isNull returns true if the core instance represents the null value for core
func (c *core) isNull() bool {
	return c == nil || c.kind == "" || c.kind == "nil" || c.folder.IsNull()
}

// GetService returns the iaas.GetService used to create/load the persistent object
func (c *core) GetService() iaas.Service {
	if c.isNull() {
		return nil
	}

	return c.folder.GetService()
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (c *core) GetID() string {
	if c.isNull() {
		return "<NullCore>"
	}

	id, ok := c.id.Load().(string)
	if !ok {
		return ""
	}
	return id
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (c *core) GetName() string {
	if c.isNull() {
		return "<NullCore>"
	}

	name, ok := c.name.Load().(string)
	if !ok {
		return ""
	}
	return name
}

// Inspect protects the data for shared read
func (c *core) Inspect(callback resources.Callback) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
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

	// Reload reloads data from Object Storage to be sure to have the last revision
	if xerr = c.reload(); xerr != nil {
		return fail.Wrap(xerr, "failed to reload metadata")
	}

	return c.shielded.Inspect(func(clonable data.Clonable) fail.Error {
		return callback(clonable, c.properties)
	})
}

// Review allows to access data contained in the instance, without reloading from the Object Storage; it's intended
// to speed up operations that accept data is not up-to-date (for example, SSH configuration to access host should not
// change thru time).
func (c *core) Review(callback resources.Callback) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
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
func (c *core) Alter(callback resources.Callback, options ...data.ImmutableKeyValue) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
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
		if c.properties, xerr = serialize.NewJSONProperties("resources." + c.kind); xerr != nil {
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
		if xerr = c.reload(); xerr != nil {
			return fail.Wrap(xerr, "failed to reload metadata")
		}
	}

	xerr = c.shielded.Alter(func(clonable data.Clonable) fail.Error {
		return callback(clonable, c.properties)
	})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			return nil
		default:
			return xerr
		}
	}

	c.committed = false

	if xerr = c.write(); xerr != nil {
		return xerr
	}

	// notify observers there has been changed in the instance
	return fail.ConvertError(c.notifyObservers())
}

// carry links metadata with real data
// If c is already carrying a shielded data, returns fail.NotAvailableError
//
// errors returned :
// - fail.ErrInvalidInstance
// - fail.ErrInvalidParameter
// - fail.ErrNotAvailable if the core instance already carries a data
func (c *core) carry(clonable data.Clonable) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
		return fail.InvalidInstanceError()
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

	c.shielded = concurrency.NewShielded(clonable)
	c.loaded = true

	if xerr = c.updateIdentity(); xerr != nil {
		return xerr
	}

	c.committed = false

	return c.write()
}

// updateIdentity updates instance cached identity
func (c *core) updateIdentity() fail.Error {
	if c.loaded {
		return c.shielded.Inspect(func(clonable data.Clonable) fail.Error {
			ident, ok := clonable.(data.Identifiable)
			if !ok {
				return fail.InconsistentError("'data.Identifiable' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			c.name.Store(ident.GetName())
			c.id.Store(ident.GetID())
			return nil
		})
	}

	c.name.Store("")
	c.id.Store("")

	// notify observers there has been changed in the instance
	if err := c.notifyObservers(); err != nil {
		return fail.ConvertError(err)
	}

	return nil
}

// Read gets the data from Object Storage
func (c *core) Read(ref string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
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

	if xerr = c.readByReference(ref); xerr != nil {
		return xerr
	}

	c.loaded = true
	c.committed = true

	return c.updateIdentity()
}

// ReadByID reads a metadata identified by ID from Object Storage
func (c *core) ReadByID(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
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
		temporal.GetMinDelay(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(xerr.Cause(), "failed to read %s by id %s", c.kind, id)
		case *retry.ErrStopRetry:
			return fail.Wrap(xerr.Cause(), "failed to read %s by id %s", c.kind, id)
		default:
			return fail.Wrap(xerr, "failed to read %s by id %s", c.kind, id)
		}
	}

	c.loaded = true
	c.committed = true

	return c.updateIdentity()
}

// readByID reads a metadata identified by ID from Object Storage
func (c *core) readByID(id string) fail.Error {
	return c.folder.Read(byIDFolderName, id, func(buf []byte) fail.Error {
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
func (c *core) readByReference(ref string) (xerr fail.Error) {
	timeout := temporal.GetCommunicationTimeout()
	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			if innerXErr := c.readByID(ref); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound: // If not found, stop immediately
					if xerr = c.readByName(ref); xerr != nil {
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
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			xerr = fail.Wrap(xerr.Cause(), "failed to read metadata of %s '%s' after %s", c.kind, ref, temporal.FormatDuration(timeout))
		case *retry.ErrStopRetry:
			xerr = fail.Wrap(xerr.Cause(), "failed to read metadata of %s '%s'", c.kind, ref)
		case *fail.ErrNotFound:
			xerr = fail.Wrap(xerr, "failed to find metadata of %s '%s'", c.kind, ref)
		default:
			xerr = fail.Wrap(xerr, "failed to read metadata of %s '%s'", c.kind, ref)
		}
	}
	return xerr
}

// readByName reads a metadata identified by name
func (c *core) readByName(name string) fail.Error {
	return c.folder.Read(byNameFolderName, name, func(buf []byte) fail.Error {
		if innerXErr := c.deserialize(buf); innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to deserialize %s resource", c.kind)
		}
		return nil
	})
}

// write updates the metadata corresponding to the host in the Object Storage
func (c *core) write() fail.Error {
	if !c.committed {
		jsoned, xerr := c.serialize()
		if xerr != nil {
			return xerr
		}

		if xerr = c.folder.Write(byNameFolderName, c.name.Load().(string), jsoned); xerr != nil {
			return xerr
		}

		if xerr = c.folder.Write(byIDFolderName, c.id.Load().(string), jsoned); xerr != nil {
			return xerr
		}

		c.loaded = true
		c.committed = true
	}
	return nil
}

// Reload reloads the content from the Object Storage
func (c *core) Reload() (xerr fail.Error) {
	if c.isNull() {
		return fail.InvalidInstanceError()
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	return c.reload()
}

// reload reloads the content from the Object Storage
// Note: must be called after locking the instance
func (c *core) reload() (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.loaded && !c.committed {
		return fail.InconsistentError("cannot reload a not committed data")
	}

	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			if innerXErr := c.readByID(c.id.Load().(string)); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound: // If not found, stop immediately
					return retry.StopRetryError(innerXErr)
				default:
					return innerXErr
				}
			}
			return nil
		},
		temporal.GetMinDelay(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			return fail.Wrap(xerr.Cause(), "failed to read %s by id %s", c.kind, c.id)
		case *retry.ErrStopRetry:
			return fail.Wrap(xerr.Cause(), "failed to read %s by id %s", c.kind, c.id)
		default:
			return fail.Wrap(xerr, "failed to read %s by id %s", c.kind, c.id)
		}
	}

	c.loaded = true
	c.committed = true

	return fail.ConvertError(c.notifyObservers())
}

// BrowseFolder walks through folder and executes a callback for each entries
func (c *core) BrowseFolder(callback func(buf []byte) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.folder.Browse(byIDFolderName, func(buf []byte) fail.Error {
		return callback(buf)
	})
}

// delete deletes the metadata
func (c *core) delete() (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
		return fail.InvalidInstanceError()
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	var (
		idFound, nameFound bool
		errors             []error
	)

	// Checks entries exist in Object Storage
	if xerr = c.folder.Lookup(byIDFolderName, c.id.Load().(string)); xerr != nil {
		// If not found, consider it not an error
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If entry not found, consider it not an error
		default:
			errors = append(errors, xerr)
		}
	} else {
		idFound = true
	}

	if xerr = c.folder.Lookup(byNameFolderName, c.name.Load().(string)); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If entry not found, consider it not an error
		default:
			errors = append(errors, xerr)
		}
	} else {
		nameFound = true
	}

	// Deletes entries found
	if idFound {
		if xerr = c.folder.Delete(byIDFolderName, c.id.Load().(string)); xerr != nil {
			errors = append(errors, xerr)
		}
	}
	if nameFound {
		if xerr = c.folder.Delete(byNameFolderName, c.name.Load().(string)); xerr != nil {
			errors = append(errors, xerr)
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
func (c *core) Serialize() (_ []byte, xerr fail.Error) {
	if c.isNull() {
		return nil, fail.InvalidInstanceError()
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.serialize()
}

// serialize serializes instance into bytes (output json code)
// Note: must be called after locking the instance
func (c *core) serialize() (_ []byte, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var (
		shieldedJSONed []byte
		shieldedMapped = map[string]interface{}{}
		propsMapped    = map[string]string{}
	)

	shieldedJSONed, xerr = c.shielded.Serialize()
	if xerr != nil {
		return nil, xerr
	}

	if err := json.Unmarshal(shieldedJSONed, &shieldedMapped); err != nil {
		// logrus.Tracef("*core.Serialize(): Unmarshalling JSONed shielded into map failed!")
		return nil, fail.NewError(err.Error())
	}

	if c.properties.Count() > 0 {
		propsJSONed, xerr := c.properties.Serialize()
		if xerr != nil {
			return nil, xerr
		}

		if len(propsJSONed) > 0 && string(propsJSONed) != `"{}"` {
			if jserr := json.Unmarshal(propsJSONed, &propsMapped); jserr != nil {
				// logrus.Tracef("*core.Serialize(): Unmarshalling JSONed properties into map failed!")
				return nil, fail.ConvertError(jserr)
			}
		}
	}

	shieldedMapped["properties"] = propsMapped
	// logrus.Tracef("everything mapped:\n%s\n", spew.Sdump(shieldedMapped))

	r, err := json.Marshal(shieldedMapped)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	return r, nil
}

// Deserialize reads json code and reinstantiates
func (c *core) Deserialize(buf []byte) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if c.isNull() {
		return fail.InvalidInstanceError()
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	return c.deserialize(buf)
}

// deserialize reads json code and reinstantiates
// Note: must be called after locking the instance
func (c *core) deserialize(buf []byte) (xerr fail.Error) {
	if c.properties == nil {
		c.properties, xerr = serialize.NewJSONProperties("resources." + c.kind)
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
		if err := json.Unmarshal(buf, &mapped); err != nil {
			return fail.SyntaxError("unmarshalling JSON to map failed: %s", err.Error())
		}
		if props, ok = mapped["properties"].(map[string]interface{}); ok {
			delete(mapped, "properties")
		}
	}

	jsoned, err := json.Marshal(mapped)
	if err != nil {
		return fail.SyntaxError("failed to marshal core to JSON: %s", err.Error())
	}

	if xerr = c.shielded.Deserialize(jsoned); xerr != nil {
		return fail.Wrap(xerr, "deserializing core failed")
	}

	if len(props) > 0 {
		jsoned, err = json.Marshal(props)
		if err != nil {
			return fail.SyntaxError("failed to marshal properties to JSON: %s", err.Error())
		}

		if xerr = c.properties.Deserialize(jsoned); xerr != nil {
			return fail.Wrap(xerr, "failed to deserialize properties")
		}
	}
	return nil
}

// Released is used to tell cache that the instance has been used and will not be anymore.
// Helps the cache handler to know when a cached item can be removed from cache (if needed)
// Note: Does nothing for now, prepared for future use
// satisfies interface data.Cacheable
func (c *core) Released() {
	if c.isNull() {
		return
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	c.released()
}

// released is used to tell cache that the instance has been used and will not be anymore.
// Helps the cache handler to know when a cached item can be removed from cache (if needed)
// Note: must be called after locking the instance
func (c *core) released() {
	for _, v := range c.observers {
		v.MarkAsFreed(c.id.Load().(string))
	}
}

// Destroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// Note: Does nothing for now, prepared for future use
// satisfies interface data.Cacheable
func (c *core) Destroyed() {
	if c.isNull() {
		return
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	c.destroyed()
}

// destroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// Note: Does nothing for now, prepared for future use
// Note: must be called after locking the instance
func (c *core) destroyed() {
	for _, v := range c.observers {
		v.MarkAsDeleted(c.id.Load().(string))
	}
}

// AddObserver ...
// satisfies interface data.Observable
func (c *core) AddObserver(o observer.Observer) error {
	if c.isNull() {
		return fail.InvalidInstanceError()
	}
	if o == nil {
		return fail.InvalidParameterError("o", "cannot be nil")
	}

	c.lock.Lock()
	defer c.lock.Unlock()

	if pre, ok := c.observers[c.id.Load().(string)]; ok {
		if pre == o {
			return fail.DuplicateError("there is already an Observer identified by '%s'", o.GetID())
		}
		return nil
	}
	c.observers[c.id.Load().(string)] = o
	return nil
}

// NotifyObservers sends a signal to all registered Observers to notify change
// Satisfies interface data.Observable
func (c *core) NotifyObservers() error {
	if c.isNull() {
		return fail.InvalidInstanceError()
	}

	c.lock.RLock()
	defer c.lock.RUnlock()

	return c.notifyObservers()
}

// notifyObservers sends a signal to all registered Observers to notify change
// Note: must be called after locking the instance
func (c *core) notifyObservers() error {
	for _, v := range c.observers {
		v.SignalChange(c.id.Load().(string))
	}
	return nil
}

// RemoveObserver ...
func (c *core) RemoveObserver(name string) error {
	if c.isNull() {
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
