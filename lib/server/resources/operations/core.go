/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"sync/atomic"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

const (
	// byIDFolderName tells in what folder to put 'byID' information
	byIDFolderName = "byID"
	// byNameFolderName tells in what folder to store 'byName' information
	byNameFolderName = "byName"
)

// core contains the core functions of a persistent object
type core struct {
	concurrency.TaskedLock `json:"-"`

	kind       string
	shielded   *concurrency.Shielded
	properties *serialize.JSONProperties
	folder     folder
	loaded     bool
	committed  bool
	name       atomic.Value
	id         atomic.Value
}

func nullCore() *core {
	return &core{kind: "nil"}
}

// newCore creates an instance of core
func newCore(svc iaas.Service, kind string, path string, instance data.Clonable) (*core, fail.Error) {
	if svc.IsNull() {
		return nullCore(), fail.InvalidParameterError("svc", "cannot be nil")
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
		TaskedLock: concurrency.NewTaskedLock(),
		shielded:   concurrency.NewShielded(instance),
	}
	return &c, nil
}

// IsNull returns true if the core instance represents the null value for core
func (c *core) IsNull() bool {
	return c == nil || c.kind == "" || c.kind == "nil" || c.folder.IsNull()
}

// GetService returns the iaas.GetService used to create/load the persistent object
func (c core) GetService() iaas.Service {
	if !c.IsNull() {
		return c.folder.GetService()
	}
	return nil
}

// GetID returns the id of the data protected
// satisfies interface data.Identifiable
func (c core) GetID() string {
	if c.IsNull() {
		return "<NullCore>"
	}
	if id, ok := c.id.Load().(string); ok {
		return id
	}
	return ""
}

// GetName returns the name of the data protected
// satisfies interface data.Identifiable
func (c core) GetName() string {
	if c.IsNull() {
		return "<NullCore>"
	}
	if name, ok := c.name.Load().(string); ok {
		return name
	}
	return ""
}

// Inspect protects the data for shared read
func (c *core) Inspect(task concurrency.Task, callback resources.Callback) (xerr fail.Error) {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}
	if c.properties == nil {
		return fail.InvalidInstanceContentError("c.properties", "cannot be nil")
	}

	// Reload reloads data from objectstorage to be sure to have the last revision
	if xerr = c.Reload(task); xerr != nil {
		return fail.Wrap(xerr, "failed to reload")
	}

	return c.shielded.Inspect(task, func(clonable data.Clonable) fail.Error {
		return callback(clonable, c.properties)
	})
}

// Alter protects the data for exclusive write
func (c *core) Alter(task concurrency.Task, callback resources.Callback) (xerr fail.Error) {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if c.shielded == nil {
		return fail.InvalidInstanceContentError("c.shielded", "cannot be nil")
	}

	// Make sure c.properties is populated
	if c.properties == nil {
		if c.properties, xerr = serialize.NewJSONProperties("resources." + c.kind); xerr != nil {
			return xerr
		}
	}

	// Reload reloads data from objectstorage to be sure to have the last revision
	if xerr = c.Reload(task); xerr != nil {
		return fail.Wrap(xerr, "failed to reload metadata")
	}

	xerr = c.shielded.Alter(task, func(clonable data.Clonable) fail.Error {
		return callback(clonable, c.properties)
	})
	if xerr != nil {
		return xerr
	}

	c.committed = false
	return c.write(task)
}

// Carry links metadata with real data
// If c is already carrying a shielded data, returns fail.NotAvailableError
//
// errors returned :
// - fail.ErrInvalidInstance
// - fail.ErrInvalidParameter
// - fail.ErrNotAvailable if the core instance already carries a data
func (c *core) Carry(task concurrency.Task, clonable data.Clonable) fail.Error {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if clonable == nil {
		return fail.InvalidParameterError("clonable", "cannot be nil")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if c.shielded == nil {
		return fail.InvalidInstanceContentError("c.shielded", "cannot be nil")
	}
	if c.loaded {
		return fail.NotAvailableError("already carrying a value")
	}

	c.shielded = concurrency.NewShielded(clonable)
	c.loaded = true
	err := c.updateIdentity(task)
	if err != nil {
		return err
	}
	c.committed = false
	return c.write(task)
}

func (c *core) updateIdentity(task concurrency.Task) fail.Error {
	if c.loaded {
		return c.shielded.Inspect(task, func(clonable data.Clonable) fail.Error {
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
	return nil
}

// Read gets the data from Object Storage
func (c *core) Read(task concurrency.Task, ref string) fail.Error {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return fail.InvalidParameterError("ref", "cannot be empty string")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if c.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	// VPL: because of read-after-write check, no need to retry read
	// xerr := retry.WhileUnsuccessfulDelay1Second(
	// 	func() error {
	// 		if innerErr := c.readByReference(task, ref); innerErr != nil {
	// 			switch innerErr.(type) {
	// 			case *fail.ErrNotFound: // If not found, stop immediately
	// 				return retry.StopRetryError(innerErr)
	// 			default:
	// 				return innerErr
	// 			}
	// 		}
	// 		return nil
	// 	},
	// 	temporal.GetMinDelay(),
	// )
	xerr := c.readByReference(task, ref)
	if xerr != nil {
		// switch xerr.(type) {
		// case *retry.ErrTimeout:
		// 	return fail.NotFoundError("failed to load metadata of %s '%s'", c.kind, ref)
		// case *retry.ErrStopRetry:
		// 	// If stopped immediately, the cause contains the reason which should be a *fail.ErrNotFound
		// 	return fail.ToError(xerr.Cause())
		// default:
		return xerr
		// }
	}

	c.loaded = true
	c.committed = true
	return c.updateIdentity(task)
}

// ReadByID reads a metadata identified by ID from Object Storage
func (c *core) ReadByID(task concurrency.Task, id string) fail.Error {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if id = strings.TrimSpace(id); id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if c.loaded {
		return fail.NotAvailableError("metadata is already carrying a value")
	}

	// xerr := retry.WhileUnsuccessfulDelay1Second(
	// 	func() error {
	// 		if innerErr := c.readByID(task, id); innerErr != nil {
	// 			switch innerErr.(type) {
	// 			case *fail.ErrNotFound: // If not found, stop immediately
	// 				return retry.StopRetryError(innerErr)
	// 			default:
	// 				return innerErr
	// 			}
	// 		}
	// 		return nil
	// 	},
	// 	temporal.GetMinDelay(),
	// )
	xerr := c.readByID(task, id)
	if xerr != nil {
		// switch xerr.(type) {
		// case *retry.ErrTimeout:
		// 	return fail.NotFoundError("failed to load metadata of %s %s", c.kind, id)
		// case *retry.ErrStopRetry:
		// 	// If stopped immediately, the cause contains the reason which should be a *fail.ErrNotFound
		// 	return fail.ToError(xerr.Cause())
		// default:
		return xerr
		// }
	}

	c.loaded = true
	c.committed = true
	return c.updateIdentity(task)
}

// readByID reads a metadata identified by ID from Object Storage
func (c *core) readByID(task concurrency.Task, id string) fail.Error {
	return c.folder.Read(byIDFolderName, id, func(buf []byte) fail.Error {
		if innerXErr := c.Deserialize(task, buf); innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to deserialize %s resource", c.kind)
		}
		return nil
	})
}

// readByReference gets the data from Object Storage
// First read using 'ref' as an ID; if *fail.ErrNotFound occurs, read using 'ref' as a name
func (c *core) readByReference(task concurrency.Task, ref string) (xerr fail.Error) {
	if xerr = c.readByID(task, ref); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound /*, *fail.ErrTimeout*/ :
			xerr = c.readByName(task, ref)
		default:
			return xerr
		}
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound /*, *fail.ErrTimeout*/ :
			return fail.NotFoundError("failed to find %s '%s'", c.kind, ref)
		}
	}
	return xerr
}

// readByName reads a metadata identified by name
func (c *core) readByName(task concurrency.Task, name string) fail.Error {
	return c.folder.Read(byNameFolderName, name, func(buf []byte) fail.Error {
		if innerXErr := c.Deserialize(task, buf); innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to deserialize %s resource", c.kind)
		}
		return nil
	})
}

// write updates the metadata corresponding to the host in the Object Storage
func (c *core) write(task concurrency.Task) fail.Error {
	if !c.committed {
		jsoned, xerr := c.Serialize(task)
		if xerr != nil {
			return xerr
		}

		if xerr = c.folder.Write(byNameFolderName, c.GetName(), jsoned); xerr != nil {
			return xerr
		}

		if xerr = c.folder.Write(byIDFolderName, c.GetID(), jsoned); xerr != nil {
			return xerr
		}

		c.loaded = true
		c.committed = true
	}
	return nil
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance (being written or not...)
func (c *core) Reload(task concurrency.Task) fail.Error {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	if c.loaded && !c.committed {
		return fail.OverloadError("altered and not committed")
	}

	if xerr := c.readByReference(task, c.GetID()); xerr != nil {
		return xerr
	}
	c.loaded = true
	c.committed = true
	return nil
}

// BrowseFolder walks through host folder and executes a callback for each entries
func (c core) BrowseFolder(task concurrency.Task, callback func(buf []byte) fail.Error) fail.Error {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	return c.folder.Browse(byIDFolderName, func(buf []byte) fail.Error {
		return callback(buf)
	})
}

// Delete deletes the matadata
func (c *core) Delete(task concurrency.Task) fail.Error {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	var idFound, nameFound bool
	id := c.GetID()
	name := c.GetName()

	var errors []error
	// Checks entries exist in Object Storage
	if xerr := c.folder.Lookup(byIDFolderName, id); xerr != nil {
		// If not found, consider it not an error
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			errors = append(errors, xerr)
		}
	} else {
		idFound = true
	}

	if xerr := c.folder.Lookup(byNameFolderName, name); xerr != nil {
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
		if xerr := c.folder.Delete(byIDFolderName, id); xerr != nil {
			errors = append(errors, xerr)
		}
	}
	if nameFound {
		if xerr := c.folder.Delete(byNameFolderName, name); xerr != nil {
			errors = append(errors, xerr)
		}
	}

	c.loaded = false
	c.committed = false

	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}
	return nil
}

// Serialize serializes instance into bytes (output json code)
// Note: doesn't follow interface data.Serializable (task parameter not used in it)
func (c core) Serialize(task concurrency.Task) (_ []byte, xerr fail.Error) {
	if c.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to serialize %s resource '%s'", c.kind, c.GetName())
		}
	}()

	var (
		shieldedJSONed []byte
		shieldedMapped = map[string]interface{}{}
		propsMapped    = map[string]string{}
	)
	defer fail.OnPanic(&xerr) // json.Unmarshal may panic

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	shieldedJSONed, xerr = c.shielded.Serialize(task)
	if xerr != nil {
		return nil, xerr
	}
	if err := json.Unmarshal(shieldedJSONed, &shieldedMapped); err != nil {
		// logrus.Tracef("*core.Serialize(): Unmarshalling JSONed shielded into map failed!")
		return nil, fail.NewError(err.Error())
	}

	if c.properties.Count() > 0 {
		propsJSONed, err := c.properties.Serialize(task)
		if err != nil {
			return nil, err
		}
		if len(propsJSONed) > 0 && string(propsJSONed) != `"{}"` {
			if jserr := json.Unmarshal(propsJSONed, &propsMapped); jserr != nil {
				// logrus.Tracef("*core.Serialize(): Unmarshalling JSONed properties into map failed!")
				return nil, fail.ToError(jserr)
			}
		}
	}

	shieldedMapped["properties"] = propsMapped
	// logrus.Tracef("everything mapped:\n%s\n", spew.Sdump(shieldedMapped))

	r, err := json.Marshal(shieldedMapped)
	if err != nil {
		return nil, fail.ToError(err)
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates
// Note: doesn't follow interface data.Serializable (task parameter not used in the interface and needed here)
func (c *core) Deserialize(task concurrency.Task, buf []byte) (xerr fail.Error) {
	if c.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	// defer func() {
	// 	if xerr != nil {
	// 		xerr = fail.Wrap(xerr, "failed to deserialize %s resource", c.kind)
	// 	}
	// }()

	defer fail.OnPanic(&xerr) // json.Unmarshal may panic

	c.SafeLock(task)
	defer c.SafeUnlock(task)

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

	if err := json.Unmarshal(buf, &mapped); err != nil {
		logrus.Tracef("*core.Deserialize(): Unmarshalling buf to map failed!")
		return fail.ToError(err)
	}
	if props, ok = mapped["properties"].(map[string]interface{}); ok {
		delete(mapped, "properties")
	}
	jsoned, err := json.Marshal(mapped)
	if err != nil {
		return fail.ToError(err)
	}
	if xerr = c.shielded.Deserialize(task, jsoned); xerr != nil {
		return xerr
	}
	if len(props) > 0 {
		jsoned, err = json.Marshal(props)
		if err != nil {
			return fail.ToError(err)
		}
		if xerr = c.properties.Deserialize(task, jsoned); xerr != nil {
			return xerr
		}
	}
	return nil
}
