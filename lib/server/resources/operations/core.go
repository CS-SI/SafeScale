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
	"reflect"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

const (
	//byIDFolderName tells in what folder to put 'byID' information
	byIDFolderName = "byID"
	//byNameFolderName tells in what folder to store 'byName' information
	byNameFolderName = "byName"
)

// core contains the core functions of a persistent object
type core struct {
	concurrency.TaskedLock `json:"-"`

	kind       string
	shielded   *concurrency.Shielded
	properties *serialize.JSONProperties
	folder     *folder
	loaded     bool
	committed  bool
	name       atomic.Value
	id         atomic.Value
}

func nullCore() *core {
	return &core{kind: "nil"}
}

// NewCore creates an instance of core
func NewCore(svc iaas.Service, kind string, path string, instance data.Clonable) (*core, error) {
	if svc == nil {
		return nullCore(), scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if kind == "" {
		return nullCore(), scerr.InvalidParameterError("kind", "cannot be empty string")
	}
	if path == "" {
		return nullCore(), scerr.InvalidParameterError("path", "cannot be empty string")
	}

	fld, err := newFolder(svc, path)
	if err != nil {
		return nullCore(), err
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
	return c == nil || c.kind == "" || c.kind == "nil"
}

// SafeGetService returns the iaas.Service used to create/load the persistent object
func (c *core) SafeGetService() iaas.Service {
	if !c.IsNull() && c.folder != nil {
		return c.folder.SafeGetService()
	}
	return nil
}

// SafeGetID returns the id of the data protected
//
// satisfies interface data.Identifyable
func (c *core) SafeGetID() string {
	if c.IsNull() {
		return "<NullCore>"
	}
	if id, ok := c.id.Load().(string); ok {
		return id
	}
	return ""
}

// SafeGetName returns the name of the data protected
//
// satisfies interface data.Identifyable
func (c *core) SafeGetName() string {
	if c.IsNull() {
		return "<NullCore>"
	}
	if name, ok := c.name.Load().(string); ok {
		return name
	}
	return ""
}

// Inspect protects the data for shared read
func (c *core) Inspect(task concurrency.Task, callback resources.Callback) (err error) {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	// Check c.properties is populated
	c.SafeLock(task)
	if c.properties == nil {
		c.properties, err = serialize.NewJSONProperties("resources." + c.kind)
		if err != nil {
			c.SafeUnlock(task)
			return err
		}
	}
	c.SafeUnlock(task)

	// Reload reloads data from objectstorage to be sure to have the last revision
	err = c.Reload(task)
	if err != nil {
		return err
	}

	return c.shielded.Inspect(task, func(clonable data.Clonable) error {
		return callback(clonable, c.properties)
	})
}

// Alter protects the data for exclusive write
func (c *core) Alter(task concurrency.Task, callback resources.Callback) (err error) {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if c.shielded == nil {
		return scerr.InvalidInstanceContentError("c.shielded", "cannot be nil")
	}

	// Make sure c.properties is populated
	if c.properties == nil {
		c.properties, err = serialize.NewJSONProperties("resources." + c.kind)
		if err != nil {
			return err
		}
	}

	// Reload reloads data from objectstorage to be sure to have the last revision
	err = c.Reload(task)
	if err != nil {
		return err
	}

	err = c.shielded.Alter(task, func(clonable data.Clonable) error {
		return callback(clonable, c.properties)
	})
	if err != nil {
		return err
	}
	c.committed = false
	return c.write(task)
}

// Carry links metadata with real data
// If c is already carrying a shielded data, returns scerr.NotAvailableError
//
// errors returned :
// - scerr.ErrInvalidInstance
// - scerr.ErrInvalidParameter
// - scerr.ErrNotAvailable if the core instance already carries a data
func (c *core) Carry(task concurrency.Task, clonable data.Clonable) error {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if clonable == nil {
		return scerr.InvalidParameterError("clonable", "cannot be nil")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if c.loaded {
		return scerr.NotAvailableError("already carrying a shielded value")
	}
	if c.shielded == nil {
		return scerr.InvalidInstanceContentError("c.shielded", "cannot be nil")
	}

	c.shielded = concurrency.NewShielded(clonable)
	c.loaded = true
	err := c.updateIdentity(task)
	if err != nil {
		return err
	}
	return c.write(task)
}

func (c *core) updateIdentity(task concurrency.Task) error {
	if c.loaded {
		return c.shielded.Inspect(task, func(clonable data.Clonable) error {
			ident, ok := clonable.(data.Identifyable)
			if !ok {
				return scerr.InconsistentError("'data.Identifyable' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			c.name.Store(ident.SafeGetName())
			c.id.Store(ident.SafeGetID())
			return nil
		})
	}

	c.name.Store("")
	c.id.Store("")
	return nil
}

// Read gets the data from Object Storage
// if error is ErrNotFound then read by name; if error is ErrNotFound return this error
// In case of any other error, abort the retry to propagate the error
// If retry times out, returns errNotFound
func (c *core) Read(task concurrency.Task, ref string) error {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if ref == "" {
		return scerr.InvalidParameterError("ref", "cannot be empty string")
	}
	if c.loaded {
		return scerr.NotAvailableError("metadata is already carrying a value")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	err := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			inErr := c.readByReference(task, ref)
			if inErr != nil {
				if _, ok := inErr.(scerr.ErrNotFound); ok {
					return inErr
				}
				return retry.StopRetryError(inErr)
			}
			return nil
		},
		10*time.Second,
	)
	if err != nil {
		switch err.(type) {
		case retry.ErrTimeout:
			logrus.Debugf("timeout reading metadata of %s '%s'", c.kind, ref)
			return scerr.NotFoundError(fmt.Sprintf("failed to load metadata of %s '%s'", c.kind, ref))
		case retry.ErrStopRetry:
			// return err.Cause()
			return err
		default:
			return err
		}
	}

	c.loaded = true
	return c.updateIdentity(task)
}

func (c *core) readByReference(task concurrency.Task, ref string) error {
	err := c.readByID(task, ref)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
		err = c.readByName(task, ref)
	}
	return err
}

// readByID reads a metadata identified by ID from Object Storage
func (c *core) readByID(task concurrency.Task, id string) error {
	return c.folder.Read(byIDFolderName, id, func(buf []byte) error {
		return c.Deserialize(task, buf)
	})
}

// readByName reads a metadata identified by name
func (c *core) readByName(task concurrency.Task, name string) error {
	return c.folder.Read(byNameFolderName, name, func(buf []byte) error {
		return c.Deserialize(task, buf)
	})
}

// write updates the metadata corresponding to the host in the Object Storage
func (c *core) write(task concurrency.Task) error {
	if !c.committed {
		jsoned, err := c.Serialize(task)
		if err != nil {
			return err
		}
		err = c.folder.Write(byNameFolderName, c.SafeGetName(), jsoned)
		if err != nil {
			return err
		}
		err = c.folder.Write(byIDFolderName, c.SafeGetID(), jsoned)
		if err != nil {
			return err
		}
		c.loaded = true
		c.committed = true
	}
	return nil
}

// Reload reloads the content of the Object Storage, overriding what is in the metadata instance (being written or not...)
func (c *core) Reload(task concurrency.Task) error {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	err := c.readByID(task, c.SafeGetID())
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return scerr.NotFoundError(fmt.Sprintf("the metadata of %s '%s' vanished", c.kind, c.name))
		}
		return err
	}
	return nil
}

// BrowseFolder walks through host folder and executes a callback for each entries
func (c *core) BrowseFolder(task concurrency.Task, callback func(buf []byte) error) error {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	return c.folder.Browse(byIDFolderName, func(buf []byte) error {
		return callback(buf)
	})
}

// Delete deletes the matadata
func (c *core) Delete(task concurrency.Task) error {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	var idFound, nameFound bool
	id := c.SafeGetID()
	name := c.SafeGetName()

	// Checks entries exist in Object Storage
	err := c.folder.Search(byIDFolderName, id)
	if err != nil {
		// If not found, consider it not an error
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
	} else {
		idFound = true
	}

	err = c.folder.Search(byNameFolderName, name)
	if err != nil {
		// If entry not found, consider it not an error
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
	} else {
		nameFound = true
	}

	// Deletes entries found
	if idFound {
		err = c.folder.Delete(byIDFolderName, id)
		if err != nil {
			return err
		}
	}
	if nameFound {
		err = c.folder.Delete(byNameFolderName, name)
		if err != nil {
			return err
		}
	}

	c.loaded = false
	c.committed = false
	return nil
}

// Serialize serializes instance into bytes (output json code)
// Note: doesn't follow interface data.Serializable (task parameter not used in it)
func (c *core) Serialize(task concurrency.Task) (_ []byte, err error) {
	if c.IsNull() {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "failed to serialize %s resource '%s'", c.kind, c.SafeGetName())
		}
	}()

	var (
		shieldedJSONed []byte
		shieldedMapped = map[string]interface{}{}
		propsMapped    = map[string]string{}
	)
	defer scerr.OnPanic(&err)() // json.Unmarshal may panic

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	shieldedJSONed, err = c.shielded.Serialize(task)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(shieldedJSONed, &shieldedMapped)
	if err != nil {
		// logrus.Tracef("*core.Serialize(): Unmarshalling JSONed shielded into map failed!")
		return nil, err
	}

	if c.properties.Count() > 0 {
		propsJSONed, err := c.properties.Serialize(task)
		if err != nil {
			return nil, err
		}
		if len(propsJSONed) > 0 && string(propsJSONed) != `"{}"` {
			err = json.Unmarshal(propsJSONed, &propsMapped)
			if err != nil {
				// logrus.Tracef("*core.Serialize(): Unmarshalling JSONed properties into map failed!")
				return nil, err
			}
		}
	}

	shieldedMapped["properties"] = propsMapped
	// logrus.Tracef("everything mapped:\n%s\n", spew.Sdump(shieldedMapped))

	return json.Marshal(shieldedMapped)
}

// Deserialize reads json code and reinstantiates
// Note: doesn't follow interface data.Serializable (task parameter not used in it)
func (c *core) Deserialize(task concurrency.Task, buf []byte) (err error) {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "failed to deserialize %s resource", c.kind)
		}
	}()

	defer scerr.OnPanic(&err)() // json.Unmarshal may panic

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	if c.properties == nil {
		c.properties, err = serialize.NewJSONProperties("resources." + c.kind)
		if err != nil {
			return err
		}
	}

	var (
		mapped, props map[string]interface{}
		ok            bool
		jsoned        []byte
	)

	err = json.Unmarshal(buf, &mapped)
	if err != nil {
		logrus.Tracef("*core.Deserialize(): Unmarshalling buf to map failed!")
		return err
	}
	if props, ok = mapped["properties"].(map[string]interface{}); ok {
		delete(mapped, "properties")
	}
	jsoned, err = json.Marshal(mapped)
	if err != nil {
		return err
	}
	err = c.shielded.Deserialize(task, jsoned)
	if err != nil {
		return err
	}
	if len(props) > 0 {
		jsoned, err = json.Marshal(props)
		if err != nil {
			return err
		}
		err = c.properties.Deserialize(task, jsoned)
		if err != nil {
			return err
		}
	}
	return nil
}
