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

package concurrency

import (
	"encoding/json"
	"sync"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Shielded allows to store data with controlled access to it
type Shielded struct {
	witness data.Clonable
	// lock    TaskedLock
	lock sync.RWMutex
}

// NewShielded creates a new protected data from a cloned witness
func NewShielded(witness data.Clonable) *Shielded {
	return &Shielded{
		witness: witness.Clone(),
		// lock:    NewTaskedLock(),
	}
}

// Clone ...
func (instance *Shielded) Clone() *Shielded {
	return NewShielded(instance.witness.Clone())
}

// Inspect is used to lock a clonable for read
func (instance *Shielded) Inspect(task Task, inspector func(clonable data.Clonable) fail.Error) (xerr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if inspector == nil {
		return fail.InvalidParameterCannotBeNilError("inspector")
	}
	if instance.witness == nil {
		return fail.InvalidParameterError("d.witness", "cannot be nil; use concurrency.NewShielded() to instantiate")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// if xerr = d.lock.RLock(task); xerr != nil {
	// 	return xerr
	// }
	instance.lock.RLock()
	// defer func() {
	// 	unlockErr := d.lock.RUnlock(task)
	// 	if unlockErr != nil {
	// 		logrus.Warn(unlockErr)
	// 	}
	// 	if xerr == nil && unlockErr != nil {
	// 		xerr = unlockErr
	// 	}
	// }()
	defer instance.lock.RUnlock()

	return inspector(instance.witness.Clone())
}

// Alter allows to update a cloneable using a write lock
// 'alterer' can use a special error to tell the outside there was no change : fail.ErrAlteredNothing, which can be
// generated with fail.AlteredNothingError().
// The caller of the Alter() method will then be able to known, when an error occurs, if it's because there was no change.
func (instance *Shielded) Alter(task Task, alterer func(data.Clonable) fail.Error) (xerr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if alterer == nil {
		return fail.InvalidParameterCannotBeNilError("alterer")
	}
	if instance.witness == nil {
		return fail.InvalidParameterError("d.witness", "cannot be nil; use concurrency.NewData() to instantiate")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	// if xerr = d.lock.Lock(task); xerr != nil {
	// 	return xerr
	// }
	defer instance.lock.Unlock()
	// defer func() {
	// 	unlockErr := d.lock.Unlock(task)
	// 	if unlockErr != nil {
	// 		logrus.Warn(unlockErr)
	// 	}
	// 	if xerr == nil && unlockErr != nil {
	// 		xerr = unlockErr
	// 	}
	// }()

	clone := instance.witness.Clone()
	if xerr = alterer(clone); xerr != nil {
		return xerr
	}

	_ = instance.witness.Replace(clone)
	return nil
}

// Serialize transforms content of Shielded instance to data suitable for serialization
// Note: doesn't follow interface data.Serializable (task parameter not used in it)
func (instance *Shielded) Serialize(task Task) ([]byte, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	var jsoned []byte
	xerr := instance.Inspect(task, func(clonable data.Clonable) fail.Error {
		var innerErr error
		jsoned, innerErr = json.Marshal(clonable)
		if innerErr != nil {
			return fail.SyntaxError("failed to marshal: %s", innerErr.Error())
		}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return jsoned, nil
}

// Deserialize transforms serialization data to valid content of Shielded instance
// Note: doesn't follow interface data.Serializable (task parameter not used in it)
func (instance *Shielded) Deserialize(task Task, buf []byte) fail.Error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if len(buf) == 0 {
		return fail.InvalidParameterError("buf", "cannot be empty []byte")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.Alter(task, func(clonable data.Clonable) fail.Error {
		if innerErr := json.Unmarshal(buf, clonable); innerErr != nil {
			return fail.SyntaxError("failed to unmarshal: %s", innerErr.Error())
		}

		return nil
	})
}
