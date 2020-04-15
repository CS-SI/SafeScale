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

package concurrency

import (
	"encoding/json"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// Shielded allows to store data with controlled access to it
type Shielded struct {
	witness data.Clonable
	lock    TaskedLock
}

// NewShielded creates a new protected data
func NewShielded(witness data.Clonable) *Shielded {
	return &Shielded{
		witness: witness,
		lock:    NewTaskedLock(),
	}
}

// Clone ...
func (d *Shielded) Clone() *Shielded {
	return NewShielded(d.witness.Clone())
}

// Inspect is used to lock a clonable for read
func (d *Shielded) Inspect(task Task, inspector func(clonable data.Clonable) error) (err error) {
	if d == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if inspector == nil {
		return scerr.InvalidParameterError("inspector", "cannot be nil")
	}
	if d.witness == nil {
		return scerr.InvalidParameterError("d.witness", "cannot be nil; use concurrency.NewShielded() to instantiate")
	}

	err = d.lock.RLock(task)
	if err != nil {
		return err
	}
	defer func() {
		unlockErr := d.lock.RUnlock(task)
		if unlockErr != nil {
			logrus.Warn(unlockErr)
		}
		if err == nil && unlockErr != nil {
			err = unlockErr
		}
	}()

	return inspector(d.witness.Clone())
}

// Alter allows to update a cloneable using a write lock
func (d *Shielded) Alter(task Task, alterer func(data.Clonable) error) (err error) {
	if d == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if alterer == nil {
		return scerr.InvalidParameterError("alterer", "cannot be nil")
	}
	if d.witness == nil {
		return scerr.InvalidParameterError("d.witness", "cannot be nil; use concurrency.NewData() to instantiate")
	}

	err = d.lock.Lock(task)
	if err != nil {
		return err
	}
	defer func() {
		unlockErr := d.lock.Unlock(task)
		if unlockErr != nil {
			logrus.Warn(unlockErr)
		}
		if err == nil && unlockErr != nil {
			err = unlockErr
		}
	}()

	clone := d.witness.Clone()
	err = alterer(clone)
	if err != nil {
		return err
	}
	_ = d.witness.Replace(clone)
	return nil
}

// Serialize transforms content of Shielded instance to data suitable for serialization
// Note: doesn't follow interface data.Serializable (task parameter not used in it)
func (d *Shielded) Serialize(task Task) ([]byte, error) {
	if d == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	var jsoned []byte
	err := d.Inspect(task, func (clonable data.Clonable) error {
		var innerErr error
		jsoned, innerErr = json.Marshal(clonable)
		return innerErr
	})
	if err != nil {
		return nil, err
	}
	return jsoned, nil
}

// Deserialize transforms serialization data to valid content of Shielded instance
// Note: doesn't follow interface data.Serializable (task parameter not used in it)
func (d *Shielded) Deserialize(task Task, buf []byte) error {
	if d == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if len(buf) == 0 {
		return scerr.InvalidParameterError("buf", "cannot be empty []byte")
	}

	return d.Alter(task, func(clonable data.Clonable) error {
		return json.Unmarshal(buf, clonable)
	})
}