/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package shielded

import (
	"sync"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sanity-io/litter"
)

// Shielded allows to store data with controlled access to it
type Shielded[T clonable.Clonable] struct {
	witness T
	lock    *sync.RWMutex
}

// NewShielded creates a new protected data from a witness
func NewShielded[T clonable.Clonable](witness T) (*Shielded[T], error) {
	out := &Shielded[T]{
		witness: witness,
		lock:    &sync.RWMutex{},
	}
	return out, nil
}

// IsNull ...
// satisfies interface clonable.Clonable
func (instance *Shielded[T]) IsNull() bool {
	return instance == nil || valid.IsNil(instance.witness) || instance.lock == nil
}

// Clone ...
func (instance *Shielded[T]) Clone() (clonable.Clonable, error) {
	castedClone, err := clonable.CastedClone[T](instance.witness)
	if err != nil {
		return nil, err
	}

	return NewShielded[T](castedClone)
}

// Replace ...
func (instance *Shielded[T]) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Shielded[T]](in)
	if err != nil {
		return err
	}

	return instance.witness.Replace(src.witness)
}

// String returns a string representation of the Shielded
func (instance *Shielded[T]) String() (string, error) {
	instance.lock.RLock()
	defer instance.lock.RUnlock()

	sq := litter.Options{
		HidePrivateFields: false,
	}
	return sq.Sdump(instance.witness), nil
}

// Inspect is used to lock a clonable for read
func (instance *Shielded[T]) Inspect(inspector func(p T) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if inspector == nil {
		return fail.InvalidParameterCannotBeNilError("inspector")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	if any(instance.witness) == any(nil) {
		return fail.InvalidInstanceContentError("d.witness", "cannot be nil; use concurrency.NewShielded() to instantiate")
	}

	cloned, err := clonable.CastedClone[T](instance.witness)
	if err != nil {
		return fail.InconsistentErrorWithCause(err, nil, "d.witness", "cannot be cloned")
	}

	return inspector(cloned)
}

// Alter allows to update a cloneable using a write-lock
// 'alterer' can use a special error to tell the outside there was no change : fail.ErrAlteredNothing, which can be
// generated with fail.AlteredNothingError().
// The caller of the Alter() method will then be able to known, when an error occurs, if it's because there was no change.
func (instance *Shielded[T]) Alter(alterer func(T) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if alterer == nil {
		return fail.InvalidParameterCannotBeNilError("alterer")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	if any(instance.witness) == any(nil) {
		return fail.InvalidInstanceContentError("d.witness", "cannot be nil; use concurrency.NewData() to instantiate")
	}

	var xerr fail.Error
	clone, err := clonable.CastedClone[T](instance.witness)
	if err != nil {
		return fail.Wrap(err)
	}

	if xerr = alterer(clone); xerr != nil {
		return xerr
	}

	err = instance.witness.Replace(clone)
	if err != nil {
		return fail.Wrap(err)
	}

	return nil
}

// Serialize transforms content of Shielded instance to data suitable for serialization
// Note: doesn't follow interface data.Serializable (task parameter not used in it)
func (instance *Shielded[T]) Serialize() (_ []byte, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	var jsoned []byte
	xerr := instance.Inspect(func(p T) fail.Error {
		var innerErr error
		jsoned, innerErr = json.Marshal(p)
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
func (instance *Shielded[T]) Deserialize(buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if len(buf) == 0 {
		return fail.InvalidParameterError("buf", "cannot be empty []byte")
	}

	return instance.Alter(func(p T) fail.Error {
		innerErr := json.Unmarshal(buf, p)
		if innerErr != nil {
			return fail.SyntaxError("failed to unmarshal: %s", innerErr.Error())
		}

		return nil
	})
}
