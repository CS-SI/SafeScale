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

package result

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/utils/data/result.Group -o mocks/mock_group.go

// Group ...
type Group[T any, HT Holder[T]] interface {
	Add(string, HT) fail.Error
	Error() error
	ErrorMessage() string
	IsCompleted() bool
	IsFrozen() bool
	IsSuccessful() bool
	Keys() ([]string, fail.Error)
	Payload() (data.Map[string, HT], fail.Error)
	PayloadOf(key string) (HT, fail.Error)
	UncompletedKeys() ([]string, fail.Error)
}

// Group contains the errors of the step for each host target
type group[T any, HT Holder[T]] struct {
	data.Map[string, HT]
}

// NewGroup returns a new instance of group
func NewGroup[T any, HT Holder[T]]() *group[T, HT] {
	return &group[T, HT]{
		Map: data.NewMap[string, HT](),
	}
}

// Add adds a new entry with key; will fail if key is already used
func (rg *group[T, HT]) Add(key string, r HT) fail.Error {
	if valid.IsNull(rg) {
		return fail.InvalidInstanceError()
	}

	_, ok := rg.Map[key]
	if ok {
		return fail.DuplicateError("there is already a value associated with key '%s'", key)
	}

	rg.Map[key] = r
	return nil
}

// Replace works as Add, except it will replace the key value if it already exists
func (rg *group[T, HT]) Replace(key string, r HT) fail.Error {
	if valid.IsNull(rg) {
		return fail.InvalidInstanceError()
	}

	rg.Map[key] = r
	return nil
}

// ErrorMessage returns a string containing all the errors registered
func (rg *group[T, HT]) ErrorMessage() string {
	if valid.IsNull(rg) {
		return ""
	}

	output := ""
	for k, v := range rg.Map {
		val := v.ErrorMessage()
		if val != "" {
			if output != "" {
				output += ", "
			}
			output += k + ": " + val
		}
	}
	return output
}

// Error returns a fail.ErrorList contains all the errors of the members of the group
func (rg *group[T, HT]) Error() error {
	var errs []error
	for _, v := range rg.Map {
		val := v.Error()
		if val != nil {
			errs = append(errs, val)
		}
	}
	if len(errs) > 0 {
		return fail.NewErrorList(errs)
	}

	return nil
}

// Keys ...
func (rg *group[T, HT]) Keys() ([]string, fail.Error) {
	if valid.IsNull(rg) {
		return nil, fail.InvalidInstanceError()
	}

	return rg.Map.Keys(), nil
}

// UncompletedKeys returns an array of all keys that are marked as uncompleted
func (rg *group[T, HT]) UncompletedKeys() ([]string, fail.Error) {
	if valid.IsNull(rg) {
		return nil, fail.InvalidInstanceError()
	}

	var output []string
	for k, v := range rg.Map {
		casted, _ := lang.Cast[Holder[T]](v)
		if !casted.IsCompleted() {
			output = append(output, k)
		}
	}
	return output, nil
}

// IsSuccessful tells if all the group are successful
func (rg *group[T, HT]) IsSuccessful() bool {
	if valid.IsNull(rg) {
		return false
	}
	if rg.Map.Length() == 0 {
		return false
	}

	for _, v := range rg.Map {
		if !v.IsSuccessful() {
			return false
		}
	}
	return true
}

// IsCompleted tells if all the group are completed
func (rg *group[T, HT]) IsCompleted() bool {
	if valid.IsNull(rg) {
		return false
	}

	if rg.Map.Length() == 0 {
		return false
	}

	for _, v := range rg.Map {
		if !v.IsCompleted() {
			return false
		}
	}
	return true
}

// PayloadOf returns the T corresponding to the key
func (rg *group[T, HT]) PayloadOf(key string) (HT, fail.Error) {
	var empty HT
	if valid.IsNull(rg) {
		return empty, fail.InvalidInstanceError()
	}
	if key == "" {
		return empty, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	item, ok := rg.Map[key]
	if ok {
		return item, nil
	}

	return empty, fail.NotFoundError("failed to find a holder for key '%s'", key)
}

// Payload can not be used with Group, but need to be implemented to satisfy Holder[T] interface
func (rg *group[T, HT]) Payload() (data.Map[string, HT], fail.Error) {
	if valid.IsNull(rg) {
		return nil, fail.InvalidInstanceError()
	}

	clone := rg.Map.Clone()
	return clone, nil
}

// ErrorMessageOfKey ...
func (rg *group[T, HT]) ErrorMessageOfKey(key string) string {
	if valid.IsNull(rg) {
		return ""
	}
	if key == "" {
		return ""
	}

	if item, ok := rg.Map[key]; ok {
		casted, _ := lang.Cast[Holder[T]](item)
		return casted.ErrorMessage()
	}

	return ""
}

// TagCompletedFromError can not be used with Group, but need to be implemented to satisfy Holder[T] interface
func (rg *group[T, HT]) TagCompletedFromError(error) error {
	return fail.InvalidRequestError("cannot use TagCompletedFromError() with result.Group")
}

// TagSuccessFromCondition can not be used with Group, but need to be implemented to satisfy Holder[T] interface
func (rg *group[T, HT]) TagSuccessFromCondition(bool) error {
	return fail.InvalidRequestError("cannot use TagSuccessFromCondition() with result.Group")
}

// IsFrozen can not be used with Group, but need to be implemented to satisfy Holder[T] interface
func (rg *group[T, HT]) IsFrozen() bool {
	return false
}

// Update can not be used with Group, but need to be implemented to satisfy Holder[T] interface
func (rg *group[T, HT]) Update(opts ...Option[T]) error {
	return fail.InvalidRequestError("cannot use TagSuccessFromCondition() with result.Group")
}
