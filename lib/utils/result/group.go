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
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/utils/data/result.Group -o mocks/mock_group.go

// Group ...
type Group[T any] interface {
	Holder[T]

	Add(string, T) fail.Error
	Keys() ([]string, fail.Error)
	PayloadOf(key string) (T, fail.Error)
	UncompletedKeys() ([]string, fail.Error)
}

// Group contains the errors of the step for each host target
type group[T any] struct {
	data.Map[string, Holder[T]]
}

// NewGroup returns a new instance of group
func NewGroup[T any]() *group[T] {
	return &group[T]{
		Map: data.NewMap[string, Holder[T]](),
	}
}

// Add adds a new entry with key; will fail if key is already used
func (rg *group[T]) Add(key string, r Holder[T]) fail.Error {
	if valid.IsNull(rg) {
		return fail.InvalidInstanceError()
	}

	_, ok := rg.Map[key]
	if ok {
		return fail.DuplicateError("rthere is already a value associated with key '%s'", key)
	}

	rg.Map[key] = r
	return nil
}

// Replace works as Add, except it will replace the key value if it already exists
func (rg *group[T]) Replace(key string, r Holder[T]) fail.Error {
	if valid.IsNull(rg) {
		return fail.InvalidInstanceError()
	}

	rg.Map[key] = r
	return nil
}

// ErrorMessage returns a string containing all the errors registered
func (rg *group[T]) ErrorMessage() string {
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

// UncompletedKeys returns an array of all keys that are marked as uncompleted
func (rg *group[T]) UncompletedKeys() ([]string, fail.Error) {
	if valid.IsNull(rg) {
		return nil, fail.InvalidInstanceError()
	}

	var output []string
	for k, v := range rg.Map {
		if !v.IsCompleted() {
			output = append(output, k)
		}
	}
	return output, nil
}

// Successful tells if all the group are successful
func (rg *group[T]) Successful() bool {
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

// Completed tells if all the group are completed
func (rg *group[T]) Completed() bool {
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

// PayloadOf returns the Holder[T] corresponding to the key
func (rg *group[T]) PayloadOf(key string) (Holder[T], fail.Error) {
	if valid.IsNull(rg) {
		return nil, fail.InvalidInstanceError()
	}
	if key == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	item, ok := rg.Map[key]
	if ok {
		return item, nil
	}

	return nil, fail.NotFoundError("failed to find a holder for key '%s'", key)
}

// Payload can not be used with Group, but need to be implemented to satisfy Holder[T] interface
func (rg *group[T]) Payload(_ string) (Holder[T], fail.Error) {
	return nil, fail.InvalidRequestError("cannot use Payload() with result.Group")
}

// ErrorMessageOfKey ...
func (rg *group[T]) ErrorMessageOfKey(key string) string {
	if valid.IsNull(rg) {
		return ""
	}
	if key == "" {
		return ""
	}

	if item, ok := rg.Map[key]; ok {
		return item.ErrorMessage()
	}

	return ""
}
