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

package result

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/utils/data/holder.results -o mocks/mock_resultgroup.go

// ResultGroup ...
type ResultGroup[T any] interface {
	AddOne(string, Holder[T]) fail.Error
	Completed() (bool, fail.Error)
	UncompletedKeys() ([]string, fail.Error)
	ErrorMessages() (string, fail.Error)
	Successful() (bool, fail.Error)
	Keys() ([]string, fail.Error)
	ResultOfKey(key string) (Holder[T], fail.Error)
}

// ResultGroup contains the errors of the step for each host target
type resultGroup[T any] struct {
	data.Map[string, Holder[T]]
}

// NewResultGroup returns a new instance of resultGroup
func NewResultGroup[T any]() *resultGroup[T] {
	return &resultGroup[T]{
		Map: data.NewMap[string, Holder[T]](),
	}
}

func (rg *resultGroup[T]) AddOne(key string, r Holder[T]) fail.Error {
	if valid.IsNull(rg) {
		return fail.InvalidInstanceError()
	}

	rg.Map[key] = r
	return nil
}

// ErrorMessages returns a string containing all the errors registered
func (rg *resultGroup[T]) ErrorMessages() (string, fail.Error) {
	if valid.IsNull(rg) {
		return "", fail.InvalidInstanceError()
	}

	output := ""
	for k, v := range rg.Map {
		val, xerr := v.ErrorMessage()
		if xerr != nil {
			return "", xerr
		}

		if val != "" {
			if output != "" {
				output += ", "
			}
			output += k + ": " + val
		}
	}
	return output, nil
}

// UncompletedKeys returns an array of all keys that are marked as uncompleted
func (rg *resultGroup[T]) UncompletedKeys() ([]string, fail.Error) {
	if valid.IsNull(rg) {
		return nil, fail.InvalidInstanceError()
	}

	var output []string
	for k, v := range rg.Map {
		ok, xerr := v.Completed()
		if xerr != nil {
			return nil, xerr
		}

		if !ok {
			output = append(output, k)
		}
	}
	return output, nil
}

// Successful tells if all the resultGroup are successful
func (rg *resultGroup[T]) Successful() (bool, fail.Error) {
	if valid.IsNull(rg) {
		return false, fail.InvalidInstanceError()
	}
	if rg.Map.Length() == 0 {
		return false, nil
	}

	for _, v := range rg.Map {
		ok, xerr := v.Successful()
		if xerr != nil {
			return false, xerr
		}

		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// Completed tells if all the resultGroup are completed
func (rg *resultGroup[T]) Completed() (bool, fail.Error) {
	if valid.IsNull(rg) {
		return false, fail.InvalidInstanceError()
	}

	if rg.Map.Length() == 0 {
		return false, nil
	}

	for _, v := range rg.Map {
		ok, xerr := v.Completed()
		if xerr != nil {
			return false, xerr
		}

		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// ResultOfKey returns the holder corresponding to the key
func (rg *resultGroup[T]) ResultOfKey(key string) (Holder[T], fail.Error) {
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

// ErrorMessageOfKey ...
func (rg *resultGroup[T]) ErrorMessageOfKey(key string) (string, fail.Error) {
	if valid.IsNull(rg) {
		return "", fail.InvalidInstanceError()
	}
	if key == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("key")
	}

	if item, ok := rg.Map[key]; ok {
		msg, _ := item.ErrorMessage()
		return msg, nil
	}

	return "", fail.NotFoundError()
}
