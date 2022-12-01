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

package clonable

import (
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Cast casts a variable to another type and validate
func Cast[T any](in Clonable) (T, error) {
	var empty T

	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	out, ok := in.(T)
	if !ok {
		return empty, fail.InconsistentError("failed to cast, expected '%s', provided '%s'", reflect.TypeOf(empty).String(), reflect.TypeOf(in).String())
	}

	return out, nil
}
