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

package lang

import (
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o mocks/mock_validatable.go -i github.com/CS-SI/SafeScale/v22/lib/utils/data.Validatable

// Cast casts a variable to another type and validate
func Cast[T any, PT interface{ *T }](in any) (T, error) {
	empty := PT(new(T))
	if in == nil {
		return *empty, fail.InvalidParameterCannotBeNilError("in")
	}

	// Note: failed to find a way for now to determine if 'in' is typed nil (like *string(nil)) other than using reflection...
	r := reflect.ValueOf(in)
	if r.Kind() == reflect.Ptr && r.IsNil() {
		return *empty, fail.InvalidParameterCannotBeNilError("in")
	}

	out, ok := in.(T)
	if !ok {
		return *empty, fail.InconsistentError("failed to cast, expecting '%s', providing '%s'", reflect.TypeOf(*empty).String(), r.String())
	}

	return out, nil
}

// // CastError casts a variable to another type and validate
// func CastError[T any, PT interface{*T}](in any) fail.Error {
// 	empty := PT(new(T))
// 	return fail.InconsistentError("failed to cast, expecting '%s', providing '%s'", reflect.TypeOf(*empty).String(), reflect.TypeOf(in).String())
// }
