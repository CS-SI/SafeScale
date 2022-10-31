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

package lang

import (
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o mocks/mock_validatable.go -i github.com/CS-SI/SafeScale/v22/lib/utils/data.Validatable

// Cast casts a variable to another type and validate
func Cast[T any](in any) (T, error) {
	var out T
	if in == nil {
		return out, fail.InconsistentError("invalid parameter 'in': cannot be nil")
	}

	out, ok := in.(T)
	if !ok {
		return out, fail.InconsistentError("failed to cast, expected '%s', provided '%s'", reflect.TypeOf(out).String(), reflect.TypeOf(in).String())
	}

	return out, nil
}
