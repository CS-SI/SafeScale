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

package data

import (
	"reflect"
)

func IsNull(something interface{}) bool {
	if something == nil {
		return true
	}

	// Calling NullValue.IsNull() is valid only if something is a pointer of a struct implementing the interface
	if reflect.ValueOf(something).Kind() == reflect.Ptr {
		casted, ok := something.(NullValue)
		if ok {
			return casted.IsNull()
		}
	}

	return something == nil
}

func IsNil(something interface{}) bool {
	return IsNull(something)
}
