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

func hasFieldWithNameAndIsNil(iface interface{}, name string) bool {
	ifv := reflect.ValueOf(iface)

	fiv := ifv.FieldByName(name)
	if fiv.IsValid() {
		return fiv.IsNil()
	}
	return false
}

func IsNil(something interface{}) bool {
	if something == nil {
		return true
	}

	if casted, ok := something.(interface{ IsNull() bool }); ok {
		if casted == nil {
			return true
		}
		return casted.IsNull()
	}

	if casted, ok := something.(interface{ IsNil() bool }); ok {
		if casted == nil {
			return true
		}
		return casted.IsNil()
	}

	theKind := reflect.ValueOf(something).Kind()
	if theKind == reflect.Ptr {
		val := reflect.Indirect(reflect.ValueOf(something))
		if !val.IsValid() {
			return true
		}

		casted, ok := something.(interface{ IsNull() bool })
		if ok {
			return casted.IsNull()
		}
	} else if theKind == reflect.Struct {
		return hasFieldWithNameAndIsNil(something, "errorCore")
	}

	return false
}

func IsNull(something interface{}) bool {
	return IsNil(something)
}
