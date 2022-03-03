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

package valid

import (
	"fmt"
	"reflect"
)

func hasFieldWithNameAndIsNil(iface interface{}, name string) (bool, error) {
	if iface == nil { // this can happen
		return false, nil
	}
	if name == "" { // but this is a dev mistake
		return false, fmt.Errorf("parameter 'name' CANNOT be empty")
	}

	ifv := reflect.ValueOf(iface)

	fiv := ifv.FieldByName(name)
	if fiv.IsValid() {
		switch fiv.Kind() {
		case reflect.Chan:
		case reflect.Func:
		case reflect.Interface:
		case reflect.Map:
		case reflect.Ptr:
		case reflect.Slice:
		default:
			return false, nil
		}
		return fiv.IsNil(), nil
	}
	return false, nil
}

func IsNil(something interface{}) bool {
	if something == nil {
		return true
	}

	if casted, ok := something.(interface{ IsNull() bool }); ok {
		if casted == nil {
			return true
		}

		// comparing to "0x0" might bring surprises like "0x0000000000"
		var num *int // this is 0x0
		if fmt.Sprintf("%p", casted) == fmt.Sprintf("%p", num) {
			return true
		}

		return casted.IsNull()
	}

	if casted, ok := something.(interface{ IsNil() bool }); ok {
		if casted == nil {
			return true
		}

		// comparing to "0x0" might bring surprises like "0x0000000000"
		var num *int // this is 0x0
		if fmt.Sprintf("%p", casted) == fmt.Sprintf("%p", num) {
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
		res, err := hasFieldWithNameAndIsNil(something, EmbeddedErrorStructName) // FIXME: this is an implementation detail tied to our fail.Error design, it should NOT be hardcoded, it should be here through codegen (importing results in cyclic dependency error)
		if err != nil {
			panic(err) // It should never happen in production code if we test this right.
		}
		return res
	}

	return false
}

func IsNull(something interface{}) bool {
	return IsNil(something)
}
