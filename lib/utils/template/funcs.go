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

package template

import (
	"reflect"
	txttmpl "text/template"
)

var internalFuncMap = txttmpl.FuncMap{
	"hasField": hasField,
}

// hasField tells if value 'v' has a field named 'name"
// Works with v as struct or map
func hasField(v interface{}, name string) bool {
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Struct:
		return rv.FieldByName(name).IsValid()
	case reflect.Map:
		m, ok := v.(map[string]interface{})
		if !ok {
			return false
		}

		_, ok = m[name]
		return ok
	default:
		return false
	}
}
