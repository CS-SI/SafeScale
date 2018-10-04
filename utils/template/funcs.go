/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

// FuncMap defines the custom functions to be used in templates
var FuncMap = txttmpl.FuncMap{
	"inc":      func(i int) int { return i + 1 },
	"empty":    empty,
	"notempty": func(given interface{}) bool { return !empty(given) },
}

func empty(param interface{}) bool {
	g := reflect.ValueOf(param)
	if !g.IsValid() {
		return true
	}

	// Basically adapted from text/template.isTrue
	switch g.Kind() {
	default:
		return g.IsNil()
	case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
		return g.Len() == 0
	case reflect.Bool:
		return g.Bool() == false
	case reflect.Complex64, reflect.Complex128:
		return g.Complex() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return g.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return g.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return g.Float() == 0
	case reflect.Struct:
		return false
	}
}

// MergeFuncs merges the template functions passed as parameter with FuncMap content
// If overwrite is true, will overwrite any existing entry
func MergeFuncs(funcs map[string]interface{}, overwrite bool) map[string]interface{} {
	if funcs != nil {
		for k, v := range FuncMap {
			_, ok := funcs[k]
			if !ok || overwrite {
				funcs[k] = v
			}
		}
		return funcs
	}
	return FuncMap
}
