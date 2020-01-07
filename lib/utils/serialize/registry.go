/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package serialize

import "fmt"

// propertyTypeRegistry contains the registry to have mapping between key strings and real struct
type propertyTypeRegistry map[string]map[string]interface{}

// Registry allows to register a new association
func (r propertyTypeRegistry) Register(module, key string, zeroValue Property) {
	if _, found := r[module]; !found {
		r[module] = map[string]interface{}{}
	}
	r[module][key] = zeroValue
}

// Lookup tells if an entry corresponding to (module,key) exists
func (r propertyTypeRegistry) Lookup(module, key string) bool {
	_, found := r[module][key]
	return found
}

// ZeroValue returns a zeroed value corresponding to module and key (if it exists)
func (r propertyTypeRegistry) ZeroValue(module, key string) interface{} {
	if zeroValue, found := r[module][key]; found {
		return zeroValue.(Property).Clone()
	}
	panic(fmt.Sprintf("Missing match for key '%s' in module '%s' and go type! Please use PropertyTypeRegistry.Register!", key, module))
}

// PropertyTypeRegistry ...
var PropertyTypeRegistry = struct{ propertyTypeRegistry }{propertyTypeRegistry: propertyTypeRegistry{}}
