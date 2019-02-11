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

package propertiesv1

import (
	"fmt"

	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// Features ...
type Features struct {
	// Installed ...
	Installed map[string]string `json:"installed"`
	// Disabled keeps track of features normally automatically added with cluster creation,
	// but explicitely disabled; if a disabled feature is added, must be removed from this property
	Disabled map[string]struct{} `json:"disabled"`
}

func newFeatures() *Features {
	return &Features{
		Installed: map[string]string{},
		Disabled:  map[string]struct{}{},
	}
}

// Content ... (serialize.Property interface)
func (f *Features) Content() interface{} {
	return f
}

// Clone ... (serialize.Property interface)
func (f *Features) Clone() serialize.Property {
	fn := newFeatures()
	err := serialize.CloneValue(f, fn)
	if err != nil {
		panic(fmt.Sprintf("failed to clone 'Features': %v", err))
	}
	return fn
}

// Replace ... (serialize.Property interface)
func (f *Features) Replace(v interface{}) {
	err := serialize.CloneValue(v, f)
	if err != nil {
		panic(fmt.Sprintf("failed to replace 'Features': %v", err))
	}
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", Property.FeaturesV1, newFeatures())
}
