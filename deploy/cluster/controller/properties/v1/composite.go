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
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// Composite ...
type Composite struct {
	// Array of tenants hosting a multu-tenant cluster (multi starting from 1)
	Tenants []string `json:"tenants"`
}

func newComposite() *Composite {
	return &Composite{
		Tenants: []string{},
	}
}

// Content ... (serialize.Property interface)
func (c *Composite) Content() interface{} {
	return c
}

// Clone ... (serialize.Property interface)
func (c *Composite) Clone() serialize.Property {
	cn := newComposite()
	if serialize.CloneValue(c, cn) != nil {
		panic("failed to clone 'Composite'")
	}
	return cn
}

// Replace ... (serialize.Property interface)
func (c *Composite) Replace(v interface{}) {
	if serialize.CloneValue(v, c) != nil {
		panic("failed to replace 'Composite'")
	}
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", Property.CompositeV1, newComposite())
}
