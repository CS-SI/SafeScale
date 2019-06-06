/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
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
	return newComposite().Replace(c)
}

// Replace ... (serialize.Property interface)
func (c *Composite) Replace(p serialize.Property) serialize.Property {
	src := p.(*Composite)
	c.Tenants = make([]string, len(src.Tenants))
	copy(c.Tenants, src.Tenants)
	return c
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", Property.CompositeV1, newComposite())
}
