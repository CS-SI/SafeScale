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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// Composite ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type Composite struct {
	// Array of tenants hosting a multi-tenant cluster (multi starting from 1)
	Tenants []string `json:"tenants"`
}

func newComposite() *Composite {
	return &Composite{
		Tenants: []string{},
	}
}

// Content ...
// satisfies interface data.Clonable
func (c *Composite) Content() data.Clonable {
	return c
}

// Clone ...
// satisfies interface data.Clonable
func (c *Composite) Clone() data.Clonable {
	return newComposite().Replace(c)
}

// Replace ...
// satisfies interface data.Clonable
func (c *Composite) Replace(p data.Clonable) data.Clonable {
	src := p.(*Composite)
	c.Tenants = make([]string, len(src.Tenants))
	copy(c.Tenants, src.Tenants)
	return c
}

func init() {
	serialize.PropertyTypeRegistry.Register("clusters", property.CompositeV1, newComposite())
}
