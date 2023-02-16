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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// ClusterComposite ...
type ClusterComposite struct {
	// Array of tenants hosting a multi-tenant cluster (multi starting from 1)
	Tenants []string `json:"tenants,omitempty"`
}

func newClusterComposite() *ClusterComposite {
	return &ClusterComposite{
		Tenants: []string{},
	}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (c *ClusterComposite) IsNull() bool {
	return c == nil || len(c.Tenants) == 0
}

// Clone ...
// satisfies interface clonable.Clonable
func (c ClusterComposite) Clone() (clonable.Clonable, error) {
	nc := newClusterComposite()
	return nc, nc.Replace(&c)
}

// Replace ...
// satisfies interface clonable.Clonable
func (c *ClusterComposite) Replace(p clonable.Clonable) error {
	if c == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*ClusterComposite](p)
	if err != nil {
		return fail.Wrap(err)
	}

	c.Tenants = make([]string, len(src.Tenants))
	copy(c.Tenants, src.Tenants)
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.CompositeV1, newClusterComposite())
}
