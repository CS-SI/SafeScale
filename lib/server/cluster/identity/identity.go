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

package identity

import (
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/flavor"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Identity contains the bare minimum information about a cluster
type Identity struct {
	Name       string             `json:"name"`       // Name is the name of the cluster
	Flavor     flavor.Enum        `json:"flavor"`     // Flavor tells what kind of cluster it is
	Complexity complexity.Enum    `json:"complexity"` // Mode is the mode of cluster; can be Simple, HighAvailability, HighVolume
	Keypair    *resources.KeyPair `json:"keypair"`    // Keypair contains the key-pair used inside the Cluster

	// AdminPassword contains the password of cladm account. This password
	// is used to connect via Guacamole, but cannot be used with SSH
	AdminPassword string `json:"admin_password"`

	// list of disabled properties
	DisabledProperties []string `json:"disabled_properties"`
}

// NewIdentity ...
func NewIdentity() *Identity {
	return &Identity{}
}

// Content ...
// satisfies interface data.Clonable
func (i *Identity) Content() data.Clonable {
	return i
}

// Clone ...
// satisfies interface data.Clonable
func (i *Identity) Clone() data.Clonable {
	return NewIdentity().Replace(i)
}

// Replace ...
// satisfies interface data.Clonable
func (i *Identity) Replace(p data.Clonable) data.Clonable {
	src := p.(*Identity)
	*i = *src
	i.Keypair = &resources.KeyPair{}
	*i.Keypair = *src.Keypair
	return i
}

// OK ...
func (i *Identity) OK() bool {
	if i == nil {
		return false
	}

	result := true
	result = result && i.Name != ""
	result = result && i.Flavor != 0
	return result
}
