/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
)

// HostClusterMembership ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type HostClusterMembership struct {
	Cluster string `json:"cluster,omitempty"`   // Cluster is the name of the cluster the host is member of
	Type    string `json:"node_type,omitempty"` // Tells if host is "node", "master" or "gateway"
}

// NewHostClusterMembership ...
func NewHostClusterMembership() *HostClusterMembership {
	return &HostClusterMembership{}
}

// Reset resets the content of the property
func (hcm *HostClusterMembership) Reset() {
	*hcm = HostClusterMembership{}
}

// IsNull ...
// satisfies interface data.Clonable
func (hcm *HostClusterMembership) IsNull() bool {
	return hcm == nil || hcm.Cluster == ""
}

// Clone ...
func (hcm HostClusterMembership) Clone() data.Clonable {
	return NewHostClusterMembership().Replace(&hcm)
}

// Replace ...
func (hcm *HostClusterMembership) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if hcm == nil || p == nil {
		return hcm
	}

	src, _ := p.(*HostClusterMembership) // FIXME: Replace should also return an error
	*hcm = *src
	return hcm
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.ClusterMembershipV1, NewHostClusterMembership())
}
