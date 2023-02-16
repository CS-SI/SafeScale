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
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
)

// HostClusterMembership ...
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
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
// satisfies interface clonable.Clonable
func (hcm *HostClusterMembership) IsNull() bool {
	return hcm == nil || hcm.Cluster == ""
}

// Clone ...
func (hcm *HostClusterMembership) Clone() (clonable.Clonable, error) {
	if hcm == nil {
		return nil, fail.InvalidInstanceError()
	}

	nhcm := NewHostClusterMembership()
	return nhcm, nhcm.Replace(hcm)
}

// Replace ...
func (hcm *HostClusterMembership) Replace(p clonable.Clonable) error {
	if hcm == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*HostClusterMembership](p)
	if err != nil {
		return err
	}

	*hcm = *src
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.host", hostproperty.ClusterMembershipV1, NewHostClusterMembership())
}
