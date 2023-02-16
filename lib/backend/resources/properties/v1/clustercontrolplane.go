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
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// ClusterControlplane contains information used by cluster control plane (when there is one)
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//
//	Create a new version instead with needed supplemental fields
type ClusterControlplane struct {
	VirtualIP *abstract.VirtualIP `json:"virtual_ip,omitempty"` // contains the VirtualIP used to contact the control plane when HA is enabled
}

func newClusterControlPlane() *ClusterControlplane {
	return &ClusterControlplane{}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (cp *ClusterControlplane) IsNull() bool {
	return cp == nil || valid.IsNil(cp.VirtualIP)
}

// Clone ...
// satisfies interface clonable.Clonable
func (cp ClusterControlplane) Clone() (clonable.Clonable, error) {
	ncp := newClusterControlPlane()
	return ncp, ncp.Replace(&cp)
}

// Replace ...
// satisfies interface clonable.Clonable
func (cp *ClusterControlplane) Replace(p clonable.Clonable) error {
	if cp == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*ClusterControlplane](p)
	if err != nil {
		return fail.Wrap(err)
	}

	*cp = *src
	if src.VirtualIP != nil {
		cloned, err := clonable.CastedClone[*abstract.VirtualIP](src.VirtualIP)
		if err != nil {
			return err
		}

		cp.VirtualIP = cloned
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.ControlPlaneV1, &ClusterControlplane{})
}
