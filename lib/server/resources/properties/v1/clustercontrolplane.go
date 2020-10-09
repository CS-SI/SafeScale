/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// ClusterControlplane contains information used by cluster control plane (when there is one)
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type ClusterControlplane struct {
	VirtualIP *abstract.VirtualIP `json:"virtual_ip"` // contains the VirtualIP used to contact the control plane when HA is enabled
}

func newClusterControlPlane() *ClusterControlplane {
	return &ClusterControlplane{}
}

// Clone ...
// satisfies interface data.Clonable
func (cp *ClusterControlplane) Clone() data.Clonable {
	return newClusterControlPlane().Replace(cp)
}

// Replace ...
// satisfies interface data.Clonable
func (cp *ClusterControlplane) Replace(p data.Clonable) data.Clonable {
	src := p.(*ClusterControlplane)
	*cp = *src
	if src.VirtualIP != nil {
		cp.VirtualIP = src.VirtualIP.Clone().(*abstract.VirtualIP)
	}
	return cp
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.ControlPlaneV1, &ClusterControlplane{})
}
