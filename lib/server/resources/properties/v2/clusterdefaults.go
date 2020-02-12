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

package propertiesv2

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// ClusterDefaults ...
// !!! FROZEN !!!
type ClusterDefaults struct {
	GatewaySizing HostSizingRequirements `json:"gateway_sizing"` // GatewaySizing keeps the default node definition
	MasterSizing  HostSizingRequirements `json:"master_sizing"`  // MasterSizing keeps the default node definition
	NodeSizing    HostSizingRequirements `json:"node_sizing"`    // NodeSizing keeps the default node definition
	Image         string                 `json:"image"`          // Image keeps the default Linux image to use
}

func newClusterDefaults() *ClusterDefaults {
	return &ClusterDefaults{}
}

// Clone ...
// satisfies interface data.Clonable
func (d *ClusterDefaults) Clone() data.Clonable {
	return newClusterDefaults().Replace(d)
}

// Replace ...
// satisfies interface data.Clonable
func (cd *ClusterDefaults) Replace(p data.Clonable) data.Clonable {
	*cd = *p.(*ClusterDefaults)
	return cd
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.DefaultsV2, newClusterDefaults())
}
