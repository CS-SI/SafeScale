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

// ClusterDefaults contains default information used by the cluster after initial creation
// !!! FROZEN !!!
// !!! DEPRECATED !!! superseded by propertiesv2.ClusterDefaults
type ClusterDefaults struct {
	// GatewaySizing keeps the default node definition
	GatewaySizing abstract.HostEffectiveSizing `json:"gateway_sizing"`
	// MasterSizing keeps the default node definition
	MasterSizing abstract.HostEffectiveSizing `json:"master_sizing"`
	// NodeSizing keeps the default node definition
	NodeSizing abstract.HostEffectiveSizing `json:"node_sizing"`
	// Image keeps the default Linux image to use
	Image string `json:"image"`
}

func newClusterDefaults() *ClusterDefaults {
	return &ClusterDefaults{}
}

// Clone ... (data.Clonable interface)
func (d *ClusterDefaults) Clone() data.Clonable {
	return newClusterDefaults().Replace(d)
}

// Replace ... (data.Clonable interface)
func (d *ClusterDefaults) Replace(p data.Clonable) data.Clonable {
	*d = *p.(*ClusterDefaults)
	return d
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.DefaultsV1, &ClusterDefaults{})
}
