/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ClusterDefaults contains default information used by the cluster after initial creation
// !!! FROZEN !!!
// !!! DEPRECATED !!! superseded by propertiesv2.ClusterDefaults
type ClusterDefaults struct {
	// GatewaySizing keeps the default node definition
	GatewaySizing abstract.HostEffectiveSizing `json:"gateway_sizing,omitempty"`
	// MasterSizing keeps the default node definition
	MasterSizing abstract.HostEffectiveSizing `json:"master_sizing,omitempty"`
	// NodeSizing keeps the default node definition
	NodeSizing abstract.HostEffectiveSizing `json:"node_sizing,omitempty"`
	// Image keeps the default Linux image to use
	Image string `json:"image,omitempty"`
}

func newClusterDefaults() *ClusterDefaults {
	return &ClusterDefaults{}
}

// IsNull ...
// satisfies interface data.Clonable
func (d *ClusterDefaults) IsNull() bool {
	return d == nil || (d.GatewaySizing == abstract.HostEffectiveSizing{} && d.MasterSizing == abstract.HostEffectiveSizing{} && d.NodeSizing == abstract.HostEffectiveSizing{})
}

// Clone ... (data.Clonable interface)
func (d ClusterDefaults) Clone() (data.Clonable, error) {
	return newClusterDefaults().Replace(&d)
}

// Replace ... (data.Clonable interface)
func (d *ClusterDefaults) Replace(p data.Clonable) (data.Clonable, error) {
	if d == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	casted, ok := p.(*ClusterDefaults)
	if !ok {
		return nil, fmt.Errorf("p is not a *ClusterDefaults")
	}
	*d = *casted
	return d, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.DefaultsV1, &ClusterDefaults{})
}
