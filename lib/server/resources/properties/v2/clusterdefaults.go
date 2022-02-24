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

package propertiesv2

import (
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
)

// ClusterDefaults ...
// !!! FROZEN !!!
type ClusterDefaults struct {
	GatewaySizing     HostSizingRequirements `json:"gateway_sizing,omitempty"`      // GatewaySizing keeps the default node definition
	GatewayTemplateID string                 `json:"gateway_template_id,omitempty"` // template id used at creation for gateways
	MasterSizing      HostSizingRequirements `json:"master_sizing,omitempty"`       // MasterSizing keeps the default node definition
	MasterTemplateID  string                 `json:"master_template_id,omitempty"`  // template ID used at creation for masters
	NodeSizing        HostSizingRequirements `json:"node_sizing,omitempty"`         // NodeSizing keeps the default node definition
	NodeTemplateID    string                 `json:"node_template_id,omitempty"`    // template ID used at creation for nodes
	Image             string                 `json:"image,omitempty"`               // Image keeps the default Linux image name to use
	ImageID           string                 `json:"image_id,omitempty"`            // contains the ID of the image used at creation
}

func newClusterDefaults() *ClusterDefaults {
	return &ClusterDefaults{}
}

// IsNull ...
// satisfies interface data.Clonable
func (cd *ClusterDefaults) IsNull() bool {
	return cd == nil || (valid.IsNil(cd.GatewaySizing) && valid.IsNil(cd.MasterSizing) && valid.IsNil(cd.NodeSizing))
}

// Clone ...
// satisfies interface data.Clonable
func (cd ClusterDefaults) Clone() data.Clonable {
	return newClusterDefaults().Replace(&cd)
}

// Replace ...
// satisfies interface data.Clonable
func (cd *ClusterDefaults) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if cd == nil || p == nil {
		return cd
	}

	*cd = *p.(*ClusterDefaults)
	return cd
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.DefaultsV2, newClusterDefaults())
}
