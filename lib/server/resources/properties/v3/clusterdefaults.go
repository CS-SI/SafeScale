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

package propertiesv3

import (
	"fmt"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/clusterproperty"
	propertiesv2 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
)

// ClusterDefaults ...
// !!! FROZEN !!!
type ClusterDefaults struct {
	GatewaySizing     propertiesv2.HostSizingRequirements `json:"gateway_sizing,omitempty"`      // GatewaySizing keeps the default node definition
	GatewayTemplateID string                              `json:"gateway_template_id,omitempty"` // template id used at creation for gateways
	MasterSizing      propertiesv2.HostSizingRequirements `json:"master_sizing,omitempty"`       // MasterSizing keeps the default node definition
	MasterTemplateID  string                              `json:"master_template_id,omitempty"`  // template ID used at creation for masters
	NodeSizing        propertiesv2.HostSizingRequirements `json:"node_sizing,omitempty"`         // NodeSizing keeps the default node definition
	NodeTemplateID    string                              `json:"node_template_id,omitempty"`    // template ID used at creation for nodes
	Image             string                              `json:"image,omitempty"`               // Image keeps the default Linux image name to use
	ImageID           string                              `json:"image_id,omitempty"`            // contains the ID of the image used at creation
	FeatureParameters []string                            `json:"feature_params,omitempty"`      // contains the parameters submitted for automatic installed Features during Cluster creation
}

func newClusterDefaults() *ClusterDefaults {
	return &ClusterDefaults{}
}

// IsNull ...
// satisfies interface data.Clonable
func (cd *ClusterDefaults) IsNull() bool {
	return cd == nil || (cd.GatewaySizing == propertiesv2.HostSizingRequirements{} && cd.MasterSizing == propertiesv2.HostSizingRequirements{} && cd.NodeSizing == propertiesv2.HostSizingRequirements{})
}

// Clone ...
// satisfies interface data.Clonable
func (cd ClusterDefaults) Clone() (data.Clonable, error) {
	return newClusterDefaults().Replace(&cd)
}

// Replace ...
// satisfies interface data.Clonable
func (cd *ClusterDefaults) Replace(p data.Clonable) (data.Clonable, error) {
	// Do not test with isNull(), it's allowed to clone a null value...
	if cd == nil || p == nil {
		return cd, nil
	}

	src, ok := p.(*ClusterDefaults)
	if !ok {
		return nil, fmt.Errorf("p is not a *ClusterDefaults")
	}

	*cd = *src
	length := len(src.FeatureParameters)
	if length > 0 {
		cd.FeatureParameters = make([]string, len(src.FeatureParameters))
		copy(cd.FeatureParameters, src.FeatureParameters)
	}
	return cd, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.DefaultsV3, newClusterDefaults())
}
