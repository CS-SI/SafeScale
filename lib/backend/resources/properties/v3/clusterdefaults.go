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

package propertiesv3

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
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
	Image             string                              `json:"image,omitempty"`               // Image contains the ID of the image used at creation
	ImageID           string                              `json:"image_id,omitempty"`            // also contains the ID of the image used at creation (previous field was supposed to use Image NAME, but never did)
	FeatureParameters []string                            `json:"feature_params,omitempty"`      // contains the parameters submitted for automatic installed Features during Cluster creation
}

func newClusterDefaults() *ClusterDefaults {
	return &ClusterDefaults{}
}

// IsNull ...
// satisfies interface clonable.Clonable
func (cd *ClusterDefaults) IsNull() bool {
	return cd == nil || (cd.GatewaySizing == propertiesv2.HostSizingRequirements{} && cd.MasterSizing == propertiesv2.HostSizingRequirements{} && cd.NodeSizing == propertiesv2.HostSizingRequirements{})
}

// Clone ...
// satisfies interface clonable.Clonable
func (cd *ClusterDefaults) Clone() (clonable.Clonable, error) {
	if cd == nil {
		return nil, fail.InvalidInstanceError()
	}

	ncd := newClusterDefaults()
	return ncd, ncd.Replace(cd)
}

// Replace ...
// satisfies interface clonable.Clonable
func (cd *ClusterDefaults) Replace(p clonable.Clonable) error {
	if cd == nil {
		return fail.InvalidInstanceError()
	}

	src, err := clonable.Cast[*ClusterDefaults](p)
	if err != nil {
		return err
	}

	*cd = *src
	length := len(src.FeatureParameters)
	if length > 0 {
		cd.FeatureParameters = make([]string, len(src.FeatureParameters))
		copy(cd.FeatureParameters, src.FeatureParameters)
	}
	return nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.cluster", clusterproperty.DefaultsV3, newClusterDefaults())
}
