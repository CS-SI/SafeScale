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
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
)

// NetworkDescription contains additional information describing the network, in V1
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type NetworkDescription struct {
	Purpose string    `json:"purpose,omitempty"` // contains the purpose of this network
	Created time.Time `json:"created,omitempty"` // Contains the date of creation of the network
	Domain  string    `json:"domain,omitempty"`  // Deprecated (moved to SubnetDescription): defines the domain to use for host FQDN in this network
}

// NewNetworkDescription ...
func NewNetworkDescription() *NetworkDescription {
	return &NetworkDescription{}
}

// IsNull ...
// (data.Clonable interface)
func (nd *NetworkDescription) IsNull() bool {
	return nd == nil || (nd.Created.IsZero() && nd.Purpose == "")
}

// Clone ... (data.Clonable interface)
func (nd NetworkDescription) Clone() (data.Clonable, error) {
	return NewNetworkDescription().Replace(&nd)
}

// Replace ... (data.Clonable interface)
func (nd *NetworkDescription) Replace(p data.Clonable) (data.Clonable, error) {
	// Do not test with isNull(), it's allowed to clone a null value...
	if nd == nil || p == nil {
		return nd, nil
	}

	casted, ok := p.(*NetworkDescription)
	if !ok {
		return nil, fmt.Errorf("p is not a *NetworkDescription")
	}

	*nd = *casted
	return nd, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.network", networkproperty.DescriptionV1, NewNetworkDescription())
}
