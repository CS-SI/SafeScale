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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// SecurityGroupNetworks contains information about attached networks to a security group
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type SecurityGroupNetworks struct {
	ByID   map[string]*SecurityGroupBond `json:"by_id"`   // contains the status of a security group (true=active, false=suspended) of networks using it, indexed on network ID
	ByName map[string]*SecurityGroupBond `json:"by_name"` // contains the status of a security group (true=active, false=suspended) of networks using it, indexed on network Name
}

// NewSecurityGroupNetworks ...
func NewSecurityGroupNetworks() *SecurityGroupNetworks {
	return &SecurityGroupNetworks{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]*SecurityGroupBond{},
	}
}

// Reset ...
func (sgn *SecurityGroupNetworks) Reset() *SecurityGroupNetworks {
	if sgn != nil {
		sgn.ByID = map[string]*SecurityGroupBond{}
		sgn.ByName = map[string]*SecurityGroupBond{}
		return sgn
	}
	return NewSecurityGroupNetworks()
}

// Clone ...
func (sgn *SecurityGroupNetworks) Clone() data.Clonable {
	return NewSecurityGroupNetworks().Replace(sgn)
}

// Replace ...
func (sgn *SecurityGroupNetworks) Replace(p data.Clonable) data.Clonable {
	src := p.(*SecurityGroupNetworks)
	sgn.ByID = make(map[string]*SecurityGroupBond, len(src.ByID))
	for k, v := range src.ByID {
		sgn.ByID[k] = v.Clone().(*SecurityGroupBond)
	}
	sgn.ByName = make(map[string]*SecurityGroupBond, len(src.ByName))
	for k, v := range src.ByName {
		sgn.ByName[k] = v.Clone().(*SecurityGroupBond)
	}
	return sgn
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.security-group", securitygroupproperty.NetworksV1, NewSecurityGroupNetworks())
}
