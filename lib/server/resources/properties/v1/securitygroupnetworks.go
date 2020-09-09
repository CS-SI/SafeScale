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
    ByID   []string `json:"by_id"`      // contains the ID of the hosts using a security group
    ByName []string `json:"by_name"`    // contains the names of the hosts using a security group
}

// NewSecurityGroupNetworks ...
func NewSecurityGroupNetworks() *SecurityGroupNetworks {
    return &SecurityGroupNetworks{}
}

// Reset ...
func (sgn *SecurityGroupNetworks) Reset() {
    *sgn = SecurityGroupNetworks{}
}

// Clone ...
func (sgn *SecurityGroupNetworks) Clone() data.Clonable {
    return NewSecurityGroupNetworks().Replace(sgn)
}

// Replace ...
func (sgn *SecurityGroupNetworks) Replace(p data.Clonable) data.Clonable {
    src := p.(*SecurityGroupNetworks)
    sgn.ByID = make([]string, len(src.ByID))
    copy(sgn.ByID, src.ByID)

    sgn.ByName = make([]string, len(src.ByName))
    copy(sgn.ByName, src.ByName)
    return p
}

func init() {
    serialize.PropertyTypeRegistry.Register("resources.security-group", securitygroupproperty.NetworksV1, NewHostVolumes())
}
