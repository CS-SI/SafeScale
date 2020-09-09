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

// SecurityGroupHosts contains information about attached hosts to a security group
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type SecurityGroupHosts struct {
    ByID   []string `json:"by_id"`      // contains the ID of the hosts using a security group
    ByName []string `json:"by_name"`    // contains the names of the hosts using a security group
}

// NewSecurityGroupHosts ...
func NewSecurityGroupHosts() *SecurityGroupHosts {
    return &SecurityGroupHosts{}
}

// Reset ...
func (sgh *SecurityGroupHosts) Reset() {
    *sgh = SecurityGroupHosts{}
}

// Clone ...
func (sgh *SecurityGroupHosts) Clone() data.Clonable {
    return NewSecurityGroupHosts().Replace(sgh)
}

// Replace ...
func (sgh *SecurityGroupHosts) Replace(p data.Clonable) data.Clonable {
    src := p.(*SecurityGroupHosts)
    sgh.ByID = make([]string, len(src.ByID))
    copy(sgh.ByID, src.ByID)

    sgh.ByName = make([]string, len(src.ByName))
    copy(sgh.ByName, src.ByName)
    return p
}

func init() {
    serialize.PropertyTypeRegistry.Register("resources.security-group", securitygroupproperty.HostsV1, NewHostVolumes())
}
