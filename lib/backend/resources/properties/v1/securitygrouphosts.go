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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// SecurityGroupHosts contains information about attached hosts to a security group
// not FROZEN yet
// Note: if tagged as FROZEN, must not be changed ever.
//       Create a new version instead with needed supplemental fields
type SecurityGroupHosts struct {
	DefaultFor string                        `json:"default_for,omitempty"` // contains the ID of the host for which the SecurityGroup is a default
	ByID       map[string]*SecurityGroupBond `json:"by_id,omitempty"`       // contains the status of a security group (true=active, false=suspended) of hosts using it, indexed on host ID
	ByName     map[string]string             `json:"by_name,omitempty"`     // contains the status of a security group (true=active, false=suspended) of hosts using it, indexed on host Name
}

// NewSecurityGroupHosts ...
func NewSecurityGroupHosts() *SecurityGroupHosts {
	return &SecurityGroupHosts{
		ByID:   map[string]*SecurityGroupBond{},
		ByName: map[string]string{},
	}
}

// IsNull ...
func (sgh *SecurityGroupHosts) IsNull() bool {
	return sgh == nil || len(sgh.ByID) == 0
}

// Clone ...
func (sgh *SecurityGroupHosts) Clone() (data.Clonable, error) {
	return NewSecurityGroupHosts().Replace(sgh)
}

// Replace ...
func (sgh *SecurityGroupHosts) Replace(p data.Clonable) (data.Clonable, error) {
	if sgh == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*SecurityGroupHosts)
	if !ok {
		return nil, fmt.Errorf("p is not a *SecurityGroupHosts")
	}

	sgh.ByID = make(map[string]*SecurityGroupBond, len(src.ByID))
	for k, v := range src.ByID {
		cloned, err := v.Clone()
		if err != nil {
			return nil, err
		}
		sgh.ByID[k], ok = cloned.(*SecurityGroupBond)
		if !ok {
			return nil, fmt.Errorf("cloned is not a *SecurityGroupBond")
		}
	}
	sgh.ByName = make(map[string]string, len(src.ByName))
	for k, v := range src.ByName {
		sgh.ByName[k] = v
	}
	return sgh, nil
}

func init() {
	serialize.PropertyTypeRegistry.Register("resources.security-group", securitygroupproperty.HostsV1, NewSecurityGroupHosts())
}
