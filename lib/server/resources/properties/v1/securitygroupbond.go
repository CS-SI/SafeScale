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
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// SecurityGroupBond stores information about a resource bound to the SecurityGroup
type SecurityGroupBond struct {
	Name     string `json:"name"`
	ID       string `json:"id"`
	Disabled bool   `json:"disabled"`
}

// NewSecurityGroupBond ...
func NewSecurityGroupBond() *SecurityGroupBond {
	return &SecurityGroupBond{}
}

// Reset ...
func (sgb *SecurityGroupBond) Reset() *SecurityGroupBond {
	if sgb != nil {
		sgb.Name = ""
		sgb.ID = ""
		sgb.Disabled = false
		return sgb
	}
	return NewSecurityGroupBond()
}

// Clone ...
func (sgb *SecurityGroupBond) Clone() data.Clonable {
	return NewSecurityGroupBond().Replace(sgb)
}

// Replace ...
func (sgb *SecurityGroupBond) Replace(p data.Clonable) data.Clonable {
	src := p.(*SecurityGroupBond)
	*sgb = *src
	return sgb
}

// Note: no need to register this property, it is not used directly (component of other properties)
