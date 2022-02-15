/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
)

// SecurityGroupBond stores information about a resource bound to the SecurityGroup
type SecurityGroupBond struct {
	Name       string `json:"name"`
	ID         string `json:"id"`
	Disabled   bool   `json:"disabled"`
	FromSubnet bool   `json:"from_subnet"`
}

// NewSecurityGroupBond ...
func NewSecurityGroupBond() *SecurityGroupBond {
	return &SecurityGroupBond{}
}

// IsNull ...
// Satisfies interface data.Clonable
func (sgb *SecurityGroupBond) IsNull() bool {
	return sgb == nil || (sgb.Name == "" && sgb.ID == "")
}

// Clone ...
func (sgb SecurityGroupBond) Clone() data.Clonable {
	return NewSecurityGroupBond().Replace(&sgb)
}

// Replace ...
func (sgb *SecurityGroupBond) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if sgb == nil || p == nil {
		return sgb
	}

	src, _ := p.(*SecurityGroupBond) // FIXME: Replace should also return an error
	*sgb = *src
	return sgb
}

// Note: no need to register this property, it is not used directly (component of other properties)
