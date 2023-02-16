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

package propertiesv1

import (
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
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
// Satisfies interface clonable.Clonable
func (sgb *SecurityGroupBond) IsNull() bool {
	return sgb == nil || (sgb.Name == "" && sgb.ID == "")
}

// Clone ...
func (sgb *SecurityGroupBond) Clone() (clonable.Clonable, error) {
	if sgb == nil {
		return nil, fail.InvalidInstanceError()
	}

	nsgb := NewSecurityGroupBond()
	return nsgb, nsgb.Replace(sgb)
}

// Replace ...
func (sgb *SecurityGroupBond) Replace(p clonable.Clonable) error {
	if sgb == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*SecurityGroupBond](p)
	if err != nil {
		return err
	}

	*sgb = *src
	return nil
}

// Note: no need to register this property, it is not used directly (component of other properties)
