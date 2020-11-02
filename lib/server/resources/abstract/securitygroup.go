/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package abstract

import (
	"encoding/json"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// SecurityGroupRule represents a rule of a SecurityGroup
type SecurityGroupRule struct {
	IDs         []string                        `json:"ids"`                   // ids of the rule (an abstracted rule may be split to several provider rules)
	Description string                          `json:"description,omitempty"` // description of the rule
	EtherType   ipversion.Enum                  `json:"ether_type,omitempty"`  // IPv4 or IPv6
	Direction   securitygroupruledirection.Enum `json:"direction"`             // ingress (input) or egress (output)
	Protocol    string                          `json:"protocol,omitempty"`    // concerned protocol
	PortFrom    uint16                          `json:"port_from,omitempty"`   // first port of the rule
	PortTo      uint16                          `json:"port_to,omitempty"`     // last port of the rule
	IPRanges    []string                        `json:"ip_ranges"`             // concerned IPRanges (source or target depending of Direction)
	//Action      securitygroupruleaction.Enum    `json:"action,omitempty"`      // action of the rule: ALLOW, DENY
}

// IsNull tells if the Security Group Rule is a null value
func (sgr *SecurityGroupRule) IsNull() bool {
	return sgr == nil || (len(sgr.IDs) == 0 && sgr.Protocol == "" && sgr.PortFrom == 0)
}

// EqualTo is a strict equality tester between 2 rules
func (sgr SecurityGroupRule) EqualTo(in SecurityGroupRule) bool {
	if sgr.Description != in.Description {
		return false
	}
	if sgr.EtherType != in.EtherType {
		return false
	}
	if sgr.Direction != in.Direction {
		return false
	}
	if sgr.Protocol != in.Protocol {
		return false
	}
	if sgr.PortFrom != in.PortFrom {
		return false
	}
	if sgr.PortTo != in.PortTo {
		return false
	}
	if len(sgr.IDs) != len(in.IDs) {
		return false
	}
	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for k, v := range sgr.IDs {
		if in.IDs[k] != v {
			return false
		}
	}
	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for k, v := range sgr.IPRanges {
		if v != in.IPRanges[k] {
			return false
		}
	}
	return true
}

// EquivalentTo compares 2 rules, except ID and Description, to tell if the target is comparable
func (sgr SecurityGroupRule) EquivalentTo(in SecurityGroupRule) bool {
	if sgr.Direction != in.Direction {
		return false
	}
	if sgr.EtherType != in.EtherType {
		return false
	}
	if sgr.Protocol != in.Protocol {
		return false
	}
	if sgr.PortFrom != in.PortFrom {
		return false
	}
	if sgr.PortTo != in.PortTo {
		return false
	}

	if len(sgr.IDs) != len(in.IDs) {
		return false
	}
	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for _, v := range sgr.IDs {
		found := false
		for _, w := range in.IDs {
			if w == v {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for _, v := range sgr.IPRanges {
		found := false
		for _, w := range in.IPRanges {
			if v == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// NewSecurityGroupRule creates an abstract.SecurityGroupRule
func NewSecurityGroupRule() SecurityGroupRule {
	return SecurityGroupRule{}
}

// SecurityGroupRules ...
type SecurityGroupRules []SecurityGroupRule

// IndexOfEquivalentRule returns the index of the rule equivalent to the one provided
func (sgr SecurityGroupRules) IndexOfEquivalentRule(rule SecurityGroupRule) (int, fail.Error) {
	found := false
	index := -1
	for k, v := range sgr {
		if rule.EquivalentTo(v) {
			found = true
			index = k
			break
		}
	}
	if !found {
		return -1, fail.NotFoundError("no comparable rule found")
	}
	return index, nil
}

// IndexOfRuleByID returns the index of the rule containing the provider rule ID provided
func (sgr SecurityGroupRules) IndexOfRuleByID(id string) (int, fail.Error) {
	found := false
	index := -1
	for k, v := range sgr {
		for _, item := range v.IDs {
			if item == id {
				found = true
				index = k
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		return -1, fail.NotFoundError("failed to find a rule with id %s", id)
	}
	return index, nil
}

// RemoveRuleByIndex removes a rule identified by its index and returns the corresponding SecurityGroupRules
func (sgr SecurityGroupRules) RemoveRuleByIndex(index int) (SecurityGroupRules, fail.Error) {
	// Remove corresponding rule in asg, willingly maintaining order
	length := len(sgr)
	if index >= length {
		return sgr, fail.InvalidParameterError("ruleIdx", "cannot be equal or greater to length of 'rules'")
	}

	newRules := make(SecurityGroupRules, 0, length-1)
	newRules = append(newRules, sgr[:index]...)
	if index < length-1 {
		newRules = append(newRules, sgr[index+1:]...)
	}
	return newRules, nil
}

// SecurityGroup represents a security group
// Note: by design, security group names must be unique tenant-wide
type SecurityGroup struct {
	ID               string             `json:"id"`                  // ID of the group
	Name             string             `json:"name"`                // name of the group
	Description      string             `json:"description"`         // description of the group
	Rules            SecurityGroupRules `json:"rules"`               // rules of the Security Group
	DefaultForSubnet string             `json:"default_for_subnets"` // lists the ID of the subnet for which this SecurityGroup is considered as default (to be able to prevent removal of Subnet default Security Group until removal of the Subnet itself)
	DefaultForHost   string             `json:"default_for_hosts"`   // lists the ID of the host for which this SecurityGroup is considered as default (to be able to prevent removal of default Security Group until removal of the Host itself)
}

// IsNull tells if the SecurityGroup is a null value
func (sg *SecurityGroup) IsNull() bool {
	return sg == nil || (sg.Name == "" && sg.ID == "")
}

// IsConsistent tells if the content of the security group is consistent
func (sg SecurityGroup) IsConsistent() bool {
	if sg.ID == "" {
		return false
	}
	if sg.Name == "" {
		return false
	}
	return true
}

// NewSecurityGroup ...
func NewSecurityGroup( /*name string*/ ) *SecurityGroup {
	return &SecurityGroup{ /*Name: name*/ }
}

// Clone does a deep-copy of the Host
//
// satisfies interface data.Clonable
func (sg SecurityGroup) Clone() data.Clonable {
	return NewSecurityGroup().Replace(&sg)
}

// Replace ...
//
// satisfies interface data.Clonable
func (sg *SecurityGroup) Replace(p data.Clonable) data.Clonable {
	// Do not test with IsNull(), it's allowed to clone a null value
	if sg == nil || p == nil {
		return sg
	}

	src := p.(*SecurityGroup)
	*sg = *src
	sg.Rules = make(SecurityGroupRules, len(src.Rules))
	copy(sg.Rules, src.Rules)
	return sg
}

// Serialize serializes Host instance into bytes (output json code)
func (sg *SecurityGroup) Serialize() ([]byte, fail.Error) {
	if sg.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(sg)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates a SecurityGroup
func (sg *SecurityGroup) Deserialize(buf []byte) (xerr fail.Error) {
	if sg == nil {
		return fail.InvalidInstanceError()
	}

	var panicErr error
	defer func() {
		if panicErr != nil {
			xerr = fail.ToError(panicErr) // If panic occured, transforms err to a fail.Error if needed
		}
	}()
	defer fail.OnPanic(&panicErr) // json.Unmarshal may panic

	jserr := json.Unmarshal(buf, sg)
	if jserr != nil {
		switch jserr.(type) {
		case *json.SyntaxError:
			return fail.SyntaxError(jserr.Error())
		default:
			return fail.NewError(jserr.Error())
		}
	}
	return nil
}

// GetName returns the name of the volume
// Satisfies interface data.Identifiable
func (sg *SecurityGroup) GetName() string {
	if sg == nil {
		return ""
	}
	return sg.Name
}

// GetID returns the ID of the volume
// Satisfies interface data.Identifiable
func (sg *SecurityGroup) GetID() string {
	if sg == nil {
		return ""
	}
	return sg.ID
}
