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

package abstract

import (
	stdjson "encoding/json"
	"net"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// SecurityGroupRule represents a rule of a SecurityGroup
type SecurityGroupRule struct {
	IDs         []string                        `json:"ids"`                   // ids of the rule (an abstracted rule may be split to several provider rules)
	Description string                          `json:"description,omitempty"` // description of the rule
	EtherType   ipversion.Enum                  `json:"ether_type,omitempty"`  // IPv4 or IPv6
	Direction   securitygroupruledirection.Enum `json:"direction"`             // ingress (input) or egress (output)
	Protocol    string                          `json:"protocol,omitempty"`    // concerned protocol
	PortFrom    int32                           `json:"port_from,omitempty"`   // first port of the rule
	PortTo      int32                           `json:"port_to,omitempty"`     // last port of the rule
	Sources     []string                        `json:"sources"`               // concerned sources (depending of Direction); can be array of IP ranges or array of Security Group IDs (no mix)
	Targets     []string                        `json:"targets"`               // concerned source or target (depending of Direction); can be array of IP ranges or array of Security Group IDs (no mix)
}

// IsNull tells if the Security Group Rule is a null value
func (sgr *SecurityGroupRule) IsNull() bool {
	return sgr == nil || (len(sgr.Sources) == 0 && len(sgr.Targets) == 0 /*&& sgr.Protocol == "" && sgr.PortFrom == 0*/)
}

// EqualTo is a strict equality tester between 2 rules
func (sgr *SecurityGroupRule) EqualTo(in *SecurityGroupRule) bool {
	if sgr == nil || in == nil {
		return false
	}

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
	for k, v := range sgr.Sources {
		if v != in.Sources[k] {
			return false
		}
	}
	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for k, v := range sgr.Targets {
		if v != in.Targets[k] {
			return false
		}
	}
	return true
}

// EquivalentTo compares 2 rules, except ID and Description, to tell if the target is comparable
func (sgr *SecurityGroupRule) EquivalentTo(in *SecurityGroupRule) bool {
	if sgr == nil || in == nil {
		return false
	}

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

	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for _, v := range sgr.Sources {
		found := false
		for _, w := range in.Sources {
			if v == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for _, v := range sgr.Targets {
		found := false
		for _, w := range in.Targets {
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

// SourcesConcernGroups figures out if rule contains Security Group IDs as sources
// By design, CIDR and SG ID cannot be mixed
func (sgr *SecurityGroupRule) SourcesConcernGroups() (bool, fail.Error) {
	if sgr.IsNull() {
		return false, fail.InvalidParameterError("rule", "cannot be null value of 'abstract.SecurityGroupRule'")
	}
	return concernsGroups(sgr.Sources)
}

// TargetsConcernGroups figures out if rule contains Security Group IDs as targets
// By design, CIDR and SG ID cannot be mixed
func (sgr *SecurityGroupRule) TargetsConcernGroups() (bool, fail.Error) {
	if sgr.IsNull() {
		return false, fail.InvalidParameterError("rule", "cannot be null value of 'abstract.SecurityGroupRule'")
	}
	return concernsGroups(sgr.Targets)
}

func concernsGroups(in []string) (bool, fail.Error) {
	var cidrFound, idFound int
	for _, v := range in {
		if _, _, err := net.ParseCIDR(v); err == nil {
			cidrFound++
		} else {
			idFound++
		}
	}
	if cidrFound > 0 && idFound > 0 {
		return false, fail.InvalidRequestError("cannot mix CIDRs and Security Group IDs in source/target of rule")
	}
	if cidrFound == 0 && idFound == 0 {
		return false, fail.InvalidRequestError("missing valid sources/targets in rule")
	}
	return idFound > 0, nil
}

// Validate returns an error if the content of the rule is incomplete
func (sgr *SecurityGroupRule) Validate() fail.Error {
	// Note: DO NOT USE SecurityGroupRule.IsNull() here
	if sgr == nil {
		return fail.InvalidInstanceError()
	}

	switch sgr.EtherType {
	case ipversion.IPv4, ipversion.IPv6:
		break
	default:
		return fail.InvalidRequestError("rule --type must be 'ipv4' or 'ipv6'")
	}

	switch sgr.Direction {
	case securitygroupruledirection.Egress, securitygroupruledirection.Ingress:
		break
	default:
		return fail.InvalidRequestError("rule --direction must be 'egress' or 'ingress'")
	}

	switch sgr.Protocol {
	case "icmp":
		break
	case "tcp", "udp":
		if sgr.PortFrom <= 0 {
			return fail.InvalidRequestError("rule --port-from must contain a positive integer")
		}
		if len(sgr.Sources) == 0 && len(sgr.Targets) == 0 {
			return fail.InvalidRequestError("rule --cidr must be defined")
		}
	default:
		// protocol may be empty, meaning allow everything, only if there are no ports defined
		if sgr.PortFrom > 0 || sgr.PortTo > 0 {
			return fail.InvalidRequestError("rule --protocol must be 'tcp', 'udp' or 'icmp'")
		}
	}

	return nil
}

// NewSecurityGroupRule creates an abstract.SecurityGroupRule
func NewSecurityGroupRule() *SecurityGroupRule {
	return &SecurityGroupRule{
		IDs:         make([]string, 0),
		Description: "",
		EtherType:   ipversion.IPv6,
		Direction:   securitygroupruledirection.Ingress,
		Protocol:    "icmp",
		PortFrom:    0,
		PortTo:      0,
		Sources:     make([]string, 0),
		Targets:     make([]string, 0),
	}
}

// Clone does a deep-copy of the SecurityGroup
//
// satisfies interface data.Clonable
func (sgr *SecurityGroupRule) Clone() data.Clonable {
	return NewSecurityGroupRule().Replace(sgr)
}

// Replace ...
// satisfies interface data.Clonable
func (sgr *SecurityGroupRule) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value
	if sgr == nil || p == nil {
		return sgr
	}

	src := p.(*SecurityGroupRule)
	*sgr = *src
	sgr.IDs = make([]string, len(src.IDs))
	copy(sgr.IDs, src.IDs)
	sgr.Sources = make([]string, len(src.Sources))
	copy(sgr.Sources, src.Sources)
	sgr.Targets = make([]string, len(src.Targets))
	copy(sgr.Targets, src.Targets)
	return sgr
}

// SecurityGroupRules ...
type SecurityGroupRules []*SecurityGroupRule

// IndexOfEquivalentRule returns the index of the rule equivalent to the one provided
func (sgrs SecurityGroupRules) IndexOfEquivalentRule(rule *SecurityGroupRule) (int, fail.Error) {
	if sgrs == nil {
		return -1, fail.InvalidInstanceError()
	}
	if rule == nil {
		return -1, fail.InvalidParameterCannotBeNilError("rule")
	}

	found := false
	index := -1
	for k, v := range sgrs {
		if rule.EquivalentTo(v) {
			found = true
			index = k
			break
		}
	}
	if !found {
		return -1, fail.NotFoundError("no corresponding rule found")
	}
	return index, nil
}

// Clone does a deep-copy of the SecurityGroupRules
func (sgrs SecurityGroupRules) Clone() SecurityGroupRules {
	var asgr = make(SecurityGroupRules, 0)
	var cloneRule *SecurityGroupRule
	for _, v := range sgrs {
		cloneRule = v.Clone().(*SecurityGroupRule)
		asgr = append(asgr, cloneRule)
	}
	return asgr
}

// IndexOfRuleByID returns the index of the rule containing the provider rule ID provided
func (sgrs SecurityGroupRules) IndexOfRuleByID(id string) (int, fail.Error) {
	if sgrs == nil {
		return -1, fail.InvalidInstanceError()
	}

	found := false
	index := -1
	for k, v := range sgrs {
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
func (sg *SecurityGroup) RemoveRuleByIndex(index int) fail.Error {
	length := len(sg.Rules)
	if index < 0 || index >= length {
		return fail.InvalidParameterError("ruleIdx", "cannot be equal or greater to length of 'rules'")
	}
	newRules := make(SecurityGroupRules, 0)
	if index > 0 {
		newRules = append(newRules, sg.Rules[:index]...)
	}
	if index < length-1 {
		newRules = append(newRules, sg.Rules[index+1:]...)
	}
	sg.Rules = newRules
	return nil
}

// SecurityGroup represents a security group
// Note: by design, security group names must be unique tenant-wide
type SecurityGroup struct {
	ID               string             `json:"id"`                    // ID of the group
	Name             string             `json:"name"`                  // name of the group
	Network          string             `json:"network,omitempty"`     // Contains the ID of the Network owning the Security Group
	Description      string             `json:"description,omitempty"` // description of the group
	Rules            SecurityGroupRules `json:"rules"`                 // rules of the Security Group
	DefaultForSubnet string             `json:"default_for_subnets"`   // lists the ID of the subnet for which this SecurityGroup is considered as default (to be able to prevent removal of Subnet default Security Group until removal of the Subnet itself)
	DefaultForHost   string             `json:"default_for_hosts"`     // lists the ID of the host for which this SecurityGroup is considered as default (to be able to prevent removal of default Security Group until removal of the Host itself)
}

// IsNull tells if the SecurityGroup is a null value
func (sg *SecurityGroup) IsNull() bool {
	return sg == nil || (sg.Name == "" && sg.ID == "")
}

// IsConsistent tells if the content of the security group is consistent
func (sg SecurityGroup) IsConsistent() bool {
	if sg.ID == "" && (sg.Name == "" || sg.Network == "") {
		return false
	}
	return true
}

// IsComplete tells if the content of the security group is complete
func (sg SecurityGroup) IsComplete() bool {
	return sg.ID != "" && sg.Name != "" && sg.Network != ""
}

// SetID sets the value of field ID in sg
func (sg *SecurityGroup) SetID(id string) *SecurityGroup {
	if sg != nil {
		sg.ID = id
	}
	return sg
}

// SetName sets the value of field Name in sg
func (sg *SecurityGroup) SetName(name string) *SecurityGroup {
	if sg != nil {
		sg.Name = name
	}
	return sg
}

// SetNetworkID sets the value of field NetworkID in sg
func (sg *SecurityGroup) SetNetworkID(networkID string) *SecurityGroup {
	if sg != nil {
		sg.Network = networkID
	}
	return sg
}

// NewSecurityGroup ...
func NewSecurityGroup() *SecurityGroup {
	var asg = SecurityGroup{
		ID:               "",
		Name:             "",
		Network:          "",
		Description:      "",
		Rules:            make(SecurityGroupRules, 0),
		DefaultForSubnet: "",
		DefaultForHost:   "",
	}
	return &asg
}

// Clone does a deep-copy of the SecurityGroup
// satisfies interface data.Clonable
func (sg SecurityGroup) Clone() data.Clonable {
	return NewSecurityGroup().Replace(&sg)
}

// Replace ...
// satisfies interface data.Clonable
func (sg *SecurityGroup) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value
	if sg == nil || p == nil {
		return sg
	}
	src := p.(*SecurityGroup)
	*sg = *src
	sg.Rules = src.Rules.Clone()
	return sg
}

// Serialize serializes instance into bytes (output json code)
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
	defer fail.OnPanic(&xerr)

	if sg == nil {
		return fail.InvalidInstanceError()
	}

	if jserr := json.Unmarshal(buf, sg); jserr != nil {
		switch jserr.(type) {
		case *stdjson.SyntaxError:
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
