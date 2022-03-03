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

package abstract

import (
	stdjson "encoding/json"
	"net"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/sirupsen/logrus"
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
func (instance *SecurityGroupRule) IsNull() bool {
	return instance == nil || (len(instance.Sources) == 0 && len(instance.Targets) == 0 /*&& instance.Protocol == "" && instance.PortFrom == 0*/)
}

// EqualTo is a strict equality tester between 2 rules
func (instance *SecurityGroupRule) EqualTo(in *SecurityGroupRule) bool {
	if instance == nil || in == nil {
		return false
	}

	if instance.Description != in.Description {
		return false
	}
	if instance.EtherType != in.EtherType {
		return false
	}
	if instance.Direction != in.Direction {
		return false
	}
	if instance.Protocol != in.Protocol {
		return false
	}
	if instance.PortFrom != in.PortFrom {
		return false
	}
	if instance.PortTo != in.PortTo {
		return false
	}
	if len(instance.IDs) != len(in.IDs) {
		return false
	}

	found := false

	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for _, v1 := range instance.IDs {
		found = false
		for _, v2 := range in.IDs {
			if v1 == v2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for _, v1 := range instance.Sources {
		found = false
		for _, v2 := range in.Sources {
			if v1 == v2 {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for _, v1 := range instance.Targets {
		found = false
		for _, v2 := range in.Targets {
			if v1 == v2 {
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

// EquivalentTo compares 2 rules, except ID and Description, to tell if the target is comparable
func (instance *SecurityGroupRule) EquivalentTo(in *SecurityGroupRule) bool {
	if instance == nil || in == nil {
		return false
	}

	if instance.Direction != in.Direction {
		return false
	}
	if instance.EtherType != in.EtherType {
		return false
	}
	if instance.Protocol != in.Protocol {
		return false
	}
	if instance.PortFrom != in.PortFrom {
		return false
	}
	if instance.PortTo != in.PortTo {
		return false
	}

	// TODO: study the opportunity to use binary search (but slices have to be ascending sorted...)
	for _, v := range instance.Sources {
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
	for _, v := range instance.Targets {
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
func (instance *SecurityGroupRule) SourcesConcernGroups() (bool, fail.Error) {
	if valid.IsNil(instance) {
		return false, fail.InvalidParameterError("rule", "cannot be null value of 'abstract.SecurityGroupRule'")
	}
	return concernsGroups(instance.Sources)
}

// TargetsConcernGroups figures out if rule contains Security Group IDs as targets
// By design, CIDR and SG ID cannot be mixed
func (instance *SecurityGroupRule) TargetsConcernGroups() (bool, fail.Error) {
	if valid.IsNil(instance) {
		return false, fail.InvalidParameterError("rule", "cannot be null value of 'abstract.SecurityGroupRule'")
	}
	return concernsGroups(instance.Targets)
}

func concernsGroups(in []string) (bool, fail.Error) {
	var cidrFound, idFound int
	for _, v := range in {
		if _, _, err := net.ParseCIDR(v); err != nil {
			idFound++
		} else {
			cidrFound++
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
func (instance *SecurityGroupRule) Validate() fail.Error {
	// Note: DO NOT USE SecurityGroupRule.IsNull() here
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	switch instance.EtherType {
	case ipversion.IPv4, ipversion.IPv6:
		break
	default:
		return fail.InvalidRequestError("rule --type must be 'ipv4' or 'ipv6'")
	}

	switch instance.Direction {
	case securitygroupruledirection.Egress, securitygroupruledirection.Ingress:
		break
	default:
		return fail.InvalidRequestError("rule --direction must be 'egress' or 'ingress'")
	}

	switch instance.Protocol {
	case "icmp":
		break
	case "tcp", "udp":
		if instance.PortFrom <= 0 {
			return fail.InvalidRequestError("rule --port-from must contain a positive integer")
		}
		if len(instance.Sources) == 0 && len(instance.Targets) == 0 {
			return fail.InvalidRequestError("rule --cidr must be defined")
		}
	default:
		// protocol may be empty, meaning allow everything, only if there are no ports defined
		if instance.PortFrom > 0 || instance.PortTo > 0 {
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
func (instance *SecurityGroupRule) Clone() data.Clonable {
	return NewSecurityGroupRule().Replace(instance)
}

// Replace ...
// satisfies interface data.Clonable
func (instance *SecurityGroupRule) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value
	if instance == nil || p == nil {
		return instance
	}

	// FIXME: Replace should also return an error
	src, _ := p.(*SecurityGroupRule) // nolint
	*instance = *src
	instance.IDs = make([]string, len(src.IDs))
	copy(instance.IDs, src.IDs)
	instance.Sources = make([]string, len(src.Sources))
	copy(instance.Sources, src.Sources)
	instance.Targets = make([]string, len(src.Targets))
	copy(instance.Targets, src.Targets)
	return instance
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
	if len(sgrs) == 0 {
		return -1, fail.NotFoundError("no corresponding rule found")
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
		return -1, fail.NotFoundError("no corresponding rule found: %s", rule.Description)
	}
	return index, nil
}

// Clone does a deep-copy of the SecurityGroupRules
func (sgrs SecurityGroupRules) Clone() SecurityGroupRules {
	var asgr = make(SecurityGroupRules, 0)
	var cloneRule *SecurityGroupRule
	for _, v := range sgrs {
		if v == nil {
			continue
		}
		var ok bool
		cloneRule, ok = v.Clone().(*SecurityGroupRule)
		if !ok {
			logrus.Warnf("this is not a *SecurityGroupRule: %v", v.Clone())
			continue
		}
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
		if v == nil {
			continue
		}
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
func (instance *SecurityGroup) RemoveRuleByIndex(index int) fail.Error {
	length := len(instance.Rules)
	if index < 0 || index >= length {
		return fail.InvalidParameterError("ruleIdx", "cannot be equal or greater to length of 'rules'")
	}
	newRules := make(SecurityGroupRules, 0)
	if index > 0 {
		newRules = append(newRules, instance.Rules[:index]...)
	}
	if index < length-1 {
		newRules = append(newRules, instance.Rules[index+1:]...)
	}
	instance.Rules = newRules
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
func (instance *SecurityGroup) IsNull() bool {
	return instance == nil || (instance.Name == "" && instance.ID == "")
}

// IsConsistent tells if the content of the security group is consistent
func (instance SecurityGroup) IsConsistent() bool {
	if instance.ID == "" && (instance.Name == "" || instance.Network == "") {
		return false
	}
	return true
}

// IsComplete tells if the content of the security group is complete
func (instance SecurityGroup) IsComplete() bool {
	return instance.ID != "" && instance.Name != "" && instance.Network != ""
}

// SetID sets the value of field ID in sg
func (instance *SecurityGroup) SetID(id string) *SecurityGroup {
	if instance != nil {
		instance.ID = id
	}
	return instance
}

// SetName sets the value of field Name in sg
func (instance *SecurityGroup) SetName(name string) *SecurityGroup {
	if instance != nil {
		instance.Name = name
	}
	return instance
}

// SetNetworkID sets the value of field NetworkID in sg
func (instance *SecurityGroup) SetNetworkID(networkID string) *SecurityGroup {
	if instance != nil {
		instance.Network = networkID
	}
	return instance
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
func (instance SecurityGroup) Clone() data.Clonable {
	return NewSecurityGroup().Replace(&instance)
}

// Replace ...
// satisfies interface data.Clonable
func (instance *SecurityGroup) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value
	if instance == nil || p == nil {
		return instance
	}

	// FIXME: Replace should also return an error
	src, _ := p.(*SecurityGroup) // nolint
	*instance = *src
	instance.Rules = src.Rules.Clone()
	return instance
}

// Serialize serializes instance into bytes (output json code)
func (instance *SecurityGroup) Serialize() ([]byte, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	r, jserr := json.Marshal(instance)
	if jserr != nil {
		return nil, fail.NewError(jserr.Error())
	}
	return r, nil
}

// Deserialize reads json code and reinstantiates a SecurityGroup
func (instance *SecurityGroup) Deserialize(buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil {
		return fail.InvalidInstanceError()
	}

	if jserr := json.Unmarshal(buf, instance); jserr != nil {
		switch jserr.(type) {
		case *stdjson.SyntaxError:
			return fail.SyntaxError(jserr.Error())
		default:
			return fail.NewError(jserr.Error())
		}
	}
	return nil
}

// GetNetworkID returns the networkId of the securitygroup
func (instance *SecurityGroup) GetNetworkID() string {
	if instance == nil {
		return ""
	}
	return instance.Network
}

// GetName returns the name of the securitygroup
// Satisfies interface data.Identifiable
func (instance *SecurityGroup) GetName() string {
	if instance == nil {
		return ""
	}
	return instance.Name
}

// GetID returns the ID of the securitygroup
// Satisfies interface data.Identifiable
func (instance *SecurityGroup) GetID() string {
	if instance == nil {
		return ""
	}
	return instance.ID
}
