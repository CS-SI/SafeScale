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

package abstract

import (
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruleaction"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
)

// SecurityGroupRule represents a rule of a SecurityGroup
type SecurityGroupRule struct {
    ID          string                          `json:"id"`                    // id of the rule
    Description string                          `json:"description,omitempty"` // description of the rule
    EtherType   ipversion.Enum                  `json:"ether_type,omitempty"`  // IPv4 or IPv6
    Direction   securitygroupruledirection.Enum `json:"direction"`             // ingress (input) or egress (output)
    Protocol    string                          `json:"protocol,omitempty"`    // concerned protocol
    FirstPort   uint16                          `json:"port_first,omitempty"`  // first port of the rule
    LastPort    uint16                          `json:"port_last,omitempty"`   // last port of the rule
    CIDR        string                          `json:"cidr"`                  // concerned CIDR (source or target depending of Direction)
    Action      securitygroupruleaction.Enum    `json:"action,omitempty"`      // action of the rule: ALLOW, DENY
}

// IsNull tells if the Security Group Rule is a null value
func (sgr *SecurityGroupRule) IsNull() bool {
    return sgr == nil || (sgr.ID == "" && sgr.Protocol == "" && sgr.FirstPort == 0)
}

func (sgr *SecurityGroupRule) EqualTo(in SecurityGroupRule) bool {
    if sgr == nil {
        return false
    }
    return *sgr == in
}

// NewSecurityGroupRule creates an *abstract.SecurityGroupRule
func NewSecurityGroupRule() *SecurityGroupRule {
    return &SecurityGroupRule{}
}

// SecurityGroup represents a security group
type SecurityGroup struct {
    ID          string                `json:"id"`             // ID of the group
    Name        string                `json:"name"`           // name of the group
    Description string                `json:"description"`    // description of the group
    Rules       []SecurityGroupRule   `json:"rules"`          // rules of the Security Group
}

// IsNull tells if the SecurityGroup is a null value
func (sg *SecurityGroup) IsNull() bool {
    return sg == nil || (sg.Name == "" && sg.ID == "" )
}

// NewSecurityGroup ...
func NewSecurityGroup(name string) *SecurityGroup {
    return &SecurityGroup{Name: name}
}
