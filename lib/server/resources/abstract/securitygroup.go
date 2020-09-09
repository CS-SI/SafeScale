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
    "encoding/json"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruleaction"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
    "github.com/CS-SI/SafeScale/lib/utils/data"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// SecurityGroupRule represents a rule of a SecurityGroup
type SecurityGroupRule struct {
    ID          string                          `json:"id"`                    // id of the rule
    Description string                          `json:"description,omitempty"` // description of the rule
    EtherType   ipversion.Enum                  `json:"ether_type,omitempty"`  // IPv4 or IPv6
    Direction   securitygroupruledirection.Enum `json:"direction"`             // ingress (input) or egress (output)
    Protocol    string                          `json:"protocol,omitempty"`    // concerned protocol
    PortFrom    uint16                          `json:"port_from,omitempty"`   // first port of the rule
    PortTo      uint16                          `json:"port_to,omitempty"`     // last port of the rule
    CIDR        string                          `json:"cidr"`                  // concerned CIDR (source or target depending of Direction)
    Action      securitygroupruleaction.Enum    `json:"action,omitempty"`      // action of the rule: ALLOW, DENY
}

// IsNull tells if the Security Group Rule is a null value
func (sgr *SecurityGroupRule) IsNull() bool {
    return sgr == nil || (sgr.ID == "" && sgr.Protocol == "" && sgr.PortFrom == 0)
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

// Clone does a deep-copy of the Host
//
// satisfies interface data.Clonable
func (sg *SecurityGroup) Clone() data.Clonable {
    if sg.IsNull() {
        return sg
    }
    return NewSecurityGroup("").Replace(sg)
}

// Replace ...
//
// satisfies interface data.Clonable
func (sg *SecurityGroup) Replace(p data.Clonable) data.Clonable {
    if sg.IsNull() {
        return sg
    }

    src := p.(*SecurityGroup)
    *sg = *src
    sg.Rules = make([]SecurityGroupRule, len(src.Rules))
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

