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

package stacks

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	DefaultSecurityGroupName        string = "safescale-default-sg"
	DefaultSecurityGroupDescription string = "Default Security Group for SafeScale resources"
)

// SecurityGroupParameter can represent a Security Group by a string as ID or an *abstract.SecurityGroup
type SecurityGroupParameter interface{}

// ValidateSecurityGroupParameter validates securitygroup parameter that can be a string as ID or an *abstract.SecurityGroup
func ValidateSecurityGroupParameter(sgParam SecurityGroupParameter) (asg *abstract.SecurityGroup, _ fail.Error) {
	asg = abstract.NewSecurityGroup("")
	switch sgParam := sgParam.(type) {
	case string:
		if sgParam == "" {
			return asg, fail.InvalidParameterError("sgaram", "cannot be empty string")
		}
		asg.ID = sgParam
	case *abstract.SecurityGroup:
		if sgParam.IsNull() {
			return asg, fail.InvalidParameterError("sgParam", "cannot be *abstract.ScurityGroup null value")
		}
		asg = sgParam
	default:
		return asg, fail.InvalidParameterError("sgParam", "valid types are non-empty string or *abstract.SecurityGroup")
	}
	return asg, nil
}

// DefaultTCPRules creates TCP rules to configure the default security group for public hosts
// egress: allow all, ingress: allow ssh only
func DefaultTCPRules() []abstract.SecurityGroupRule {
	return []abstract.SecurityGroupRule{
		// Ingress: allow SSH only
		abstract.SecurityGroupRule{
			Description: "INGRESS: TCP4: Allow everything",
			Direction:   securitygroupruledirection.INGRESS,
			PortFrom:    22,
			//PortTo:      22,
			EtherType: ipversion.IPv4,
			Protocol:  "tcp",
			CIDR:      "0.0.0.0/0",
		},
		abstract.SecurityGroupRule{
			Description: "INGRESS: TCP6: Allow everything",
			Direction:   securitygroupruledirection.INGRESS,
			PortFrom:    22,
			//PortTo:      22,
			EtherType: ipversion.IPv6,
			Protocol:  "tcp",
			CIDR:      "::/0",
		},

		// Egress: allow everything
		abstract.SecurityGroupRule{
			Description: "EGRESS: TCP4: Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			PortFrom:    1,
			PortTo:      65535,
			EtherType:   ipversion.IPv4,
			Protocol:    "tcp",
			CIDR:        "0.0.0.0/0",
		},
		abstract.SecurityGroupRule{
			Description: "EGRESS: TCP6: Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			PortFrom:    1,
			PortTo:      65535,
			EtherType:   ipversion.IPv6,
			Protocol:    "tcp",
			CIDR:        "::/0",
		},
	}
}

// DefaultUDPRules creates UDP rules to configure the default security group
// egress: allow all, ingress: deny all
func DefaultUDPRules() []abstract.SecurityGroupRule {
	return []abstract.SecurityGroupRule{
		// Outbound = egress == going to Outside
		abstract.SecurityGroupRule{
			Description: "EGRESS: UDP4: Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			PortFrom:    1,
			PortTo:      65535,
			EtherType:   ipversion.IPv4,
			Protocol:    "udp",
			CIDR:        "0.0.0.0/0",
		},
		abstract.SecurityGroupRule{
			Description: "EGRESS: UDP4: Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			PortFrom:    1,
			PortTo:      65535,
			EtherType:   ipversion.IPv6,
			Protocol:    "udp",
			CIDR:        "::/0",
		},
	}
}

// DefaultICMPRules creates ICMP rules inside the default security group
// egress: allow all, ingress: allow all
func DefaultICMPRules() []abstract.SecurityGroupRule {
	return []abstract.SecurityGroupRule{
		// Inbound == ingress == coming from Outside
		abstract.SecurityGroupRule{
			Description: "INGRESS: ICMP4: Allow everything",
			Direction:   securitygroupruledirection.INGRESS,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			CIDR:        "0.0.0.0/0",
		},
		abstract.SecurityGroupRule{
			Description: "INGRESS: ICMP6: Allow everything",
			Direction:   securitygroupruledirection.INGRESS,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			CIDR:        "::/0",
		},
		// Outbound = egress == going to Outside
		abstract.SecurityGroupRule{
			Description: "EGRESS: ICMP4: Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			CIDR:        "0.0.0.0/0",
		},
		abstract.SecurityGroupRule{
			Description: "EGRESS: ICMP6: Allow everything",
			Direction:   securitygroupruledirection.EGRESS,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			CIDR:        "::/0",
		},
	}
}
