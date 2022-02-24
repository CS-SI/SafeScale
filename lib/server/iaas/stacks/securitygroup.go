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

package stacks

import (
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
)

// const (
//	DefaultSecurityGroupName        string = "safescale-default-sg"
//	DefaultSecurityGroupDescription string = "Default Security Group for SafeScale resources"
// )

// SecurityGroupParameter can represent a Security Group by a string as ID or an *abstract.SecurityGroup
type SecurityGroupParameter interface{}

// ValidateSecurityGroupParameter validates securitygroup parameter that can be a string as ID or an *abstract.SecurityGroup
func ValidateSecurityGroupParameter(sgParam SecurityGroupParameter) (asg *abstract.SecurityGroup, sgLabel string, _ fail.Error) {
	asg = abstract.NewSecurityGroup()
	switch sgParam := sgParam.(type) {
	case string:
		if sgParam == "" {
			return asg, "", fail.InvalidParameterCannotBeEmptyStringError("sgaram")
		}
		asg.ID = sgParam
		sgLabel = asg.ID
	case *abstract.SecurityGroup:
		if valid.IsNil(sgParam) {
			return asg, "", fail.InvalidParameterError("sgParam", "cannot be *abstract.ScurityGroup null value")
		}
		asg = sgParam
		if asg.Name != "" {
			sgLabel = "'" + asg.Name + "'"
		} else {
			sgLabel = asg.ID
		}
	default:
		return asg, "", fail.InvalidParameterError("sgParam", "valid types are non-empty string or *abstract.SecurityGroup")
	}
	return asg, sgLabel, nil
}

// DefaultTCPRules creates TCP rules to configure the default security group for public hosts
// egress: allow all, ingress: allow ssh only
func DefaultTCPRules(sshPort int32) []abstract.SecurityGroupRule {
	return []abstract.SecurityGroupRule{
		// Ingress: allow SSH only
		{
			Description: "Ingress: TCP4: Allow everything",
			Direction:   securitygroupruledirection.Ingress,
			PortFrom:    sshPort,
			// PortTo:      sshPort,
			EtherType: ipversion.IPv4,
			Protocol:  "tcp",
			Targets:   []string{"0.0.0.0/0"},
		},
		{
			Description: "Ingress: TCP6: Allow everything",
			Direction:   securitygroupruledirection.Ingress,
			PortFrom:    sshPort,
			// PortTo:      sshPort,
			EtherType: ipversion.IPv6,
			Protocol:  "tcp",
			Targets:   []string{"::/0"},
		},

		// Egress: allow everything
		{
			Description: "Egress: TCP4: Allow everything",
			Direction:   securitygroupruledirection.Egress,
			PortFrom:    1,
			PortTo:      65535,
			EtherType:   ipversion.IPv4,
			Protocol:    "tcp",
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: "Egress: TCP6: Allow everything",
			Direction:   securitygroupruledirection.Egress,
			PortFrom:    1,
			PortTo:      65535,
			EtherType:   ipversion.IPv6,
			Protocol:    "tcp",
			Targets:     []string{"::/0"},
		},
	}
}

// DefaultUDPRules creates UDP rules to configure the default security group
// egress: allow all, ingress: deny all
func DefaultUDPRules() []abstract.SecurityGroupRule {
	return []abstract.SecurityGroupRule{
		// Outbound = egress == going to Outside
		{
			Description: "Egress: UDP4: Allow everything",
			Direction:   securitygroupruledirection.Egress,
			PortFrom:    1,
			PortTo:      65535,
			EtherType:   ipversion.IPv4,
			Protocol:    "udp",
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: "Egress: UDP4: Allow everything",
			Direction:   securitygroupruledirection.Egress,
			PortFrom:    1,
			PortTo:      65535,
			EtherType:   ipversion.IPv6,
			Protocol:    "udp",
			Targets:     []string{"::/0"},
		},
	}
}

// DefaultICMPRules creates ICMP rules inside the default security group
// egress: allow all, ingress: allow all
func DefaultICMPRules() []abstract.SecurityGroupRule {
	return []abstract.SecurityGroupRule{
		// Inbound == ingress == coming from Outside
		{
			Description: "Ingress: ICMP4: Allow everything",
			Direction:   securitygroupruledirection.Ingress,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: "Ingress: ICMP6: Allow everything",
			Direction:   securitygroupruledirection.Ingress,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			Targets:     []string{"::/0"},
		},
		// Outbound = egress == going to Outside
		{
			Description: "Egress: ICMP4: Allow everything",
			Direction:   securitygroupruledirection.Egress,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: "Egress: ICMP6: Allow everything",
			Direction:   securitygroupruledirection.Egress,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			Targets:     []string{"::/0"},
		},
	}
}
