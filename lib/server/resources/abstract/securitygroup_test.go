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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/davecgh/go-spew/spew"
	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityGroupRule_IsNull(t *testing.T) {
	var sgr SecurityGroupRule
	if !sgr.IsNull() {
		t.Error("SecurityGroupRule is null")
		t.Fail()
	}
	sgr = SecurityGroupRule{}
	if !sgr.IsNull() {
		t.Error("SecurityGroupRule is null")
		t.Fail()
	}
	sgr.Sources = append(sgr.Sources, "Source 1")
	if sgr.IsNull() {
		t.Error("SecurityGroupRule is not null")
		t.Fail()
	}
	sgr.Sources = []string{}
	sgr.Targets = append(sgr.Sources, "Target 1")
	if sgr.IsNull() {
		t.Error("SecurityGroupRule is not null")
		t.Fail()
	}
}

func TestSecurityGroupRule_EqualTo(t *testing.T) {

	sgr := &SecurityGroupRule{}
	sgr.IDs = []string{"a", "b", "c"}
	sgr.Description = "SecurityGroupRule Description"
	sgr.EtherType = ipversion.IPv4                     // ipversion.IPv6
	sgr.Direction = securitygroupruledirection.Ingress // securitygroupruledirection.Egress
	sgr.Protocol = "TCP"
	sgr.PortFrom = -1
	sgr.PortTo = -1
	sgr.Sources = []string{"Source1", "Source2", "Source3"}
	sgr.Targets = []string{"Target1", "Target2", "Target3"}

	var sgr2 *SecurityGroupRule = nil
	if sgr2.EqualTo(sgr) {
		t.Error("Can't resolve equals with nil SecurityGroupRule")
		t.Fail()
	}
	if sgr.EqualTo(sgr2) {
		t.Error("Can't resolve equals with nil SecurityGroupRule")
		t.Fail()
	}

	sgr2 = &SecurityGroupRule{}
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.Description = sgr.Description
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.EtherType = sgr.EtherType
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.Direction = sgr.Direction
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.Protocol = sgr.Protocol
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.PortFrom = sgr.PortFrom
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.PortTo = sgr.PortTo
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.IDs = []string{"d", "e", "f"}
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.IDs = []string{"c", "b"}
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.IDs = []string{"c", "b", "a"}
	sgr2.Sources = []string{"Source1", "Source2"} // "Source3"}
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.Sources = []string{"Source1", "Source3", "Source2"}
	sgr2.Targets = []string{"Target1", "Target2"} // "Target3"
	if sgr.EqualTo(sgr2) {
		t.Error("No, not equals")
		t.Fail()
	}
	sgr2.Targets = []string{"Target1", "Target2", "Target3"}
	if !sgr.EqualTo(sgr2) {
		t.Error("No, is equals")
		t.Fail()
	}

}

func TestSecurityGroupRule_EquivalentTo(t *testing.T) {

	var sgr1 *SecurityGroupRule = &SecurityGroupRule{
		IDs:         []string{"a", "b", "c"},
		Description: "SecurityGroupRule Description",
		EtherType:   ipversion.IPv4,
		Direction:   securitygroupruledirection.Ingress,
		Protocol:    "TCP",
		PortFrom:    -1,
		PortTo:      -1,
		Sources:     []string{"Source1", "Source2", "Source3"},
		Targets:     []string{"Target1", "Target2", "Target3"},
	}
	var sgr2 *SecurityGroupRule = nil
	if sgr2.EquivalentTo(sgr1) {
		t.Error("Can't resolve EquivalentTo with nil SecurityGroupRule")
		t.Fail()
	}
	sgr2 = &SecurityGroupRule{}
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.Direction = sgr1.Direction
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.EtherType = sgr1.EtherType
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.Protocol = sgr1.Protocol
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.PortFrom = sgr1.PortFrom
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.PortTo = sgr1.PortTo
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.IDs = []string{"a", "b"}
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.IDs = []string{"a", "c", "b"}
	sgr2.Sources = []string{"Source1", "Source2"}
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.Sources = []string{"Source1", "Source3", "Source2"}
	sgr2.Targets = []string{"Target1", "Target2"}
	if sgr1.EquivalentTo(sgr2) {
		t.Error("No, not equivalent")
		t.Fail()
	}
	sgr2.Targets = []string{"Target1", "Target2", "Target3"}
	if !sgr1.EquivalentTo(sgr2) {
		t.Error("No, is equivalent")
		t.Fail()
	}

}

func TestSecurityGroupRule_SourcesConcernGroups(t *testing.T) {

	var sgr *SecurityGroupRule = nil
	_, err := sgr.SourcesConcernGroups()
	if err == nil {
		t.Error("Can't run SourcesConcernGroups on nil SecurityGroupRule")
		t.Fail()
	}
	sgr = &SecurityGroupRule{
		Sources: []string{"127.0.0.1", "172.12.0.1", "192.168.0.1"},
	}
	result, err := sgr.SourcesConcernGroups()
	if err != nil {
		t.Error("No, process valid")
		t.Fail()
	}
	if !result {
		t.Error("No, is it")
		t.Fail()
	}
}

func TestSecurityGroupRule_TargetsConcernGroups(t *testing.T) {

	var sgr *SecurityGroupRule = nil
	_, err := sgr.TargetsConcernGroups()
	if err == nil {
		t.Error("Can't run SourcesConcernGroups on nil SecurityGroupRule")
		t.Fail()
	}
	sgr = &SecurityGroupRule{
		Targets: []string{"127.0.0.1/24", "172.12.0.1/24", "192.168.0.1/24"},
	}
	_, err = sgr.TargetsConcernGroups()
	if err != nil {
		t.Error("No, process valid")
		t.Fail()
	}
}

func Test_concernsGroups(t *testing.T) {
	cidrs := []string{"256.0.0.0/0"}
	_, err := concernsGroups(cidrs)
	if err == nil {
		t.Error("Invalid CIDRs MUST also be considered as errors")
		t.FailNow()
	}

	cidrs = []string{"127.0.0.0/8", "SecurityGroupName"}
	_, err = concernsGroups(cidrs)
	if err == nil {
		t.Error("No, cannot mix CIDR and SG name")
		t.Fail()
	}

	cidrs = []string{}
	_, err = concernsGroups(cidrs)
	if err == nil {
		t.Error("Empty CIDR list expect \"missing valid sources/targets\" error")
		t.Fail()
	}

}

func TestSecurityGroupRule_Validate(t *testing.T) {

	var sgr *SecurityGroupRule = nil
	err := sgr.Validate()
	if err == nil {
		t.Error("Can't validate nil SecurityGroupRule")
		t.Fail()
	}

	sgr = &SecurityGroupRule{}
	err = sgr.Validate()
	if err == nil {
		t.Error("Validate require valid EtherType")
		t.Fail()
	}
	sgr = &SecurityGroupRule{
		EtherType: ipversion.IPv4,
	}
	err = sgr.Validate()
	if err == nil {
		t.Error("Validate require valid Direction")
		t.Fail()
	}
	sgr = &SecurityGroupRule{
		EtherType: ipversion.IPv4,
		Direction: securitygroupruledirection.Ingress,
		PortFrom:  666,
	}
	err = sgr.Validate()
	if err == nil {
		t.Error("Validate require valid Protocol")
		t.Fail()
	}
	sgr = &SecurityGroupRule{
		EtherType: ipversion.IPv4,
		Direction: securitygroupruledirection.Ingress,
		Protocol:  "icmp",
	}
	err = sgr.Validate()
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	sgr = &SecurityGroupRule{
		EtherType: ipversion.IPv4,
		Direction: securitygroupruledirection.Ingress,
		Protocol:  "tcp",
	}
	err = sgr.Validate()
	if err == nil {
		t.Error("SecurityGroupRule TCP Require portFrom ")
		t.Fail()
	}
	sgr = &SecurityGroupRule{
		EtherType: ipversion.IPv4,
		Direction: securitygroupruledirection.Ingress,
		Protocol:  "tcp",
		PortFrom:  666,
	}
	err = sgr.Validate()
	if err == nil {
		t.Error("SecurityGroupRule TCP Require Sources/Targets")
		t.Fail()
	}
	sgr = &SecurityGroupRule{
		EtherType: ipversion.IPv4,
		Direction: securitygroupruledirection.Ingress,
		Protocol:  "tcp",
		PortFrom:  666,
		Sources:   []string{"Earth"},
		Targets:   []string{"Hell"},
	}
	err = sgr.Validate()
	if err != nil {
		// Na, is valid
		t.Error(err)
		t.Fail()
	}

}

func TestSecurityGroupRule_Replace(t *testing.T) {

	var sgr1 *SecurityGroupRule = nil
	sgr2 := &SecurityGroupRule{
		EtherType: ipversion.IPv4,
		Direction: securitygroupruledirection.Ingress,
		Protocol:  "tcp",
		PortFrom:  666,
		Sources:   []string{"Earth"},
		Targets:   []string{"Hell"},
	}
	result, _ := sgr1.Replace(sgr2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Can't Replace a nil SecurityGroupRule pointer")
		t.Fail()
	}

}

func TestSecurityGroupRules_IndexOfEquivalentRule(t *testing.T) {

	var sgrs SecurityGroupRules = nil
	var sgr *SecurityGroupRule = &SecurityGroupRule{
		IDs:         []string{"a1", "b1", "c1"},
		Description: "SG1 Description",
		EtherType:   ipversion.IPv6,
		Direction:   securitygroupruledirection.Ingress,
		Protocol:    "icmp",
		PortFrom:    0,
		PortTo:      0,
		Sources:     []string{"src_a1", "src_b1", "src_c1"},
		Targets:     []string{"trg_a1", "trg_b1", "trg_c1"},
	}

	result, err := sgrs.IndexOfEquivalentRule(nil)
	if err == nil {
		t.Error("Can't find nil value")
		t.Fail()
	}
	result, err = sgrs.IndexOfEquivalentRule(sgr)
	if err == nil {
		t.Error("Can't find an item in empty list")
		t.Fail()
	}

	sgrs = SecurityGroupRules{
		&SecurityGroupRule{
			IDs:         []string{"a2", "b2", "c2"},
			Description: "SG2 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a2", "src_b2", "src_c2"},
			Targets:     []string{"trg_a2", "trg_b2", "trg_c2"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a3", "b3", "c3"},
			Description: "SG3 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a3", "src_b3", "src_c3"},
			Targets:     []string{"trg_a3", "trg_b3", "trg_c3"},
		},
	}
	result, err = sgrs.IndexOfEquivalentRule(sgr)
	if err == nil {
		t.Error("Can't find an item, is it not in list")
		t.Fail()
	}

	sgrs = SecurityGroupRules{
		&SecurityGroupRule{
			IDs:         []string{"a1", "b1", "c1"},
			Description: "SG1 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a1", "src_b1", "src_c1"},
			Targets:     []string{"trg_a1", "trg_b1", "trg_c1"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a2", "b2", "c2"},
			Description: "SG2 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a2", "src_b2", "src_c2"},
			Targets:     []string{"trg_a2", "trg_b2", "trg_c2"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a3", "b3", "c3"},
			Description: "SG3 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a3", "src_b3", "src_c3"},
			Targets:     []string{"trg_a3", "trg_b3", "trg_c3"},
		},
	}
	result, err = sgrs.IndexOfEquivalentRule(sgr)
	if err != nil {
		t.Error("Shound found item in list")
		t.Fail()
	}
	if result != 0 {
		t.Error("Mathing item in list is the first one")
		t.Fail()
	}

}

func TestSecurityGroupRules_IndexOfRuleByID(t *testing.T) {

	var sgrs SecurityGroupRules = SecurityGroupRules{
		nil,
		&SecurityGroupRule{
			IDs:         []string{"a1", "b1", "c1"},
			Description: "SG1 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a1", "src_b1", "src_c1"},
			Targets:     []string{"trg_a1", "trg_b1", "trg_c1"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a2", "b2", "c2"},
			Description: "SG2 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a2", "src_b2", "src_c2"},
			Targets:     []string{"trg_a2", "trg_b2", "trg_c2"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a3", "b3", "c3"},
			Description: "SG3 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a3", "src_b3", "src_c3"},
			Targets:     []string{"trg_a3", "trg_b3", "trg_c3"},
		},
	}

	result, err := sgrs.IndexOfRuleByID("toto")
	if err == nil {
		t.Error("Mathing item not in list")
		t.Fail()
	}
	result, err = sgrs.IndexOfRuleByID("b2")
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if result != 2 {
		t.Error("Mathing item is #1 one")
		t.Fail()
	}

}

func TestSecurityGroup_RemoveRuleByIndex(t *testing.T) {
	sg := &SecurityGroup{
		ID:               "SG ID",
		Name:             "SG Name",
		Network:          "SG Network",
		Description:      "SG Description",
		Rules:            SecurityGroupRules{},
		DefaultForSubnet: "SG DefaultForSubnet",
		DefaultForHost:   "SG DefaultForHost",
	}
	err := sg.RemoveRuleByIndex(0)
	if err == nil {
		t.Error("Can't remove anything from empty list")
		t.Fail()
	}
	sg = &SecurityGroup{
		ID:          "SG ID",
		Name:        "SG Name",
		Network:     "SG Network",
		Description: "SG Description",
		Rules: SecurityGroupRules{
			&SecurityGroupRule{
				IDs:         []string{"a1", "b1", "c1"},
				Description: "SG1 Description",
				EtherType:   ipversion.IPv6,
				Direction:   securitygroupruledirection.Ingress,
				Protocol:    "icmp",
				PortFrom:    0,
				PortTo:      0,
				Sources:     []string{"src_a1", "src_b1", "src_c1"},
				Targets:     []string{"trg_a1", "trg_b1", "trg_c1"},
			},
			&SecurityGroupRule{
				IDs:         []string{"a2", "b2", "c2"},
				Description: "SG2 Description",
				EtherType:   ipversion.IPv6,
				Direction:   securitygroupruledirection.Ingress,
				Protocol:    "icmp",
				PortFrom:    0,
				PortTo:      0,
				Sources:     []string{"src_a2", "src_b2", "src_c2"},
				Targets:     []string{"trg_a2", "trg_b2", "trg_c2"},
			},
			&SecurityGroupRule{
				IDs:         []string{"a3", "b3", "c3"},
				Description: "SG3 Description",
				EtherType:   ipversion.IPv6,
				Direction:   securitygroupruledirection.Ingress,
				Protocol:    "icmp",
				PortFrom:    0,
				PortTo:      0,
				Sources:     []string{"src_a3", "src_b3", "src_c3"},
				Targets:     []string{"trg_a3", "trg_b3", "trg_c3"},
			},
		},
		DefaultForSubnet: "SG DefaultForSubnet",
		DefaultForHost:   "SG DefaultForHost",
	}
	err = sg.RemoveRuleByIndex(-1)
	if err == nil {
		t.Error("Can't remove anything from -1 index")
		t.Fail()
	}
	err = sg.RemoveRuleByIndex(3)
	if err == nil {
		t.Error("Can't remove anything from index over list length")
		t.Fail()
	}
	err = sg.RemoveRuleByIndex(1)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	if len(sg.Rules) != 2 {
		t.Error("List should have lower len after index removed")
		t.Fail()
	}
	result, err := sg.Rules.IndexOfRuleByID("b2")
	if err == nil {
		t.Error(fmt.Sprintf("Item still present in list after being removed at position #%d", result))
		t.Fail()
	}

}

func TestSecurityGroup_SetID(t *testing.T) {

	var sg *SecurityGroup = nil
	sg.SetID("toto")
	id := sg.GetID()
	if id != "" {
		t.Error("Can set id to nil SecurityGroup")
		t.Fail()
	}
	sg = NewSecurityGroup()
	sg.SetID("toto")
	id = sg.GetID()
	if id != "toto" {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestSecurityGroup_SetName(t *testing.T) {

	var sg *SecurityGroup = nil
	sg.SetName("toto")
	name := sg.GetName()
	if name != "" {
		t.Error("Can set name to nil SecurityGroup")
		t.Fail()
	}
	sg = NewSecurityGroup()
	sg.SetName("toto")
	name = sg.GetName()
	if name != "toto" {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestSecurityGroup_SetNetworkID(t *testing.T) {

	var sg *SecurityGroup = nil
	sg.SetNetworkID("toto")
	network := sg.GetNetworkID()
	if network != "" {
		t.Error("Can set network to nil SecurityGroup")
		t.Fail()
	}
	sg = NewSecurityGroup()
	sg.SetNetworkID("toto")
	network = sg.GetNetworkID()
	if network != "toto" {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestSecurityGroupRules_Clone(t *testing.T) {

	var sgrs SecurityGroupRules = SecurityGroupRules{nil}
	clone, err := sgrs.Clone()
	if err != nil {
		t.Error(err)
	}

	areEqual := reflect.DeepEqual(sgrs, clone)
	if areEqual {
		t.Error("Clone must not keep nil (wring values) in list")
		t.Fail()
	}
	sgrs = SecurityGroupRules{
		&SecurityGroupRule{
			IDs:         []string{"a1", "b1", "c1"},
			Description: "SG1 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a1", "src_b1", "src_c1"},
			Targets:     []string{"trg_a1", "trg_b1", "trg_c1"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a2", "b2", "c2"},
			Description: "SG2 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a2", "src_b2", "src_c2"},
			Targets:     []string{"trg_a2", "trg_b2", "trg_c2"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a3", "b3", "c3"},
			Description: "SG3 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a3", "src_b3", "src_c3"},
			Targets:     []string{"trg_a3", "trg_b3", "trg_c3"},
		},
	}
	clone, err = sgrs.Clone()
	if err != nil {
		t.Error(err)
	}
	areEqual = reflect.DeepEqual(sgrs, clone)
	fmt.Println(sgrs, clone, areEqual)
	if !areEqual {
		t.Error("Clone uncomplete")
		t.Fail()
	}
}

func TestFuzzSg(t *testing.T) {
	for i := 0; i < 2000; i++ {
		o := NewSecurityGroupRule()

		f := fuzz.New().NilChance(0.7)
		f.Fuzz(&o)

		if o.IsNull() && o.Validate() == nil { // If it's null cannot be valid
			t.FailNow()
		}
	}
}

func TestSecurityGroup_Clone(t *testing.T) {
	sg := NewSecurityGroup()
	sg.ID = "SecurityGroup ID"
	sg.Name = "SecurityGroup Name"
	sg.Network = "SecurityGroup Network"
	sg.Description = "SecurityGroup Description"
	sg.Rules = SecurityGroupRules{
		&SecurityGroupRule{
			IDs:         []string{"a1", "b1", "c1"},
			Description: "SG1 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a1", "src_b1", "src_c1"},
			Targets:     []string{"trg_a1", "trg_b1", "trg_c1"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a2", "b2", "c2"},
			Description: "SG2 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a2", "src_b2", "src_c2"},
			Targets:     []string{"trg_a2", "trg_b2", "trg_c2"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a3", "b3", "c3"},
			Description: "SG3 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a3", "src_b3", "src_c3"},
			Targets:     []string{"trg_a3", "trg_b3", "trg_c3"},
		},
	}

	at, err := sg.Clone()
	if err != nil {
		t.Error(err)
	}

	sgc, ok := at.(*SecurityGroup)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, sg, sgc)
	sgc.Description = "changed description"

	areEqual := reflect.DeepEqual(sg, sgc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}

	sgr := NewSecurityGroupRule()
	sgr.Description = "run for cover"
	sg.Rules = append(sg.Rules, sgr)

	sgr = NewSecurityGroupRule()
	sgr.Description = "the road is long"
	sg.Rules = append(sg.Rules, sgr)

	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "don't")
	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "look")
	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "back")

	at, err = sg.Clone()
	if err != nil {
		t.Error(err)
	}

	sgc, ok = at.(*SecurityGroup)
	if !ok {
		t.Fail()
	}

	// If we are cloning right, the 'value' (ignoring pointer memory addresses) of both sg and sgc should be the same
	require.EqualValues(t, *sg, *sgc)

	// then, if we modify one of the two clones, the other should NOT be modified, because Clone should create an INDEPENDENT copy
	sg.Rules[0].Sources[0] = "do"

	areEqual = reflect.DeepEqual(*sg, *sgc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}

	// and finally, make sure are NOT equal after modifying one and not the other
	require.NotEqualValues(t, *sg, *sgc)
}

func TestSecurityGroup_NewSecurityGroup(t *testing.T) {

	sg := NewSecurityGroup()
	if !sg.IsNull() {
		t.Error("SecurityGroup is null !")
		t.Fail()
	}
	if sg.IsConsistent() {
		t.Error("SecurityGroup is not consistent !")
		t.Fail()
	}
	if sg.IsComplete() {
		t.Error("SecurityGroup is not complete !")
		t.Fail()
	}
	sg.ID = "SecurityGroup ID"
	sg.Name = "SecurityGroup Name"
	sg.Network = "SecurityGroup Network"
	if sg.IsNull() {
		t.Error("SecurityGroup is not null !")
		t.Fail()
	}
	if !sg.IsConsistent() {
		t.Error("SecurityGroup is consistent !")
		t.Fail()
	}
	if !sg.IsComplete() {
		t.Error("SecurityGroup is complete !")
		t.Fail()
	}

}

func TestSecurityGroup_Replace(t *testing.T) {

	sg := NewSecurityGroup()
	sg.Name = "securitygroup"

	sgr := NewSecurityGroupRule()
	sgr.Description = "run for cover"
	sg.Rules = append(sg.Rules, sgr)

	sgr = NewSecurityGroupRule()
	sgr.Description = "run for cover"
	sg.Rules = append(sg.Rules, sgr)

	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "don't")
	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "look")
	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "back")

	var sgc *SecurityGroup = nil
	sgcr, _ := sgc.Replace(sg)
	if fmt.Sprintf("%p", sgcr) != "0x0" {
		t.Error("Can't replace a nil pointer")
		t.Fail()
	}

	sgc = NewSecurityGroup()
	sgcr, _ = sgc.Replace(sg)

	assert.Equal(t, sgc, sgcr)
	var clob data.Clonable
	clob = sg
	require.EqualValues(t, clob, sgcr)

	areEqual := reflect.DeepEqual(&sg, sgcr.(*SecurityGroup))
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}

	sg.Rules[0].Sources[0] = "found"
	if strings.Contains(spew.Sdump(sgcr), "found") {
		t.Error("It's a shallow clone !")
		t.Fail()
	}

	require.NotEqualValues(t, clob, sgcr)
}

func TestSecurityGroup_Serialize(t *testing.T) {

	var sg *SecurityGroup = nil
	serial, err := sg.Serialize()
	if err == nil {
		t.Error("Can't serialize nil pointer")
		t.Fail()
	}

	sg = NewSecurityGroup()
	sg.ID = "SecurityGroup ID"
	sg.Name = "SecurityGroup Name"
	sg.Network = "SecurityGroup Network"
	sg.Description = "SecurityGroup Description"
	sg.Rules = SecurityGroupRules{
		&SecurityGroupRule{
			IDs:         []string{"a1", "b1", "c1"},
			Description: "SG1 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a1", "src_b1", "src_c1"},
			Targets:     []string{"trg_a1", "trg_b1", "trg_c1"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a2", "b2", "c2"},
			Description: "SG2 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a2", "src_b2", "src_c2"},
			Targets:     []string{"trg_a2", "trg_b2", "trg_c2"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a3", "b3", "c3"},
			Description: "SG3 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a3", "src_b3", "src_c3"},
			Targets:     []string{"trg_a3", "trg_b3", "trg_c3"},
		},
	}

	serial, err = sg.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	sg2 := NewSecurityGroup()
	err = sg2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	areEqual := reflect.DeepEqual(sg, sg2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not restitute values")
		t.Fail()
	}

}

func TestSecurityGroup_Deserialize(t *testing.T) {

	sg := NewSecurityGroup()
	sg.ID = "SecurityGroup ID"
	sg.Name = "SecurityGroup Name"
	sg.Network = "SecurityGroup Network"
	sg.Description = "SecurityGroup Description"
	sg.Rules = SecurityGroupRules{
		&SecurityGroupRule{
			IDs:         []string{"a1", "b1", "c1"},
			Description: "SG1 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a1", "src_b1", "src_c1"},
			Targets:     []string{"trg_a1", "trg_b1", "trg_c1"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a2", "b2", "c2"},
			Description: "SG2 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a2", "src_b2", "src_c2"},
			Targets:     []string{"trg_a2", "trg_b2", "trg_c2"},
		},
		&SecurityGroupRule{
			IDs:         []string{"a3", "b3", "c3"},
			Description: "SG3 Description",
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Protocol:    "icmp",
			PortFrom:    0,
			PortTo:      0,
			Sources:     []string{"src_a3", "src_b3", "src_c3"},
			Targets:     []string{"trg_a3", "trg_b3", "trg_c3"},
		},
	}

	serial, err := sg.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	var sg2 *SecurityGroup = nil
	err = sg2.Deserialize(serial)
	if err == nil {
		t.Error("Can't serialize nil pointer")
		t.Fail()
	}
	sg2 = NewSecurityGroup()
	err = sg2.Deserialize([]byte{})
	if err == nil {
		t.Error("Can't serialize empty serial")
		t.Fail()
	}
	err = sg2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.Fail()
	}
	areEqual := reflect.DeepEqual(sg, sg2)
	if !areEqual {
		t.Error("Deserialize not restitute full SecurityGroup")
		t.Fail()
	}

}
