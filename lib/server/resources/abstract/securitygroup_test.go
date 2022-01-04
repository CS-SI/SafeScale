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
	"reflect"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityGroupRule_IsNull(t *testing.T) {
	sgr := SecurityGroupRule{}
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

	sgr2 := &SecurityGroupRule{}
	sgr2.IDs = []string{"c", "b", "a"}
	sgr2.Description = "SecurityGroupRule Description"
	sgr2.EtherType = ipversion.IPv4                     // ipversion.IPv6
	sgr2.Direction = securitygroupruledirection.Ingress // securitygroupruledirection.Egress
	sgr2.Protocol = "TCP"
	sgr2.PortFrom = -1
	sgr2.PortTo = -1
	sgr2.Sources = []string{"Source2", "Source1", "Source3"}
	sgr2.Targets = []string{"Target2", "Target3", "Target1"}

	if !sgr.EqualTo(sgr2) {
		t.Error("Securitygroups are equals !")
		t.Fail()
	}

}

func TestSecurityGroupRule_EquivalentTo(t *testing.T) {

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

	sgr2 := &SecurityGroupRule{}
	sgr2.IDs = []string{"d", "e", "f"}
	sgr2.Description = "SecurityGroupRule Description"
	sgr2.EtherType = ipversion.IPv4                     // ipversion.IPv6
	sgr2.Direction = securitygroupruledirection.Ingress // securitygroupruledirection.Egress
	sgr2.Protocol = "TCP"
	sgr2.PortFrom = -1
	sgr2.PortTo = -1
	sgr2.Sources = []string{"Source2", "Source1", "Source3"}
	sgr2.Targets = []string{"Target2", "Target3", "Target1"}

	if !sgr.EquivalentTo(sgr2) {
		t.Error("Securitygroups are equivalents !")
		t.Fail()
	}

}

func TestSecurityGroup_Clone(t *testing.T) {
	sg := NewSecurityGroup()
	sg.Name = "securitygroup"

	sgc, ok := sg.Clone().(*SecurityGroup)
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

	sgc, ok = sg.Clone().(*SecurityGroup)
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

	sgc := NewSecurityGroup()
	sgcr := sgc.Replace(sg)

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

func TestSecurityGroup_RemoveRuleByIndex(t *testing.T) {

	sg := NewSecurityGroup()
	sg.Name = "securitygroup"

	sgr := NewSecurityGroupRule()
	sgr.Description = "Rule 1"
	sg.Rules = append(sg.Rules, sgr)

	sgr = NewSecurityGroupRule()
	sgr.Description = "Rule 2"
	sg.Rules = append(sg.Rules, sgr)

	sgr = NewSecurityGroupRule()
	sgr.Description = "Rule 3"
	sg.Rules = append(sg.Rules, sgr)

	var err fail.Error
	err = sg.RemoveRuleByIndex(0)

	if err != nil {
		t.Error("Mismatch length after RemoveRuleByIndex, expect 2")
		t.Fail()
	}
	if len(sg.Rules) != 2 {
		t.Error("Mismatch length after RemoveRuleByIndex, expect 2")
		t.Fail()
	}
	if sg.Rules[0].Description != "Rule 2" {
		t.Error("Unexpect element after RemoveRuleByIndex, have to keep sort")
		t.Fail()
	}

	err = sg.RemoveRuleByIndex(-1)
	if err == nil {
		t.Error("Expect out of range error")
		t.Fail()
	}
	err = sg.RemoveRuleByIndex(2)
	if err == nil {
		t.Error("Expect out of range error")
		t.Fail()
	}

}
