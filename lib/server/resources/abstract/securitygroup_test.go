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
	"testing"

	"github.com/stretchr/testify/assert"
)

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

	sg.Rules = append(sg.Rules, &SecurityGroupRule{
		Description: "run for cover",
	})

	sg.Rules = append(sg.Rules, &SecurityGroupRule{
		Description: "the road is long",
	})

	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "don't")
	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "look")
	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "back")

	sgc, ok = sg.Clone().(*SecurityGroup)
	if !ok {
		t.Fail()
	}

	sg.Rules[0].Sources[0] = "do"

	areEqual = reflect.DeepEqual(*sg, *sgc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestSecurityGroup_Replace(t *testing.T) {
	sg := NewSecurityGroup()
	sg.Name = "securitygroup"


	sg.Rules = append(sg.Rules, &SecurityGroupRule{
		Description: "run for cover",
	})
	sg.Rules = append(sg.Rules, &SecurityGroupRule{
		Description: "the road is long",
	})

	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "don't")
	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "look")
	sg.Rules[0].Sources = append(sg.Rules[0].Sources, "back")

	sgc := NewSecurityGroup()
	sgcr := sgc.Replace(sg)
	assert.Equal(t, sgc, sgcr)

	areEqual := reflect.DeepEqual(*sg, *(sgcr.(*SecurityGroup)))
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
