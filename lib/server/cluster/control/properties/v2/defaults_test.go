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

package propertiesv2

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/stretchr/testify/assert"
)

func TestDefaults_Clone(t *testing.T) {
	ct := newDefaults()
	ct.Image = "something"
	ct.GatewaySizing = resources.SizingRequirements{
		MinCores: 3,
		MinGPU:   1,
	}

	clonedCt, ok := ct.Clone().(*Defaults)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.GatewaySizing.MinCores = 7

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
