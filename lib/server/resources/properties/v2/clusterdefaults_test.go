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

package propertiesv2

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClusterDefault_IsNull(t *testing.T) {

	var sd *ClusterDefaults = nil
	if !sd.IsNull() {
		t.Error("ClusterDefaults nil pointer is null")
		t.Fail()
	}
	sd = newClusterDefaults()
	if !sd.IsNull() {
		t.Error("Empty ClusterDefaults is null")
		t.Fail()
	}
	sd.GatewaySizing.MinCores = 1
	if sd.IsNull() {
		t.Error("ClusterDefaults is not null")
		t.Fail()
	}
}

func TestClusterDefault_Replace(t *testing.T) {
	var sgs *ClusterDefaults = nil
	sgs2 := newClusterDefaults()
	result := sgs.Replace(sgs2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("ClusterDefaults nil pointer can't be replace")
		t.Fail()
	}
}

func TestClusterDefault_Clone(t *testing.T) {
	ct := newClusterDefaults()
	ct.Image = "something"
	ct.GatewaySizing = HostSizingRequirements{
		MinCores: 3,
		MinGPU:   1,
	}

	clonedCt, ok := ct.Clone().(*ClusterDefaults)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.GatewaySizing.MinCores = 7

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
