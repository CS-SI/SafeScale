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

func TestClusterNetwork_IsNull(t *testing.T) {

	var cn *ClusterNetwork = nil
	if !cn.IsNull() {
		t.Error("ClusterNetwork nil pointer is null")
		t.Fail()
	}
	cn = newClusterNetwork()
	if !cn.IsNull() {
		t.Error("Empty ClusterNetwork is null")
		t.Fail()
	}
	cn.NetworkID = "ClusterNetwork NetworkID"
	if cn.IsNull() {
		t.Error("ClusterNetwork is not null")
		t.Fail()
	}
}

func TestClusterNetwork_Replace(t *testing.T) {
	var cn *ClusterNetwork = nil
	cn2 := newClusterDefaults()
	result, _ := cn.Replace(cn2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("ClusterDefaults nil pointer can't be replace")
		t.Fail()
	}
}

func TestClusterNetwork_Clone(t *testing.T) {
	ct := newClusterNetwork()
	ct.GatewayID = "None"

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterNetwork)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.GatewayID = "Other"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
