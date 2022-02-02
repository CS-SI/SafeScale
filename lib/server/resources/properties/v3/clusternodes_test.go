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

package propertiesv3

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClusterNodes_IsNull(t *testing.T) {

	var cn *ClusterNodes = nil
	if !cn.IsNull() {
		t.Error("ClusterNodes nil pointer is null")
		t.Fail()
	}
	cn = newClusterNodes()
	if !cn.IsNull() {
		t.Error("Empty ClusterNodes is null")
		t.Fail()
	}
	cn.ByNumericalID = map[uint]*ClusterNode{
		0: {
			ID:          "ClusterNode ID",
			NumericalID: 1,
			Name:        "ClusterNode Name",
			PublicIP:    "ClusterNode PublicIP",
			PrivateIP:   "ClusterNode PrivateIP",
		},
	}
	if cn.IsNull() {
		t.Error("ClusterNodes is not null")
		t.Fail()
	}
}

func TestClusterNodes_Replace(t *testing.T) {
	var cn *ClusterNodes = nil
	cn2 := newClusterNodes()
	result := cn.Replace(cn2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("ClusterNodes nil pointer can't be replace")
		t.Fail()
	}
}

func TestClusterNodes_Clone(t *testing.T) {

	cns := &ClusterNodes{
		Masters: []uint{0},
		MasterByName: map[string]uint{
			"Master1": 0,
		},
		MasterByID: map[string]uint{
			"Master1 ID": 0,
		},
		PrivateNodes: []uint{
			1,
		},
		PrivateNodeByName: map[string]uint{
			"Private1": 1,
		},
		PrivateNodeByID: map[string]uint{
			"Private1 ID": 1,
		},
		PublicNodes: []uint{
			2,
		},
		PublicNodeByName: map[string]uint{
			"Public1": 2,
		},
		PublicNodeByID: map[string]uint{
			"Public1 ID": 2,
		},
		ByNumericalID: map[uint]*ClusterNode{
			0: {
				ID:          "ClusterNode Master1 ID",
				NumericalID: 0,
				Name:        "ClusterNode Master1 Name",
				PublicIP:    "ClusterNode Master1 PublicIP",
				PrivateIP:   "ClusterNode Master1 PrivateIP",
			},
			1: {
				ID:          "ClusterNode Private1 ID",
				NumericalID: 1,
				Name:        "ClusterNode Private1 Name",
				PublicIP:    "ClusterNode Private1 PublicIP",
				PrivateIP:   "ClusterNode Private1 PrivateIP",
			},
			2: {
				ID:          "ClusterNode Public1 ID",
				NumericalID: 2,
				Name:        "ClusterNode Public1 Name",
				PublicIP:    "ClusterNode Public1 PublicIP",
				PrivateIP:   "ClusterNode Public1 PrivateIP",
			},
		},
		MasterLastIndex:  0,
		PrivateLastIndex: 1,
		PublicLastIndex:  2,
		GlobalLastIndex:  2,
	}

	clonedCns, ok := cns.Clone().(*ClusterNodes)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, cns, clonedCns)
	require.EqualValues(t, cns, clonedCns)
	clonedCns.MasterByID["Master1 ID"] = 666

	areEqual := reflect.DeepEqual(cns, clonedCns)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, cns, clonedCns)

}
