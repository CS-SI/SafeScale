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

package propertiesv3

import (
	"reflect"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClusterNodes_IsNull(t *testing.T) {

	var cn *ClusterNodes
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
	var cn *ClusterNodes
	cn2 := newClusterNodes()
	result, err := cn.Replace(cn2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := cn2.Replace(network)
	if xerr == nil {
		t.Error("ClusterNodes.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *ClusterNodes") {
		t.Errorf("Expect error \"p is not a *ClusterNodes\", has \"%s\"", xerr.Error())
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

	cloned, err := cns.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCns, ok := cloned.(*ClusterNodes)
	if !ok {
		t.Error("Cloned ClusterNodes not castable to *ClusterNodes", err)
		t.Fail()
	}

	assert.Equal(t, cns, clonedCns)
	require.EqualValues(t, cns, clonedCns)
	clonedCns.MasterByID["Master1 ID"] = 666

	areEqual := reflect.DeepEqual(cns, clonedCns)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, cns, clonedCns)

}
