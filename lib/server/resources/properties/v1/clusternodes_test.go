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

package propertiesv1

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
)

func TestClusterNodes_IsNull(t *testing.T) {

	var cn *ClusterNodes
	if !cn.IsNull() {
		t.Error("Nil pointer ClusterNodes is null")
		t.Fail()
	}

}

func TestClusterNodes_Replace(t *testing.T) {

	var cn *ClusterNodes
	cn2 := &ClusterNodes{
		Masters:          make([]*ClusterNode, 0),
		PublicNodes:      make([]*ClusterNode, 0),
		PrivateNodes:     make([]*ClusterNode, 0),
		MasterLastIndex:  0,
		PrivateLastIndex: 0,
		PublicLastIndex:  0,
	}
	result, err := cn.Replace(cn2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	cn = &ClusterNodes{}
	cn2 = &ClusterNodes{
		Masters: []*ClusterNode{
			{
				ID:        "Master1 ID",
				Name:      "Master1 Name",
				PublicIP:  "Master1 PublicIP",
				PrivateIP: "Master1 PrivateIP",
			},
			{
				ID:        "Master2 ID",
				Name:      "Master2 Name",
				PublicIP:  "Master2 PublicIP",
				PrivateIP: "Master2 PrivateIP",
			},
		},
		PublicNodes: []*ClusterNode{
			{
				ID:        "Public1 ID",
				Name:      "Public1 Name",
				PublicIP:  "Public1 PublicIP",
				PrivateIP: "Public1 PrivateIP",
			},
			{
				ID:        "Public2 ID",
				Name:      "Public2 Name",
				PublicIP:  "Public2 PublicIP",
				PrivateIP: "Public2 PrivateIP",
			},
		},
		PrivateNodes: []*ClusterNode{
			{
				ID:        "Private1 ID",
				Name:      "Private1 Name",
				PublicIP:  "Private1 PublicIP",
				PrivateIP: "Private1 PrivateIP",
			},
			{
				ID:        "Private2 ID",
				Name:      "Private2 Name",
				PublicIP:  "Private2 PublicIP",
				PrivateIP: "Private2 PrivateIP",
			},
		},
		MasterLastIndex:  2,
		PrivateLastIndex: 2,
		PublicLastIndex:  2,
	}

	// Check for clusternode pointer transfert
	result, _ = cn.Replace(cn2)
	rcn := result.(*ClusterNodes)
	areEqual := reflect.DeepEqual(cn2.Masters, rcn.Masters)
	if !areEqual {
		t.Error("Replace does not return expected Masters")
		t.Fail()
	}
	areEqual = reflect.DeepEqual(cn2.PublicNodes, rcn.PublicNodes)
	if !areEqual {
		t.Error("Replace does not return expected PublicNodes")
		t.Fail()
	}
	areEqual = reflect.DeepEqual(cn2.PrivateNodes, rcn.PrivateNodes)
	if !areEqual {
		t.Error("Replace does not return expected PrivateNodes")
		t.Fail()
	}

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := cn.Replace(network)
	if xerr == nil {
		t.Error("ClusterNodes.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *ClusterNodes") {
		t.Errorf("Expect error \"p is not a *ClusterNodes\", has \"%s\"", xerr.Error())
	}

}

func TestClusterNodes_Clone(t *testing.T) {
	node := &ClusterNode{
		ID:        "",
		Name:      "Something",
		PublicIP:  "",
		PrivateIP: "",
	}

	ct := newClusterNodes()
	ct.PrivateNodes = append(ct.PrivateNodes, node)

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterNodes)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.PrivateNodes[0].Name = "Else"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
