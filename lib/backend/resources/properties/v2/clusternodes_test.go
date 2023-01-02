/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
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
	cn.Masters = []*ClusterNode{
		{
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
		Masters: []*ClusterNode{
			{
				ID:        "ClusterNode ID1",
				Name:      "ClusterNode Master",
				PublicIP:  "ClusterNode PublicIP1",
				PrivateIP: "ClusterNode PrivateIP1",
			},
		},
		PublicNodes: []*ClusterNode{
			{
				ID:        "ClusterNode ID2",
				Name:      "ClusterNode Public",
				PublicIP:  "ClusterNode PublicIP2",
				PrivateIP: "ClusterNode PrivateIP2",
			},
		},
		PrivateNodes: []*ClusterNode{
			{
				ID:        "ClusterNode ID3",
				Name:      "ClusterNode Private",
				PublicIP:  "ClusterNode PublicIP3",
				PrivateIP: "ClusterNode PrivateIP3",
			},
		},
		GlobalLastIndex: 3,
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
	clonedCns.Masters[0].Name = "ClusterNode Master Else"

	areEqual := reflect.DeepEqual(cns, clonedCns)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, cns, clonedCns)
}
