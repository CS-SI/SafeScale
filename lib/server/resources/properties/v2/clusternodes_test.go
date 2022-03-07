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
	var cn *ClusterNodes = nil
	cn2 := newClusterNodes()
	result, _ := cn.Replace(cn2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("ClusterNodes nil pointer can't be replace")
		t.Fail()
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
		t.Fail()
	}

	assert.Equal(t, cns, clonedCns)
	require.EqualValues(t, cns, clonedCns)
	clonedCns.Masters[0].Name = "ClusterNode Master Else"

	areEqual := reflect.DeepEqual(cns, clonedCns)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, cns, clonedCns)
}
