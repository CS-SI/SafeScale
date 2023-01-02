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

package converters

import (
	"context"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
)

func Test_IndexedListOfClusterNodesFromResourceToProtocol(t *testing.T) {

	icn := resources.IndexedListOfClusterNodes{}
	cnl, xerr := IndexedListOfClusterNodesFromResourceToProtocol(icn)
	if xerr != nil {
		t.Error(xerr)
		t.Fail()
	}
	if len(cnl.Nodes) != 0 {
		t.Error("Expect empty ClusterNodeListResponse.Nodes")
		t.Fail()
	}
	icn = resources.IndexedListOfClusterNodes{
		0: &propertiesv3.ClusterNode{
			ID:          "ClusterNode ID 1",
			NumericalID: 0,
			Name:        "ClusterNode Name 1",
			PublicIP:    "ClusterNode PublicIP 1",
			PrivateIP:   "ClusterNode PrivateIP 1",
		},
		1: &propertiesv3.ClusterNode{
			ID:          "ClusterNode ID 2",
			NumericalID: 1,
			Name:        "ClusterNode Name 2",
			PublicIP:    "ClusterNode PublicIP 2",
			PrivateIP:   "ClusterNode PrivateIP 2",
		},
		2: &propertiesv3.ClusterNode{
			ID:          "ClusterNode ID 3",
			NumericalID: 2,
			Name:        "ClusterNode Name 3",
			PublicIP:    "ClusterNode PublicIP 3",
			PrivateIP:   "ClusterNode PrivateIP 3",
		},
	}
	cnl, xerr = IndexedListOfClusterNodesFromResourceToProtocol(icn)
	if xerr != nil {
		t.Error(xerr)
		t.Fail()
	}
	if len(cnl.Nodes) != 3 {
		t.Error("Invalid ClusterNodeListResponse len")
		t.Fail()
	}

}

func Test_FeatureSliceFromResourceToProtocol(t *testing.T) {

	var rf []resources.Feature
	flr := FeatureSliceFromResourceToProtocol(context.Background(), rf)
	if len(flr.Features) != 0 {
		t.Error("Invalid FeatureListResponse len")
		t.Fail()
	}

}
