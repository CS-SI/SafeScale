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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TestClusterNetwork_IsNull(t *testing.T) {

	var cn *ClusterNetwork
	if !cn.IsNull() {
		t.Error("Nil pointer ClusterNetwork is null")
		t.Fail()
	}
	cn = &ClusterNetwork{
		NetworkID: "",
		GatewayID: "",
		GatewayIP: "",
		PublicIP:  "",
		CIDR:      "",
	}
	if !cn.IsNull() {
		t.Error("ClusterFeatures without NetworkID or GatewayID null")
		t.Fail()
	}
	cn = &ClusterNetwork{
		NetworkID: "ClusterNetwork networkId",
		GatewayID: "",
		GatewayIP: "",
		PublicIP:  "",
		CIDR:      "",
	}
	if cn.IsNull() {
		t.Error("ClusterFeatures is not null")
		t.Fail()
	}

}

func TestClusterNetwork_Replace(t *testing.T) {

	var cn *ClusterNetwork
	cn2 := &ClusterNetwork{
		NetworkID: "ClusterNetwork networkId",
		GatewayID: "",
		GatewayIP: "",
		PublicIP:  "",
		CIDR:      "",
	}
	err := cn.Replace(cn2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	network, _ := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	err = cn2.Replace(network)
	if err == nil {
		t.Error("ClusterNetwork.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(err.Error(), "p is not a *ClusterNetwork") {
		t.Errorf("Expect error \"p is not a *ClusterNetwork\", has \"%s\"", err.Error())
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
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
