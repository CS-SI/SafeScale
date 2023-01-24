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

package propertiesv1

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TestClusterDefaults_IsNull(t *testing.T) {

	var cd *ClusterDefaults
	if !cd.IsNull() {
		t.Error("Nil pointer ClusterDefaults is null")
		t.Fail()
	}
	cd = &ClusterDefaults{
		GatewaySizing: abstract.HostEffectiveSizing{},
		MasterSizing:  abstract.HostEffectiveSizing{},
		NodeSizing:    abstract.HostEffectiveSizing{},
		Image:         "",
	}
	if !cd.IsNull() {
		t.Error("ClusterDefaults needs (GatewaySizing, MasterSizing or NodeSizing not null) to be not null => is null")
		t.Fail()
	}
	cd.GatewaySizing.Cores = 1
	if cd.IsNull() {
		t.Error("ClusterDefaults needs (GatewaySizing, MasterSizing or NodeSizing not null) to be not null =>  is null")
		t.Fail()
	}
	cd.GatewaySizing.Cores = 0
	cd.MasterSizing.Cores = 1
	if cd.IsNull() {
		t.Error("ClusterDefaults needs (GatewaySizing, MasterSizing or NodeSizing not null) to be not null =>  is null")
		t.Fail()
	}
	cd.MasterSizing.Cores = 0
	cd.NodeSizing.Cores = 1
	if cd.IsNull() {
		t.Error("ClusterDefaults needs (GatewaySizing, MasterSizing or NodeSizing not null) to be not null =>  is null")
		t.Fail()
	}
}

func TestClusterDefaults_Replace(t *testing.T) {

	var cd *ClusterDefaults
	cd2 := &ClusterDefaults{
		GatewaySizing: abstract.HostEffectiveSizing{
			Cores: 1,
		},
		MasterSizing: abstract.HostEffectiveSizing{
			Cores: 1,
		},
		NodeSizing: abstract.HostEffectiveSizing{
			Cores: 1,
		},
		Image: "",
	}
	err := cd.Replace(cd2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	network, _ := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	err = cd2.Replace(network)
	if err == nil {
		t.Error("ClusterDefaults.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(err.Error(), "p is not a *ClusterDefaults") {
		t.Errorf("Expect error \"p is not a *ClusterDefaults\", has \"%s\"", err.Error())
	}

}

func TestClusterDefaults_Clone(t *testing.T) {
	ct := newClusterDefaults()
	ct.Image = "something"
	ct.GatewaySizing = abstract.HostEffectiveSizing{
		RAMSize: 3,
		GPUType: "NVidia",
	}

	cloned, err := ct.Clone()
	if err != nil {
		t.Error("Clone fail", err)
	}

	clonedCt, ok := cloned.(*ClusterDefaults)
	if !ok {
		t.Fail()
	}
	require.EqualValues(t, ct, clonedCt)

	assert.Equal(t, ct, clonedCt)
	clonedCt.GatewaySizing.GPUNumber = 7
	clonedCt.GatewaySizing.GPUType = "Culture"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
