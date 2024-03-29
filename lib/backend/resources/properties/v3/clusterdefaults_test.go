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

package propertiesv3

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
)

func TestClusterDefaults_IsNull(t *testing.T) {

	var cd *ClusterDefaults
	if !cd.IsNull() {
		t.Error("ClusterDefaults nil pointer is null")
		t.Fail()
	}
	cd = newClusterDefaults()
	if !cd.IsNull() {
		t.Error("Empty ClusterDefaults is null")
		t.Fail()
	}
	cd.GatewaySizing = propertiesv2.HostSizingRequirements{
		MinCores: 3,
		MinGPU:   1,
	}
	if cd.IsNull() {
		t.Error("ClusterNetwork is not null")
		t.Fail()
	}

}

func TestClusterDefaults_Replace(t *testing.T) {
	var cd *ClusterDefaults
	cd2 := newClusterDefaults()
	result, err := cd.Replace(cd2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := cd2.Replace(network)
	if xerr == nil {
		t.Error("ClusterDefaults.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *ClusterDefaults") {
		t.Errorf("Expect error \"p is not a *ClusterDefaults\", has \"%s\"", xerr.Error())
	}

}

func TestClusterDefaults_Clone(t *testing.T) {
	cd := newClusterDefaults()
	cd.Image = "something"
	cd.GatewaySizing = propertiesv2.HostSizingRequirements{
		MinCores: 3,
		MinGPU:   1,
	}
	cd.FeatureParameters = []string{"FeatureParam1", "FeatureParam2", "FeatureParam3"}

	cloned, err := cd.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCd, ok := cloned.(*ClusterDefaults)
	if !ok {
		t.Error("Cloned ClusterDefaults not castable to *ClusterDefaults", err)
		t.Fail()
	}

	assert.Equal(t, cd, clonedCd)
	require.EqualValues(t, cd, clonedCd)
	clonedCd.GatewaySizing.MinCores = 7

	areEqual := reflect.DeepEqual(cd, clonedCd)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, cd, clonedCd)
	require.EqualValues(t, len(clonedCd.FeatureParameters), 3)

}
