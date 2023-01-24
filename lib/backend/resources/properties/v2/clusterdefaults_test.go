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

func TestClusterDefault_IsNull(t *testing.T) {

	var sd *ClusterDefaults = nil
	if !sd.IsNull() {
		t.Error("ClusterDefaults nil pointer is null")
		t.Fail()
	}
	sd = newClusterDefaults()
	if !sd.IsNull() {
		t.Error("Empty ClusterDefaults is null")
		t.Fail()
	}
	sd.GatewaySizing.MinCores = 1
	if sd.IsNull() {
		t.Error("ClusterDefaults is not null")
		t.Fail()
	}
}

func TestClusterDefault_Replace(t *testing.T) {
	var sgs *ClusterDefaults = nil
	sgs2 := newClusterDefaults()
	err := sgs.Replace(sgs2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	network, _ := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	xerr := sgs2.Replace(network)
	if xerr == nil {
		t.Error("ClusterDefaults.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *ClusterDefaults") {
		t.Errorf("Expect error \"p is not a *ClusterDefaults\", has \"%s\"", xerr.Error())
	}

}

func TestClusterDefault_Clone(t *testing.T) {
	ct := newClusterDefaults()
	ct.Image = "something"
	ct.GatewaySizing = HostSizingRequirements{
		MinCores: 3,
		MinGPU:   1,
	}

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterDefaults)
	if !ok {
		t.Error("Cloned ClusterDefaults not castable to *ClusterDefaults", err)
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.GatewaySizing.MinCores = 7

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
