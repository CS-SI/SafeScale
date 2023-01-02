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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
)

func TestClusterState_IsNull(t *testing.T) {

	var cs *ClusterState = nil
	if !cs.IsNull() {
		t.Error("Nil pointer ClusterState is null")
		t.Fail()
	}
	cs = &ClusterState{
		State:                clusterstate.Created,
		StateCollectInterval: 0 * time.Second,
	}
	if !cs.IsNull() {
		t.Error("ClusterState with StateCollectInterval=0 is null")
		t.Fail()
	}
	cs.StateCollectInterval = -40 * time.Second
	if !cs.IsNull() {
		t.Error("ClusterState with StateCollectInterval<0 is null")
		t.Fail()
	}
	cs.StateCollectInterval = 40 * time.Second
	if cs.IsNull() {
		t.Error("ClusterState is not null")
		t.Fail()
	}

}

func TestClusterState_Replace(t *testing.T) {

	var cs *ClusterState = nil
	cs2 := newClusterState()
	result, err := cs.Replace(cs2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := cs2.Replace(network)
	if xerr == nil {
		t.Error("ClusterState.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *ClusterState") {
		t.Errorf("Expect error \"p is not a *ClusterState\", has \"%s\"", xerr.Error())
	}

}

func TestClusterState_Clone(t *testing.T) {
	ct := newClusterState()
	ct.State = clusterstate.Created

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterState)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.State = clusterstate.Error

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
