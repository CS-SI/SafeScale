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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostClusterMembership_Reset(t *testing.T) {

	hcm := &HostClusterMembership{}
	hcm2 := &HostClusterMembership{
		Cluster: "HostClusterMembership Cluster",
		Type:    "HostClusterMembership Type",
	}
	hcm2.Reset()
	areEqual := reflect.DeepEqual(hcm, hcm2)
	if !areEqual {
		t.Error("Reset does not clean HostClusterMembership")
		t.Fail()
	}

}

func TestHostClusterMembership_IsNull(t *testing.T) {

	var hcm *HostClusterMembership = nil
	if !hcm.IsNull() {
		t.Error("Nil pointer HostClusterMembership is null")
		t.Fail()
	}
	hcm = &HostClusterMembership{
		Cluster: "",
		Type:    "",
	}
	if !hcm.IsNull() {
		t.Error("HostClusterMembership without 'Cluster' is null")
		t.Fail()
	}
	hcm = &HostClusterMembership{
		Cluster: "HostClusterMembership Cluster",
		Type:    "HostClusterMembership Type",
	}
	if hcm.IsNull() {
		t.Error("HostClusterMembership is not null")
		t.Fail()
	}

}

func TestHostClusterMembership_Replace(t *testing.T) {

	var hcm *HostClusterMembership = nil
	if !hcm.IsNull() {
		t.Error("Nil pointer HostClusterMembership is null")
		t.Fail()
	}
	hcm2 := NewHostClusterMembership()
	result, err := hcm.Replace(hcm2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)
}

func TestHostClusterMembership_Clone(t *testing.T) {

	cm := NewHostClusterMembership()
	cm.Cluster = "HostClusterMembership Cluster"

	cloned, err := cm.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCm, ok := cloned.(*HostClusterMembership)
	if !ok {
		t.Fail()
	}
	assert.Equal(t, cm, clonedCm)
	require.EqualValues(t, cm, clonedCm)

	clonedCm.Cluster = "HostClusterMembership Cluster2"
	areEqual := reflect.DeepEqual(cm, clonedCm)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, cm, clonedCm)

}
