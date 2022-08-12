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

	"github.com/magiconair/properties/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
)

func TestClusterCompositeV1_Clone(t *testing.T) {
	ct := newClusterComposite()
	ct.Tenants = append(ct.Tenants, "google")
	ct.Tenants = append(ct.Tenants, "amazon")

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterComposite)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.Tenants[0] = "choose"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}

func TestClusterComposite_IsNull(t *testing.T) {

	var cc *ClusterComposite = nil
	if !cc.IsNull() {
		t.Error("Nil pointer ClusterComposite is null")
		t.Fail()
	}
	cc = &ClusterComposite{
		Tenants: make([]string, 0),
	}
	if !cc.IsNull() {
		t.Error("ClusterComposite without at least one tenant is null")
		t.Fail()
	}
	cc = &ClusterComposite{
		Tenants: []string{"MyWonderTenant"},
	}
	if cc.IsNull() {
		t.Error("ClusterComposite is not null")
		t.Fail()
	}

}

func TestClusterComposite_Replace(t *testing.T) {

	var bm *ClusterComposite = nil
	bm2 := &ClusterComposite{
		Tenants: []string{"MyWondertenant"},
	}
	result, err := bm.Replace(bm2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	bm = &ClusterComposite{
		Tenants: []string{"MyWondertenant"},
	}
	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, xerr := bm.Replace(network)
	if xerr == nil {
		t.Error("ClusterComposite.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *ClusterComposite") {
		t.Errorf("Expect error \"p is not a *ClusterComposite\", has \"%s\"", xerr.Error())
	}

}

func TestClusterComposite_Clone(t *testing.T) {
	ct := newClusterComposite()
	ct.Tenants = append(ct.Tenants, "google")
	ct.Tenants = append(ct.Tenants, "amazon")

	cloned, err := ct.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedCt, ok := cloned.(*ClusterComposite)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	require.EqualValues(t, ct, clonedCt)
	clonedCt.Tenants[0] = "choose"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, ct, clonedCt)
}
