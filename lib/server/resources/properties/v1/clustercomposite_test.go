/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"reflect"
	"testing"

	"github.com/magiconair/properties/assert"
	"github.com/stretchr/testify/require"
)

func TestClusterCompositeV1_Clone(t *testing.T) {
	ct := newClusterComposite()
	ct.Tenants = append(ct.Tenants, "google")
	ct.Tenants = append(ct.Tenants, "amazon")

	clonedCt, ok := ct.Clone().(*ClusterComposite)
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
	result := bm.Replace(bm2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Nil pointer can't be replaced")
		t.Fail()
	}

}

func TestClusterComposite_Clone(t *testing.T) {
	ct := newClusterComposite()
	ct.Tenants = append(ct.Tenants, "google")
	ct.Tenants = append(ct.Tenants, "amazon")

	clonedCt, ok := ct.Clone().(*ClusterComposite)
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
