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

package abstract

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClusterIdentity_Clone(t *testing.T) {
	c := NewClusterIdentity()
	c.Name = "cluster"

	cc, ok := c.Clone().(*ClusterIdentity)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, c, cc)
	require.EqualValues(t, c, cc)
	cc.AdminPassword = "changed password"

	areEqual := reflect.DeepEqual(c, cc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, c, cc)
}

func TestClusterIdentity_OK(t *testing.T) {

	c := NewClusterIdentity()
	if c.OK() {
		t.Error("Not ok, name and flavor missing")
		t.Fail()
	}
	c.Name = "cluster"
	if c.OK() {
		t.Error("Not ok, flavor missing")
		t.Fail()
	}
	c.Flavor = clusterflavor.K8S
	if !c.OK() {
		t.Error("No, Cluster is OK")
		t.Fail()
	}
	c.Name = ""
	if c.OK() {
		t.Error("Not ok, name is empty")
		t.Fail()
	}

}

func TestClusterIdentity_Serialize(t *testing.T) {

	c1 := NewClusterIdentity()
	c1.Name = "cluster"
	c1.Flavor = clusterflavor.K8S

	serial, err := c1.Serialize()
	if err != nil {
		t.Error(err)
	}
	c2 := NewClusterIdentity()
	err = c2.Deserialize(serial)
	if err != nil {
		t.Error(err)
	}

	areEqual := reflect.DeepEqual(c1, c2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not preserve informations")
		t.Fail()
	}

}
