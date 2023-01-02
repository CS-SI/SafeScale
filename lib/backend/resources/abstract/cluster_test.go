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

package abstract

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClusterIdentity_Clone(t *testing.T) {
	c := NewClusterIdentity()
	c.Name = "cluster"

	cloned, err := c.Clone()
	if err != nil {
		t.Error(err)
	}

	cc, ok := cloned.(*ClusterIdentity)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, c, cc)
	require.EqualValues(t, c, cc)
	cc.AdminPassword = "changed password"

	areEqual := reflect.DeepEqual(c, cc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.FailNow()
	}
	require.NotEqualValues(t, c, cc)
}

func TestClusterIdentity_OK(t *testing.T) {

	c := NewClusterIdentity()
	if c.OK() {
		t.Error("Not ok, name and flavor missing")
		t.FailNow()
	}
	c.Name = "cluster"
	if c.OK() {
		t.Error("Not ok, flavor missing")
		t.FailNow()
	}
	c.Flavor = clusterflavor.K8S
	if !c.OK() {
		t.Error("No, Cluster is OK")
		t.FailNow()
	}
	c.Name = ""
	if c.OK() {
		t.Error("Not ok, name is empty")
		t.FailNow()
	}

}

func TestClusterIdentity_Serialize(t *testing.T) {

	// Serialize empty clusterIdentity
	c1 := NewClusterIdentity()
	_, err := c1.Serialize()
	if err == nil {
		t.Error("Should throw fail.InvalidInstanceError")
		t.FailNow()
	}

	// Junk attributes (broken pointer) for makes fail json.Marshal
	var fkp *KeyPair
	c1 = NewClusterIdentity()
	c1.Keypair = fkp
	_, err = c1.Serialize()
	if err == nil {
		t.Error("Should throw a Marshal.json error")
		t.FailNow()
	}

	// Serialize filled clusterIdentity
	c1.Name = "cluster"
	c1.Flavor = clusterflavor.K8S
	c1.Keypair, err = NewKeyPair("MySecretKey")
	if err != nil {
		t.Error("Fail to generate new KeyPair")
		t.FailNow()
	}

	// Serialize
	serial, err := c1.Serialize()
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Deserialize
	c2 := NewClusterIdentity()
	err = c2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Compare
	areEqual := reflect.DeepEqual(c1, c2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not preserve informations")
		t.FailNow()
	}
}

func TestClusterIdentity_Deserialize(t *testing.T) {

	// Serialize empty clusterIdentity
	var err error
	var serial []byte
	c1 := NewClusterIdentity()
	c1.Name = "cluster"
	c1.Flavor = clusterflavor.K8S
	c1.Keypair, err = NewKeyPair("MySecretKey")
	if err != nil {
		t.Error("Fail to generate new KeyPair")
		t.FailNow()
	}
	serial, err = c1.Serialize()
	if err != nil {
		t.Error("Fail to generate serialized cluster")
		t.FailNow()
	}

	// Empty cluster
	var emptyCluster *ClusterIdentity
	err = emptyCluster.Deserialize(serial)
	if err == nil {
		t.Error("Should throw a fail.InvalidInstanceError")
		t.FailNow()
	}

	// Control from baked data
	validSerial := []byte("{\"name\":\"cluster\",\"flavor\":2,\"complexity\":0,\"keypair\":{\"id\":\"MySecretKey\",\"name\":\"MySecretKey\",\"private_key\":\"BEGIN RSA PRIVATE KEY\"},\"admin_password\":\"\",\"tags\":{\"CreationDate\":\"2022-01-19T15:25:59+01:00\",\"ManagedBy\":\"safescale\"}}")
	err = c1.Deserialize(validSerial)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	// Corrupted serial (trunked)
	corruptedSerial := []byte("{\"name\":\"cluster\",\"flavor\":2,\"complexity\":0,\"keypair\":{\"id\":\"MySecretKey\",\"name\":\"MySecr")
	err = c1.Deserialize(corruptedSerial)
	if err == nil {
		t.Error("Should throw a fail.ErrUnqualified")
		t.FailNow()
	}

	// Unexpected fields serial
	unexpectedyntaxSerial := []byte("{\"name\":\"cluster\",\"flavor\":2,\"complexity\":0, ,\"unexpected\":true }")
	err = c1.Deserialize(unexpectedyntaxSerial)
	if err == nil {
		t.Error("Should throw a fail.ErrUnqualified")
		t.FailNow()
	}

	// Junked serial
	var junkedSerial = make([]byte, 0)
	err = c1.Deserialize(junkedSerial)
	if err == nil {
		t.Error("Should throw a fail.ErrUnqualified")
		t.FailNow()
	}

}

func TestClusterIdentity_Replace(t *testing.T) {

	var emptyCluster *ClusterIdentity
	var emptyData data.Clonable = nil

	cluster := NewClusterIdentity()
	cluster.Name = "cluster"
	cluster.Flavor = clusterflavor.K8S
	kp1, err := NewKeyPair("Key1")
	require.NoError(t, err)
	cluster.Keypair = kp1

	// Nil cluster, nil data
	result, xerr := emptyCluster.Replace(emptyData)
	if xerr == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	// Filled cluster, nil data
	result, xerr = cluster.Replace(emptyData)
	if xerr == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

	// Filled cluster, invalid data
	network := NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	_, derr := cluster.Replace(network)
	require.Contains(t, derr.Error(), "p is not a *ClusterIdentity")

	// Filled cluster, filled data
	cluster2 := NewClusterIdentity()
	cluster2.Name = "cluster2"
	cluster2.Flavor = clusterflavor.BOH
	kp2, err := NewKeyPair("Key2")
	require.NoError(t, err)
	cluster2.Keypair = kp2

	result, _ = cluster.Replace(cluster2)
	require.EqualValues(t, result, cluster2)
	require.EqualValues(t, result.(*ClusterIdentity).Keypair, kp2)
	require.EqualValues(t, result.(*ClusterIdentity).GetName(), cluster2.Name)
	clid, _ := result.(*ClusterIdentity).GetID()
	require.EqualValues(t, clid, cluster2.Name)

}
