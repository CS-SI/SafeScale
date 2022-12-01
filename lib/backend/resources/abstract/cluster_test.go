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

package abstract

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCluster_Clone(t *testing.T) {
	c, _ := NewCluster()
	c.Name = "cluster"

	cc, err := clonable.CastedClone[*Cluster](c)
	require.Nil(t, err)

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

func TestCluster_OK(t *testing.T) {

	c, _ := NewCluster()
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

func TestCluster_Serialize(t *testing.T) {

	// Serialize empty clusterIdentity
	c1, _ := NewCluster()
	_, err := c1.Serialize()
	if err == nil {
		t.Error("Should throw fail.InvalidInstanceError")
		t.FailNow()
	}

	// Junk attributes (broken pointer) for makes fail json.Marshal
	var fkp *KeyPair
	c1, _ = NewCluster()
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
	c2, _ := NewCluster()
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

func TestCluster_Deserialize(t *testing.T) {

	// Serialize empty clusterIdentity
	var err error
	var serial []byte
	c1, _ := NewCluster()
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
	var emptyCluster *Cluster
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

func TestCluster_Replace(t *testing.T) {

	var emptyCluster *Cluster
	var emptyData clonable.Clonable = nil

	cluster, _ := NewCluster()
	cluster.Name = "cluster"
	cluster.Flavor = clusterflavor.K8S
	kp1, err := NewKeyPair("Key1")
	require.NoError(t, err)
	cluster.Keypair = kp1

	// Nil cluster, nil data
	xerr := emptyCluster.Replace(emptyData)
	if xerr == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	// Filled cluster, nil data
	xerr = cluster.Replace(emptyData)
	if xerr == nil {
		t.Errorf("Replace should NOT work with nil")
	}

	// Filled cluster, invalid data
	network, _ := NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	derr := cluster.Replace(network)
	require.Contains(t, derr.Error(), "failed to cast")

	// Filled cluster, filled data
	cluster2, _ := NewCluster()
	cluster2.Name = "cluster2"
	cluster2.Flavor = clusterflavor.BOH
	kp2, err := NewKeyPair("Key2")
	require.NoError(t, err)
	cluster2.Keypair = kp2

	_ = cluster.Replace(cluster2)
	require.EqualValues(t, cluster, cluster2)
	require.EqualValues(t, cluster.Keypair, kp2)
	require.EqualValues(t, cluster.GetName(), cluster2.Name)
	clid, _ := cluster.GetID()
	require.EqualValues(t, clid, cluster2.Name)

}
