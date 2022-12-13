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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestObjectStorageBucket_NewObjectStorageBucket(t *testing.T) {

	n := NewObjectStorageBucket()
	if !n.IsNull() {
		t.Error("ObjectStorageBucket is null !")
		t.Fail()
	}
	if n.IsConsistent() {
		t.Error("ObjectStorageBucket is not consistent !")
		t.Fail()
	}
	if n.OK() {
		t.Error("ObjectStorageBucket is not ok !")
		t.Fail()
	}
	n.ID = "ObjectStorageBucket ID"
	n.Name = "ObjectStorageBucket Name"
	if n.IsNull() {
		t.Error("ObjectStorageBucket is not null !")
		t.Fail()
	}
	if !n.IsConsistent() {
		t.Error("ObjectStorageBucket is consistent !")
		t.Fail()
	}
	if !n.OK() {
		t.Error("ObjectStorageBucket is ok !")
		t.Fail()
	}
}

func TestObjectStorageBucket_Replace(t *testing.T) {

	var o1 *ObjectStorageBucket
	var o2 *ObjectStorageBucket
	result, err := o1.Replace(o2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
	require.Nil(t, result)

}

func TestObjectStorageBucket_Clone(t *testing.T) {
	b := NewObjectStorageBucket()
	b.Name = "host"

	at, err := b.Clone()
	if err != nil {
		t.Error(err)
	}

	bc, ok := at.(*ObjectStorageBucket)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, b, bc)
	require.EqualValues(t, b, bc)
	bc.MountPoint = "/mountpoint"

	areEqual := reflect.DeepEqual(b, bc)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, b, bc)
}

func TestObjectStorageBucket_Serialize(t *testing.T) {

	var n *ObjectStorageBucket = nil
	_, err := n.Serialize()
	if err == nil {
		t.Error("Can't serialize nil ObjectStorageBucket")
		t.Fail()
	}

	n = NewObjectStorageBucket()
	n.ID = "ObjectStorageBucket ID"
	n.Name = "ObjectStorageBucket Name"
	n.Host = "ObjectStorageBucket Host"
	n.MountPoint = "ObjectStorageBucket MountPoint"

	serial, err := n.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	n2 := NewObjectStorageBucket()
	err = n2.Deserialize(serial)
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	areEqual := reflect.DeepEqual(n, n2)
	if !areEqual {
		t.Error("Serialize/Deserialize does not restitute values")
		t.Fail()
	}

}

func TestObjectStorageBucket_Deserialize(t *testing.T) {

	n := NewObjectStorageBucket()
	n.ID = "ObjectStorageBucket ID"
	n.Name = "ObjectStorageBucket Name"
	n.Host = "ObjectStorageBucket Host"
	n.MountPoint = "ObjectStorageBucket MountPoint"

	serial, err := n.Serialize()
	if err != nil {
		t.Error(err)
		t.Fail()
	}

	var n2 *ObjectStorageBucket
	err = n2.Deserialize(serial)
	if err == nil {
		t.Error("Can't deserialize nil ObjectStorageBucket")
		t.Fail()
	}

	brokenSerial := []byte("\"id\":\"ObjectStorageBucket ID\",\"name\":\"ObjectStorageBucket Name\",\"host\":\"ObjectStorageBucket Host\",\"mountPoint\":\"ObjectStorageBucket MountPoint\"}")
	err = n.Deserialize(brokenSerial)
	if err == nil {
		t.Error("Can't deserialize broken serial, expect *fail.ErrUnqualified")
		t.Fail()
	}

}

func TestObjectStorageBucket_GetName(t *testing.T) {

	n := ObjectStorageBucket{}
	name := n.GetName()
	if name != "" {
		t.Error("Can't read name when no name given")
		t.Fail()
	}
	n = ObjectStorageBucket{
		Name: "ObjectStorageBucket Name",
	}
	name = n.GetName()
	if name != n.Name {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestObjectStorageBucket_GetID(t *testing.T) {

	n := ObjectStorageBucket{}
	id := n.GetID()
	if id != "" {
		t.Error("Can't read id when no name given")
		t.Fail()
	}
	n = ObjectStorageBucket{
		ID:   "ObjectStorageBucket ID",
		Name: "ObjectStorageBucket Name",
	}
	id = n.GetID()
	if id != n.ID {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestObjectStorageItemMetadata_Clone(t *testing.T) {

	c1 := ObjectStorageItemMetadata{
		"Field1": "Value1",
		"Field2": "Value2",
		"Field3": "Value3",
		"Field4": "Value4",
		"Field5": "Value5",
		"Field6": "Value6",
		"Field7": "Value7",
		"Field8": "Value8",
		"Field9": "Value9",
	}
	c2 := c1.Clone()
	areEqual := reflect.DeepEqual(c1, c2)
	if !areEqual {
		t.Error("Wrong clone restitution")
		t.Fail()
	}

}

func TestObjectStorageItem_GetName(t *testing.T) {

	osi := ObjectStorageItem{
		BucketName: "ObjectStorageItem BucketName",
		ItemID:     "ObjectStorageItem ItemID",
		ItemName:   "ObjectStorageItem ItemName",
		Metadata: ObjectStorageItemMetadata{
			"Field1": "Value1",
			"Field2": "Value2",
			"Field3": "Value3",
			"Field4": "Value4",
			"Field5": "Value5",
			"Field6": "Value6",
			"Field7": "Value7",
			"Field8": "Value8",
			"Field9": "Value9",
		},
	}

	if osi.GetName() != osi.ItemName {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}

func TestObjectStorageItem_GetID(t *testing.T) {

	osi := ObjectStorageItem{
		BucketName: "ObjectStorageItem BucketName",
		ItemID:     "ObjectStorageItem ItemID",
		ItemName:   "ObjectStorageItem ItemName",
		Metadata: ObjectStorageItemMetadata{
			"Field1": "Value1",
			"Field2": "Value2",
			"Field3": "Value3",
			"Field4": "Value4",
			"Field5": "Value5",
			"Field6": "Value6",
			"Field7": "Value7",
			"Field8": "Value8",
			"Field9": "Value9",
		},
	}

	if osi.GetID() != osi.ItemID {
		t.Error("Wrong value restitution")
		t.Fail()
	}

}
