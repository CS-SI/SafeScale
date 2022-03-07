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

func TestBucketMounts_IsNull(t *testing.T) {

	var bm *BucketMounts = nil
	if !bm.IsNull() {
		t.Error("BucketMounts Nil pointer is null")
		t.Fail()
	}

	bm = &BucketMounts{
		ByHostID:   map[string]string{},
		ByHostName: map[string]string{},
	}
	if !bm.IsNull() {
		t.Error("BucketMounts with empty ByHostID is null")
		t.Fail()
	}
	bm = &BucketMounts{
		ByHostID: map[string]string{
			"HostID": "HostData",
		},
		ByHostName: map[string]string{},
	}
	if bm.IsNull() {
		t.Error("No, BucketMounts is not null")
		t.Fail()
	}

}

func TestBucketMounts_Replace(t *testing.T) {

	var bm *BucketMounts = nil
	bm2 := NewBucketMounts()
	_, err := bm.Replace(bm2)
	if err == nil {
		t.Errorf("Replace should NOT work with nil")
	}
}

func TestBucketMounts_Clone(t *testing.T) {
	mounts := NewBucketMounts()
	mounts.ByHostID["i18930"] = "/buckets/my-bucket"
	mounts.ByHostName["my-server"] = "/buckets/my-bucket"

	cloned, err := mounts.Clone()
	if err != nil {
		t.Error(err)
	}

	clonedMounts, ok := cloned.(*BucketMounts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, mounts, clonedMounts)
	require.EqualValues(t, mounts, clonedMounts)

	clonedMounts.ByHostName["my-other-server"] = "/elsewhere/bucket-for-me"
	clonedMounts.ByHostID["i198931"] = "/elsewhere/bucket-for-me"

	areEqual := reflect.DeepEqual(mounts, clonedMounts)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, mounts, clonedMounts)
}
