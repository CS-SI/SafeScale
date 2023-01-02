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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
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

	network := abstract.NewNetwork()
	network.ID = "Network ID"
	network.Name = "Network Name"

	bm = NewBucketMounts()
	_, xerr := bm.Replace(network)
	if xerr == nil {
		t.Error("BucketMounts.Replace(abstract.Network{}) expect an error")
		t.FailNow()
	}
	if !strings.Contains(xerr.Error(), "p is not a *BucketMounts") {
		t.Errorf("Expect error \"p is not a *BucketMounts\", has \"%s\"", xerr.Error())
	}

}

func TestBucketMounts_Clone(t *testing.T) {
	mounts := NewBucketMounts()
	mounts.ByHostID["i18930"] = "/buckets/my-bucket"
	mounts.ByHostName["my-server"] = "/buckets/my-bucket"

	cloned, err := mounts.Clone()
	if err != nil {
		t.Error("Clone error", err)
	}

	clonedMounts, ok := cloned.(*BucketMounts)
	if !ok {
		t.Error("Cloned BucketMounts not castable to *BucketMounts", err)
		t.Fail()
	}

	assert.Equal(t, mounts, clonedMounts)
	require.EqualValues(t, mounts, clonedMounts)

	clonedMounts.ByHostName["my-other-server"] = "/elsewhere/bucket-for-me"
	clonedMounts.ByHostID["i198931"] = "/elsewhere/bucket-for-me"

	areEqual := reflect.DeepEqual(mounts, clonedMounts)
	if areEqual {
		t.Error("Clone deep equal test: swallow clone")
		t.Fail()
	}
	require.NotEqualValues(t, mounts, clonedMounts)
}
