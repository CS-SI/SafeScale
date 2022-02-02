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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHostLocalMount_IsNull(t *testing.T) {
	var mnt *HostLocalMount = nil
	if !mnt.IsNull() {
		t.Error("HostLocalMount nil pointer is null")
		t.Fail()
	}
	mnt = NewHostLocalMount()
	if !mnt.IsNull() {
		t.Error("Empty HostLocalMount is null")
		t.Fail()
	}
	mnt.Device = "HostLocalMount Device"
	if mnt.IsNull() {
		t.Error("HostLocalMount is not null")
		t.Fail()
	}

}

func TestHostLocalMount_Replace(t *testing.T) {
	var mnt *HostLocalMount = nil
	mnt2 := &HostLocalMount{
		Device:     "",
		Path:       "",
		FileSystem: "",
		Options:    "",
	}
	result := mnt.Replace(mnt2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Can't replace nil pointer")
		t.Fail()

	}

}

func TestHostRemoteMount_IsNull(t *testing.T) {

	var mnt *HostRemoteMount = nil
	if !mnt.IsNull() {
		t.Error("HostRemoteMount nil pointer is null")
		t.Fail()
	}
	mnt = NewHostRemoteMount()
	if !mnt.IsNull() {
		t.Error("Empty HostRemoteMount is null")
		t.Fail()
	}
	mnt.ShareID = "HostRemoteMount ShareID"
	if mnt.IsNull() {
		t.Error("HostRemoteMount is not null")
		t.Fail()
	}
}

func TestHostRemoteMount_Clone(t *testing.T) {

	hrm := &HostRemoteMount{
		ShareID:    "HostRemoteMount ShareID",
		Export:     "HostRemoteMount Export",
		Path:       "HostRemoteMount Path",
		FileSystem: "HostRemoteMount FileSystem",
		Options:    "HostRemoteMount Options",
	}
	clonedHrm, ok := hrm.Clone().(*HostRemoteMount)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, hrm, clonedHrm)
	require.EqualValues(t, hrm, clonedHrm)
	clonedHrm.ShareID = "HostRemoteMount ShareID2"

	areEqual := reflect.DeepEqual(hrm, clonedHrm)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, hrm, clonedHrm)
}

func TestHostRemoteMount_Replace(t *testing.T) {

	var hrm *HostRemoteMount = nil
	hrm2 := &HostRemoteMount{
		ShareID:    "HostRemoteMount ShareID",
		Export:     "HostRemoteMount Export",
		Path:       "HostRemoteMount Path",
		FileSystem: "HostRemoteMount FileSystem",
		Options:    "HostRemoteMount Options",
	}
	result := hrm.Replace(hrm2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Can't replace nil pointer")
		t.Fail()

	}
	hrm = &HostRemoteMount{
		ShareID:    "HostRemoteMount ShareID2",
		Export:     "HostRemoteMount Export2",
		Path:       "HostRemoteMount Path2",
		FileSystem: "HostRemoteMount FileSystem2",
		Options:    "HostRemoteMount Options2",
	}

	result = hrm.Replace(hrm2)
	areEqual := reflect.DeepEqual(result, hrm2)
	if !areEqual {
		t.Error("Replace does not retitute values")
		t.Fail()
	}
}

func TestHostMount_IsNull(t *testing.T) {

	var mnt *HostMounts = nil
	if !mnt.IsNull() {
		t.Error("HostMounts nil pointer is null")
		t.Fail()
	}
	mnt = NewHostMounts()
	if !mnt.IsNull() {
		t.Error("Empty HostMounts is null")
		t.Fail()
	}
	mnt.LocalMountsByPath["/share/my-data"] = NewHostLocalMount()
	if mnt.IsNull() {
		t.Error("HostMounts is not null")
		t.Fail()
	}

}

func TestHostMounts_Clone(t *testing.T) {
	mounts := NewHostMounts()
	mounts.BucketMounts["my-bucket"] = "/buckets/my-bucket"
	mounts.LocalMountsByPath["/share/my-data"] = NewHostLocalMount()
	mounts.LocalMountsByPath["/share/my-data"].Path = "/share/my-data"
	mounts.LocalMountsByPath["/share/my-data"].Device = "/dev/sdc"
	mounts.LocalMountsByPath["/share/my-data"].FileSystem = "ext4"

	clonedMounts, ok := mounts.Clone().(*HostMounts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, mounts, clonedMounts)
	require.EqualValues(t, mounts, clonedMounts)
	clonedMounts.BucketMounts["my-bucket"] = "/elsewhere/bucket-for-me"

	areEqual := reflect.DeepEqual(mounts, clonedMounts)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
	require.NotEqualValues(t, mounts, clonedMounts)
}

func TestHostMounts_Replace(t *testing.T) {

	var mnt *HostMounts = nil
	mnt2 := NewHostMounts()
	result := mnt.Replace(mnt2)
	if fmt.Sprintf("%p", result) != "0x0" {
		t.Error("Can't replace nil pointer")
		t.Fail()
	}
	mnt = &HostMounts{
		LocalMountsByDevice: map[string]string{
			"Device1": "Mount1",
			"Device2": "Mount2",
			"Device3": "Mount3",
		},
		LocalMountsByPath: map[string]*HostLocalMount{
			"Path1": NewHostLocalMount(),
			"Path2": NewHostLocalMount(),
			"Path3": NewHostLocalMount(),
		},
		RemoteMountsByShareID: map[string]string{
			"Share1": "Mount1",
			"Share2": "Mount2",
			"Share3": "Mount3",
		},
		RemoteMountsByExport: map[string]string{
			"Export1": "Mount1",
			"Export2": "Mount2",
			"Export3": "Mount3",
		},
		RemoteMountsByPath: map[string]*HostRemoteMount{
			"Path1": NewHostRemoteMount(),
			"Path2": NewHostRemoteMount(),
			"Path3": NewHostRemoteMount(),
		},
		BucketMounts: map[string]string{
			"Bucket1": "Mount1",
			"Bucket2": "Mount2",
			"Bucket3": "Mount3",
		},
	}
	result = mnt2.Replace(mnt)

	areEqual := reflect.DeepEqual(result, mnt)
	if !areEqual {
		t.Error("Replace does not restitute values")
		t.Fail()
	}

}
