package propertiesv1

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestHostDescription_Clone(t *testing.T) {
	ct := NewHostDescription()
	ct.Creator = "Someone"

	clonedCt, ok := ct.Clone().(*HostDescription)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Creator = "Other"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestHostNetwork_Clone(t *testing.T) {
	ct := NewHostNetwork()
	ct.IPv4Addresses["something"] = "else"

	clonedCt, ok := ct.Clone().(*HostNetwork)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.IPv4Addresses["else"] = "Other"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestHostSizing_Clone(t *testing.T) {
	ct := NewHostSizing()
	ct.AllocatedSize = &HostSize{
		DiskSize:  1,
		GPUNumber: 3,
	}

	clonedCt, ok := ct.Clone().(*HostSizing)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.AllocatedSize.DiskSize = 2

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestHostVolumes_Clone(t *testing.T) {
	ct := NewHostVolumes()
	ct.VolumesByID["soho"] = &HostVolume{
		AttachID: "Something",
	}

	clonedCt, ok := ct.Clone().(*HostVolumes)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.VolumesByID["soho"].AttachID = "Else"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestHostMounts_Clone(t *testing.T) {
	ct := NewHostMounts()
	ct.LocalMountsByPath["soho"] = &HostLocalMount{
		Path: "Something",
	}

	clonedCt, ok := ct.Clone().(*HostMounts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.LocalMountsByPath["soho"].Path = "Else"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestHostShare_Clone(t *testing.T) {
	ct := NewHostShare()
	ct.Path = "Something"

	clonedCt, ok := ct.Clone().(*HostShare)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Path = "Else"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestHostShares_Clone(t *testing.T) {
	ct := NewHostShares()
	ct.ByID["DarkestRoads"] = &HostShare{
		Name: "Graveyard",
	}

	clonedCt, ok := ct.Clone().(*HostShares)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.ByID["DarkestRoads"].Name = "mistake"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestHostInstalledFeature_Clone(t *testing.T) {
	ct := NewHostInstalledFeature()
	ct.Requires = append(ct.Requires, "DarkestRoads")

	clonedCt, ok := ct.Clone().(*HostInstalledFeature)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Requires[0] = "mistake"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestHostFeatures_Clone(t *testing.T) {
	ct := NewHostFeatures()
	ct.Installed["DarkestRoads"] = &HostInstalledFeature{
		HostContext: false,
	}

	clonedCt, ok := ct.Clone().(*HostFeatures)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Installed["DarkestRoads"].HostContext = true

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
