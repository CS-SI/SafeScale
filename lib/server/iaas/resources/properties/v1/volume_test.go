package propertiesv1

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestVolumeDescription_Clone(t *testing.T) {
	ct := NewVolumeDescription()
	ct.Purpose = "Never"

	clonedCt, ok := ct.Clone().(*VolumeDescription)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Purpose = "Other"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestVolumeAttachments_Clone(t *testing.T) {
	ct := NewVolumeAttachments()
	ct.Hosts["Never"] = "Change"

	clonedCt, ok := ct.Clone().(*VolumeAttachments)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Hosts["Never"] = "Other"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
