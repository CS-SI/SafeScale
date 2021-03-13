package propertiesv1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVolumeAttachments_Clone(t *testing.T) {
	ct := NewVolumeAttachments()
	ct.Shareable = true
	ct.Hosts = map[string]string{"id1": "host1"}

	clonedCt, ok := ct.Clone().(*VolumeAttachments)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Hosts["id2"] = "host2"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
