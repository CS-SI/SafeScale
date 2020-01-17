package propertiesv1

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestNetworkDescription_Clone(t *testing.T) {
	ct := NewNetworkDescription()
	ct.Purpose = "Someone"

	clonedCt, ok := ct.Clone().(*NetworkDescription)
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

func TestNetworkHosts_Clone(t *testing.T) {
	ct := NewNetworkHosts()
	ct.ByName["Never"] = "Change"

	clonedCt, ok := ct.Clone().(*NetworkHosts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.ByName["Never"] = "Other"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
