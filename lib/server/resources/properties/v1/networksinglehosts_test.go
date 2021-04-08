package propertiesv1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetworkSingleHosts_Clone(t *testing.T) {
	ct := NewNetworkSingleHosts()
	ct.FreeSlots = append(ct.FreeSlots, FreeCIDRSlot{1, 5})

	clonedCt, ok := ct.Clone().(*NetworkSingleHosts)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.FreeSlots = append(clonedCt.FreeSlots, FreeCIDRSlot{15, 16})

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}

func TestNetworkSingleHosts_ReserveSlot(t *testing.T) {
	ct := NewNetworkSingleHosts()
	index := ct.ReserveSlot()
	assert.Equal(t, index, uint(1))

	index = ct.ReserveSlot()
	assert.Equal(t, index, uint(2))

	index = ct.ReserveSlot()
	assert.Equal(t, index, uint(3))

	ct.FreeSlot(2)
	expected := []FreeCIDRSlot{
		{ First: 2, Last: 2},
		{ First: 4, Last: SingleHostsMaxCIDRSlotValue},
	}
	areEqual := reflect.DeepEqual(ct.FreeSlots, expected)
	if !areEqual {
		t.Error("content is unexpected!")
		t.Fail()
	}

	index = ct.ReserveSlot()
	assert.Equal(t, index, uint(2))

	expected = []FreeCIDRSlot{
		{ First: 4, Last: SingleHostsMaxCIDRSlotValue},
	}
	areEqual = reflect.DeepEqual(ct.FreeSlots, expected)
	if !areEqual {
		t.Error("content is unexpected!")
		t.Fail()
	}
}