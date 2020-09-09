package propertiesv2

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNetwork_Clone(t *testing.T) {
	ct := newNetwork()
	ct.GatewayID = "None"

	clonedCt, ok := ct.Clone().(*Network)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.GatewayID = "Other"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
