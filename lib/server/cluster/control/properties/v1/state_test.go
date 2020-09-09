package propertiesv1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/clusterstate"
)

func TestState_Clone(t *testing.T) {
	ct := newState()
	ct.State = clusterstate.Created

	clonedCt, ok := ct.Clone().(*State)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.State = clusterstate.Error

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
