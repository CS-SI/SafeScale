package propertiesv1

import (
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/clusterstate"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
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
