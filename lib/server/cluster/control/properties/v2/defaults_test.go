package propertiesv2

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestDefaults_Clone(t *testing.T) {
	ct := newDefaults()
	ct.Image = "something"
	ct.GatewaySizing = resources.SizingRequirements{
		MinCores: 3,
		MinGPU:   1,
	}

	clonedCt, ok := ct.Clone().(*Defaults)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.GatewaySizing.MinCores = 7

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
