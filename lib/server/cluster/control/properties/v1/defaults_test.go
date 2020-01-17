package propertiesv1

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestDefaults_Clone(t *testing.T) {
	ct := newDefaults()
	ct.Image = "something"
	ct.GatewaySizing = resources.HostDefinition{
		RAMSize: 3,
		GPUType: "NVidia",
	}

	clonedCt, ok := ct.Clone().(*Defaults)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.GatewaySizing.GPUNumber = 7
	clonedCt.GatewaySizing.GPUType = "Culture"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
