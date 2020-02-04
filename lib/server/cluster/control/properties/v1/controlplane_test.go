package propertiesv1

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/stretchr/testify/assert"
)

func TestControlPlane_Clone(t *testing.T) {
	vip := resources.NewVirtualIP()
	vip.Hosts = append(vip.Hosts, "Whatever")

	ct := newControlPlane()
	ct.VirtualIP = vip

	clonedCt, ok := ct.Clone().(*ControlPlane)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.VirtualIP.Hosts[0] = "Test"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
