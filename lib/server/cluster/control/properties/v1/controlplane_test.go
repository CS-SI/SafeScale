package propertiesv1

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestControlPlane_Clone(t *testing.T) {
	host := resources.NewHost()
	host.Name = "Whatever"

	vip := resources.NewVirtualIP()
	vip.Hosts = append(vip.Hosts, host)

	ct := newControlPlane()
	ct.VirtualIP = vip

	clonedCt, ok := ct.Clone().(*ControlPlane)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.VirtualIP.Hosts[0].Name = "Test"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
