package propertiesv1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
)

func TestControlPlane_Clone(t *testing.T) {
	vip := abstract.NewVirtualIP()
	hc := abstract.NewHostCore()
	hc.Name = "whatever"
	vip.Hosts = append(vip.Hosts, hc)

	ct := newClusterControlPlane()
	ct.VirtualIP = vip

	clonedCt, ok := ct.Clone().(*ClusterControlPlane)
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
