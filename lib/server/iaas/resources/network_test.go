package resources

import (
	"reflect"
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestVirtualIP_Clone(t *testing.T) {
	ho := NewHost()
	ho.Name = "Whatever"

	vip := NewVirtualIP()
	vip.Hosts = append(vip.Hosts, ho.ID)
	vipclone, _ := vip.Clone().(*VirtualIP)
	assert.Equal(t, vip, vipclone)

	vipclone.Hosts[0] = "Sleep"
	areEqual := reflect.DeepEqual(vip, vipclone)
	if areEqual {
		t.Error("It's a shallow clone, a modification in cloned instance changed the original")
		t.Fail()
	}

	areEqual = vip.Hosts[0] == vipclone.Hosts[0]
	if areEqual {
		t.Error("It's a shallow clone, a modification in cloned instance changed the original")
		t.Fail()
	}
}
