package propertiesv1

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHostNetwork_Clone(t *testing.T) {
	ct := &HostNetwork{
		DefaultNetworkID: "id1",
		NetworksByID: map[string]string{"id1": "subnet1"},
		NetworksByName: map[string]string{"subnet1": "id1"},
		PublicIPv4: "195.32.4.1",
		IPv4Addresses: map[string]string{"id1": "192.168.2.10"},
		IPv6Addresses: map[string]string{"id1": "2001:db8:3333:4444:5555:6666:7777:8888"},
	}

	clonedCt, ok := ct.Clone().(*HostNetwork)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.NetworksByID["id2"] = "subnet2"
	clonedCt.NetworksByName["subnet2"] = "id2"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
