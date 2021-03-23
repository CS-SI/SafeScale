package propertiesv3

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNodes_Clone(t *testing.T) {
	node := &ClusterNode{
		ID:        "",
		Name:      "Something",
		PublicIP:  "",
		PrivateIP: "",
	}

	ct := newClusterNodes()
	ct.ByNumericalID[1] = node
	clonedCt, ok := ct.Clone().(*ClusterNodes)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.ByNumericalID[1].Name = "Else"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.FailNow()
	}
}

func TestNodes_Clone2(t *testing.T) {
	node := &ClusterNode{
		ID:        "",
		Name:      "Something",
		PublicIP:  "",
		PrivateIP: "",
	}

	ct := newClusterNodes()
	ct.ByNumericalID[1] = node
	clonedCt, ok := ct.Clone().(*ClusterNodes)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Masters = append(clonedCt.Masters, 10)

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.FailNow()
	}
}
