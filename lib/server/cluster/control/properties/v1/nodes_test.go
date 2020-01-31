package propertiesv1

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestNodes_Clone(t *testing.T) {
	node := &Node{
		ID:        "",
		Name:      "Something",
		PublicIP:  "",
		PrivateIP: "",
	}

	ct := newNodes()
	ct.PrivateNodes = append(ct.PrivateNodes, node)

	clonedCt, ok := ct.Clone().(*Nodes)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.PrivateNodes[0].Name = "Else"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
