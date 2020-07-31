package propertiesv1

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
    ct.PrivateNodes = append(ct.PrivateNodes, node)

    clonedCt, ok := ct.Clone().(*ClusterNodes)
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
