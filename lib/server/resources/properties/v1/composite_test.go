package propertiesv1

import (
	"reflect"
	"testing"

	"github.com/magiconair/properties/assert"
)

func TestClusterComposite_Clone(t *testing.T) {
	ct := newClusterComposite()
	ct.Tenants = append(ct.Tenants, "google")
	ct.Tenants = append(ct.Tenants, "amazon")

	clonedCt, ok := ct.Clone().(*ClusterComposite)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Tenants[0] = "choose"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
