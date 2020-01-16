package propertiesv1

import (
	"github.com/magiconair/properties/assert"
	"reflect"
	"testing"
)

func TestComposite_Clone(t *testing.T) {
	ct := newComposite()
	ct.Tenants = append(ct.Tenants, "google")
	ct.Tenants = append(ct.Tenants, "amazon")

	clonedCt, ok := ct.Clone().(*Composite)
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
