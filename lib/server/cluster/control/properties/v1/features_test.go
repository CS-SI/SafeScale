package propertiesv1

import (
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestFeatures_Clone(t *testing.T) {
	ct := newFeatures()
	ct.Installed["fair"] = "something"
	ct.Disabled["kind"] = struct{}{}

	clonedCt, ok := ct.Clone().(*Features)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Installed["fair"] = "commitment"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
