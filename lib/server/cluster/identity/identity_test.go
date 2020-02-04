package identity

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
)

func TestIdentity_Clone(t *testing.T) {
	ct := NewIdentity()
	ct.Keypair = &resources.KeyPair{
		ID:   "None",
		Name: "salvation",
	}

	clonedCt, ok := ct.Clone().(*Identity)
	if !ok {
		t.Fail()
	}

	assert.Equal(t, ct, clonedCt)
	clonedCt.Keypair.Name = "Other"

	areEqual := reflect.DeepEqual(ct, clonedCt)
	if areEqual {
		t.Error("It's a shallow clone !")
		t.Fail()
	}
}
