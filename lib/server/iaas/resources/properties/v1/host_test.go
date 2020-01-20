package propertiesv1

import (
	"github.com/bxcodec/faker/v3"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHostDescription_Filler(t *testing.T) {
	var f HostDescription
	err := faker.FakeData(&f)

	assert.Nil(t, err)
	assert.NotEmpty(t, f.Tenant)
}
