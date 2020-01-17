package propertiesv1

import (
	"github.com/bxcodec/faker/v3"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHostDescription_Filler(t *testing.T) {
	var f HostDescription
	faker.FakeData(&f)

	assert.NotEmpty(t, f.Tenant)
}
