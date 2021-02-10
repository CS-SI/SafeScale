package fail

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHierarchy(t *testing.T) {
	var err Error // nolint
	err = ExecutionError(fmt.Errorf("whatever"))
	assert.NotNil(t, err)
}

func TestConcreteHierarchy(t *testing.T) {
	var err *ErrExecution // nolint
	err = ExecutionError(fmt.Errorf("whatever"))
	assert.NotNil(t, err)
}
