package fail

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHierarchy(t *testing.T) {
	var err Error
	err = ExecutionError(fmt.Errorf("whatever"))
	assert.NotNil(t, err)
}

func TestConcreteHierarchy(t *testing.T) {
	var err ErrExecution
	err = ExecutionError(fmt.Errorf("whatever"))
	assert.NotNil(t, err)
}
