package concurrency

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidInternalTaskCtx(t *testing.T) {
	ta, err := newTask(nil, nil)
	require.Nil(t, ta)
	require.NotNil(t, err)
}

func TestInternalChecks(t *testing.T) {
	ta, err := newTaskGroup(nil, nil) // It doesn't behave the same way newTask does, it should
	require.Nil(t, ta)
	require.NotNil(t, err)
}
