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
