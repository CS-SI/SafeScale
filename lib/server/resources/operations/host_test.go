package operations

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_host_IsNull_Empty(t *testing.T) {
	rh := &host{}
	isNotNullButItsEmpty := rh.IsNull()
	require.False(t, isNotNullButItsEmpty)

	rh = nil
	isnot := rh.IsNull()
	require.True(t, isnot)
}

func Test_host_IsNull_Nil(t *testing.T) {
	rh := &host{}
	rh = nil
	itis := rh.IsNull()
	require.True(t, itis)
}
