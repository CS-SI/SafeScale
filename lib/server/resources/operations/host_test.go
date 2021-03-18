package operations

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_host_IsNull_Empty(t *testing.T) {
	rh := &host{}
	itis := rh.isNull()
	require.True(t, itis)
}

func Test_host_IsNull_Nil(t *testing.T) {
	var rh *host
	//goland:noinspection GoNilness
	itis := rh.isNull()
	require.True(t, itis)
}
