package main

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
)

func Test_Env_Setup(t *testing.T) {
	runOnlyInIntegrationTest("TEST_OVH")

	brokerd_launched, err := isBrokerdLaunched()
	if !brokerd_launched {
		fmt.Println("This requires that you launch brokerd in background and set the tenant")
		require.True(t, brokerd_launched)
	}
	require.Nil(t, err)

	in_path, err := canBeRun("broker")
	require.Nil(t, err)

	require.True(t, brokerd_launched)
	require.True(t, in_path)
}
