package tenant

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests"
	"github.com/stretchr/testify/require"
)

func Test_Env_Setup(t *testing.T) {
	integration_tests.RunOnlyInIntegrationTest("TEST_CLOUDFERRO")

	brokerd_launched, err := integration_tests.IsBrokerdLaunched()
	if !brokerd_launched {
		fmt.Println("This requires that you launch brokerd in background and set the tenant")
		require.True(t, brokerd_launched)
	}
	require.Nil(t, err)

	in_path, err := integration_tests.CanBeRun("broker")
	require.Nil(t, err)

	require.True(t, brokerd_launched)
	require.True(t, in_path)
}

func Test_Setup(t *testing.T) {
	integration_tests.RunOnlyInIntegrationTest("TEST_CLOUDFERRO")

	brokerd_launched, err := integration_tests.IsBrokerdLaunched()
	if !brokerd_launched {
		fmt.Println("This requires that you launch brokerd in background and set the tenant")
		require.True(t, brokerd_launched)
	}
	require.Nil(t, err)

	in_path, err := integration_tests.CanBeRun("broker")
	require.Nil(t, err)

	require.True(t, brokerd_launched)
	require.True(t, in_path)

	out, err := integration_tests.GetOutput("broker tenant list")
	require.Nil(t, err)
	require.True(t, len(out) > 0)

	out, err = integration_tests.GetOutput("broker tenant get")
	if err != nil {
		fmt.Println("This requires that you set the right tenant before launching the tests")
		require.Nil(t, err)
	}
	require.True(t, len(out) > 0)
	require.True(t, strings.Contains(out, "ferro"))
}
