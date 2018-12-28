package integration_tests

import (
	"fmt"
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
	"github.com/stretchr/testify/require"
)

func keyFromProvider(provider Providers.Enum) string {
	switch provider {
	case Providers.LOCAL:
		return "TEST_LOCAL"
	case Providers.OVH:
		return "TEST_OVH"
	case Providers.CLOUDFERRO:
		return "TEST_CLOUDFERRO"
	}
	return ""
}

func nameFromProvider(provider Providers.Enum) string {
	switch provider {
	case Providers.LOCAL:
		return "local"
	case Providers.OVH:
		return "ovh"
	case Providers.CLOUDFERRO:
		return "cloudferro"
	}
	return ""
}

func EnvSetup(t *testing.T, provider Providers.Enum) {
	key := keyFromProvider(provider)
	require.NotEmpty(t, key)

	RunOnlyInIntegrationTest(key)

	brokerdLaunched, err := IsBrokerdLaunched()
	if !brokerdLaunched {
		fmt.Println("This requires that you launch brokerd in background and set the tenant")
	}
	require.True(t, brokerdLaunched)
	require.Nil(t, err)

	inPath, err := CanBeRun("broker")
	require.Nil(t, err)

	require.True(t, brokerdLaunched)
	require.True(t, inPath)
}

func Setup(t *testing.T, provider Providers.Enum) {
	EnvSetup(t, provider)

	name := nameFromProvider(provider)
	require.NotEmpty(t, name)

	listStr, err := GetOutput("broker tenant list")
	require.Nil(t, err)
	require.True(t, len(listStr) > 0)

	getStr, err := GetOutput("broker tenant get")
	if err != nil {
		fmt.Println("This requires that you set the right tenant before launching the tests")
	}
	require.Nil(t, err)
	require.True(t, len(getStr) > 0)
	//require.True(t, strings.Contains(getStr, fmt.Sprintf("\"Provider\":\"%s\"", name)))
}
