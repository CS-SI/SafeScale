package integration_tests

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
	"github.com/stretchr/testify/require"
)

func Docker(t *testing.T, provider Providers.Enum) {
	featureTeardown()
	defer featureTeardown()

	Setup(t, provider)

	out, err := GetOutput("broker network create deploytest")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run gw-deploytest -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("deploy host check-feature gw-deploytest docker")
	require.NotNil(t, err)

	out, err = GetOutput("deploy host add-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run gw-deploytest -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = GetOutput("deploy host check-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = GetOutput("deploy host delete-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = GetOutput("deploy host check-feature gw-deploytest docker")
	require.NotNil(t, err)

	out, err = GetOutput("broker ssh run gw-deploytest -c \"docker ps\"")
	fmt.Print(out)
	require.NotNil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func DockerNotGateway(t *testing.T, provider Providers.Enum) {
	featureTeardown()
	defer featureTeardown()

	Setup(t, provider)

	out, err := GetOutput("broker network create deploytest")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run gw-deploytest -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("broker host create easyvm --public --net deploytest")
	require.Nil(t, err)

	out, err = GetOutput("deploy host check-feature easyvm docker")
	require.NotNil(t, err)

	out, err = GetOutput("deploy host add-feature easyvm docker")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run easyvm -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = GetOutput("deploy host check-feature easyvm docker")
	require.Nil(t, err)

	out, err = GetOutput("deploy host delete-feature easyvm docker")
	require.Nil(t, err)

	out, err = GetOutput("deploy host check-feature easyvm docker")
	require.NotNil(t, err)

	out, err = GetOutput("broker ssh run easyvm -c \"docker ps\"")
	fmt.Print(out)
	require.NotNil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func featureTeardown() {
	log.Printf("Starting cleanup...")
	_, _ = GetOutput("broker host delete easyvm")
	_, _ = GetOutput("broker network delete deploytest")
	log.Printf("Finishing cleanup...")
}
