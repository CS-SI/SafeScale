package integration_tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests/enums/Providers"
	"github.com/stretchr/testify/require"
)

func Docker(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("Docker", 0, 0, 0, 0, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.100.0/24")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("deploy host check-feature gw-" + names.Networks[0] + " docker")
	require.NotNil(t, err)

	out, err = GetOutput("deploy host add-feature gw-" + names.Networks[0] + " docker")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run gw-" + names.Networks[0] + " -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = GetOutput("deploy host check-feature gw-" + names.Networks[0] + " docker")
	require.Nil(t, err)

	out, err = GetOutput("deploy host delete-feature gw-" + names.Networks[0] + " docker")
	require.Nil(t, err)

	out, err = GetOutput("deploy host check-feature gw-" + names.Networks[0] + " docker")
	require.NotNil(t, err)

	out, err = GetOutput("broker ssh run gw-" + names.Networks[0] + " -c \"docker ps\"")
	fmt.Print(out)
	require.NotNil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func DockerNotGateway(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("DockerNotGateway", 0, 0, 0, 1, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.101.0/24")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("deploy host check-feature " + names.Hosts[0] + " docker")
	require.NotNil(t, err)

	out, err = GetOutput("deploy host add-feature " + names.Hosts[0] + " docker")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run " + names.Hosts[0] + " -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = GetOutput("deploy host check-feature " + names.Hosts[0] + " docker")
	require.Nil(t, err)

	out, err = GetOutput("deploy host delete-feature " + names.Hosts[0] + " docker")
	require.Nil(t, err)

	out, err = GetOutput("deploy host check-feature " + names.Hosts[0] + " docker")
	require.NotNil(t, err)

	out, err = GetOutput("broker ssh run " + names.Hosts[0] + " -c \"docker ps\"")
	fmt.Print(out)
	require.NotNil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func DockerCompose(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("DockerCompose", 0, 0, 0, 0, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.100.0/24")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("deploy host check-feature gw-" + names.Networks[0] + " docker-compose")
	require.NotNil(t, err)

	out, err = GetOutput("deploy host add-feature gw-" + names.Networks[0] + " docker-compose")
	require.Nil(t, err)

	out, err = GetOutput("broker ssh run gw-" + names.Networks[0] + " -c \"docker-compose -v\"")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = GetOutput("deploy host check-feature gw-" + names.Networks[0] + " docker-compose")
	require.Nil(t, err)

	out, err = GetOutput("deploy host delete-feature gw-" + names.Networks[0] + " docker-compose")
	require.Nil(t, err)

	out, err = GetOutput("deploy host check-feature gw-" + names.Networks[0] + " docker-compose")
	require.NotNil(t, err)

	out, err = GetOutput("broker ssh run gw-" + names.Networks[0] + " -c \"docker-compose -v\"")
	fmt.Print(out)
	require.NotNil(t, err)
}
