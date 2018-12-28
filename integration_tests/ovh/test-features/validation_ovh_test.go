package main

import (
	"fmt"
	"log"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/integration_tests"
	"github.com/stretchr/testify/require"
)

func Test_Docker_Feature(t *testing.T) {
	integration_tests.RunOnlyInIntegrationTest("TEST_OVH")
	featureTeardown()
	defer featureTeardown()

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

	out, err = integration_tests.GetOutput("broker network create deploytest")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker ssh run gw-deploytest -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = integration_tests.GetOutput("deploy host check-feature gw-deploytest docker")
	require.NotNil(t, err)

	out, err = integration_tests.GetOutput("deploy host add-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker ssh run gw-deploytest -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = integration_tests.GetOutput("deploy host check-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("deploy host delete-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("deploy host check-feature gw-deploytest docker")
	require.NotNil(t, err)

	out, err = integration_tests.GetOutput("broker ssh run gw-deploytest -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func Test_Docker_Feature_Not_Gateway(t *testing.T) {
	integration_tests.RunOnlyInIntegrationTest("TEST_OVH")
	featureTeardown()
	defer featureTeardown()

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

	out, err = integration_tests.GetOutput("broker network create deploytest")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker ssh run gw-deploytest -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = integration_tests.GetOutput("broker host create easyvm --public --net deploytest")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("deploy host check-feature easyvm docker")
	require.NotNil(t, err)

	out, err = integration_tests.GetOutput("deploy host add-feature easyvm docker")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker ssh run easyvm -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = integration_tests.GetOutput("deploy host check-feature easyvm docker")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("deploy host delete-feature easyvm docker")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("deploy host check-feature easyvm docker")
	require.NotNil(t, err)

	out, err = integration_tests.GetOutput("broker ssh run easyvm -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func featureTeardown() {
	log.Printf("Starting cleanup...")
	_, _ = integration_tests.GetOutput("broker host delete easyvm")
	_, _ = integration_tests.GetOutput("broker network delete deploytest")
	log.Printf("Finishing cleanup...")
}
