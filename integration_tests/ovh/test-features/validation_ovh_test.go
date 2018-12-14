package main

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"log"
	"strings"
	"testing"
)

func Test_Docker_Feature(t *testing.T) {
	runOnlyInIntegrationTest("TEST_OVH")
	featureTeardown()
	defer featureTeardown()

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

	out, err := getOutput("broker tenant list")
	require.Nil(t, err)
	require.True(t, len(out) > 0)

	out, err = getOutput("broker tenant get")
	if err != nil {
		fmt.Println("This requires that you set the right tenant before launching the tests")
		require.Nil(t, err)
	}
	require.True(t, len(out) > 0)

	out, err = getOutput("broker network create deploytest")
	require.Nil(t, err)

	out, err = getOutput("broker ssh run gw-deploytest -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = getOutput("deploy host check-feature gw-deploytest docker")
	require.NotNil(t, err)

	out, err = getOutput("deploy host add-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = getOutput("broker ssh run gw-deploytest -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = getOutput("deploy host check-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = getOutput("deploy host delete-feature gw-deploytest docker")
	require.Nil(t, err)

	out, err = getOutput("deploy host check-feature gw-deploytest docker")
	require.NotNil(t, err)

	out, err = getOutput("broker ssh run gw-deploytest -c \"docker ps\"")
	fmt.Print(out)
	require.NotNil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func Test_Docker_Feature_Not_Gateway(t *testing.T) {
	runOnlyInIntegrationTest("TEST_OVH")
	featureTeardown()
	defer featureTeardown()

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

	out, err := getOutput("broker tenant list")
	require.Nil(t, err)
	require.True(t, len(out) > 0)

	out, err = getOutput("broker tenant get")
	if err != nil {
		fmt.Println("This requires that you set the right tenant before launching the tests")
		require.Nil(t, err)
	}
	require.True(t, len(out) > 0)

	out, err = getOutput("broker network create deploytest")
	require.Nil(t, err)

	out, err = getOutput("broker ssh run gw-deploytest -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = getOutput("broker host create easyvm --public --net deploytest")
	require.Nil(t, err)

	out, err = getOutput("deploy host check-feature easyvm docker")
	require.NotNil(t, err)

	out, err = getOutput("deploy host add-feature easyvm docker")
	require.Nil(t, err)

	out, err = getOutput("broker ssh run easyvm -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = getOutput("deploy host check-feature easyvm docker")
	require.Nil(t, err)

	out, err = getOutput("deploy host delete-feature easyvm docker")
	require.Nil(t, err)

	out, err = getOutput("deploy host check-feature easyvm docker")
	require.NotNil(t, err)

	out, err = getOutput("broker ssh run easyvm -c \"docker ps\"")
	fmt.Print(out)
	require.NotNil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func featureTeardown()  {
	log.Printf("Starting cleanup...")
	_, _ = getOutput("broker host delete easyvm")
	_, _ = getOutput("broker network delete deploytest")
	log.Printf("Finishing cleanup...")
}
