package main

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"log"
	"strings"
	"testing"
)

func Test_Nas_Error(t *testing.T) {
	runOnlyInIntegrationTest("TEST_CLOUDFERRO")

	ferroTearDown()
	defer ferroTearDown()

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

	out, err = getOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network ferronet...")

	out, err = getOutput("broker network create ferronet")
	require.Nil(t, err)

	fmt.Println("Creating VM ferrohost...")

	out, err = getOutput("broker host create ferrohost --public --net ferronet")
	require.Nil(t, err)

	out, err = getOutput("broker host inspect ferrohost")
	require.Nil(t, err)

	fmt.Println("Creating Nas ferronas...")

	out, err = getOutput("broker nas create ferronas ferrohost")
	require.Nil(t, err)

	fmt.Println("Creating Volume volumetest...")

	out, err = getOutput("broker volume create volumetest")
	require.Nil(t, err)

	out, err = getOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "volumetest"))

	out, err = getOutput("broker volume  attach volumetest ferrohost")
	require.Nil(t, err)

	out, err = getOutput("broker volume delete volumetest")
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "still attached"))

	out, err = getOutput("broker volume  detach volumetest ferrohost")
	require.Nil(t, err)

	out, err = getOutput("broker volume delete volumetest")
	require.Nil(t, err)
}

func Test_Until_Volume_Error(t *testing.T) {
	runOnlyInIntegrationTest("TEST_CLOUDFERRO")

	ferroTearDown()
	// defer ferroTearDown()

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

	out, err = getOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network ferronet...")

	out, err = getOutput("broker network create ferronet")
	require.Nil(t, err)

	fmt.Println("Creating VM ferrohost...")

	out, err = getOutput("broker host create ferrohost --public --net ferronet")
	require.Nil(t, err)

	out, err = getOutput("broker host inspect ferrohost")
	require.Nil(t, err)

	fmt.Println("Creating Nas ferronas...")

	out, err = getOutput("broker nas create ferronas ferrohost")
	require.Nil(t, err)

	fmt.Println("Creating Volume volumetest...")

	out, err = getOutput("broker volume create volumetest")
	require.Nil(t, err)
}

func Test_Ready_To_Ssh(t *testing.T) {
	runOnlyInIntegrationTest("TEST_CLOUDFERRO")

	ferroTearDown()

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

	out, err = getOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network ferronet...")

	out, err = getOutput("broker network create ferronet")
	require.Nil(t, err)

	fmt.Println("Creating VM ferrohost...")

	out, err = getOutput("broker host create ferrohost --public --net ferronet")
	require.Nil(t, err)

	out, err = getOutput("broker host inspect ferrohost")
	require.Nil(t, err)

	fmt.Println(out)
}

func Test_Nas_Cleanup(t *testing.T) {
	runOnlyInIntegrationTest("TEST_CLOUDFERRO")

	ferroTearDown()
}

func ferroTearDown() {
	runOnlyInIntegrationTest("TEST_CLOUDFERRO")

	log.Printf("Starting cleanup...")
	_, _ = getOutput("broker nas delete ferronas")
	_, _ = getOutput("broker volume delete volumetest")
	_, _ = getOutput("broker host delete ferrohost")
	_, _ = getOutput("broker network delete ferronet")
	log.Printf("Finishing cleanup...")
}
