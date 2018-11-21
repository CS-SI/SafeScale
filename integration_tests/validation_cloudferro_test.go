package main

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"log"
	"strings"
	"testing"
	"time"
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

	out, err = getOutput("broker volume create --speed SSD volumetest")
	require.Nil(t, err)

	out, err = getOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "volumetest"))

	out, err = getOutput("broker volume  attach volumetest ferrohost")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = getOutput("broker volume delete volumetest")
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "still attached"))

	time.Sleep(5 * time.Second)

	out, err = getOutput("broker volume  detach volumetest ferrohost")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = getOutput("broker volume delete volumetest")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = getOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = getOutput("broker ssh run ferrohost -c \"uptime\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = getOutput("broker host delete ferrohost")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = getOutput("broker network delete ferronet")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))
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

	time.Sleep(5 * time.Second)

	out, err = getOutput("broker volume  attach volumetest ferrohost")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = getOutput("broker volume delete volumetest")
	if err != nil {
		captured := err.Error()
		log.Println(captured)
	}
	require.NotNil(t, err)
	require.True(t, strings.Contains(err.Error(), "still attached"))
}

func Test_Minimal(t *testing.T) {
	out, err := getOutput("broker volume delete volumetest")
	if err != nil {
		captured := err.Error()
		log.Println(out)
		log.Println(captured)
	}
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
	time.Sleep(5 * time.Second)
	_, _ = getOutput("broker volume detach volumetest ferrohost")
	time.Sleep(5 * time.Second)
	_, _ = getOutput("broker volume delete volumetest")
	time.Sleep(5 * time.Second)
	_, _ = getOutput("broker host delete ferrohost")
	time.Sleep(5 * time.Second)
	_, _ = getOutput("broker network delete ferronet")
	time.Sleep(5 * time.Second)
	log.Printf("Finishing cleanup...")
}
