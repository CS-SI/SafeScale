package integration_tests

import (
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_Until_Volume_Error(t *testing.T) {
	RunOnlyInIntegrationTest("TEST_CLOUDFERRO")

	ferroTearDown()
	// defer ferroTearDown()

	brokerd_launched, err := IsBrokerdLaunched()
	if !brokerd_launched {
		fmt.Println("This requires that you launch brokerd in background and set the tenant")
		require.True(t, brokerd_launched)
	}
	require.Nil(t, err)

	in_path, err := CanBeRun("broker")
	require.Nil(t, err)

	require.True(t, brokerd_launched)
	require.True(t, in_path)

	out, err := GetOutput("broker tenant list")
	require.Nil(t, err)
	require.True(t, len(out) > 0)

	out, err = GetOutput("broker tenant get")
	if err != nil {
		fmt.Println("This requires that you set the right tenant before launching the tests")
		require.Nil(t, err)
	}
	require.True(t, len(out) > 0)

	out, err = GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network ferronet...")

	out, err = GetOutput("broker network create ferronet")
	require.Nil(t, err)

	fmt.Println("Creating VM ferrohost...")

	out, err = GetOutput("broker host create ferrohost --public --net ferronet")
	require.Nil(t, err)

	out, err = GetOutput("broker host inspect ferrohost")
	require.Nil(t, err)

	fmt.Println("Creating Nas ferronas...")

	out, err = GetOutput("broker nas create ferronas ferrohost")
	require.Nil(t, err)

	fmt.Println("Creating Volume volumetest...")

	out, err = GetOutput("broker volume create volumetest")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume  attach volumetest ferrohost")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume delete volumetest")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))
}

func Test_Nas_Cleanup(t *testing.T) {
	RunOnlyInIntegrationTest("TEST_CLOUDFERRO")

	ferroTearDown()
}

func ferroTearDown() {
	RunOnlyInIntegrationTest("TEST_CLOUDFERRO")

	log.Printf("Starting cleanup...")
	_, _ = GetOutput("broker nas delete ferronas")
	time.Sleep(5 * time.Second)
	_, _ = GetOutput("broker volume detach volumetest ferrohost")
	time.Sleep(5 * time.Second)
	_, _ = GetOutput("broker volume delete volumetest")
	time.Sleep(5 * time.Second)
	_, _ = GetOutput("broker host delete ferrohost")
	time.Sleep(5 * time.Second)
	_, _ = GetOutput("broker network delete ferronet")
	time.Sleep(5 * time.Second)
	log.Printf("Finishing cleanup...")
}
