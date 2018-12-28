package test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/integration_tests"
	"github.com/stretchr/testify/require"
)

func Test_Basic(t *testing.T) {
	integration_tests.RunOnlyInIntegrationTest("TEST_OVH")
	integration_tests.TearDown()
	defer integration_tests.TearDown()

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

	out, err = integration_tests.GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network crazy...")

	out, err = integration_tests.GetOutput("broker network create crazy")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker network create crazy")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM easyVM...")

	out, err = integration_tests.GetOutput("broker host create easyvm --public --net crazy")
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker host create easyvm --public --net crazy")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = integration_tests.GetOutput("broker host inspect easyvm")
	require.Nil(t, err)

	easyvm := integration_tests.HostInfo{}
	json.Unmarshal([]byte(out), &easyvm)

	fmt.Println("Creating VM complexvm...")

	out, err = integration_tests.GetOutput("broker host create complexvm --public --net crazy")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker host create complexvm --public --net crazy")
	fmt.Print(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = integration_tests.GetOutput("broker nas list")
	fmt.Print(out)
	require.Nil(t, err)

	fmt.Println("Creating NAS bnastest...")

	out, err = integration_tests.GetOutput("broker nas  create bnastest easyvm")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker nas  mount bnastest complexvm")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker nas list")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "bnastest"))

	out, err = integration_tests.GetOutput("broker nas inspect bnastest")
	fmt.Print(out)
	require.Nil(t, err)

	require.True(t, strings.Contains(out, "bnastest"))
	require.True(t, strings.Contains(out, "easyvm"))
	require.True(t, strings.Contains(out, "complexvm"))

	out, err = integration_tests.GetOutput("broker nas  umount bnastest complexvm")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker nas inspect bnastest")
	fmt.Print(out)
	require.Nil(t, err)

	require.True(t, strings.Contains(out, "bnastest"))
	require.True(t, strings.Contains(out, "easyvm"))
	require.False(t, strings.Contains(out, "complexvm"))

	out, err = integration_tests.GetOutput("broker nas delete bnastest ")
	fmt.Print(out)
	require.Nil(t, err)

	time.Sleep(4 * time.Second)

	out, err = integration_tests.GetOutput("broker nas list")
	fmt.Print(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, "bnastest"))

	out, err = integration_tests.GetOutput("broker volume list")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume volumetest...")

	out, err = integration_tests.GetOutput("broker volume  create volumetest")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker volume list")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "volumetest"))

	out, err = integration_tests.GetOutput("broker volume  attach  volumetest easyvm ")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker volume delete volumetest")
	fmt.Print(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))

	out, err = integration_tests.GetOutput("broker volume inspect volumetest")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, easyvm.ID) || strings.Contains(out, "easyvm"))

	out, err = integration_tests.GetOutput("broker volume  detach  volumetest easyvm ")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker volume inspect volumetest")
	fmt.Print(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, easyvm.ID) || strings.Contains(out, "easyvm"))

	out, err = integration_tests.GetOutput("broker volume delete volumetest")
	fmt.Print(out)
	require.Nil(t, err)

	out, err = integration_tests.GetOutput("broker volume list")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = integration_tests.GetOutput("broker ssh run easyvm -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = integration_tests.GetOutput("broker host delete easyvm")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = integration_tests.GetOutput("broker host delete complexvm")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = integration_tests.GetOutput("broker host delete gw-crazy")
	fmt.Print(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "gateway"))

	out, err = integration_tests.GetOutput("broker network delete crazy")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))
}
