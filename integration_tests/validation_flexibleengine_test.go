package integration_tests

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_Flexible_Basic(t *testing.T) {
	RunOnlyInIntegrationTest("TEST_FLEXIBLE")
	defer TearDown()

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

	fmt.Println("Creating network crazy...")

	out, err = GetOutput("broker network create crazy")
	require.Nil(t, err)

	out, err = GetOutput("broker network create crazy")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM easyVM...")

	out, err = GetOutput("broker host create easyvm --public --net crazy --cpu 4 --ram 50 ")
	require.Nil(t, err)

	out, err = GetOutput("broker host create easyvm --public --net crazy --cpu 4 --ram 50 ")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker host inspect easyvm")
	require.Nil(t, err)

	easyvm := HostInfo{}
	json.Unmarshal([]byte(out), &easyvm)

	fmt.Println("Creating VM complexvm...")

	out, err = GetOutput("broker host create complexvm --public --net crazy")
	require.Nil(t, err)

	out, err = GetOutput("broker host create complexvm --public --net crazy")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker nas list")
	require.Nil(t, err)

	fmt.Println("Creating NAS bnastest...")

	out, err = GetOutput("broker nas  create bnastest easyvm")
	require.Nil(t, err)

	out, err = GetOutput("broker nas  mount bnastest complexvm")
	require.Nil(t, err)

	out, err = GetOutput("broker nas list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "bnastest"))

	out, err = GetOutput("broker nas inspect bnastest")
	require.Nil(t, err)

	require.True(t, strings.Contains(out, "bnastest"))
	require.True(t, strings.Contains(out, "easyvm"))
	require.True(t, strings.Contains(out, "complexvm"))

	out, err = GetOutput("broker nas  umount bnastest complexvm")
	require.Nil(t, err)

	out, err = GetOutput("broker nas inspect bnastest")
	require.Nil(t, err)

	require.True(t, strings.Contains(out, "bnastest"))
	require.True(t, strings.Contains(out, "easyvm"))
	require.False(t, strings.Contains(out, "complexvm"))

	out, err = GetOutput("broker nas delete bnastest ")
	require.Nil(t, err)

	out, err = GetOutput("broker nas list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume volumetest...")

	out, err = GetOutput("broker volume  create volumetest")
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "volumetest"))

	out, err = GetOutput("broker volume  attach  volumetest easyvm ")
	require.Nil(t, err)

	out, err = GetOutput("broker volume delete volumetest")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))

	out, err = GetOutput("broker volume inspect volumetest")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, easyvm.ID) || strings.Contains(out, "easyvm"))

	out, err = GetOutput("broker volume  detach  volumetest easyvm ")
	require.Nil(t, err)

	out, err = GetOutput("broker volume inspect volumetest")
	require.Nil(t, err)
	require.False(t, strings.Contains(out, easyvm.ID) || strings.Contains(out, "easyvm"))

	out, err = GetOutput("broker volume delete volumetest")
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = GetOutput("broker ssh run easyvm -c \"uptime\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("broker host delete easyvm")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = GetOutput("broker host delete complexvm")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = GetOutput("broker host delete gw-crazy")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "gateway"))

	out, err = GetOutput("broker network delete crazy")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))
}
