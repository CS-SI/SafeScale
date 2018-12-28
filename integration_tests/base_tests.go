package integration_tests

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

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
	case Providers.FLEXIBLEENGINE:
		return "TEST_FLEXIBLE"
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
	case Providers.FLEXIBLEENGINE:
		return "flexibleengine"
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

func Basic(t *testing.T, provider Providers.Enum) {
	TearDown()
	defer TearDown()

	Setup(t, provider)

	out, err := GetOutput("broker network list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating network crazy...")

	out, err = GetOutput("broker network create crazy")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker network create crazy")
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM easyVM...")

	out, err = GetOutput("broker host create easyvm --public --net crazy")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker host create easyvm --public --net crazy")
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker host inspect easyvm")
	fmt.Println(out)
	require.Nil(t, err)

	easyvm := HostInfo{}
	json.Unmarshal([]byte(out), &easyvm)

	fmt.Println("Creating VM complexvm...")

	out, err = GetOutput("broker host create complexvm --public --net crazy")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker host create complexvm --public --net crazy")
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker nas list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating NAS bnastest...")

	out, err = GetOutput("broker nas  create bnastest easyvm")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker nas  mount bnastest complexvm")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker nas list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "bnastest"))

	out, err = GetOutput("broker nas inspect bnastest")
	fmt.Println(out)
	require.Nil(t, err)

	require.True(t, strings.Contains(out, "bnastest"))
	require.True(t, strings.Contains(out, "easyvm"))
	require.True(t, strings.Contains(out, "complexvm"))

	out, err = GetOutput("broker nas  umount bnastest complexvm")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker nas inspect bnastest")
	fmt.Println(out)
	require.Nil(t, err)

	require.True(t, strings.Contains(out, "bnastest"))
	require.True(t, strings.Contains(out, "easyvm"))
	require.False(t, strings.Contains(out, "complexvm"))

	out, err = GetOutput("broker nas delete bnastest ")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker nas list")
	fmt.Println(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, "bnastest"))

	out, err = GetOutput("broker volume list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume volumetest...")

	out, err = GetOutput("broker volume  create volumetest")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "volumetest"))

	out, err = GetOutput("broker volume  attach  volumetest easyvm ")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker volume delete volumetest")
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))

	out, err = GetOutput("broker volume inspect volumetest")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, easyvm.ID) || strings.Contains(out, "easyvm"))

	out, err = GetOutput("broker volume  detach  volumetest easyvm ")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker volume inspect volumetest")
	fmt.Println(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, easyvm.ID) || strings.Contains(out, "easyvm"))

	out, err = GetOutput("broker volume delete volumetest")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = GetOutput("broker ssh run easyvm -c \"uptime\"")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("broker host delete easyvm")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = GetOutput("broker host delete complexvm")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = GetOutput("broker host delete gw-crazy")
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "gateway"))

	out, err = GetOutput("broker network delete crazy")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))
}

func ReadyToSsh(t *testing.T, provider Providers.Enum) {
	TearDown()
	defer TearDown()

	Setup(t, provider)

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network crazy...")

	out, err = GetOutput("broker network create crazy")
	require.Nil(t, err)

	fmt.Println("Creating VM easyvm...")

	out, err = GetOutput("broker host create easyvm --public --net crazy")
	require.Nil(t, err)

	out, err = GetOutput("broker host inspect easyvm")
	require.Nil(t, err)

	fmt.Println(out)
}

//untested
func NasError(t *testing.T, provider Providers.Enum) {
	TearDown()
	defer TearDown()

	Setup(t, provider)

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network crazy...")

	out, err = GetOutput("broker network create crazy")
	require.Nil(t, err)

	fmt.Println("Creating VM easyvm...")

	out, err = GetOutput("broker host create easyvm --public --net crazy")
	require.Nil(t, err)

	out, err = GetOutput("broker host inspect easyvm")
	require.Nil(t, err)

	fmt.Println("Creating Nas bnastest...")

	out, err = GetOutput("broker nas create bnastest easyvm")
	require.Nil(t, err)

	fmt.Println("Creating Volume volumetest...")

	out, err = GetOutput("broker volume create --speed SSD volumetest")
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "volumetest"))

	out, err = GetOutput("broker volume  attach volumetest easyvm")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume delete volumetest")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume  detach volumetest easyvm")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume delete volumetest")
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = GetOutput("broker ssh run easyvm -c \"uptime\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("broker nas delete bnastest ")
	require.Nil(t, err)

	out, err = GetOutput("broker host delete easyvm")
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(out)
	}
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = GetOutput("broker network delete crazy")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))
}
