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
	Setup(t, provider)

	names := GetNames("BasicTest", 0, 1, 1, 2, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.0.0/24")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.0.0/24")
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker host inspect " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	host0 := HostInfo{}
	json.Unmarshal([]byte(out), &host0)

	fmt.Println("Creating VM ", names.Hosts[1])

	out, err = GetOutput("broker host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker share list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = GetOutput("broker share create " + names.Shares[0] + " " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker share mount " + names.Shares[0] + " " + names.Hosts[1])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker share list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Shares[0]))

	out, err = GetOutput("broker share inspect " + names.Shares[0])
	fmt.Println(out)
	require.Nil(t, err)

	require.True(t, strings.Contains(out, names.Shares[0]))
	require.True(t, strings.Contains(out, names.Hosts[0]))
	require.True(t, strings.Contains(out, names.Hosts[1]))

	out, err = GetOutput("broker share umount " + names.Shares[0] + " " + names.Hosts[1])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker share inspect " + names.Shares[0])
	fmt.Println(out)
	require.Nil(t, err)

	require.True(t, strings.Contains(out, names.Shares[0]))
	require.True(t, strings.Contains(out, names.Hosts[0]))
	require.False(t, strings.Contains(out, names.Hosts[1]))

	out, err = GetOutput("broker share delete " + names.Shares[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker share list")
	fmt.Println(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, names.Shares[0]))

	out, err = GetOutput("broker volume list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = GetOutput("broker volume create " + names.Volumes[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Volumes[0]))

	out, err = GetOutput("broker volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker volume delete " + names.Volumes[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))

	out, err = GetOutput("broker volume inspect " + names.Volumes[0])
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, host0.ID) || strings.Contains(out, names.Hosts[0]))

	out, err = GetOutput("broker volume  detach " + names.Volumes[0] + " " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker volume inspect " + names.Volumes[0])
	fmt.Println(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, host0.ID) || strings.Contains(out, names.Hosts[0]))

	out, err = GetOutput("broker volume delete " + names.Volumes[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = GetOutput("broker ssh run " + names.Hosts[0] + " -c \"uptime\"")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("broker host delete " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = GetOutput("broker host delete " + names.Hosts[1])
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = GetOutput("broker host delete gw-" + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "gateway"))

	out, err = GetOutput("broker network delete " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))
}

func ReadyToSsh(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("ReadyToSSH", 0, 0, 0, 1, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0] + " --cidr 168.192.1.0/24")

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.1.0/24")
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host inspect " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println(out)
}

func ShareError(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("ShareError", 0, 1, 1, 1, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.2.0/24")
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host inspect " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = GetOutput("broker share create " + names.Shares[0] + " " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = GetOutput("broker volume create --speed SSD " + names.Volumes[0])
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Volumes[0]))

	out, err = GetOutput("broker volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume delete " + names.Volumes[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume detach " + names.Volumes[0] + " " + names.Hosts[0])
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume delete " + names.Volumes[0])
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	out, err = GetOutput("broker ssh run " + names.Hosts[0] + " -c \"uptime\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("broker share delete " + names.Shares[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host delete " + names.Hosts[0])
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(out)
	}
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))

	out, err = GetOutput("broker network delete " + names.Networks[0])
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "deleted"))
}

func VolumeError(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("VolumeError", 0, 1, 1, 1, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.3.0/24")
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host inspect " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = GetOutput("broker share create " + names.Shares[0] + " " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = GetOutput("broker volume create " + names.Volumes[0])
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume  attach " + names.Volumes[0] + " " + names.Hosts[0])
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	out, err = GetOutput("broker volume delete " + names.Volumes[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))
}

func StopStart(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("StopStart", 0, 1, 1, 1, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.4.0/24")
	require.Nil(t, err)

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.4.0/24")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host stop " + names.Hosts[0])
	require.Nil(t, err)

	out = ""
	for !strings.Contains(out, "STOPPED") {
		out, err = GetOutput("broker host status " + names.Hosts[0])
	}

	out, err = GetOutput("broker host start " + names.Hosts[0])
	require.Nil(t, err)

	time.Sleep(4 * time.Second)

	out, err = GetOutput("broker ssh run " + names.Hosts[0] + " -c \"uptime\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))

	out, err = GetOutput("broker host reboot " + names.Hosts[0])
	require.Nil(t, err)

	time.Sleep(4 * time.Second)

	out, err = GetOutput("broker ssh run " + names.Hosts[0] + " -c \"uptime\"")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "0 users"))
}

func DeleteVolumeMounted(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("DeleteVolumeMounted", 0, 1, 1, 2, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.5.0/24")
	require.Nil(t, err)

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.5.0/24")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker host inspect " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[1])

	out, err = GetOutput("broker host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker share list")
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = GetOutput("broker share create " + names.Shares[0] + " " + names.Hosts[0])
	require.Nil(t, err)

	out, err = GetOutput("broker share mount " + names.Shares[0] + " " + names.Hosts[1])
	require.Nil(t, err)

	out, err = GetOutput("broker share list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Shares[0]))

	out, err = GetOutput("broker share inspect " + names.Shares[0])
	require.Nil(t, err)

	require.True(t, strings.Contains(out, names.Shares[0]))
	require.True(t, strings.Contains(out, names.Hosts[0]))
	require.True(t, strings.Contains(out, names.Hosts[1]))

	out, err = GetOutput("broker share umount " + names.Shares[0] + " " + names.Hosts[1])
	require.Nil(t, err)

	out, err = GetOutput("broker share inspect " + names.Shares[0])
	require.Nil(t, err)

	require.True(t, strings.Contains(out, names.Shares[0]))
	require.True(t, strings.Contains(out, names.Hosts[0]))
	require.False(t, strings.Contains(out, names.Hosts[1]))

	out, err = GetOutput("broker share delete " + names.Shares[0])
	require.Nil(t, err)

	out, err = GetOutput("broker share list")
	require.Nil(t, err)
	require.False(t, strings.Contains(out, names.Shares[0]))

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = GetOutput("broker volume create " + names.Volumes[0])
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Volumes[0]))

	out, err = GetOutput("broker volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	require.Nil(t, err)

	out, err = GetOutput("broker volume delete " + names.Volumes[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))

	// TODO Parse message received
	message_received := "Could not delete volume 'volumetest': rpc error: code = Unknown desc = Error deleting volume: Bad request with: [DELETE https://volume.compute.sbg3.cloud.ovh.net/v1/7bf42a51e07a4be98e62b0435bfc1765/volumes/906e8b9c-b6ac-461b-9916-a8bc7afa8449], error message: {'badRequest': {'message': 'Volume 906e8b9c-b6ac-461b-9916-a8bc7afa8449 is still attached, detach volume first.', 'code': 400}}"
	_ = message_received

	fmt.Println(err.Error())
}

func UntilShare(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("UntilShare", 0, 1, 1, 2, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.6.0/24")
	require.Nil(t, err)

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.6.0/24")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker host inspect " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[1])

	out, err = GetOutput("broker host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker share list")
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = GetOutput("broker share create " + names.Shares[0] + " " + names.Hosts[0])
	require.Nil(t, err)
}

func UntilVolume(t *testing.T, provider Providers.Enum) {
	Setup(t, provider)

	names := GetNames("UntilVolume", 0, 1, 1, 2, 1)
	names.TearDown()
	defer names.TearDown()

	out, err := GetOutput("broker network list")
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.7.0/24")
	require.Nil(t, err)

	out, err = GetOutput("broker network create " + names.Networks[0] + " --cidr 168.192.7.0/24")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker host inspect " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[1])

	out, err = GetOutput("broker host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.Nil(t, err)

	out, err = GetOutput("broker host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = GetOutput("broker volume create " + names.Volumes[0])
	require.Nil(t, err)

	out, err = GetOutput("broker volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Volumes[0]))
}
