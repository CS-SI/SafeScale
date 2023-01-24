//go:build disabled
// +build disabled

/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package subnets

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"

	"github.com/CS-SI/SafeScale/v22/integrationtests/providers"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

func keyFromProvider(provider providers.Enum) string {
	switch provider {
	case providers.OVH:
		return "TEST_OVH"
	case providers.CLOUDFERRO:
		return "TEST_CLOUDFERRO"
	case providers.FLEXIBLEENGINE:
		return "TEST_FLEXIBLE"
	case providers.AWS:
		return "TEST_AWS"
	case providers.GCP:
		return "TEST_GCP"
	case providers.OUTSCALE:
		return "TEST_OUTSCALE"
	}
	return ""
}

func nameFromProvider(provider providers.Enum) string {
	switch provider {
	case providers.OVH:
		return "ovh"
	case providers.CLOUDFERRO:
		return "cloudferro"
	case providers.FLEXIBLEENGINE:
		return "flexibleengine"
	case providers.AWS:
		return "aws"
	case providers.GCP:
		return "gcp"
	case providers.OUTSCALE:
		return "outscale"
	}
	return ""
}

func EnvSetup(t *testing.T, provider providers.Enum) {
	key := keyFromProvider(provider)
	require.NotEmpty(t, key)

	err := helpers.RunOnlyInIntegrationTest(key)
	if err != nil {
		t.Skip(err)
	}

	safescaledLaunched, err := helpers.IsSafescaledLaunched()
	if !safescaledLaunched {
		fmt.Println("This requires that you launch safescaled in background and set the tenant")
	}
	require.True(t, safescaledLaunched)
	require.Nil(t, err)

	inPath, err := helpers.CanBeRun("safescale")
	require.Nil(t, err)

	require.True(t, safescaledLaunched)
	require.True(t, inPath)
}

func Setup(t *testing.T, provider providers.Enum) {
	EnvSetup(t, provider)

	name := nameFromProvider(provider)
	require.NotEmpty(t, name)

	listStr, err := helpers.GetOutput("safescale tenant list")
	require.Nil(t, err)
	require.True(t, len(listStr) > 0)

	getStr, err := helpers.GetOutput("safescale tenant get")
	if err != nil {
		fmt.Println("This requires that you set the right tenant before launching the tests")
	}
	require.Nil(t, err)
	require.True(t, len(getStr) > 0)
	// require.True(t, strings.Contains(getStr, fmt.Sprintf("\"Provider\":\"%s\"", name)))
}

func Basic(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("BasicTest", 0, 1, 1, 2, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	t.Log(out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24")
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24")
	t.Log(out)
	require.NotNil(t, err)
	require.Contains(t, out, "already exist")

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	t.Log(out)
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	t.Log(out)
	require.Nil(t, err)

	host0 := helpers.HostInfo{}
	_ = json.Unmarshal([]byte(out), &host0)

	fmt.Println("Creating VM ", names.Hosts[1])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	t.Log(out)
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale share list")
	t.Log(out)
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share mount " + names.Shares[0] + " " + names.Hosts[1])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share list")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, names.Shares[0])

	out, err = helpers.GetOutput("safescale share inspect " + names.Shares[0])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, names.Shares[0])
	require.Contains(t, out, names.Hosts[0])
	require.Contains(t, out, names.Hosts[1])

	out, err = helpers.GetOutput("safescale share umount " + names.Shares[0] + " " + names.Hosts[1])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share inspect " + names.Shares[0])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, names.Shares[0])
	require.Contains(t, out, names.Hosts[0])
	require.NotContains(t, out, names.Hosts[1])

	out, err = helpers.GetOutput("safescale share delete " + names.Shares[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share list")
	t.Log(out)
	require.Nil(t, err)
	require.NotContains(t, out, names.Shares[0])

	out, err = helpers.GetOutput("safescale volume list")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "null")

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale volume list")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	t.Log(out)
	require.NotNil(t, err)
	require.Contains(t, out, "still attached")

	out, err = helpers.GetOutput("safescale volume inspect " + names.Volumes[0])
	t.Log(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, host0.ID) || strings.Contains(out, names.Hosts[0]))

	out, err = helpers.GetOutput("safescale volume  detach " + names.Volumes[0] + " " + names.Hosts[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale volume inspect " + names.Volumes[0])
	t.Log(out)
	require.Nil(t, err)
	require.NotContains(t, out, host0.ID)
	require.NotContains(t, out, names.Hosts[0])

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale volume list")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "null")

	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"uptime\"")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, " user")

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[0])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "success")

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[1])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "success")

	out, err = helpers.GetOutput("safescale host delete gw-" + names.Networks[0])
	t.Log(out)
	require.NotNil(t, err)
	require.Contains(t, out, "gateway")

	out, err = helpers.GetOutput("safescale network delete " + names.Networks[0])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "success")

	fmt.Println("Test OK")
}

func BasicPrivate(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("BasicTest", 0, 1, 1, 2, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.70.0/24")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.70.0/24")
	fmt.Println(out)
	require.NotNil(t, err)
	require.Contains(t, out, "already exist")

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	host0 := helpers.HostInfo{}
	_ = json.Unmarshal([]byte(out), &host0)

	t.Logf("Creating VM %s", names.Hosts[1])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale share list")
	t.Log(out)
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share mount " + names.Shares[0] + " " + names.Hosts[1])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share list")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, names.Shares[0])

	out, err = helpers.GetOutput("safescale share inspect " + names.Shares[0])
	t.Log(out)
	require.Nil(t, err)

	require.Contains(t, out, names.Shares[0])
	require.Contains(t, out, names.Hosts[0])
	require.Contains(t, out, names.Hosts[1])

	out, err = helpers.GetOutput("safescale share umount " + names.Shares[0] + " " + names.Hosts[1])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share inspect " + names.Shares[0])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, names.Shares[0])
	require.Contains(t, out, names.Hosts[0])
	require.NotContains(t, out, names.Hosts[1])

	out, err = helpers.GetOutput("safescale share delete " + names.Shares[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share list")
	t.Log(out)
	require.Nil(t, err)
	require.NotContains(t, out, names.Shares[0])

	out, err = helpers.GetOutput("safescale volume list")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "null")

	t.Logf("Creating Volume %s", names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale volume list")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	t.Log(out)

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	t.Log(out)
	require.NotNil(t, err)
	require.Contains(t, out, "still attached")

	out, err = helpers.GetOutput("safescale volume inspect " + names.Volumes[0])
	t.Log(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, host0.ID) || strings.Contains(out, names.Hosts[0]))

	out, err = helpers.GetOutput("safescale volume  detach " + names.Volumes[0] + " " + names.Hosts[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale volume inspect " + names.Volumes[0])
	t.Log(out)
	require.Nil(t, err)
	require.NotContains(t, out, names.Hosts[0])

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	t.Log(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale volume list")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "null")

	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"uptime\"")
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, " user")

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[0])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "success")

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[1])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "success")

	out, err = helpers.GetOutput("safescale host delete gw-" + names.Networks[0])
	t.Log(out)
	require.NotNil(t, err)
	require.Contains(t, out, "gateway")

	out, err = helpers.GetOutput("safescale network delete " + names.Networks[0])
	t.Log(out)
	require.Nil(t, err)
	require.Contains(t, out, "success")

	t.Log("Test OK")
}

func ReadyToSSH(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("ReadyToSSH", 0, 0, 0, 1, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	require.NotNil(t, out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0] + " --cidr 192.168.41.0/24")

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.41.0/24")
	require.NotNil(t, out)
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	require.Nil(t, err)

	fmt.Println(out)
}

func SharePartialError(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("SharePartialError", 0, 1, 1, 1, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.49.0/24")
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share delete " + names.Shares[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[0])
	_ = out
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(out)
	}
	require.Nil(t, err)
	require.Contains(t, out, "success")

	out, err = helpers.GetOutput("safescale network delete " + names.Networks[0])
	require.Nil(t, err)
	require.Contains(t, out, "success")
}

func ShareError(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("ShareError", 0, 1, 1, 1, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.42.0/24")
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create --speed SSD " + names.Volumes[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale volume list")
	_ = out
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Volumes[0]))

	out, err = helpers.GetOutput("safescale volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	_ = out
	require.NotNil(t, err)
	require.Contains(t, out, "still attached")

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale volume detach " + names.Volumes[0] + " " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	_ = out
	require.Nil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale volume list")
	_ = out
	require.Nil(t, err)
	require.Contains(t, out, "null")

	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"uptime\"")
	_ = out
	require.Nil(t, err)
	require.Contains(t, out, " user")

	out, err = helpers.GetOutput("safescale share delete " + names.Shares[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[0])
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(out)
	}
	require.Nil(t, err)
	require.Contains(t, out, "success")

	out, err = helpers.GetOutput("safescale network delete " + names.Networks[0])
	require.Nil(t, err)
	require.Contains(t, out, "success")
}

func VolumeError(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("VolumeError", 0, 1, 1, 1, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.43.0/24")
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
	_ = out
	require.Nil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale volume  attach " + names.Volumes[0] + " " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	_ = out
	require.NotNil(t, err)
	require.Contains(t, out, "still attached")
}

func StopStart(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("StopStart", 0, 1, 1, 1, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.44.0/24")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.44.0/24")
	require.NotNil(t, err)
	require.Contains(t, out, "already exist")
	_ = out

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host stop " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	out = ""
	for !strings.Contains(out, "STOPPED") {
		out, err = helpers.GetOutput("safescale host status " + names.Hosts[0])
		require.NotNil(t, err)
	}

	out, err = helpers.GetOutput("safescale host start " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"uptime\"")
	require.Nil(t, err)
	require.Contains(t, out, " user")
	_ = out

	out, err = helpers.GetOutput("safescale host reboot " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"uptime\"")
	require.Nil(t, err)
	require.Contains(t, out, " user")
}

func DeleteVolumeMounted(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("DeleteVolumeMounted", 0, 1, 1, 2, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.45.0/24")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.45.0/24")
	require.NotNil(t, err)
	require.Contains(t, out, "already exist")

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating VM " + names.Hosts[1])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale share list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale share mount " + names.Shares[0] + " " + names.Hosts[1])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale share list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Shares[0]))

	out, err = helpers.GetOutput("safescale share inspect " + names.Shares[0])
	require.Nil(t, err)

	require.Contains(t, out, names.Shares[0])
	require.Contains(t, out, names.Hosts[0])
	require.Contains(t, out, names.Hosts[1])

	out, err = helpers.GetOutput("safescale share umount " + names.Shares[0] + " " + names.Hosts[1])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale share inspect " + names.Shares[0])
	require.Nil(t, err)

	require.Contains(t, out, names.Shares[0])
	require.Contains(t, out, names.Hosts[0])
	require.NotContains(t, out, names.Hosts[1])

	out, err = helpers.GetOutput("safescale share delete " + names.Shares[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale share list")
	require.Nil(t, err)
	require.NotContains(t, out, names.Shares[0])

	out, err = helpers.GetOutput("safescale volume list")
	require.Nil(t, err)
	require.Contains(t, out, "null")

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale volume list")
	require.Nil(t, err)
	require.Contains(t, out, names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	require.NotNil(t, err)
	require.Contains(t, out, "still attached")

	// TODO: Parse message received
	messageReceived := "Could not delete volume 'volumetest': rpc error: code = Unknown desc = Error deleting volume: Bad request with: [DELETE https://volume.compute.sbg.cloud.ovh.net/v1/7bf42a51e07a4be98e62b0435bfc1765/volumes/906e8b9c-b6ac-461b-9916-a8bc7afa8449], error message: {'badRequest': {'message': 'Volume 906e8b9c-b6ac-461b-9916-a8bc7afa8449 is still attached, detach volume first.', 'code': 400}}"
	_ = messageReceived
	t.Log(err.Error())
}

func UntilShare(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("UntilShare", 0, 1, 1, 2, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.46.0/24")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.46.0/24")
	require.NotNil(t, err)
	require.Contains(t, out, "already exist")

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating VM " + names.Hosts[1])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale share list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	require.Nil(t, err)
	_ = out
}

func UntilVolume(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("UntilVolume", 0, 1, 1, 2, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.47.0/24")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.47.0/24")
	require.NotNil(t, err)
	require.Contains(t, out, "already exist")

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	t.Log("Creating VM " + names.Hosts[1])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.Contains(t, out, "already")

	out, err = helpers.GetOutput("safescale volume list")
	require.Nil(t, err)
	require.Contains(t, out, "null")

	t.Logf("Creating Volume %s", names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale volume list")
	require.Nil(t, err)
	require.Contains(t, out, names.Volumes[0])
}

func ShareVolumeMounted(t *testing.T, provider providers.Enum) {
	Setup(t, provider)

	names := helpers.GetNames("ShareVolumeMounted", 0, 1, 1, 2, 1, 0)
	names.TearDown()
	// defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.38.0/24")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.38.0/24")
	require.NotNil(t, err)
	require.Contains(t, out, "already exist")

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	/*
		out, err = GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
		require.NotNil(t, err)
		require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

		out, err = GetOutput("safescale host inspect " + names.Hosts[0])
		require.Nil(t, err)

		fmt.Println("Creating VM " + names.Hosts[1])

		out, err = GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
		require.Nil(t, err)

		out, err = GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
		require.NotNil(t, err)
		require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

		out, err = GetOutput("safescale share list")
		require.Nil(t, err)

		fmt.Println("Creating Share " + names.Shares[0])

		out, err = GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
		require.Nil(t, err)

		out, err = GetOutput("safescale share mount " + names.Shares[0] + " " + names.Hosts[1])
		require.Nil(t, err)
	*/
}
