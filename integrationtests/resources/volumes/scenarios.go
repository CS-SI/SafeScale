//go:build (integration && volumetests) || allintegration
// +build integration,volumetests allintegration

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

package volumes

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// func Basic(t *testing.T, provider providers.Enum) {
// 	helpers.Setup(t, provider)
//
// 	names := helpers.GetNames("BasicTest", 0, 1, 1, 2, 1, 0)
// 	names.TearDown()
// 	defer names.TearDown()
//
// 	out, err := helpers.GetOutput("safescale network list")
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	fmt.Println("Creating network " + names.Networks[0])
//
// 	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24")
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	fmt.Println("Creating VM " + names.Hosts[0])
//
// 	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + "--net" + names.Networks[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + "--net " + names.Networks[0])
// 	fmt.Println(out)
// 	require.NotNil(t, err)
// 	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))
//
// 	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	host0 := helpers.HostInfo{}
// 	_ = json.Unmarshal([]byte(out), &host0)
//
// 	fmt.Println("Creating VM ", names.Hosts[1])
//
// 	out, err = helpers.GetOutput("safescale volume list")
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.True(t, strings.Contains(out, "null"))
//
// 	fmt.Println("Creating Volume " + names.Volumes[0])
//
// 	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	out, err = helpers.GetOutput("safescale volume list")
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.True(t, strings.Contains(out, names.Volumes[0]))
//
// 	out, err = helpers.GetOutput("safescale volume attach " + names.Volumes[0] + " " + names.Hosts[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
// 	fmt.Println(out)
// 	require.NotNil(t, err)
// 	require.True(t, strings.Contains(out, "still attached"))
//
// 	out, err = helpers.GetOutput("safescale volume inspect " + names.Volumes[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.True(t, strings.Contains(out, host0.ID) || strings.Contains(out, names.Hosts[0]))
//
// 	out, err = helpers.GetOutput("safescale volume  detach " + names.Volumes[0] + " " + names.Hosts[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	out, err = helpers.GetOutput("safescale volume inspect " + names.Volumes[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.False(t, strings.Contains(out, host0.ID) || strings.Contains(out, names.Hosts[0]))
//
// 	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
//
// 	out, err = helpers.GetOutput("safescale volume list")
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.True(t, strings.Contains(out, "null"))
//
// 	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"uptime\"")
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.True(t, strings.Contains(out, " user"))
//
// 	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.True(t, strings.Contains(out, "success"))
//
// 	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[1])
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.True(t, strings.Contains(out, "success"))
//
// 	out, err = helpers.GetOutput("safescale host delete gw-" + names.Networks[0])
// 	fmt.Println(out)
// 	require.NotNil(t, err)
// 	require.True(t, strings.Contains(out, "gateway"))
//
// 	out, err = helpers.GetOutput("safescale network delete " + names.Networks[0])
// 	fmt.Println(out)
// 	require.Nil(t, err)
// 	require.True(t, strings.Contains(out, "success"))
//
// 	fmt.Println("Test OK")
// }

func VolumeError(t *testing.T) {
	names := helpers.GetNames("VolumeError", 0, 1, 1, 1, 1, 0, 0, 0)
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

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
	_ = out
	require.Nil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	time.Sleep(temporal.DefaultDelay())

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	_ = out
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))
}

func DeleteVolumeMounted(t *testing.T) {
	names := helpers.GetNames("DeleteVolumeMounted", 0, 1, 1, 2, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.45.0/24")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	_ = out
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[1])
	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public")
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = helpers.GetOutput("safescale share list")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Volumes[0]))

	out, err = helpers.GetOutput("safescale volume attach " + names.Volumes[0] + " " + names.Hosts[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale volume delete " + names.Volumes[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "still attached"))

	// TODO: Parse message received
	messageReceived := "Could not delete volume 'volumetest': rpc error: code = Unknown desc = Error deleting volume: Bad request with: [DELETE https://volume.compute.sbg.cloud.ovh.net/v1/7bf42a51e07a4be98e62b0435bfc1765/volumes/906e8b9c-b6ac-461b-9916-a8bc7afa8449], error message: {'badRequest': {'message': 'Volume 906e8b9c-b6ac-461b-9916-a8bc7afa8449 is still attached, detach volume first.', 'code': 400}}"
	_ = messageReceived

	fmt.Println(err.Error())
}

// UntilVolumeCreated creates everything until a volume is created
func UntilVolumeCreated(t *testing.T) {
	names := helpers.GetNames("UntilVolume", 0, 1, 1, 2, 1, 0, 0, 0)
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
	require.True(t, strings.Contains(out, "already exist"))

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

	fmt.Println("Creating VM " + names.Hosts[1])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = helpers.GetOutput("safescale volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "null"))

	fmt.Println("Creating Volume " + names.Volumes[0])

	out, err = helpers.GetOutput("safescale volume create " + names.Volumes[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale volume list")
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Volumes[0]))
}

func init() {
}
