//go:build (integration && sharetests) || allintegration
// +build integration,sharetests allintegration

/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package shares

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

func Standard(t *testing.T) {
	names := helpers.GetNames("BasicTest", 0, 0, 1, 2, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24")
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	host0 := helpers.HostInfo{}
	_ = json.Unmarshal([]byte(out), &host0)

	fmt.Println("Creating VM ", names.Hosts[1])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --public --net " + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = helpers.GetOutput("safescale share list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share mount " + names.Shares[0] + " " + names.Hosts[1])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share list")
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, names.Shares[0]))

	out, err = helpers.GetOutput("safescale share inspect " + names.Shares[0])
	fmt.Println(out)
	require.Nil(t, err)

	require.True(t, strings.Contains(out, names.Shares[0]))
	require.True(t, strings.Contains(out, names.Hosts[0]))
	require.True(t, strings.Contains(out, names.Hosts[1]))

	out, err = helpers.GetOutput("safescale share umount " + names.Shares[0] + " " + names.Hosts[1])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share inspect " + names.Shares[0])
	fmt.Println(out)
	require.Nil(t, err)

	require.True(t, strings.Contains(out, names.Shares[0]))
	require.True(t, strings.Contains(out, names.Hosts[0]))
	require.False(t, strings.Contains(out, names.Hosts[1]))

	out, err = helpers.GetOutput("safescale share delete " + names.Shares[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale share list")
	fmt.Println(out)
	require.Nil(t, err)
	require.False(t, strings.Contains(out, names.Shares[0]))

	fmt.Println("Test OK")
}

func SharePartialError(t *testing.T) {
	names := helpers.GetNames("SharePartialError", 0, 0, 1, 1, 1, 0, 0, 0)
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
	require.True(t, strings.Contains(out, "success"))

	out, err = helpers.GetOutput("safescale network delete " + names.Networks[0])
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "success"))
}

func ShareError(t *testing.T) {
	names := helpers.GetNames("ShareError", 0, 1, 1, 1, 1, 0, 0, 0)
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
	require.True(t, strings.Contains(out, "still attached"))

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
	require.True(t, strings.Contains(out, "null"))

	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"uptime\"")
	_ = out
	require.Nil(t, err)
	require.True(t, strings.Contains(out, " user"))

	out, err = helpers.GetOutput("safescale share delete " + names.Shares[0])
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[0])
	if err != nil {
		fmt.Println(err.Error())
		fmt.Println(out)
	}
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "success"))

	out, err = helpers.GetOutput("safescale network delete " + names.Networks[0])
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "success"))
}

// UntilShareCreated creates everything until the share
func UntilShareCreated(t *testing.T) {
	names := helpers.GetNames("UntilShare", 0, 1, 1, 2, 1, 0, 0, 0)
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

	out, err = helpers.GetOutput("safescale share list")
	require.Nil(t, err)
	_ = out

	fmt.Println("Creating Share " + names.Shares[0])

	out, err = helpers.GetOutput("safescale share create " + names.Shares[0] + " " + names.Hosts[0])
	require.Nil(t, err)
	_ = out
}

func ShareVolumeMounted(t *testing.T) {
	names := helpers.GetNames("ShareVolumeMounted", 0, 1, 1, 2, 1, 0, 0, 0)
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
	require.True(t, strings.Contains(out, "already exist"))

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

func init() {
}
