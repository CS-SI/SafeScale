//go:build integrationtests && (networks || all)
// +build integrationtests
// +build networks all

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

package networks

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/integrationtests-ng/helpers"
)

func CreateNetwork(t *testing.T) {
	names := helpers.GetNames("BasicTest", 0, 0, 0, 2, 1, 0)
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

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	host0 := helpers.HostInfo{}
	_ = json.Unmarshal([]byte(out), &host0)

	fmt.Println("Creating VM ", names.Hosts[1])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[1] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist") || strings.Contains(out, "already used"))

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "success"))

	out, err = helpers.GetOutput("safescale host delete " + names.Hosts[1])
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "success"))

	out, err = helpers.GetOutput("safescale host delete gw-" + names.Networks[0])
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "gateway"))

	out, err = helpers.GetOutput("safescale network delete " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "success"))

	fmt.Println("Test OK")
}

func CreateNetworkWithoutSubnet(t *testing.T) {
	names := helpers.GetNames("BasicTest", 0, 0, 0, 2, 1, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24 --empty")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale network inspect " + names.Networks[0])
	require.Nil(t, err)
	// FIXME: check there is no subnet attached to network
}

func init() {
	helpers.InSection("networks").
		AddScenario(CreateNetwork).
		AddScenario(CreateNetworkWithoutSubnet)
}
