//go:build (integration && featuretests) || allintegration
// +build integration,featuretests allintegration

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

package features

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
)

func Docker(t *testing.T) {
	names := helpers.GetNames("Docker", 0, 0, 0, 0, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.100.0/24")
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, " user"))

	out, err = helpers.GetOutput("safescale host feature check gw-" + names.Networks[0] + " docker")
	_ = out
	require.NotNil(t, err)

	out, err = helpers.GetOutput("safescale host feature add gw-" + names.Networks[0] + " docker")
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = helpers.GetOutput("safescale host feature check gw-" + names.Networks[0] + " docker")
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host feature delete gw-" + names.Networks[0] + " docker")
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host feature check gw-" + names.Networks[0] + " docker")
	_ = out
	require.NotNil(t, err)

	out, err = helpers.GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"docker ps\"")
	fmt.Print(out)
	require.NotNil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func DockerNotGateway(t *testing.T) {
	names := helpers.GetNames("DockerNotGateway", 0, 0, 0, 1, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.101.0/24")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"uptime\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, " user"))

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature check " + names.Hosts[0] + " docker")
	require.NotNil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature add " + names.Hosts[0] + " docker")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"docker ps\"")
	fmt.Print(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "CONTAINER"))

	out, err = helpers.GetOutput("safescale host feature check " + names.Hosts[0] + " docker")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature delete " + names.Hosts[0] + " docker")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature check " + names.Hosts[0] + " docker")
	require.NotNil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale ssh run " + names.Hosts[0] + " -c \"docker ps\"")
	fmt.Print(out)
	require.NotNil(t, err)
	require.False(t, strings.Contains(out, "CONTAINER"))
}

func RemoteDesktopOnSingleHost(t *testing.T) {
	names := helpers.GetNames("RemoteDesktop", 0, 0, 0, 1, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale host create " + names.Hosts[0] + " --public --net " + names.Networks[0] + " | jq -r .result")
	require.Nil(t, err)
	host := helpers.HostInfo{}
	_ = json.Unmarshal(([]byte)(out), &host)

	out, err = helpers.GetOutput("safescale host feature check --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.NotNil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature add --skip-proxy --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.Nil(t, err)
	_ = out

	// FIXME: how to test remotedesktio is working? the code below cannot work as-is. Will need to install edgeproxy4gateway before (on gateway on single host)
	// out, err = helpers.GetOutput("wget " + host.PublicIP + ":9080/guacamole")
	// _ = out
	// fmt.Print(out)
	// require.Nil(t, err)

	fmt.Println(names.Hosts[0])
	out, err = helpers.GetOutput("safescale host feature check --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host feature delete --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature check --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.NotNil(t, err)
	_ = out

	out, err = helpers.GetOutput("wget " + host.PublicIP + ":9080/guacamole")
	fmt.Print(out)
	require.NotNil(t, err)
}

func RemoteDesktopOnSubnetHost(t *testing.T) {
	names := helpers.GetNames("RemoteDesktop", 0, 0, 0, 1, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.103.0/24")
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0] + " | jq -r .result")
	require.Nil(t, err)
	host := helpers.HostInfo{}
	_ = json.Unmarshal([]byte(out), &host)

	out, err = helpers.GetOutput("safescale host feature check --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	require.NotNil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature add --skip-proxy --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	_ = out
	require.Nil(t, err)

	// FIXME: how to test remotedesktio is working? the code below cannot work as-is. Will need to install edgeproxy4gateway before (on gateway on single host)
	// out, err = helpers.GetOutput("wget " + host.PublicIP + ":9080/guacamole")
	// fmt.Print(out)
	// require.Nil(t, err)
	// _ = out

	fmt.Println(names.Hosts[0])
	out, err = helpers.GetOutput("safescale host feature check --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host feature delete --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	_ = out
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host feature check --param Username=user --param Password=SafeScale " + names.Hosts[0] + " remotedesktop")
	_ = out
	require.NotNil(t, err)

	out, err = helpers.GetOutput("wget " + host.PublicIP + ":9080/guacamole")
	fmt.Print(out)
	require.NotNil(t, err)
}

func ReverseProxy(t *testing.T) {
	names := helpers.GetNames("ReverseProxy", 0, 0, 0, 0, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.104.0/24")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature check gw-" + names.Networks[0] + " edgeproxy4subnet")
	require.NotNil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature add gw-" + names.Networks[0] + " edgeproxy4subnet")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"curl -Ssl -I -k https://localhost:8444/ 2>&1 | grep \\\"HTTP/1.1 200 OK\\\"\"")
	fmt.Print(out)
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature check gw-" + names.Networks[0] + " edgeproxy4subnet")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature delete gw-" + names.Networks[0] + " edgeproxy4subnet")
	require.Nil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale host feature check gw-" + names.Networks[0] + " edgeproxy4subnet")
	require.NotNil(t, err)
	_ = out

	out, err = helpers.GetOutput("safescale ssh run gw-" + names.Networks[0] + " -c \"curl -Ssl -I -k https://localhost:8444/ 2>&1 | grep \\\"HTTP/1.1 200 OK\\\"\"")
	fmt.Print(out)
	require.NotNil(t, err)
}

func NvidiaDocker(t *testing.T) {
	t.Skip("Test_NvidiaDocker not implemented")
	// TODO: Implement integration test
}

func init() {
}
