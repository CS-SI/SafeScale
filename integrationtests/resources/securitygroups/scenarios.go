//go:build (integration && securitygrouptests) || allintegration
// +build integration,securitygrouptests allintegration

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

package securitygroups

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/stretchr/testify/require"
)

func GwFirewallWorks(t *testing.T) {
	names := helpers.GetNames("sgtest", 0, 0, 0, 0, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24")
	fmt.Println(out)
	require.Nil(t, err)

	tn := fmt.Sprintf("gw-%s", names.Networks[0])
	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"wget https://github.com/svenstaro/miniserve/releases/download/v0.20.0/miniserve-v0.20.0-x86_64-unknown-linux-musl -O miniserve\" %s", tn))
	fmt.Println(out)
	require.Contains(t, out, "miniserve")
	require.Contains(t, out, "saved")
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"chmod u+x ./miniserve\" %s", tn))
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"mkdir -p test\" %s", tn))
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"sudo /usr/bin/killall miniserve\" %s", tn))
	if !strings.Contains(out, "no process found") {
		require.Nil(t, err)
	}

	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"nohup ./miniserve -p 7777 ./test > /dev/null 2>&1 &\" %s", tn))
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale host inspect %s", tn))
	require.Nil(t, err)
	fmt.Println(out)

	pubip, err := helpers.RunJq(out, ".result.public_ip")
	require.Nil(t, err)

	fmt.Printf("Checking closed port http://%s:7777\n", pubip)
	// the port is initially closed
	resp, err := http.Get(fmt.Sprintf("http://%s:7777", pubip))
	if resp != nil {
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)

		if resp.StatusCode <= 299 {
			// make sure it works reading the content
			body, err := io.ReadAll(resp.Body)
			require.Nil(t, err)
			if strings.Contains(string(body), "miniserve") {
				fmt.Println("We don't have a working firewall")
				t.Errorf("We don't have a working firewall")
			}
		}
	}
}

func OpenPortClosedByDefaultInGateway(t *testing.T) {
	names := helpers.GetNames("sgtest", 0, 0, 0, 0, 1, 0, 0, 0)
	names.TearDown()
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24")
	fmt.Println(out)
	require.Nil(t, err)

	tn := fmt.Sprintf("gw-%s", names.Networks[0])
	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"wget https://github.com/svenstaro/miniserve/releases/download/v0.20.0/miniserve-v0.20.0-x86_64-unknown-linux-musl -O miniserve\" %s", tn))
	fmt.Println(out)
	require.Contains(t, out, "miniserve")
	require.Contains(t, out, "saved")
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"chmod u+x ./miniserve\" %s", tn))
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"mkdir -p test\" %s", tn))
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"sudo /usr/bin/killall miniserve\" %s", tn))
	if !strings.Contains(out, "no process found") {
		require.Nil(t, err)
	}

	out, err = helpers.GetOutput(fmt.Sprintf("safescale ssh run -c \"nohup ./miniserve -p 7777 ./test > /dev/null 2>&1 &\" %s", tn))
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale host inspect %s", tn))
	require.Nil(t, err)
	fmt.Println(out)

	pubip, err := helpers.RunJq(out, ".result.public_ip")
	require.Nil(t, err)

	fmt.Printf("Checking closed port http://%s:7777\n", pubip)
	// the port is initially closed
	resp, err := http.Get(fmt.Sprintf("http://%s:7777", pubip))
	if resp != nil {
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(resp.Body)

		if resp.StatusCode <= 299 {
			// make sure it works reading the content
			body, err := io.ReadAll(resp.Body)
			require.Nil(t, err)
			if strings.Contains(string(body), "miniserve") {
				fmt.Println("We don't have a working firewall")
				t.Errorf("We don't have a working firewall")
			}
		}
	}
	require.NotNil(t, err)

	fmt.Println("Listing security groups")
	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group list %s", names.Networks[0]))
	require.Nil(t, err)

	out = strings.TrimSpace(out)
	fmt.Println(out)

	var good string
	first, err := helpers.RunJq(out, ".result[0].description")
	require.Nil(t, err)

	if strings.Contains(first, "gateways") {
		good = ".result[0].id"
	}

	if good == "" {
		first, err := helpers.RunJq(out, ".result[1].description")
		require.Nil(t, err)

		if strings.Contains(first, "gateways") {
			good = ".result[1].id"
		}
	}

	if good == "" {
		first, err := helpers.RunJq(out, ".result[2].description")
		require.Nil(t, err)

		if strings.Contains(first, "gateways") {
			good = ".result[2].id"
		}
	}

	theID, err := helpers.RunJq(out, good)
	require.Nil(t, err)

	// inspect before the drama
	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group inspect %s %s", tn, theID))
	fmt.Println(out)
	require.Nil(t, err)

	// after that it should be open
	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group rule add --direction ingress --port-from 7777 --port-to 7777 --cidr \"0.0.0.0/0\" --cidr \"%s/32\" %s %s", pubip, tn, theID))
	fmt.Println(out)
	require.Nil(t, err)

	time.Sleep(5 * time.Second)

	// if it's open won't fail
	resp, err = http.Get(fmt.Sprintf("http://%s:7777", pubip))
	require.Nil(t, err)

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)

	// make sure it works reading the content
	body, err := io.ReadAll(resp.Body)
	require.Nil(t, err)
	require.Contains(t, string(body), "miniserve")
}

func CreateAndDeleteNetworkSecurityGroup(t *testing.T) {
	names := helpers.GetNames("sgtest", 0, 0, 0, 1, 1, 0, 0, 0)
	defer names.TearDown()

	out, err := helpers.GetOutput("safescale network list")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating network " + names.Networks[0])

	out, err = helpers.GetOutput("safescale network create " + names.Networks[0] + " --cidr 192.168.40.0/24")
	fmt.Println(out)
	require.Nil(t, err)

	fmt.Println("Creating VM " + names.Hosts[0])

	out, err = helpers.GetOutput("safescale host create " + names.Hosts[0] + " --net " + names.Networks[0])
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput("safescale host inspect " + names.Hosts[0])
	fmt.Println(out)
	require.Nil(t, err)

	host0 := helpers.HostInfo{}
	_ = json.Unmarshal([]byte(out), &host0)

	sgName := fmt.Sprintf("%s-custom-sg", names.Networks[0])

	fmt.Println("Creating security group " + sgName)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group create --description \"Custom test sg\" %s %s", names.Networks[0], sgName))
	fmt.Println(out)
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group create --description \"Custom test sg\" %s %s", names.Networks[0], sgName))
	fmt.Println(out)
	require.NotNil(t, err)
	require.True(t, strings.Contains(out, "already exist"))

	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group inspect %s %s", names.Networks[0], sgName))
	fmt.Println(out)
	require.Nil(t, err)

	sgDesc, err := helpers.RunJq(out, ".result.description")
	require.Nil(t, err)
	require.Contains(t, string(sgDesc), "Custom test sg")

	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group bonds %s %s", names.Networks[0], sgName))
	require.Nil(t, err)
	require.Contains(t, out, "{\"result\":null,\"status\":\"success\"}")

	out, err = helpers.GetOutput(fmt.Sprintf("safescale host security group bind %s %s", names.Hosts[0], sgName))
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group bonds %s %s", names.Networks[0], sgName))
	require.Nil(t, err)

	bonds, err := helpers.RunJq(out, ".result.hosts[0].name")
	require.Nil(t, err)
	require.Contains(t, bonds, names.Hosts[0])

	out, err = helpers.GetOutput(fmt.Sprintf("safescale host security group unbind %s %s", names.Hosts[0], sgName))
	require.Nil(t, err)

	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group bonds %s %s", names.Networks[0], sgName))
	require.Nil(t, err)
	require.Contains(t, out, "{\"result\":null,\"status\":\"success\"}")

	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group delete %s %s", names.Networks[0], sgName))
	fmt.Println(out)
	require.Nil(t, err)
	require.True(t, strings.Contains(out, "success"))

	out, err = helpers.GetOutput(fmt.Sprintf("safescale network security group delete %s %s", names.Networks[0], sgName))
	fmt.Println(out)
	require.NotNil(t, err)
}

func init() {
}
