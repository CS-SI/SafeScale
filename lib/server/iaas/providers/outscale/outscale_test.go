/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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

package outscale_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/tests"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
)

func getTester() (*tests.ServiceTester, error) {
	theService, err := getService()
	if err != nil {
		return nil, err
	}
	tester := &tests.ServiceTester{
		Service: theService,
	}

	return tester, nil
}

func getService() (iaas.Service, error) {
	tenantName := ""
	if tenantOverride := os.Getenv("TEST_OUTSCALE"); tenantOverride != "" {
		tenantName = tenantOverride
	}

	if tenantName == "" {
		return nil, fmt.Errorf("you must provide a VALID tenant [%v], check your environment variables and your Safescale configuration files", tenantName)
	}

	service, err := iaas.UseService(tenantName, "")
	if err != nil || service == nil {
		return nil, fmt.Errorf("you must provide a VALID tenant [%v], check your environment variables and your Safescale configuration files", tenantName)
	}

	return service, nil
}

func Test_Images(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Images(t)
}

func Test_HostTemplates(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.HostTemplates(t)
}

func Test_KeyPair(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.KeyPairs(t)
}

func Test_Networks(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Networks(t)
}

func Test_Hosts(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Hosts(t)
}

func Test_StartStopHost(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.StartStopHost(t)
}

func Test_Volumes(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Volumes(t)
}

func Test_VolumeAttachments(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.VolumeAttachments(t)
}

func Test_Buckets(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	tt.Buckets(t)
}

func Test_NetworksWithDelete(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)
	net, err := tt.Service.CreateNetwork(abstract.NetworkRequest{
		Name:       "my-net",
		CIDR:       "192.168.23.0/24",
		DNSServers: nil,
	})
	assert.NoError(t, err)
	err = tt.Service.DeleteNetwork(net.ID)
	assert.NoError(t, err)
}

func Test_VMWithGPU(t *testing.T) {
	tt, err := getTester()
	if err != nil {
		t.Skip(err)
	}
	require.Nil(t, err)

	img, err := tt.Service.SearchImage("Ubuntu 20.04")
	assert.NoError(t, err)
	tpls, err := tt.Service.ListTemplatesBySizing(abstract.HostSizingRequirements{
		MinCores:    1,
		MaxCores:    1,
		MinRAMSize:  1,
		MaxRAMSize:  1,
		MinDiskSize: 0,
		MinGPU:      1,
		MinCPUFreq:  2.5,
		Replaceable: false,
	}, false)
	assert.NoError(t, err)
	assert.NotEmpty(t, tpls)
	tpl := func() *abstract.HostTemplate {
		for _, tpl := range tpls {
			if tpl.GPUType == "nvidia-k2" {
				return tpl
			}
		}
		return nil
	}()
	assert.NotNil(t, tpl)
	net, err := tt.Service.CreateNetwork(abstract.NetworkRequest{
		Name:       "public-net",
		CIDR:       "192.168.23.0/24",
		DNSServers: nil,
	})
	assert.NoError(t, err)
	defer func() {
		_ = tt.Service.DeleteNetwork(net.ID)
	}()

	subnet, err := tt.Service.CreateSubnet(abstract.SubnetRequest{
		Name:       "public-subnet",
		IPVersion:  ipversion.IPv4,
		CIDR:       "192.168.23.0/25",
		DNSServers: nil,
		HA:         false,
	})
	assert.NoError(t, err)
	defer func() {
		_ = tt.Service.DeleteSubnet(subnet.ID)
	}()

	h, _, err := tt.Service.CreateHost(abstract.HostRequest{
		ResourceName:   "hostWithGPU",
		HostName:       "host",
		Subnets:        []*abstract.Subnet{subnet},
		DefaultRouteIP: "",
		// DefaultGateway: nil,
		PublicIP:    true,
		TemplateID:  tpl.ID,
		ImageID:     img.ID,
		KeyPair:     nil,
		Password:    "",
		DiskSize:    50,
		Preemptible: false,
	})
	assert.NoError(t, err)
	assert.NotNil(t, h)
	err = tt.Service.DeleteHost(h.GetID())
	assert.NoError(t, err)
}
