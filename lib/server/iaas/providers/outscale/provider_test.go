/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

    "github.com/CS-SI/SafeScale/lib/server/iaas/resources"
    "github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/ipversion"

    "github.com/stretchr/testify/require"

    "github.com/CS-SI/SafeScale/lib/server/iaas"
    "github.com/CS-SI/SafeScale/lib/server/iaas/tests"
)

var (
    tester  *tests.ServiceTester
    service iaas.Service
)

func getTester() (*tests.ServiceTester, error) {
    if tester == nil {
        theService, err := getService()
        if err != nil {
            tester = nil
            return nil, err
        }
        tester = &tests.ServiceTester{
            Service: theService,
        }

    }
    return tester, nil
}

func getService() (iaas.Service, error) {
    if service == nil {
        tenantName := "TestOutscale"
        if tenantOverride := os.Getenv("TEST_OUTSCALE"); tenantOverride != "" {
            tenantName = tenantOverride
        }
        var err error
        service, err = iaas.UseService(tenantName)
        if err != nil || service == nil {
            return nil, fmt.Errorf(
                "you must provide a VALID tenant [%v], check your environment variables and your Safescale configuration files",
                tenantName,
            )
        }
    }
    return service, nil
}

func Test_ListImages(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    tt.ListImages(t)
}

func Test_ListHostTemplates(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    tt.ListHostTemplates(t)
}

func Test_CreateKeyPair(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    tt.CreateKeyPair(t)
}

func Test_GetKeyPair(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    tt.GetKeyPair(t)
}

func Test_ListKeyPairs(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    tt.ListKeyPairs(t)
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

func Test_Volume(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    tt.Volume(t)
}

func Test_VolumeAttachment(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    tt.VolumeAttachment(t)
}

func Test_Containers(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    tt.Containers(t)
}

func Test_NetworksWithDelete(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)
    net, err := tt.Service.CreateNetwork(
        resources.NetworkRequest{
            Name:       "my-net",
            IPVersion:  ipversion.IPv4,
            CIDR:       "192.168.23.0/24",
            DNSServers: nil,
            HA:         false,
        },
    )
    assert.NoError(t, err)
    err = tt.Service.DeleteNetwork(net.ID)
    assert.NoError(t, err)
}

func TestVMWithGPU(t *testing.T) {
    tt, err := getTester()
    if err != nil {
        t.Skip(err)
    }
    require.Nil(t, err)

    img, err := tt.Service.SearchImage("Ubuntu 18.04")
    assert.NoError(t, err)
    tpls, err := tt.Service.SelectTemplatesBySize(
        resources.SizingRequirements{
            MinCores:    1,
            MaxCores:    1,
            MinRAMSize:  1,
            MaxRAMSize:  1,
            MinDiskSize: 0,
            MinGPU:      1,
            MinFreq:     2.5,
            Replaceable: false,
        }, false,
    )
    assert.NoError(t, err)
    assert.NotEmpty(t, tpls)
    tpl := func() *resources.HostTemplate {
        for _, tpl := range tpls {
            if tpl.GPUType == "nvidia-k2" {
                return tpl
            }
        }
        return nil
    }()
    assert.NotNil(t, tpl)
    net, err := tt.Service.CreateNetwork(
        resources.NetworkRequest{
            Name:       "public-net",
            IPVersion:  ipversion.IPv4,
            CIDR:       "192.168.23.0/24",
            DNSServers: nil,
            HA:         false,
        },
    )
    assert.NoError(t, err)
    defer func() {
        _ = tt.Service.DeleteNetwork(net.ID)
    }()
    h, _, err := tt.Service.CreateHost(
        resources.HostRequest{
            ResourceName:   "hostWithGPU",
            HostName:       "host",
            Networks:       []*resources.Network{net},
            DefaultRouteIP: "",
            DefaultGateway: nil,
            PublicIP:       true,
            TemplateID:     tpl.ID,
            ImageID:        img.ID,
            KeyPair:        nil,
            Password:       "",
            DiskSize:       50,
            Spot:           false,
        },
    )
    assert.NoError(t, err)
    assert.NotNil(t, h)
    err = tt.Service.DeleteHost(h.ID)
    assert.NoError(t, err)

}

// func Test_Test(t *testing.T) {
//	tt, err := getTester()
//	if err != nil {
//		t.Skip(err)
//	}
//	require.Nil(t, err)
//	hosts, err := tt.Service.ListHosts()
//	for _, h := range hosts {
//		fmt.Printf("%v", h)
//	}
// }
//
// func Test_Delete(t *testing.T) {
//	tt, err := getTester()
//	if err != nil {
//		t.Skip(err)
//	}
//	require.Nil(t, err)
//	hosts, err := tt.Service.ListHosts()
//	for _, h := range hosts {
//		err = tt.Service.DeleteHost(h.ID)
//		require.Nil(t, err)
//	}
//	nets, err := tt.Service.ListNetworks()
//	require.Nil(t, err)
//	for _, n := range nets {
//		err = tt.Service.DeleteNetwork(n.ID)
//		require.Nil(t, err)
//	}
// }

// func Test_Objects(t *testing.T) {
// 	tt, err := getTester()
// 	require.Nil(t, err)
// 	tt.Objects(t)
// }
