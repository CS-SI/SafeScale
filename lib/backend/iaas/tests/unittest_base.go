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

package tests

// TODO: NOTICE Side-effects imports here
import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	_ "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers/aws"            // Imported to initialize tenant aws
	_ "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers/cloudferro"     // Imported to initialize tenant ovh
	_ "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers/flexibleengine" // Imported to initialize tenant flexibleengine
	_ "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers/gcp"            // Imported to initialize tenant gcp
	_ "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers/opentelekom"    // Imported to initialize tenant opentelekom
	_ "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers/outscale"       // Imported to initialize tenant outscale
	_ "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers/ovh"            // Imported to initialize tenant ovh
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/aws"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/gcp"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/huaweicloud"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/outscale"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ServiceTester helper class to test clients
type ServiceTester struct {
	Service iaas.Service
}

// VerifyStacks checks at compile that initialized tenants are valid stacks
func (tester *ServiceTester) VerifyStacks(t *testing.T) {
	var stack api.Stack

	stack = aws.NullStack()         // nolint
	stack = gcp.NullStack()         // nolint
	stack = huaweicloud.NullStack() // nolint
	stack = openstack.NullStack()   // nolint
	stack = outscale.NullStack()    // nolint

	_ = stack
}

// Images tests
func (tester *ServiceTester) Images(t *testing.T) {
	ctx := context.Background()
	images, err := tester.Service.ListImages(ctx, false)
	assert.Nil(t, err)
	assert.NotEmpty(t, images)
	for _, i := range images {
		fmt.Println(i.Name)
		assert.NotEqual(t, i.ID, "")
		assert.NotEqual(t, i.Name, "")
	}
	imgs, err := tester.Service.FilterImages(ctx, "ubuntu 18.04")
	require.NotNil(t, err)
	for _, img := range imgs {
		fmt.Println(">>", img.Name)
	}
	imgs, err = tester.Service.FilterImages(ctx, "ubuntu xenial")
	require.NotNil(t, err)
	for _, img := range imgs {
		fmt.Println(">>", img.Name)
	}
}

// HostTemplates test
func (tester *ServiceTester) HostTemplates(t *testing.T) {
	ctx := context.Background()
	tpls, err := tester.Service.ListTemplates(ctx, false)
	assert.Nil(t, err)
	assert.NotEmpty(t, tpls)
	for _, f := range tpls {
		t.Log(f)
		assert.NotEqual(t, f.ID, "")
		assert.NotEqual(t, f.Name, "")
		assert.NotEqual(t, f.Cores, 0)
		assert.NotEqual(t, f.RAMSize, 0)
		//	assert.NotEqual(t, f.DiskSize, 0)
	}
}

// KeyPairs tests
func (tester *ServiceTester) KeyPairs(t *testing.T) {
	ctx := context.Background()
	// CreateKeyPair test
	kp, err := tester.Service.CreateKeyPair(ctx, "kp")
	assert.Nil(t, err)
	assert.NotEqual(t, kp.ID, "")
	assert.NotEqual(t, kp.Name, "")
	assert.NotEqual(t, kp.PrivateKey, "")
	assert.NotEqual(t, kp.PublicKey, "")
	_ = tester.Service.DeleteKeyPair(ctx, kp.ID)

	// CreateKeyPairAndLeaveItThere test
	kp, err = tester.Service.CreateKeyPair(ctx, "kp")
	assert.Nil(t, err)
	assert.NotEqual(t, kp.ID, "")
	assert.NotEqual(t, kp.Name, "")
	assert.NotEqual(t, kp.PrivateKey, "")
	assert.NotEqual(t, kp.PublicKey, "")

	// InspectKeyPair test
	kp, err = tester.Service.CreateKeyPair(ctx, "unit_test_kp")
	require.Nil(t, err)

	kp2, err := tester.Service.InspectKeyPair(ctx, "unit_test_kp")
	require.Nil(t, err)

	assert.Equal(t, kp.ID, kp2.ID)
	assert.Equal(t, kp.Name, kp2.Name)
	assert.Equal(t, kp.PublicKey, kp2.PublicKey)
	assert.Equal(t, "", kp2.PrivateKey)
	_, err = tester.Service.InspectKeyPair(ctx, "notfound")
	assert.NotNil(t, err)

	defer func() {
		_ = tester.Service.DeleteKeyPair(ctx, "unit_test_kp")
	}()

	// ListKeyPairs test
	lst, err := tester.Service.ListKeyPairs(ctx)
	assert.Nil(t, err)
	nbKP := len(lst)
	kp, err = tester.Service.CreateKeyPair(ctx, "kp")
	assert.Nil(t, err)
	_ = tester.Service.DeleteKeyPair(ctx, "kp")
	kp2, err = tester.Service.CreateKeyPair(ctx, "kp2")
	assert.Nil(t, err)
	_ = tester.Service.DeleteKeyPair(ctx, "kp2")

	lst, err = tester.Service.ListKeyPairs(ctx)
	assert.Nil(t, err)
	assert.EqualValues(t, nbKP+2, len(lst))
	for _, kpe := range lst {
		var kpr abstract.KeyPair
		switch kpe.ID {
		case kp.ID:
			kpr = *kp
		case kp2.ID:
			kpr = *kp2
		default:
			continue
		}
		assert.Equal(t, kpe.ID, kpr.ID)
		assert.Equal(t, kpe.Name, kpr.Name)
		assert.Equal(t, kpe.PublicKey, kpr.PublicKey)
		assert.Equal(t, kpe.PrivateKey, "")
	}
}

// CreateNetwork creates a test network
func (tester *ServiceTester) CreateNetwork(t *testing.T, name string, cidr string) *abstract.Network {
	network, err := tester.Service.CreateNetwork(context.Background(), abstract.NetworkRequest{
		Name: name,
		CIDR: cidr,
	})
	require.NoError(t, err)

	return network
}

// CreateSubnet creates a test subnet
func (tester *ServiceTester) CreateSubnet(t *testing.T, networkID, name string, withGW bool, cidr string) (*abstract.Subnet, *abstract.HostFull) {
	ctx := context.Background()
	subnet, err := tester.Service.CreateSubnet(context.Background(), abstract.SubnetRequest{
		Name:      name,
		IPVersion: ipversion.IPv4,
		NetworkID: networkID,
		CIDR:      cidr,
	})
	require.NoError(t, err)

	var gateway *abstract.HostFull
	if withGW {
		tpls, err := tester.Service.ListTemplatesBySizing(ctx, abstract.HostSizingRequirements{
			MinCores:    1,
			MinRAMSize:  1,
			MinDiskSize: 0,
		}, false)
		require.Nil(t, err)
		img, err := tester.Service.SearchImage(ctx, "Ubuntu 20.04")
		require.Nil(t, err)
		keypair, err := tester.Service.CreateKeyPair(ctx, "kp_"+subnet.Name)
		require.Nil(t, err)

		gwRequest := abstract.HostRequest{
			ImageID:      img.ID,
			Subnets:      []*abstract.Subnet{subnet},
			KeyPair:      keypair,
			TemplateID:   tpls[0].ID,
			ResourceName: "gw-" + name,
			IsGateway:    true,
		}

		gateway, _, err = tester.Service.CreateHost(context.Background(), gwRequest, nil)
		require.Nil(t, err)
		subnet.GatewayIDs = []string{gateway.Core.ID}
	}

	return subnet, gateway
}

// CreateHost creates a test host
func (tester *ServiceTester) CreateHost(t *testing.T, name string, subnet *abstract.Subnet, public bool) (*abstract.HostFull, *userdata.Content, fail.Error) {
	ctx := context.Background()
	tpls, xerr := tester.Service.ListTemplatesBySizing(ctx, abstract.HostSizingRequirements{
		MinCores:    1,
		MinRAMSize:  1,
		MinDiskSize: 10,
	}, false)
	assert.Nil(t, xerr)
	img, xerr := tester.Service.SearchImage(ctx, "Ubuntu 20.04")
	assert.Nil(t, xerr)
	hostRequest := abstract.HostRequest{
		ResourceName:   name,
		Subnets:        []*abstract.Subnet{subnet},
		DefaultRouteIP: "",
		PublicIP:       public,
		TemplateID:     tpls[0].ID,
		ImageID:        img.ID,
		KeyPair:        nil,
		Password:       "",
		DiskSize:       0,
	}
	return tester.Service.CreateHost(context.Background(), hostRequest, nil)
}

// CreateGW creates a test GW
func (tester *ServiceTester) CreateGW(t *testing.T, subnet *abstract.Subnet) fail.Error {
	ctx := context.Background()
	tpls, xerr := tester.Service.ListTemplatesBySizing(ctx, abstract.HostSizingRequirements{
		MinCores:    1,
		MinRAMSize:  1,
		MinDiskSize: 10,
	}, false)
	assert.Nil(t, xerr)
	img, xerr := tester.Service.SearchImage(ctx, "Ubuntu 20.04")
	assert.Nil(t, xerr)
	gwRequest := abstract.HostRequest{
		ImageID:      img.ID,
		TemplateID:   tpls[0].ID,
		Subnets:      []*abstract.Subnet{subnet},
		ResourceName: "gw-" + subnet.Name,
		IsGateway:    true,
	}
	gw, _, xerr := tester.Service.CreateHost(context.Background(), gwRequest, nil)
	if xerr != nil {
		return xerr
	}
	subnet.GatewayIDs = []string{gw.Core.ID}
	return nil
}

// // CreateNetworkTest test
// func (tester *ServiceTester) CreateNetworkTest(t *testing.T) {
//	// Get initial number of networks
//	nets, err := tester.Service.ListNetworks()
//	require.Nil(t, err)
//	nbAllNetworks := len(nets)
//	require.True(t, nbAllNetworks > 0)
//
//	fmt.Println("Creating unit_test_network_6")
//	network1 := tester.CreateNetwork(t, "unit_test_network", "1.1.0.0/16")
//	require.NotNil(t, network1)
//	defer func() {
//		_ = tester.Service.DeleteNetwork(network1.ID)
//	}()
//	fmt.Println(fmt.Sprintf("Created a Network with name %v and id %v", network1.Name, network1.ID))
//
//	networkFound := false
//
//	nets, err = tester.Service.ListNetworks()
//	require.Nil(t, err)
//	for _, net := range nets {
//		if net.Name == "unit_test_network" {
//			networkFound = true
//			break
//		}
//	}
//
//	net, err := tester.Service.InspectNetwork("unit_test_network")
//
//	require.NotNil(t, net)
//	require.Nil(t, err)
//
//	require.True(t, networkFound)
// }

// Networks test
func (tester *ServiceTester) Networks(t *testing.T) {
	ctx := context.Background()
	// Get initial number of networks
	nets, err := tester.Service.ListNetworks(ctx)
	assert.Nil(t, err)
	nbAllNetworks := len(nets)

	net1CIDR := "10.1.1.0/24"
	net1Name := "unit_test_networks_1"
	fmt.Println("Creating " + net1Name)
	network1 := tester.CreateNetwork(t, net1Name, net1CIDR)
	defer func() {
		_ = tester.Service.DeleteNetwork(context.Background(), network1.ID)
	}()
	fmt.Println(net1Name + " created")

	assert.Equal(t, network1.Name, net1Name)
	assert.Equal(t, network1.CIDR, net1CIDR)

	// VPL: properties are not inside stack instances anymore
	// TODO: see if there is something to test at this level
	// gw1NetworkV1 := propertiesv1.NewHostSubnet()
	// err = gw1.properties.Inspect(HostProperty.NetworkV1, func(clonable interface{}) error {
	// 	gw1NetworkV1 = clonable.(*propertiesv1.HostNetworking)
	// 	return nil
	// })
	// assert.Nil(t, err)
	// assert.Empty(t, gw1NetworkV1.DefaultGatewayID)
	// assert.Equal(t, gw1NetworkV1.SubnetsByName[net1Name], network1.ID)
	// assert.Equal(t, gw1NetworkV1.SubnetsByID[network1.ID], net1Name)
	// assert.Equal(t, gw1NetworkV1.IsGateway, true)

	net2CIDR := "10.1.2.0/24"
	net2Name := "unit_test_networks_2"
	fmt.Println("Creating " + net2Name)
	network2 := tester.CreateNetwork(t, net2Name, net2CIDR)
	defer func() {
		_ = tester.Service.DeleteNetwork(context.Background(), network2.ID)
	}()
	fmt.Println(net2Name + " created")

	nets, err = tester.Service.ListNetworks(ctx)
	assert.Nil(t, err)
	assert.Equal(t, nbAllNetworks+2, len(nets))
	found := 0
	for _, n := range nets {
		if n.ID == network1.ID || n.ID == network2.ID {
			found++
		} else {
			continue
		}
	}
	assert.Equal(t, 2, found)

	n1, err := tester.Service.InspectNetwork(ctx, network1.ID)
	assert.Nil(t, err)
	assert.Equal(t, n1.CIDR, network1.CIDR)
	assert.Equal(t, n1.ID, network1.ID)
	assert.Equal(t, n1.Name, network1.Name)
}

// // CreateSubnetTest test
// func (tester *ServiceTester) CreateSubnetTest(t *testing.T) {
//	// Get initial number of subnets
//	subnets, err := tester.Service.ListSubnets(networkID)
//	require.Nil(t, err)
//	nbAllSubnets := len(subnets)
//	require.True(t, nbAllSubnets > 0)
//
//	fmt.Println("Creating unit_test_subnet_6")
//	subnet1, _ := tester.CreateSubnet(t, networkID, "unit_test_subnet_6", true, "1.1.1.0/25")
//	require.NotNil(t, subnet1)
//	fmt.Println(fmt.Sprintf("Created a Subnet with name %v and id %v", subnet1.Name, subnet1.ID))
//
//	subnetFound := false
//
//	subnets, err = tester.Service.ListSubnets(networkID)
//	require.Nil(t, err)
//	for _, net := range subnets {
//		if net.Name == subnet1.Name {
//			subnetFound = true
//			break
//		}
//	}
//
//	net, err := tester.Service.InspectSubnet("unit_test_subnet_6")
//
//	require.NotNil(t, net)
//	require.Nil(t, err)
//
//	require.True(t, subnetFound)
//	defer func() {
//		_ = tester.Service.DeleteSubnet(subnet1.ID)
//	}()
// }

// Subnets test
func (tester *ServiceTester) Subnets(t *testing.T) {
	network := tester.CreateNetwork(t, "unit_test_subnets", "10.2.0.0/16")
	defer func() {
		_ = tester.Service.DeleteNetwork(context.Background(), network.ID)
	}()

	// Get initial number of subnets
	subnets, err := tester.Service.ListSubnets(context.Background(), network.ID)
	assert.Nil(t, err)
	nbAllSubnets := len(subnets)

	subnet1CIDR := "10.2.1.0/24"
	subnet1Name := "unit_test_subnets_1"
	fmt.Println("Creating " + subnet1Name)
	subnet1, gw1 := tester.CreateSubnet(t, network.ID, subnet1Name, true, subnet1CIDR)
	assert.NotNil(t, subnet1)
	assert.NotNil(t, gw1)
	defer func() {
		_ = tester.Service.DeleteHost(context.Background(), gw1.Core.ID)
		_ = tester.Service.DeleteNetwork(context.Background(), subnet1.ID)
	}()
	fmt.Println(subnet1Name + " created")

	assert.Equal(t, subnet1.CIDR, subnet1CIDR)
	assert.Equal(t, subnet1.GatewayIDs[0], gw1.Core.ID)
	assert.Equal(t, gw1.Core.Name, "gw-"+subnet1.Name)
	assert.NotEmpty(t, gw1.Networking.PublicIPv4)

	// VPL: properties are not inside stack instances anymore
	// TODO: see if there is something to test at this level
	// gw1NetworkV1 := propertiesv1.NewHostSubnet()
	// err = gw1.properties.Inspect(HostProperty.NetworkV1, func(clonable interface{}) error {
	// 	gw1NetworkV1 = clonable.(*propertiesv1.HostNetworking)
	// 	return nil
	// })
	// assert.Nil(t, err)
	// assert.Empty(t, gw1NetworkV1.DefaultGatewayID)
	// assert.Equal(t, gw1NetworkV1.SubnetsByName[subnet1Name], network1.ID)
	// assert.Equal(t, gw1NetworkV1.SubnetsByID[network1.ID], subnet1Name)
	// assert.Equal(t, gw1NetworkV1.IsGateway, true)

	subnet2CIDR := "10.2.2.0/24"
	subnet2Name := "unit_test_subnets_2"
	fmt.Println("Creating " + subnet2Name)
	subnet2, gw2 := tester.CreateSubnet(t, network.ID, subnet2Name, false, subnet2CIDR)
	assert.NotNil(t, subnet2)
	assert.Nil(t, gw2)
	fmt.Println(subnet2Name + " created ")

	defer func() {
		_ = tester.Service.DeleteSubnet(context.Background(), subnet2.ID)
	}()

	subnets, err = tester.Service.ListSubnets(context.Background(), network.ID)
	assert.Nil(t, err)
	assert.Equal(t, nbAllSubnets+2, len(subnets))
	found := 0
	for _, n := range subnets {
		if n.ID == subnet1.ID || n.ID == subnet2.ID {
			found++
		} else {
			continue
		}
	}
	assert.Equal(t, 2, found)

	s1, err := tester.Service.InspectSubnet(context.Background(), subnet1.ID)
	assert.Nil(t, err)
	assert.NotNil(t, s1)
	assert.Equal(t, s1.CIDR, subnet1.CIDR)
	assert.Equal(t, s1.ID, subnet1.ID)
	assert.Equal(t, s1.IPVersion, subnet1.IPVersion)
	assert.Equal(t, s1.Name, subnet1.Name)
}

// Hosts test
func (tester *ServiceTester) Hosts(t *testing.T) {
	// Get initial number of hosts
	hosts, err := tester.Service.ListHosts(context.Background(), false)
	assert.NoError(t, err)
	nbHosts := len(hosts)

	network := tester.CreateNetwork(t, "unit_test_hosts", "10.3.0.0/16")
	defer func() {
		_ = tester.Service.DeleteNetwork(context.Background(), network.ID)
	}()

	subnet, gw := tester.CreateSubnet(t, network.ID, "unit_test_hosts", false, "10.3.1.0/24")
	assert.NotNil(t, subnet)
	assert.Nil(t, gw)
	defer func() {
		_ = tester.Service.DeleteSubnet(context.Background(), subnet.ID)
	}()
	host1, _, err := tester.CreateHost(t, "host1", subnet, true)
	assert.NoError(t, err)
	defer func() {
		_ = tester.Service.DeleteHost(context.Background(), host1.Core.ID)
	}()

	// ssh, err := tester.Service.GetSSHConfig(host.ID)
	// _, err = ssh.WaitServerReady(userdata.PHASE1_INIT, 1 * time.Minute)
	// assert.NoError(t, err)
	// cmd, err := ssh.NewCommand("whoami")
	// assert.Nil(t, err)
	// out, err := cmd.output()
	// assert.Nil(t, err)
	// content := strings.Trim(string(out), "\n")
	// assert.Equal(t, abstract.DefaultUser, content)

	// cmd, err = ssh.NewCommand("ping -c1 8.8.8.8")
	// fmt.Println(ssh.PrivateKey)
	// assert.Nil(t, err)
	// _, _, _, err = cmd.Run()
	// assert.Nil(t, err)

	// cmd, err = ssh.NewCommand("ping -c1 www.google.fr")
	// fmt.Println(ssh.PrivateKey)
	// assert.Nil(t, err)
	// _, _, _, err = cmd.Run()
	// assert.Nil(t, err)

	_, _, err = tester.CreateHost(t, "host2", subnet, false)
	assert.Error(t, err)
	// err = tester.CreateGW(t, network)
	// assert.NoError(t, err)
	// defer func() {
	// 	_ = tester.Service.DeleteGateway(network.GatewayID)
	// }()
	host2, _, err := tester.CreateHost(t, "host2", subnet, false)
	assert.NoError(t, err)
	defer func() {
		_ = tester.Service.DeleteHost(context.Background(), host2.Core.ID)
	}()

	subnet, err = tester.Service.InspectSubnet(context.Background(), subnet.ID)
	assert.NoError(t, err)
	hosts, err = tester.Service.ListHosts(context.Background(), false)
	require.Nil(t, err)
	assert.Equal(t, nbHosts+3, len(hosts))
	found := 0
	for _, v := range hosts {
		switch {
		case v.Core.Name == "gw-"+subnet.Name:
			found++
		case v.Core.ID == host1.Core.ID:
			found++
		case v.Core.ID == host2.Core.ID:
			found++
		default:
			fmt.Printf("Unknown (preexisting?) host %+v\n", v)
			continue
		}
	}
	assert.Equal(t, 3, found)

	host1Bis, err := tester.Service.InspectHost(context.Background(), host1)
	assert.NoError(t, err)
	assert.Equal(t, host1.Core.ID, host1Bis.Core.ID)
	assert.Equal(t, host1.Core.Name, host1Bis.Core.Name)
}

// StartStopHost test
func (tester *ServiceTester) StartStopHost(t *testing.T) {
	network := tester.CreateNetwork(t, "unit_test_startstophost", "10.4.0.0/16")
	defer func() {
		_ = tester.Service.DeleteNetwork(context.Background(), network.ID)
	}()

	subnet, gw := tester.CreateSubnet(t, network.ID, "unit_test_subnet_startstophost", true, "1.4.1.0/24")
	defer func() {
		_ = tester.Service.DeleteHost(context.Background(), gw.Core.ID)
		_ = tester.Service.DeleteSubnet(context.Background(), subnet.ID)
	}()
	host, err := tester.Service.InspectHost(context.Background(), "gw-"+subnet.Name)
	require.Nil(t, err)
	require.NotNil(t, host)
	{
		err := tester.Service.StopHost(context.Background(), host.Core.ID, true)
		require.Nil(t, err)
		assert.Equal(t, host.CurrentState, hoststate.Stopped)
	}
	{
		err := tester.Service.StartHost(context.Background(), host.Core.ID)
		require.Nil(t, err)
		assert.Equal(t, host.CurrentState, hoststate.Started)
	}
}

// Buckets test
func (tester *ServiceTester) Buckets(t *testing.T) {
	_, err := tester.Service.CreateBucket(context.Background(), "testC")
	assert.Nil(t, err)
	_, err = tester.Service.CreateBucket(context.Background(), "testC2")
	assert.Nil(t, err)

	cl, err := tester.Service.ListBuckets(context.Background(), "")
	require.NotNil(t, err)
	assert.Contains(t, cl, "testC", "testC2")
	err = tester.Service.DeleteBucket(context.Background(), "testC")
	assert.Nil(t, err)
	err = tester.Service.DeleteBucket(context.Background(), "testC2")
	assert.Nil(t, err)
	cl, err = tester.Service.ListBuckets(context.Background(), "")
	assert.Nil(t, err)
	assert.NotContains(t, cl, "testC", "testC2")
}
