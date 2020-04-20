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

package tests

// TODO NOTICE Side-effects imports here
import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/gcp"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/huaweicloud"
	libvirt "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/libvirt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumestate"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"

	_ "github.com/CS-SI/SafeScale/lib/server/iaas/providers/cloudferro"     // Imported to initialize tenant ovh
	_ "github.com/CS-SI/SafeScale/lib/server/iaas/providers/flexibleengine" // Imported to initialize tenant flexibleengine
	_ "github.com/CS-SI/SafeScale/lib/server/iaas/providers/gcp"            // Imported to initialize tenant gcp
	_ "github.com/CS-SI/SafeScale/lib/server/iaas/providers/local"          // Imported to initialize tenant local
	_ "github.com/CS-SI/SafeScale/lib/server/iaas/providers/opentelekom"    // Imported to initialize tenant opentelekoms
	_ "github.com/CS-SI/SafeScale/lib/server/iaas/providers/ovh"            // Imported to initialize tenant ovh
)

// ServiceTester helper class to test clients
type ServiceTester struct {
	Service iaas.Service
}

// VerifyStacks checks at compile that initialized tenants are valid stacks
func (tester *ServiceTester) VerifyStacks(t *testing.T) {
	var stack api.Stack

	stack = &libvirt.Stack{}     // nolint
	stack = &huaweicloud.Stack{} // nolint
	stack = &openstack.Stack{}   // nolint
	stack = &gcp.Stack{}         // nolint

	_ = stack
}

// Images tests
func (tester *ServiceTester) Images(t *testing.T) {
	images, err := tester.Service.ListImages(false)
	assert.Nil(t, err)
	assert.NotEmpty(t, images)
	for _, i := range images {
		fmt.Println(i.Name)
		assert.NotEqual(t, i.ID, "")
		assert.NotEqual(t, i.Name, "")
	}
	imgs, err := tester.Service.FilterImages("ubuntu 18.04")
	require.NotNil(t, err)
	for _, img := range imgs {
		fmt.Println(">>", img.Name)
	}
	imgs, err = tester.Service.FilterImages("ubuntu xenial")
	require.NotNil(t, err)
	for _, img := range imgs {
		fmt.Println(">>", img.Name)
	}
}

// HostTemplates test
func (tester *ServiceTester) HostTemplates(t *testing.T) {
	tpls, err := tester.Service.ListTemplates(false)
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
	// CreateKeyPair test
	kp, err := tester.Service.CreateKeyPair("kp")
	assert.Nil(t, err)
	assert.NotEqual(t, kp.ID, "")
	assert.NotEqual(t, kp.Name, "")
	assert.NotEqual(t, kp.PrivateKey, "")
	assert.NotEqual(t, kp.PublicKey, "")
	_ = tester.Service.DeleteKeyPair(kp.ID)

	// CreateKeyPairAndLeaveItThere test
	kp, err = tester.Service.CreateKeyPair("kp")
	assert.Nil(t, err)
	assert.NotEqual(t, kp.ID, "")
	assert.NotEqual(t, kp.Name, "")
	assert.NotEqual(t, kp.PrivateKey, "")
	assert.NotEqual(t, kp.PublicKey, "")

	// GetKeyPair test
	kp, err = tester.Service.CreateKeyPair("unit_test_kp")
	require.Nil(t, err)

	kp2, err := tester.Service.GetKeyPair("unit_test_kp")
	require.Nil(t, err)

	assert.Equal(t, kp.ID, kp2.ID)
	assert.Equal(t, kp.Name, kp2.Name)
	assert.Equal(t, kp.PublicKey, kp2.PublicKey)
	assert.Equal(t, "", kp2.PrivateKey)
	_, err = tester.Service.GetKeyPair("notfound")
	assert.NotNil(t, err)

	defer func() {
		_ = tester.Service.DeleteKeyPair("unit_test_kp")
	}()

	// ListKeyPairs test
	lst, err := tester.Service.ListKeyPairs()
	assert.Nil(t, err)
	nbKP := len(lst)
	kp, err = tester.Service.CreateKeyPair("kp")
	assert.Nil(t, err)
	_ = tester.Service.DeleteKeyPair("kp")
	kp2, err = tester.Service.CreateKeyPair("kp2")
	assert.Nil(t, err)
	_ = tester.Service.DeleteKeyPair("kp2")

	lst, err = tester.Service.ListKeyPairs()
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
func (tester *ServiceTester) CreateNetwork(t *testing.T, name string, withGW bool, cidr string) (*abstract.Network, *abstract.HostFull) {

	network, err := tester.Service.CreateNetwork(abstract.NetworkRequest{
		Name:      name,
		IPVersion: ipversion.IPv4,
		CIDR:      cidr,
	})
	require.NoError(t, err)

	var gateway *abstract.HostFull
	if withGW {
		tpls, err := tester.Service.SelectTemplatesBySize(abstract.HostSizingRequirements{
			MinCores:    1,
			MinRAMSize:  1,
			MinDiskSize: 0,
		}, false)
		require.Nil(t, err)
		img, err := tester.Service.SearchImage("Ubuntu 18.04")
		require.Nil(t, err)
		keypair, err := tester.Service.CreateKeyPair("kp_" + network.Name)
		require.Nil(t, err)

		gwRequest := abstract.HostRequest{
			ImageID:      img.ID,
			Networks:     []*abstract.Network{network},
			KeyPair:      keypair,
			TemplateID:   tpls[0].ID,
			ResourceName: "gw-" + name,
			IsGateway:    true,
		}

		gateway, _, err = tester.Service.CreateHost(gwRequest)
		require.Nil(t, err)
		network.GatewayID = gateway.Core.ID
	}

	return network, gateway
}

// CreateHost creates a test host
func (tester *ServiceTester) CreateHost(t *testing.T, name string, network *abstract.Network, public bool) (*abstract.HostFull, *userdata.Content, error) {
	tpls, err := tester.Service.SelectTemplatesBySize(abstract.HostSizingRequirements{
		MinCores:    1,
		MinRAMSize:  1,
		MinDiskSize: 10,
	}, false)
	assert.Nil(t, err)
	img, err := tester.Service.SearchImage("Ubuntu 18.04")
	assert.Nil(t, err)
	hostRequest := abstract.HostRequest{
		ResourceName:   name,
		Networks:       []*abstract.Network{network},
		DefaultRouteIP: "",
		PublicIP:       public,
		TemplateID:     tpls[0].ID,
		ImageID:        img.ID,
		KeyPair:        nil,
		Password:       "",
		DiskSize:       0,
	}
	return tester.Service.CreateHost(hostRequest)
}

// CreateGW creates a test GW
func (tester *ServiceTester) CreateGW(t *testing.T, network *abstract.Network) error {
	tpls, err := tester.Service.SelectTemplatesBySize(abstract.HostSizingRequirements{
		MinCores:    1,
		MinRAMSize:  1,
		MinDiskSize: 10,
	}, false)
	assert.Nil(t, err)
	img, err := tester.Service.SearchImage("Ubuntu 18.04")
	assert.Nil(t, err)
	gwRequest := abstract.HostRequest{
		ImageID:      img.ID,
		TemplateID:   tpls[0].ID,
		Networks:     []*abstract.Network{network},
		ResourceName: "gw-" + network.Name,
		IsGateway:    true,
	}
	gw, _, err := tester.Service.CreateHost(gwRequest)
	if err != nil {
		return err
	}
	network.GatewayID = gw.Core.ID
	return nil
}

// CreateNetworkTest test
func (tester *ServiceTester) CreateNetworkTest(t *testing.T) {
	// Get initial number of networks
	nets, err := tester.Service.ListNetworks()
	require.Nil(t, err)
	nbAllNetworks := len(nets)
	require.True(t, nbAllNetworks > 0)

	fmt.Println("Creating unit_test_network_6")
	network1, kp1 := tester.CreateNetwork(t, "unit_test_network_6", true, "1.1.1.0/24")
	require.NotNil(t, network1)
	require.NotNil(t, kp1)
	fmt.Println(fmt.Sprintf("Created a Network with name %v and id %v", network1.Name, kp1.Core.ID))

	networkFound := false

	nets, err = tester.Service.ListNetworks()
	require.Nil(t, err)
	for _, net := range nets {
		if net.Name == "unit_test_network61" {
			networkFound = true
			break
		}
	}

	net, err := tester.Service.GetNetwork("unit_test_network_6")

	require.NotNil(t, net)
	require.Nil(t, err)

	require.True(t, networkFound)
	defer func() {
		_ = tester.Service.DeleteKeyPair(kp1.Core.ID)
	}()
	defer func() {
		_ = tester.Service.DeleteNetwork(network1.ID)
	}()
}

// Networks test
func (tester *ServiceTester) Networks(t *testing.T) {
	// Get initial number of networks
	nets, err := tester.Service.ListNetworks()
	assert.Nil(t, err)
	nbAllNetworks := len(nets)

	net1CIDR := "1.1.2.0/24"
	net1Name := "unit_test_network_1"
	fmt.Println("Creating unit_test_network1")
	network1, gw1 := tester.CreateNetwork(t, net1Name, true, net1CIDR)
	fmt.Println("unit_test_network1 created")
	defer func() {
		_ = tester.Service.DeleteHost(gw1.Core.ID)
		_ = tester.Service.DeleteNetwork(network1.ID)
	}()

	assert.NotNil(t, network1)
	assert.NotNil(t, gw1)

	assert.Equal(t, network1.CIDR, net1CIDR)
	assert.Equal(t, network1.GatewayID, gw1.Core.ID)
	assert.Equal(t, gw1.Core.Name, "gw-"+network1.Name)
	assert.NotEmpty(t, gw1.Network.PublicIPv4)

	// VPL: properties are not inside stack instances anymore
	// TODO: see if there is something to test at this level
	// gw1NetworkV1 := propertiesv1.NewHostNetwork()
	// err = gw1.properties.Inspect(HostProperty.NetworkV1, func(clonable interface{}) error {
	// 	gw1NetworkV1 = clonable.(*propertiesv1.HostNetwork)
	// 	return nil
	// })
	// assert.Nil(t, err)
	// assert.Empty(t, gw1NetworkV1.DefaultGatewayID)
	// assert.Equal(t, gw1NetworkV1.NetworksByName[net1Name], network1.ID)
	// assert.Equal(t, gw1NetworkV1.NetworksByID[network1.ID], net1Name)
	// assert.Equal(t, gw1NetworkV1.IsGateway, true)

	fmt.Println("Creating unit_test_network2")
	network2, gw2 := tester.CreateNetwork(t, "unit_test_network_2", false, "1.1.3.0/24")
	fmt.Println("unit_test_network2 created ")

	assert.Nil(t, gw2)

	defer func() {
		_ = tester.Service.DeleteNetwork(network2.ID)
	}()

	nets, err = tester.Service.ListNetworks()
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

	n1, err := tester.Service.GetNetwork(network1.ID)
	assert.Nil(t, err)
	assert.Equal(t, n1.CIDR, network1.CIDR)
	assert.Equal(t, n1.ID, network1.ID)
	assert.Equal(t, n1.IPVersion, network1.IPVersion)
	assert.Equal(t, n1.Name, network1.Name)
}

// Hosts test
func (tester *ServiceTester) Hosts(t *testing.T) {
	// Get initial number of hosts
	hosts, err := tester.Service.ListHosts(false)
	assert.NoError(t, err)
	nbHosts := len(hosts)

	// TODO: handle kp delete
	network, gw := tester.CreateNetwork(t, "unit_test_network_3", false, "1.1.4.0/24")
	defer func() {
		_ = tester.Service.DeleteNetwork(network.ID)
	}()
	assert.Nil(t, gw)
	host1, _, err := tester.CreateHost(t, "host1", network, true)
	assert.NoError(t, err)
	defer func() {
		_ = tester.Service.DeleteHost(host1.Core.ID)
	}()

	// ssh, err := tester.Service.GetSSHConfig(host.ID)
	// _, err = ssh.WaitServerReady("phase1", 1 * time.Minute)
	// assert.NoError(t, err)
	// cmd, err := ssh.Command("whoami")
	// assert.Nil(t, err)
	// out, err := cmd.Output()
	// assert.Nil(t, err)
	// content := strings.Trim(string(out), "\n")
	// assert.Equal(t, abstract.DefaultUser, content)

	// cmd, err = ssh.Command("ping -c1 8.8.8.8")
	// fmt.Println(ssh.PrivateKey)
	// assert.Nil(t, err)
	// _, _, _, err = cmd.Run()
	// assert.Nil(t, err)

	// cmd, err = ssh.Command("ping -c1 www.google.fr")
	// fmt.Println(ssh.PrivateKey)
	// assert.Nil(t, err)
	// _, _, _, err = cmd.Run()
	// assert.Nil(t, err)

	_, _, err = tester.CreateHost(t, "host2", network, false)
	assert.Error(t, err)
	// err = tester.CreateGW(t, network)
	// assert.NoError(t, err)
	// defer func() {
	// 	_ = tester.Service.DeleteGateway(network.GatewayID)
	// }()
	host2, _, err := tester.CreateHost(t, "host2", network, false)
	assert.NoError(t, err)
	defer func() {
		_ = tester.Service.DeleteHost(host2.Core.ID)
	}()

	network, err = tester.Service.GetNetwork(network.ID)
	assert.NoError(t, err)
	hosts, err = tester.Service.ListHosts(false)
	require.Nil(t, err)
	assert.Equal(t, nbHosts+3, len(hosts))
	found := 0
	for _, v := range hosts {
		switch {
		case v.Core.Name == "gw-"+network.Name:
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

	host1Bis, err := tester.Service.InspectHost(host1)
	assert.NoError(t, err)
	assert.Equal(t, host1.Core.ID, host1Bis.Core.ID)
	assert.Equal(t, host1.Core.Name, host1Bis.Core.Name)
}

// StartStopHost test
func (tester *ServiceTester) StartStopHost(t *testing.T) {
	net, gw := tester.CreateNetwork(t, "unit_test_network_4", true, "1.1.5.0/24")
	defer func() {
		_ = tester.Service.DeleteHost(gw.Core.ID)
		_ = tester.Service.DeleteNetwork(net.ID)
	}()
	host, err := tester.Service.GetHostByName("gw-" + net.Name)
	require.Nil(t, err)
	require.NotNil(t, host)
	{
		err := tester.Service.StopHost(host.ID)
		require.Nil(t, err)
		start := time.Now()
		err = tester.Service.WaitHostState(host.ID, hoststate.STOPPED, temporal.GetBigDelay())
		tt := time.Now()
		fmt.Println(tt.Sub(start))
		assert.Nil(t, err)
		// assert.Equal(t, host.State, hoststate.STOPPED)
	}
	{
		err := tester.Service.StartHost(host.ID)
		require.Nil(t, err)
		start := time.Now()
		err = tester.Service.WaitHostState(host.ID, hoststate.STARTED, temporal.GetBigDelay())
		tt := time.Now()
		fmt.Println(tt.Sub(start))
		assert.Nil(t, err)
		assert.Equal(t, host.LastState, hoststate.STARTED)
	}

}

// Volumes test
func (tester *ServiceTester) Volumes(t *testing.T) {
	// Get initial number of volumes
	lst, err := tester.Service.ListVolumes()
	require.NotNil(t, err)
	nbVolumes := len(lst)

	v1, err := tester.Service.CreateVolume(abstract.VolumeRequest{
		Name:  "test_volume1",
		Size:  25,
		Speed: volumespeed.HDD,
	})
	assert.Nil(t, err)
	defer func() {
		_ = tester.Service.DeleteVolume(v1.ID)
	}()

	assert.Equal(t, "test_volume1", v1.Name)
	assert.Equal(t, 25, v1.Size)
	assert.Equal(t, volumespeed.HDD, v1.Speed)

	_, err = tester.Service.WaitVolumeState(v1.ID, volumestate.AVAILABLE, temporal.GetBigDelay())
	assert.Nil(t, err)

	v2, err := tester.Service.CreateVolume(abstract.VolumeRequest{
		Name:  "test_volume2",
		Size:  35,
		Speed: volumespeed.HDD,
	})
	assert.Nil(t, err)
	defer func() {
		_ = tester.Service.DeleteVolume(v2.ID)
	}()

	_, err = tester.Service.WaitVolumeState(v2.ID, volumestate.AVAILABLE, temporal.GetBigDelay())
	assert.Nil(t, err)

	lst, err = tester.Service.ListVolumes()
	assert.Nil(t, err)
	assert.Equal(t, nbVolumes+2, len(lst))
	for _, vl := range lst {
		switch vl.ID {
		case v1.ID:
			assert.Equal(t, v1.Name, vl.Name)
			assert.Equal(t, v1.Size, vl.Size)
			assert.Equal(t, v1.Speed, vl.Speed)
		case v2.ID:
			assert.Equal(t, v2.Name, vl.Name)
			assert.Equal(t, v2.Size, vl.Size)
			assert.Equal(t, v2.Speed, vl.Speed)
		default:
			t.Fail()
		}
	}
}

// VolumeAttachments test
func (tester *ServiceTester) VolumeAttachments(t *testing.T) {
	// TODO: handle kp delete
	net, gw := tester.CreateNetwork(t, "unit_test_network_5", true, "1.1.6.0/24")

	defer func() {
		_ = tester.Service.DeleteHost(gw.Core.ID)
		_ = tester.Service.DeleteNetwork(net.ID)
	}()

	host, err := tester.Service.GetHostByName("gw-" + net.Name)
	require.Nil(t, err)
	require.NotNil(t, host)

	v1, err := tester.Service.CreateVolume(abstract.VolumeRequest{
		Name:  "test_volume1",
		Size:  25,
		Speed: volumespeed.HDD,
	})
	assert.Nil(t, err)
	defer func() {
		_ = tester.Service.DeleteVolume(v1.ID)
	}()
	_, err = tester.Service.WaitVolumeState(v1.ID, volumestate.AVAILABLE, temporal.GetBigDelay())
	assert.Nil(t, err)

	v2, err := tester.Service.CreateVolume(abstract.VolumeRequest{
		Name:  "test_volume2",
		Size:  35,
		Speed: volumespeed.HDD,
	})
	assert.Nil(t, err)
	defer func() {
		_ = tester.Service.DeleteVolume(v2.ID)
	}()

	_, err = tester.Service.WaitVolumeState(v2.ID, volumestate.AVAILABLE, temporal.GetBigDelay())
	assert.Nil(t, err)

	va1ID, err := tester.Service.CreateVolumeAttachment(abstract.VolumeAttachmentRequest{
		Name:     "Attachment1",
		HostID:   host.ID,
		VolumeID: v1.ID,
	})
	assert.Nil(t, err)
	assert.NotEmpty(t, va1ID)
	defer func() {
		_ = tester.Service.DeleteVolumeAttachment(host.ID, va1ID)
	}()

	va2ID, err := tester.Service.CreateVolumeAttachment(abstract.VolumeAttachmentRequest{
		Name:     "Attachment2",
		HostID:   host.ID,
		VolumeID: v2.ID,
	})
	assert.Nil(t, err)
	assert.NotEmpty(t, va2ID)
	defer func() {
		_ = tester.Service.DeleteVolumeAttachment(host.ID, va2ID)
	}()

	va1, err := tester.Service.GetVolumeAttachment(host.ID, v1.ID)
	assert.Nil(t, err)

	va2, err := tester.Service.GetVolumeAttachment(host.ID, v2.ID)
	assert.Nil(t, err)

	lst, err := tester.Service.ListVolumeAttachments(host.ID)
	assert.Nil(t, err)
	assert.Equal(t, 2, len(lst))
	for _, val := range lst {
		switch val.ID {
		case va1ID:
			assert.Equal(t, va1ID, val.ID)
			assert.Equal(t, va1.Name, val.Name)
			assert.Equal(t, va1.Device, val.Device)
			assert.Equal(t, va1.ServerID, val.ServerID)
			assert.Equal(t, va1.VolumeID, val.VolumeID)
		case va2ID:
			assert.Equal(t, va2ID, val.ID)
			assert.Equal(t, va2.Name, val.Name)
			assert.Equal(t, va2.Device, val.Device)
			assert.Equal(t, va2.ServerID, val.ServerID)
			assert.Equal(t, va2.VolumeID, val.VolumeID)
		default:
			t.Fail()
		}
	}
}

// Containers test
func (tester *ServiceTester) Containers(t *testing.T) {
	_, err := tester.Service.CreateBucket("testC")
	assert.Nil(t, err)
	_, err = tester.Service.CreateBucket("testC2")
	assert.Nil(t, err)

	cl, err := tester.Service.ListBuckets("")
	require.NotNil(t, err)
	assert.Contains(t, cl, "testC", "testC2")
	err = tester.Service.DeleteBucket("testC")
	assert.Nil(t, err)
	err = tester.Service.DeleteBucket("testC2")
	assert.Nil(t, err)
	cl, err = tester.Service.ListBuckets("")
	assert.Nil(t, err)
	assert.NotContains(t, cl, "testC", "testC2")
}

// TODO: disabled, need overhaul
// // Objects test
// func (tester *ServiceTester) Objects(t *testing.T) {
// 	_, err := tester.Service.CreateBucket("testC")
// 	assert.Nil(t, err)
// 	_, err = tester.Service.WriteObject("testC", "object1", strings.NewReader("123456789"), 0, objectstorage.ObjectMetadata{"A": "B"})
// 	assert.Nil(t, err)

// 	var buff bytes.Buffer
// 	err = tester.Service.ReadObject("testC", "object1", buff, 0, 0)
// 	sc := buff.String()
// 	assert.Equal(t, "123456789", sc)
// 	assert.Equal(t, 1, len(o.Metadata))
// 	assert.Equal(t, "B", o.Metadata["A"])

// 	o, err = tester.Service.GetObjectMetadata("testC", "object1")
// 	assert.Empty(t, o.Content)
// 	assert.Equal(t, 1, len(o.Metadata))
// 	assert.Equal(t, "B", o.Metadata["A"])
// 	o, err = tester.Service.GetObject("testC", "object1", []abstract.Range{
// 		abstract.NewRange(0, 2),
// 		abstract.NewRange(4, 7),
// 	})
// 	assert.Nil(t, err)
// 	if err == nil {
// 		buff.Reset()
// 		_, err = buff.ReadFrom(o.Content)
// 		assert.Nil(t, err)
// 		sc = buff.String()
// 		assert.Equal(t, "1235678", sc)
// 	}

// 	assert.Nil(t, err)
// 	time.Sleep(5 * time.Second)
// 	_, err = tester.Service.GetObject("testC", "object1", nil)
// 	assert.NotNil(t, err)

// 	err = tester.Service.DeleteObject("testC", "object1")
// 	assert.NotNil(t, err)
// 	err = tester.Service.DeleteBucket("testC")
// 	assert.Nil(t, err)
// }

// TODO: Implement missing methods here (Look at TODO Implement Test)
