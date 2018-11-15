/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeState"

	_ "github.com/CS-SI/SafeScale/providers/cloudferro"     // Imported to initialize tenant ovh
	_ "github.com/CS-SI/SafeScale/providers/cloudwatt"      // Imported to initialize tenant cloudwatt
	_ "github.com/CS-SI/SafeScale/providers/flexibleengine" // Imported to initialize tenant flexibleengine
	_ "github.com/CS-SI/SafeScale/providers/opentelekom"    // Imported to initialize tenant opentelekoms
	_ "github.com/CS-SI/SafeScale/providers/ovh"            // Imported to initialize tenant ovh
)

// ClientTester helper class to test clients
type ClientTester struct {
	Service providers.Service
}

//ListImages test
func (tester *ClientTester) ListImages(t *testing.T) {

	images, err := tester.Service.ListImages(false)
	assert.Nil(t, err)
	assert.NotEmpty(t, images)
	for _, i := range images {
		fmt.Println(i.Name)
		assert.NotEqual(t, i.ID, "")
		assert.NotEqual(t, i.Name, "")
	}
	imgs, err := tester.Service.FilterImages("ubuntu 16.04")
	for _, img := range imgs {
		fmt.Println(">>", img.Name)
	}
	imgs, err = tester.Service.FilterImages("ubuntu xenial")
	for _, img := range imgs {
		fmt.Println(">>", img.Name)
	}

}

//ListHostTemplates test
func (tester *ClientTester) ListHostTemplates(t *testing.T) {
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

//CreateKeyPair test
func (tester *ClientTester) CreateKeyPair(t *testing.T) {
	kp, err := tester.Service.CreateKeyPair("kp")
	assert.Nil(t, err)
	defer tester.Service.DeleteKeyPair(kp.ID)
	assert.NotEqual(t, kp.ID, "")
	assert.NotEqual(t, kp.Name, "")
	assert.NotEqual(t, kp.PrivateKey, "")
	assert.NotEqual(t, kp.PublicKey, "")

}

// CreateKeyPairAndLeaveItThere ...
func (tester *ClientTester) CreateKeyPairAndLeaveItThere(t *testing.T) {
	kp, err := tester.Service.CreateKeyPair("kp")
	assert.Nil(t, err)
	assert.NotEqual(t, kp.ID, "")
	assert.NotEqual(t, kp.Name, "")
	assert.NotEqual(t, kp.PrivateKey, "")
	assert.NotEqual(t, kp.PublicKey, "")
}

//GetKeyPair test
func (tester *ClientTester) GetKeyPair(t *testing.T) {
	kp, err := tester.Service.CreateKeyPair("unit_test_kp")
	require.Nil(t, err)

	kp2, err := tester.Service.GetKeyPair("unit_test_kp")
	require.Nil(t, err)

	assert.Equal(t, kp.ID, kp2.ID)
	assert.Equal(t, kp.Name, kp2.Name)
	assert.Equal(t, kp.PublicKey, kp2.PublicKey)
	assert.Equal(t, "", kp2.PrivateKey)
	_, err = tester.Service.GetKeyPair("notfound")
	assert.NotNil(t, err)

	defer tester.Service.DeleteKeyPair("unit_test_kp")
}

//ListKeyPairs test
func (tester *ClientTester) ListKeyPairs(t *testing.T) {
	lst, err := tester.Service.ListKeyPairs()
	assert.Nil(t, err)
	nbKP := len(lst)
	kp, err := tester.Service.CreateKeyPair("kp")
	assert.Nil(t, err)
	defer tester.Service.DeleteKeyPair("kp")
	kp2, err := tester.Service.CreateKeyPair("kp2")
	assert.Nil(t, err)
	defer tester.Service.DeleteKeyPair("kp2")
	lst, err = tester.Service.ListKeyPairs()
	assert.Nil(t, err)
	assert.EqualValues(t, nbKP+2, len(lst))
	for _, kpe := range lst {
		var kpr model.KeyPair
		if kpe.ID == kp.ID {
			kpr = *kp
		} else if kpe.ID == kp2.ID {
			kpr = *kp2
		} else {
			continue
		}
		assert.Equal(t, kpe.ID, kpr.ID)
		assert.Equal(t, kpe.Name, kpr.Name)
		assert.Equal(t, kpe.PublicKey, kpr.PublicKey)
		assert.Equal(t, kpe.PrivateKey, "")
	}
}

//CreateNetwork creates a test network
func (tester *ClientTester) CreateNetwork(t *testing.T, name string, withGW bool) (*model.Network, *model.KeyPair) {

	network, err := tester.Service.CreateNetwork(model.NetworkRequest{
		Name:      name,
		IPVersion: IPVersion.IPv4,
		CIDR:      "192.168.1.0/24",
	})
	require.NoError(t, err)

	tpls, err := tester.Service.SelectTemplatesBySize(model.SizingRequirements{
		MinCores:    1,
		MinRAMSize:  1,
		MinDiskSize: 0,
	})
	require.Nil(t, err)
	img, err := tester.Service.SearchImage("Ubuntu 16.04")
	require.Nil(t, err)
	keypair, err := tester.Service.CreateKeyPair("kp_" + network.Name)
	require.Nil(t, err)

	gwRequest := model.GWRequest{
		ImageID:    img.ID,
		NetworkID:  network.ID,
		KeyPair:    keypair,
		TemplateID: tpls[0].ID,
	}

	if withGW {
		_, err = tester.Service.CreateGateway(gwRequest)
		require.Nil(t, err)
	}

	return network, keypair
}

// CreateHost creates a test host
func (tester *ClientTester) CreateHost(t *testing.T, name string, networkID string, public bool) (*model.Host, error) {
	tpls, err := tester.Service.SelectTemplatesBySize(model.SizingRequirements{
		MinCores:    1,
		MinRAMSize:  4,
		MinDiskSize: 10,
	})
	assert.Nil(t, err)
	img, err := tester.Service.SearchImage("Ubuntu 16.04")
	assert.Nil(t, err)
	hostRequest := model.HostRequest{
		ImageID:      img.ID,
		ResourceName: name,
		TemplateID:   tpls[0].ID,
		NetworkIDs:   []string{networkID},
		PublicIP:     public,
	}
	return tester.Service.CreateHost(hostRequest)
}

//CreateGW creates a test GW
func (tester *ClientTester) CreateGW(t *testing.T, networkID string) error {
	tpls, err := tester.Service.SelectTemplatesBySize(model.SizingRequirements{
		MinCores:    1,
		MinRAMSize:  4,
		MinDiskSize: 10,
	})
	assert.Nil(t, err)
	img, err := tester.Service.SearchImage("Ubuntu 16.04")
	assert.Nil(t, err)
	gwRequest := model.GWRequest{
		ImageID:    img.ID,
		TemplateID: tpls[0].ID,
		NetworkID:  networkID,
	}
	_, err = tester.Service.CreateGateway(gwRequest)
	return err
}

// CreateNetworkTest test
func (tester *ClientTester) CreateNetworkTest(t *testing.T) {
	// Get inital number of networks
	nets, err := tester.Service.ListNetworks(true)
	require.Nil(t, err)
	nbAllNetworks := len(nets)
	require.True(t, nbAllNetworks > 0)

	fmt.Println("Creating unit_test_network1")
	network1, kp1 := tester.CreateNetwork(t, "unit_test_network_1", true)
	require.NotNil(t, network1)
	require.NotNil(t, kp1)
	fmt.Println(fmt.Sprintf("Created a Network with name %v and id %v", network1.Name, kp1.ID))

	networkFound := false

	nets, err = tester.Service.ListNetworks(true)
	require.Nil(t, err)
	for _, net := range nets {
		if net.Name == "unit_test_network_1" {
			networkFound = true
			break
		}
	}

	net, err := tester.Service.GetNetwork("unit_test_network_1")
	require.NotNil(t, net)
	require.Nil(t, err)

	require.True(t, networkFound)
	defer tester.Service.DeleteKeyPair(kp1.ID)
	defer tester.Service.DeleteNetwork(network1.ID)
}

//Networks test
func (tester *ClientTester) Networks(t *testing.T) {
	// Get inital number of networks
	nets, err := tester.Service.ListNetworks(true)
	assert.Nil(t, err)
	nbAllNetworks := len(nets)
	// nets, err = tester.Service.ListNetworks(false)
	// assert.Nil(t, err)
	// nbMonitoredNetworks := len(nets)

	fmt.Println("Creating unit_test_network1")
	network1, kp1 := tester.CreateNetwork(t, "unit_test_network_1", true)
	fmt.Println("unit_test_network1 created")
	defer tester.Service.DeleteKeyPair(kp1.ID)
	defer tester.Service.DeleteNetwork(network1.ID)

	// host, err := tester.Service.GetHostByName("gw_" + network1.Name)
	// require.Nil(t, err)
	// assert.True(t, host.PublicIPv4 != "" || host.PublicIPv6 != "")
	// assert.NotEmpty(t, host.PrivateKey)
	// //assert.Empty(t, host.GatewayID)
	// fmt.Println(host.PublicIPv4)
	// fmt.Println(host.PrivateKey)
	// // ssh, err := tester.Service.GetSSHConfig(host.ID)
	// assert.Nil(t, err)

	// // Waits sshd deamon is up
	// ssh.WaitServerReady(1 * time.Minute)
	// cmd, err := ssh.Command("whoami")
	// assert.Nil(t, err)
	// out, err := cmd.Output()
	// assert.Nil(t, err)
	// content := strings.Trim(string(out), "\n")
	// assert.Equal(t, model.DefaultUser, content)

	fmt.Println("Creating unit_test_network2")
	network2, kp2 := tester.CreateNetwork(t, "unit_test_network_2", false)
	fmt.Println("unit_test_network2 created ")

	defer tester.Service.DeleteKeyPair(kp2.ID)
	defer tester.Service.DeleteNetwork(network2.ID)

	nets, err = tester.Service.ListNetworks(true)
	assert.Nil(t, err)
	assert.Equal(t, nbAllNetworks+2, len(nets))
	found := 0
	for _, n := range nets {
		if n.ID == network1.ID {
			found++
		} else if n.ID == network2.ID {
			found++
		} else {
			continue
			// t.Fail()
		}
	}
	assert.Equal(t, 2, found)

	n1, err := tester.Service.GetNetwork(network1.ID)
	assert.Nil(t, err)
	assert.Equal(t, n1.CIDR, network1.CIDR)
	assert.Equal(t, n1.ID, network1.ID)
	//assert.Equal(t, n1.IPVersion, network1.IPVersion)
	assert.Equal(t, n1.Name, network1.Name)
}

// Hosts test
func (tester *ClientTester) Hosts(t *testing.T) {
	// Get initial number of hosts
	hosts, err := tester.Service.ListHosts(false)
	assert.NoError(t, err)
	nbHosts := len(hosts)

	// TODO: handle kp delete
	network, kp := tester.CreateNetwork(t, "unit_test_network", false)
	defer tester.Service.DeleteNetwork(network.ID)
	defer tester.Service.DeleteKeyPair(kp.ID)

	host, err := tester.CreateHost(t, "host1", network.ID, true)
	defer tester.Service.DeleteHost(host.ID)

	assert.NoError(t, err)
	// time.Sleep(30 * time.Second)

	// ssh, err := tester.Service.GetSSHConfig(host.ID)
	// err = ssh.WaitServerReady(1 * time.Minute)
	// assert.NoError(t, err)
	// cmd, err := ssh.Command("whoami")
	// assert.Nil(t, err)
	// out, err := cmd.Output()
	// assert.Nil(t, err)
	// content := strings.Trim(string(out), "\n")
	// assert.Equal(t, model.DefaultUser, content)

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

	_, err = tester.CreateHost(t, "host2", network.ID, false)
	assert.Error(t, err)
	err = tester.CreateGW(t, network.ID)
	assert.NoError(t, err)
	host2, err := tester.CreateHost(t, "host2", network.ID, false)
	defer tester.Service.DeleteHost(host2.ID)
	assert.NoError(t, err)

	// // time.Sleep(30 * time.Second)
	// ssh2, err := tester.Service.GetSSHConfig(host2.ID)
	// err = ssh2.WaitServerReady(2 * time.Minute)
	// assert.NoError(t, err)
	// cmd2, err := ssh2.Command("whoami")
	// assert.NoError(t, err)
	// out2, err := cmd2.Output()
	// assert.NoError(t, err)
	// content2 := strings.Trim(string(out2), "\n")
	// assert.Equal(t, model.DefaultUser, content2)

	network, err = tester.Service.GetNetwork(network.ID)
	assert.NoError(t, err)
	hosts, err = tester.Service.ListHosts(false)
	assert.Equal(t, nbHosts+3, len(hosts))
	found := 0
	for _, v := range hosts {
		if v.Name == "gw_"+network.Name {
			found++
		} else if v.ID == host.ID {
			found++
		} else if v.ID == host2.ID {
			found++
		} else {
			fmt.Printf("Unknown (preexisting?) host %+v\n", v)
			continue
			// t.Fatalf("Unknown host %+v\n", v)
		}
	}
	assert.Equal(t, 3, found)

	host2, err = tester.CreateHost(t, "host1", network.ID, true)

	err = tester.Service.UpdateHost(host)
	assert.NoError(t, err)
	// assert.Equal(t, host2.PublicIPv4, host.PublicIPv4)
	// assert.Equal(t, host2.PublicIPv6, host.PublicIPv6)
	// //VPL: GatewayID moved in Host Extension NetworkV1.DefaultGatewayID...
	//assert.Equal(t, host2.GatewayID, host.GatewayID)
	assert.Equal(t, host2.ID, host.ID)
	assert.Equal(t, host2.Name, host.Name)
	assert.Equal(t, host2.PrivateKey, host.PrivateKey)
	//VPL: Size moved in Host Extension SizingV1.AllocatedSize
	//assert.Equal(t, host2.Size, host.Size)
	assert.Equal(t, host2.LastState, host.LastState)

	//VPL: PrivateIPsVx moved in Host Extension NetworkV1.IPvxAddresses
	// for _, addr := range v.PrivateIPsV4 {
	// 	fmt.Println(addr)
	// }
	// for _, addr := range v.PrivateIPsV6 {
	// 	fmt.Println(addr)
	// }
}

// StartStopHost test
func (tester *ClientTester) StartStopHost(t *testing.T) {
	// TODO: handle kp delete
	net, kp := tester.CreateNetwork(t, "unit_test_network", true)
	defer tester.Service.DeleteKeyPair(kp.ID)
	defer tester.Service.DeleteNetwork(net.ID)
	host, err := tester.Service.GetHostByName("gw_" + net.Name)
	require.Nil(t, err)
	require.NotNil(t, host)
	{
		err := tester.Service.StopHost(host.ID)
		require.Nil(t, err)
		start := time.Now()
		err = tester.Service.WaitHostState(host.ID, HostState.STOPPED, 40*time.Second)
		tt := time.Now()
		fmt.Println(tt.Sub(start))
		assert.Nil(t, err)
		//assert.Equal(t, host.State, HostState.STOPPED)
	}
	{
		err := tester.Service.StartHost(host.ID)
		require.Nil(t, err)
		start := time.Now()
		err = tester.Service.WaitHostState(host.ID, HostState.STARTED, 40*time.Second)
		tt := time.Now()
		fmt.Println(tt.Sub(start))
		assert.Nil(t, err)
		assert.Equal(t, host.LastState, HostState.STARTED)
	}

}

//Volume test
func (tester *ClientTester) Volume(t *testing.T) {
	// Get initial number of volumes
	lst, err := tester.Service.ListVolumes(true)
	nbVolumes := len(lst)

	v, err := tester.Service.CreateVolume(model.VolumeRequest{
		Name:  "test_volume1",
		Size:  100,
		Speed: VolumeSpeed.HDD,
	})
	defer tester.Service.DeleteVolume(v.ID)
	assert.Nil(t, err)
	assert.Equal(t, "test_volume1", v.Name)
	assert.Equal(t, 100, v.Size)
	assert.Equal(t, VolumeSpeed.HDD, v.Speed)

	tester.Service.WaitVolumeState(v.ID, VolumeState.AVAILABLE, 40*time.Second)
	v2, err := tester.Service.CreateVolume(model.VolumeRequest{
		Name:  "test_volume2",
		Size:  100,
		Speed: VolumeSpeed.HDD,
	})
	defer tester.Service.DeleteVolume(v2.ID)
	assert.Nil(t, err)
	tester.Service.WaitVolumeState(v2.ID, VolumeState.AVAILABLE, 40*time.Second)
	lst, err = tester.Service.ListVolumes(true)
	assert.Nil(t, err)
	assert.Equal(t, nbVolumes+2, len(lst))
	for _, vl := range lst {
		if vl.ID == v.ID {
			assert.Equal(t, v.Name, vl.Name)
			assert.Equal(t, v.Size, vl.Size)
			assert.Equal(t, v.Speed, vl.Speed)
		} else if vl.ID == v2.ID {
			assert.Equal(t, v2.Name, vl.Name)
			assert.Equal(t, v2.Size, vl.Size)
			assert.Equal(t, v2.Speed, vl.Speed)
		} else {
			t.Fail()
		}
	}

}

//VolumeAttachment test
func (tester *ClientTester) VolumeAttachment(t *testing.T) {
	// TODO: handle kp delete
	net, kp := tester.CreateNetwork(t, "unit_test_network", true)

	defer tester.Service.DeleteKeyPair(kp.ID)
	defer tester.Service.DeleteNetwork(net.ID)
	host, err := tester.Service.GetHostByName("gw_" + net.Name)
	require.Nil(t, err)
	require.NotNil(t, host)

	defer tester.Service.DeleteHost(host.ID)
	assert.NoError(t, err)

	v, err := tester.Service.CreateVolume(model.VolumeRequest{
		Name:  "test_volume1",
		Size:  100,
		Speed: VolumeSpeed.HDD,
	})
	defer tester.Service.DeleteVolume(v.ID)
	assert.Nil(t, err)

	v2, err := tester.Service.CreateVolume(model.VolumeRequest{
		Name:  "test_volume2",
		Size:  100,
		Speed: VolumeSpeed.HDD,
	})
	defer tester.Service.DeleteVolume(v2.ID)
	assert.Nil(t, err)
	//defer clt.DeleteVolume(v.ID)
	tester.Service.WaitVolumeState(v2.ID, VolumeState.AVAILABLE, 40*time.Second)
	vaID, err := tester.Service.CreateVolumeAttachment(model.VolumeAttachmentRequest{
		Name:     "Attachment1",
		HostID:   host.ID,
		VolumeID: v.ID,
	})
	defer tester.Service.DeleteVolumeAttachment(host.ID, vaID)
	assert.Nil(t, err)
	// assert.NotEmpty(t, va.Device)
	va2ID, err := tester.Service.CreateVolumeAttachment(model.VolumeAttachmentRequest{
		Name:     "Attachment2",
		HostID:   host.ID,
		VolumeID: v2.ID,
	})
	defer tester.Service.DeleteVolumeAttachment(host.ID, va2ID)
	assert.Nil(t, err)
	// assert.NotEmpty(t, va2.Device)
	val, err := tester.Service.GetVolumeAttachment(host.ID, v.ID)
	assert.Nil(t, err)
	assert.Equal(t, vaID, val.ID)
	// assert.Equal(t, va.Name, val.Name)
	// assert.Equal(t, va.Device, val.Device)
	// assert.Equal(t, va.ServerID, val.ServerID)
	// assert.Equal(t, va.VolumeID, val.VolumeID)
	assert.Nil(t, err)
	lst, err := tester.Service.ListVolumeAttachments(host.ID)
	assert.Equal(t, 2, len(lst))
	for _, val := range lst {
		if val.ID == vaID {
			assert.Equal(t, vaID, val.ID)
			// assert.Equal(t, va.Name, val.Name)
			// assert.Equal(t, va.Device, val.Device)
			// assert.Equal(t, va.ServerID, val.ServerID)
			// assert.Equal(t, va.VolumeID, val.VolumeID)
		} else if val.ID == va2ID {
			assert.Equal(t, va2ID, val.ID)
			// assert.Equal(t, va2.Name, val.Name)
			// assert.Equal(t, va2.Device, val.Device)
			// assert.Equal(t, va2.ServerID, val.ServerID)
			// assert.Equal(t, va2.VolumeID, val.VolumeID)
		} else {
			t.Fail()
		}
	}
}

//Containers test
func (tester *ClientTester) Containers(t *testing.T) {
	err := tester.Service.CreateContainer("testC")
	assert.Nil(t, err)
	err = tester.Service.CreateContainer("testC2")
	assert.Nil(t, err)

	cl, err := tester.Service.ListContainers()
	assert.Contains(t, cl, "testC", "testC2")
	err = tester.Service.DeleteContainer("testC")
	assert.Nil(t, err)
	err = tester.Service.DeleteContainer("testC2")
	assert.Nil(t, err)
	cl, err = tester.Service.ListContainers()
	assert.NotContains(t, cl, "testC", "testC2")
}

//Objects test
func (tester *ClientTester) Objects(t *testing.T) {
	err := tester.Service.CreateContainer("testC")
	assert.Nil(t, err)
	err = tester.Service.PutObject("testC", model.Object{
		Content:  strings.NewReader("123456789"),
		DeleteAt: time.Now().Add(5 * time.Second),
		Metadata: map[string]string{"A": "B"},
		Name:     "object1",
	})
	assert.Nil(t, err)

	o, err := tester.Service.GetObject("testC", "object1", nil)
	var buff bytes.Buffer
	_, err = buff.ReadFrom(o.Content)
	assert.Nil(t, err)
	sc := buff.String()
	assert.Equal(t, "123456789", sc)
	assert.Equal(t, 1, len(o.Metadata))
	assert.Equal(t, "B", o.Metadata["A"])

	o, err = tester.Service.GetObjectMetadata("testC", "object1")
	assert.Empty(t, o.Content)
	assert.Equal(t, 1, len(o.Metadata))
	assert.Equal(t, "B", o.Metadata["A"])
	o, err = tester.Service.GetObject("testC", "object1", []model.Range{
		model.NewRange(0, 2),
		model.NewRange(4, 7),
	})
	assert.Nil(t, err)
	if err == nil {
		buff.Reset()
		_, err = buff.ReadFrom(o.Content)
		assert.Nil(t, err)
		sc = buff.String()
		assert.Equal(t, "1235678", sc)
	}

	assert.Nil(t, err)
	time.Sleep(5 * time.Second)
	_, err = tester.Service.GetObject("testC", "object1", nil)
	assert.NotNil(t, err)

	err = tester.Service.DeleteObject("testC", "object1")
	assert.NotNil(t, err)
	err = tester.Service.DeleteContainer("testC")
	assert.Nil(t, err)
}

// GetImage ...
func (tester *ClientTester) GetImage(t *testing.T) {
	// TODO Implement this test
}

// TODO Implement missing methods here (Look at TODO Implement Test)
