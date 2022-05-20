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

package converters

import (
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
)

func Test_HostTemplateToHostEffectiveSizing(t *testing.T) {

	ht := abstract.HostTemplate{
		Cores:     4,
		RAMSize:   8192,
		DiskSize:  512,
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
		CPUFreq:   2133,
		ID:        "HostTemplate ID",
		Name:      "HostTemplate Name",
	}
	sz := HostTemplateToHostEffectiveSizing(ht)

	require.EqualValues(t, ht.Cores, sz.Cores)
	require.EqualValues(t, ht.RAMSize, sz.RAMSize)
	require.EqualValues(t, ht.DiskSize, sz.DiskSize)
	require.EqualValues(t, ht.GPUNumber, sz.GPUNumber)
	require.EqualValues(t, ht.CPUFreq, sz.CPUFreq)

}

func Test_VolumeAttachmentFromAbstractToProtocol(t *testing.T) {

	vt := &abstract.VolumeAttachment{
		ID:         "VolumeAttachment ID",
		Name:       "VolumeAttachment Name",
		VolumeID:   "VolumeAttachment VolumeID",
		ServerID:   "VolumeAttachment ServerID",
		Device:     "VolumeAttachment Device",
		MountPoint: "VolumeAttachment MountPoint",
		Format:     "VolumeAttachment Format",
	}
	vtr := VolumeAttachmentFromAbstractToProtocol(vt)

	require.EqualValues(t, vt.ServerID, vtr.Host.Id)
	require.EqualValues(t, vt.MountPoint, vtr.MountPath)
	require.EqualValues(t, vt.Format, vtr.Format)
	require.EqualValues(t, vt.Device, vtr.Device)

}

func Test_HostTemplateFromAbstractToProtocol(t *testing.T) {

	ht := abstract.HostTemplate{
		Cores:     4,
		RAMSize:   8192,
		DiskSize:  512,
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
		CPUFreq:   2133,
		ID:        "HostTemplate ID",
		Name:      "HostTemplate Name",
	}
	hd := HostTemplateFromAbstractToProtocol(ht)

	require.EqualValues(t, ht.ID, hd.Id)
	require.EqualValues(t, ht.Name, hd.Name)
	require.EqualValues(t, ht.Cores, hd.Cores)
	require.EqualValues(t, ht.RAMSize, hd.Ram)
	require.EqualValues(t, ht.DiskSize, hd.Disk)
	require.EqualValues(t, ht.GPUNumber, hd.GpuCount)
	require.EqualValues(t, ht.GPUType, hd.GpuType)

}

func Test_HostEffectiveSizingFromAbstractToProtocol(t *testing.T) {

	ahes := &abstract.HostEffectiveSizing{
		Cores:       4,
		RAMSize:     8192,
		DiskSize:    512,
		GPUNumber:   1,
		GPUType:     "NVIDIA 1080 TI",
		CPUFreq:     2133,
		ImageID:     "HostTemplate ImageID",
		Replaceable: false,
	}
	hd := HostEffectiveSizingFromAbstractToProtocol(ahes)

	require.EqualValues(t, hd.ImageId, ahes.ImageID)
	require.EqualValues(t, hd.Sizing.MinCpuCount, ahes.Cores)
	require.EqualValues(t, hd.Sizing.MaxCpuCount, ahes.Cores)
	require.EqualValues(t, hd.Sizing.MinRamSize, ahes.RAMSize)
	require.EqualValues(t, hd.Sizing.MaxRamSize, ahes.RAMSize)
	require.EqualValues(t, hd.Sizing.MinDiskSize, ahes.DiskSize)
	require.EqualValues(t, hd.Sizing.GpuCount, ahes.GPUNumber)
	require.EqualValues(t, hd.Sizing.MinCpuFreq, ahes.CPUFreq)

}

func Test_ImageFromAbstractToProtocol(t *testing.T) {

	i := &abstract.Image{
		ID:          "Image ID",
		Name:        "Image Name",
		URL:         "Image URL",
		Description: "Image Description",
		StorageType: "Imge StorageType",
		DiskSize:    42,
	}
	pi := ImageFromAbstractToProtocol(i)

	require.EqualValues(t, i.ID, pi.Id)
	require.EqualValues(t, i.Name, pi.Name)

}

func Test_NetworkFromAbstractToProtocol(t *testing.T) {

	an := &abstract.Network{
		ID:         "Network ID",
		Name:       "Network Name",
		CIDR:       "Network CIDR",
		DNSServers: []string{"DNS1", "DNS2", "DNS3"},
		Imported:   false,
	}
	pn := NetworkFromAbstractToProtocol(an)

	require.EqualValues(t, an.ID, pn.Id)
	require.EqualValues(t, an.Name, pn.Name)
	require.EqualValues(t, an.CIDR, pn.Cidr)
	require.EqualValues(t, an.DNSServers, pn.DnsServers)

}

func Test_SubnetFromAbstractToProtocol(t *testing.T) {

	as := &abstract.Subnet{
		ID:                      "Subnet ID",
		Name:                    "Subnet Name",
		Network:                 "Subnet Network",
		CIDR:                    "Subnet CIDR",
		Domain:                  "Subnet Domain",
		DNSServers:              []string{"DNS1", "DNS2", "DNS3"},
		GatewayIDs:              []string{"GatewayID1", "GatewayID2", "GatewayID3"},
		VIP:                     abstract.NewVirtualIP(),
		IPVersion:               ipversion.IPv6,
		State:                   subnetstate.Ready,
		GWSecurityGroupID:       "Subnet GWSecurityGroupID",
		PublicIPSecurityGroupID: "Subnet PublicIPSecurityGroupID",
		InternalSecurityGroupID: "Subnet InternalSecurityGroupID",
		DefaultSSHPort:          42,
		SingleHostCIDRIndex:     65,
	}
	ps := SubnetFromAbstractToProtocol(as)

	require.EqualValues(t, as.ID, ps.Id)
	require.EqualValues(t, as.Name, ps.Name)
	require.EqualValues(t, as.CIDR, ps.Cidr)
	require.EqualValues(t, as.GatewayIDs, ps.GatewayIds)
	require.EqualValues(t, len(as.GatewayIDs) > 1, ps.Failover)
	require.EqualValues(t, protocol.SubnetState(as.State), ps.State)

}

func Test_HostSizingRequirementsFromAbstractToProtocol(t *testing.T) {

	hsz := abstract.HostSizingRequirements{
		MinCores:    2,
		MaxCores:    4,
		MinRAMSize:  512,
		MaxRAMSize:  1024,
		MinDiskSize: 384,
		MinGPU:      1,
		MinCPUFreq:  2133,
		Replaceable: false,
		Image:       "Image",
		Template:    "Template",
	}
	hz := HostSizingRequirementsFromAbstractToProtocol(hsz)

	require.EqualValues(t, hsz.MinCores, hz.MinCpuCount)
	require.EqualValues(t, hsz.MaxCores, hz.MaxCpuCount)
	require.EqualValues(t, hsz.MinCPUFreq, hz.MinCpuFreq)
	require.EqualValues(t, hsz.MinGPU, hz.GpuCount)
	require.EqualValues(t, hsz.MinRAMSize, hz.MinRamSize)
	require.EqualValues(t, hsz.MaxRAMSize, hz.MaxRamSize)
	require.EqualValues(t, hsz.MinDiskSize, hz.MinDiskSize)

}

func Test_HostSizingRequirementsFromAbstractToPropertyV2(t *testing.T) {

	hsz := abstract.HostSizingRequirements{
		MinCores:    2,
		MaxCores:    4,
		MinRAMSize:  512,
		MaxRAMSize:  1024,
		MinDiskSize: 384,
		MinGPU:      1,
		MinCPUFreq:  2133,
		Replaceable: false,
		Image:       "Image",
		Template:    "Template",
	}
	hz := HostSizingRequirementsFromAbstractToPropertyV2(hsz)

	require.EqualValues(t, hsz.MinCores, hz.MinCores)
	require.EqualValues(t, hsz.MaxCores, hz.MaxCores)
	require.EqualValues(t, hsz.MinRAMSize, hz.MinRAMSize)
	require.EqualValues(t, hsz.MaxRAMSize, hz.MaxRAMSize)
	require.EqualValues(t, hsz.MinDiskSize, hz.MinDiskSize)
	require.EqualValues(t, hsz.MinGPU, hz.MinGPU)
	require.EqualValues(t, hsz.MinCPUFreq, hz.MinCPUFreq)
	require.EqualValues(t, hsz.Replaceable, hz.Replaceable)

}

func Test_VirtualIPFromAbstractToProtocol(t *testing.T) {

	avi := abstract.VirtualIP{
		ID:        "VirtualIP ID",
		Name:      "VirtualIP Name",
		SubnetID:  "VirtualIP SubnetID",
		PrivateIP: "VirtualIP PrivateIP",
		PublicIP:  "VirtualIP PublicIP",
		Hosts:     []*abstract.HostCore{abstract.NewHostCore(), abstract.NewHostCore(), abstract.NewHostCore()},
	}
	pvi := VirtualIPFromAbstractToProtocol(avi)

	require.EqualValues(t, avi.ID, pvi.Id)
	require.EqualValues(t, avi.NetworkID, pvi.NetworkId)
	require.EqualValues(t, avi.PrivateIP, pvi.PrivateIp)
	require.EqualValues(t, avi.PublicIP, pvi.PublicIp)
	for i, h := range avi.Hosts {
		require.EqualValues(t, HostCoreFromAbstractToProtocol(h), pvi.Hosts[i])
	}

}

func Test_HostEffectiveSizingFromAbstractToPropertyV2(t *testing.T) {

	ahes := &abstract.HostEffectiveSizing{
		Cores:       4,
		RAMSize:     8192,
		DiskSize:    512,
		GPUNumber:   1,
		GPUType:     "NVIDIA 1080 TI",
		CPUFreq:     2133,
		ImageID:     "HostTemplate ImageID",
		Replaceable: false,
	}
	phes := HostEffectiveSizingFromAbstractToPropertyV2(ahes)

	require.EqualValues(t, ahes.Cores, phes.Cores)
	require.EqualValues(t, ahes.RAMSize, phes.RAMSize)
	require.EqualValues(t, ahes.DiskSize, phes.DiskSize)
	require.EqualValues(t, ahes.GPUNumber, phes.GPUNumber)
	require.EqualValues(t, ahes.CPUFreq, phes.CPUFreq)

}

func Test_HostCoreFromAbstractToProtocol(t *testing.T) {

	ahc := abstract.NewHostCore()
	ahc.ID = "HostCore ID"
	ahc.Name = "HostCore Name"
	ahc.PrivateKey = "HostCore PrivateKey"
	ahc.SSHPort = 42
	ahc.Password = "HostCore Password"
	ahc.LastState = hoststate.Any

	phc := HostCoreFromAbstractToProtocol(ahc)

	require.EqualValues(t, ahc.ID, phc.Id)
	require.EqualValues(t, ahc.Name, phc.Name)
	require.EqualValues(t, ahc.PrivateKey, phc.PrivateKey)

}

func Test_HostFullFromAbstractToProtocol(t *testing.T) {

	ahf := abstract.NewHostFull()
	ahf.Core.ID = "HostCore ID"
	ahf.Core.Name = "HostCore Name"
	ahf.Core.PrivateKey = "HostCore PrivateKey"
	ahf.Core.SSHPort = 42
	ahf.Core.Password = "HostCore Password"
	ahf.Core.LastState = hoststate.Any
	ahf.Core.Tags["DeclaredInBucket"] = "I'm managed !"

	ahf.Sizing.Cores = 4
	ahf.Sizing.RAMSize = 8192
	ahf.Sizing.DiskSize = 512
	ahf.Sizing.GPUNumber = 1
	ahf.Sizing.GPUType = "NVIDIA 1080 TI"
	ahf.Sizing.CPUFreq = 2133
	ahf.Sizing.ImageID = "HostTemplate ImageID"
	ahf.Sizing.Replaceable = false
	ahf.Networking.IsGateway = false
	ahf.Networking.DefaultGatewayID = "Networking DefaultGatewayID"
	ahf.Networking.DefaultGatewayPrivateIP = "Networking DefaultGatewayPrivateIP"
	ahf.Networking.DefaultSubnetID = "ID1"
	ahf.Networking.SubnetsByID = map[string]string{"ID1": "SubnetID1", "ID2": "SubnetID2"}
	ahf.Networking.SubnetsByName = map[string]string{"Name1": "SubnetID1", "Name2": "SubnetID2"}
	ahf.Networking.PublicIPv4 = "Networking PublicIPv4"
	ahf.Networking.PublicIPv6 = "Networking PublicIPv6"
	ahf.Networking.IPv4Addresses = map[string]string{"ID1": "32.32.32.32/18", "ID2": "ipV4_2"}
	ahf.Networking.IPv6Addresses = map[string]string{"ID1": "ipV6_1", "ID2": "ipV6_2"}
	ahf.Description.Created = time.Now()
	ahf.Description.Creator = "Description Creator"
	ahf.Description.Updated = time.Now()
	ahf.Description.Purpose = "Description Purpose"
	ahf.Description.Tenant = "Description Tenant"
	ahf.CurrentState = hoststate.Any

	ph := HostFullFromAbstractToProtocol(ahf)

	state := ahf.Core.LastState
	if ahf.CurrentState != hoststate.Unknown {
		state = ahf.CurrentState
	}

	managed := false
	if ct, ok := ahf.Core.Tags["DeclaredInBucket"]; ok {
		if ct != "" {
			managed = true
		}
	}

	require.EqualValues(t, ahf.Core.ID, ph.Id)
	require.EqualValues(t, ahf.Core.Name, ph.Name)
	require.EqualValues(t, HostStateFromAbstractToProtocol(state), ph.State)
	require.EqualValues(t, ahf.Core.Tags["CreationDate"], ph.CreationDate)
	require.EqualValues(t, managed, ph.Managed)
	require.EqualValues(t, ahf.Networking.PublicIPv4, ph.PublicIp)
	require.EqualValues(t, ahf.Networking.DefaultGatewayID, ph.GatewayId)

}

func Test_HostCoreToHostFull(t *testing.T) {

	ahc := abstract.HostCore{
		ID:         "HostCore ID",
		Name:       "HostCore Name",
		PrivateKey: "HostCore PrivateKey",
		SSHPort:    42,
		Password:   "HostCore Password",
		LastState:  hoststate.Any,
	}

	ahf := HostCoreToHostFull(ahc)

	require.EqualValues(t, ahf.Core, &ahc)

}

func Test_HostDescriptionFromAbstractToPropertyV1(t *testing.T) {

	ahd := abstract.HostDescription{
		Created: time.Now(),
		Creator: "HostDescription Creator",
		Updated: time.Now(),
		Purpose: "HostDescription Purpose",
		Tenant:  "HostDescription Tenant",
	}

	phd := HostDescriptionFromAbstractToPropertyV1(ahd)

	require.EqualValues(t, ahd.Created, phd.Created)
	require.EqualValues(t, ahd.Creator, phd.Creator)
	require.EqualValues(t, ahd.Updated, phd.Updated)
	require.EqualValues(t, ahd.Purpose, phd.Purpose)
	require.EqualValues(t, ahd.Tenant, phd.Tenant)

}

func Test_HostNetworkingFromAbstractToPropertyV2(t *testing.T) {

	ahn := abstract.HostNetworking{
		IsGateway:               false,
		DefaultGatewayID:        "HostNetworking DefaultGatewayID",
		DefaultGatewayPrivateIP: "HostNetworking DefaultGatewayPrivateIP",
		DefaultSubnetID:         "HostNetworking DefaultSubnetID",
		SubnetsByID:             map[string]string{"ID1": "Subnet1", "ID2": "Subnet2", "ID3": "Subnet3"},
		SubnetsByName:           map[string]string{"Name1": "Subnet1", "Name2": "Subnet2", "Name3": "Subnet3"},
		PublicIPv4:              "HostNetworking PublicIPv4",
		PublicIPv6:              "HostNetworking PublicIPv6",
		IPv4Addresses:           map[string]string{"ID1": "ipv4_1", "ID2": "ipv4_2"},
		IPv6Addresses:           map[string]string{"ID1": "ipv6_1", "ID2": "ipv6_2"},
	}

	phn := HostNetworkingFromAbstractToPropertyV2(ahn)

	require.EqualValues(t, ahn.IsGateway, phn.IsGateway)
	require.EqualValues(t, ahn.DefaultSubnetID, phn.DefaultSubnetID)
	require.EqualValues(t, ahn.SubnetsByID, phn.SubnetsByID)
	require.EqualValues(t, ahn.SubnetsByName, phn.SubnetsByName)
	require.EqualValues(t, ahn.PublicIPv4, phn.PublicIPv4)
	require.EqualValues(t, ahn.PublicIPv6, phn.PublicIPv6)
	require.EqualValues(t, ahn.IPv4Addresses, phn.IPv4Addresses)
	require.EqualValues(t, ahn.IPv6Addresses, phn.IPv6Addresses)

}

func Test_HostStateFromAbstractToProtocol(t *testing.T) {

	var list []hoststate.Enum = []hoststate.Enum{
		hoststate.Any,
		hoststate.Deleted,
		hoststate.Failed,
		hoststate.Started,
		hoststate.Starting,
		hoststate.Stopped,
		hoststate.Stopping,
		hoststate.Terminated,
		hoststate.Error,
		hoststate.Unknown,
	}
	var p protocol.HostState
	var q protocol.HostState

	for _, value := range list {
		p = HostStateFromAbstractToProtocol(value)
		q = protocol.HostState(value)
		require.EqualValues(t, p, q)
	}

}

func Test_BucketListFromAbstractToProtocol(t *testing.T) {

	in := []string{"A", "B", "C"}
	blr := BucketListFromAbstractToProtocol(in)
	for i := range blr.Buckets {
		require.EqualValues(t, blr.Buckets[i].Name, in[i])
	}

}

func Test_SSHConfigFromAbstractToProtocol(t *testing.T) {

	gwConf, xerr := ssh.NewConfig("Config GW Hostname", "Config GW Hostname", 42, "Config GW Hostname", "Config GW Hostname")
	require.NotNil(t, gwConf)
	require.Nil(t, xerr)
	xerr = gwConf.SetLocalPort(43)
	require.Nil(t, xerr)

	gw2Conf, xerr := ssh.NewConfig("Config GW2 Hostname", "Config GW2 Hostname", 0, "Config GW2 Hostname", "Config GW2 Hostname")
	require.NotNil(t, gwConf)
	require.Nil(t, xerr)
	xerr = gwConf.SetLocalPort(45)
	require.Nil(t, xerr)

	hostConf, xerr := ssh.NewConfig("Config Hostname", "Config Hostname", 46, "Config Hostname", "Config Hostname", gwConf, gw2Conf)
	require.NotNil(t, gwConf)
	require.Nil(t, xerr)
	xerr = gwConf.SetLocalPort(47)
	require.Nil(t, xerr)

	pgwcfg, xerr := SSHConfigFromAbstractToProtocol(gwConf)
	require.Nil(t, xerr)
	require.EqualValues(t, gwConf.Hostname(), pgwcfg.HostName)
	require.EqualValues(t, gwConf.User(), pgwcfg.User)
	require.EqualValues(t, gwConf.IPAddress(), pgwcfg.Host)
	require.EqualValues(t, gwConf.Port(), pgwcfg.Port)
	require.EqualValues(t, gwConf.PrivateKey(), pgwcfg.PrivateKey)

	pgw2cfg, xerr := SSHConfigFromAbstractToProtocol(gw2Conf)
	require.Nil(t, xerr)
	require.EqualValues(t, gw2Conf.Hostname(), pgw2cfg.HostName)
	require.EqualValues(t, gw2Conf.User(), pgw2cfg.User)
	require.EqualValues(t, gw2Conf.IPAddress(), pgw2cfg.Host)
	require.EqualValues(t, gw2Conf.Port(), pgw2cfg.Port)
	require.EqualValues(t, gw2Conf.PrivateKey(), pgw2cfg.PrivateKey)

	phostcfg, xerr := SSHConfigFromAbstractToProtocol(hostConf)
	require.Nil(t, xerr)
	require.EqualValues(t, hostConf.Hostname(), phostcfg.HostName)
	require.EqualValues(t, hostConf.User(), phostcfg.User)
	require.EqualValues(t, hostConf.IPAddress(), phostcfg.Host)
	require.EqualValues(t, hostConf.Port(), phostcfg.Port)
	require.EqualValues(t, hostConf.PrivateKey(), phostcfg.PrivateKey)

	gwConf, xerr = hostConf.GatewayConfig(sshapi.PrimaryGateway)
	require.Nil(t, xerr)
	require.NotNil(t, gwConf)
	pgwcfg, xerr = SSHConfigFromAbstractToProtocol(gwConf)
	require.Nil(t, xerr)
	require.NotNil(t, pgwcfg)
	require.EqualValues(t, pgwcfg, phostcfg.Gateway)

	gw2Conf, xerr = hostConf.GatewayConfig(sshapi.SecondaryGateway)
	require.Nil(t, xerr)
	require.NotNil(t, gw2Conf)
	pgw2cfg, xerr = SSHConfigFromAbstractToProtocol(gw2Conf)
	require.Nil(t, xerr)
	require.NotNil(t, pgw2cfg)
	require.EqualValues(t, pgw2cfg, phostcfg.SecondaryGateway)
}

func Test_HostStatusFromAbstractToProtocol(t *testing.T) {

	var Name string = "HostName"
	var Status hoststate.Enum = hoststate.Any

	phs := HostStatusFromAbstractToProtocol(Name, Status)
	require.EqualValues(t, phs.Name, Name)
	require.EqualValues(t, phs.Status, Status)

}

func Test_VolumeSpeedFromAbstractToProtocol(t *testing.T) {
	in := []volumespeed.Enum{
		volumespeed.Cold,
		volumespeed.Ssd,
		volumespeed.Hdd,
	}
	expect := []protocol.VolumeSpeed{
		protocol.VolumeSpeed_VS_COLD,
		protocol.VolumeSpeed_VS_SSD,
		protocol.VolumeSpeed_VS_HDD,
	}
	for i := range in {
		require.EqualValues(t, VolumeSpeedFromAbstractToProtocol(in[i]), expect[i])
	}
}

func Test_ClusterIdentityFromAbstractToProtocol(t *testing.T) {

	kpName := "cluster_cladm_key"
	kp, innerXErr := abstract.NewKeyPair(kpName)
	if innerXErr != nil {
		t.Error(innerXErr)
		t.Fail()
	}
	aci := abstract.ClusterIdentity{
		Name:          "ClusterIdentity Name",
		Flavor:        clusterflavor.K8S,
		Complexity:    clustercomplexity.Small,
		Keypair:       kp,
		AdminPassword: "Password",
		Tags: map[string]string{
			"CreationDate": time.Now().Format(time.RFC3339),
			"ManagedBy":    "safescale",
		},
	}
	pclr := ClusterListFromAbstractToProtocol([]abstract.ClusterIdentity{aci})

	require.EqualValues(t, pclr.Clusters[0].Identity, ClusterIdentityFromAbstractToProtocol(aci))
}

func Test_SecurityGroupRulesFromAbstractToProtocol(t *testing.T) {

	asg := abstract.SecurityGroup{
		ID:          "SecurityGroup ID",
		Name:        "SecurityGroup Name",
		Network:     "SecurityGroup Network",
		Description: "SecurityGroup Description",
		Rules: abstract.SecurityGroupRules{
			{
				IDs:         []string{"ID1", "ID2", "ID3"},
				Description: "SecurityGroupRune Description",
				EtherType:   ipversion.IPv4,
				Direction:   securitygroupruledirection.Ingress,
				Protocol:    "tcp",
				PortFrom:    42,
				PortTo:      43,
				Sources:     []string{"Source1", "Source2", "Source3"},
				Targets:     []string{"Target1", "Target2", "Target3"},
			},
		},
		DefaultForSubnet: "SecurityGroup DefaultForSubnet",
		DefaultForHost:   "SecurityGroup DefaultForHost",
	}

	psgr := SecurityGroupFromAbstractToProtocol(asg)

	require.EqualValues(t, asg.ID, psgr.Id)
	require.EqualValues(t, asg.Name, psgr.Name)
	require.EqualValues(t, asg.Description, psgr.Description)
	require.EqualValues(t, SecurityGroupRulesFromAbstractToProtocol(asg.Rules), psgr.Rules)

	asg = abstract.SecurityGroup{
		ID:          "SecurityGroup ID",
		Name:        "SecurityGroup Name",
		Network:     "SecurityGroup Network",
		Description: "SecurityGroup Description",
		Rules: abstract.SecurityGroupRules{
			{
				IDs:         []string{"ID1", "ID2", "ID3"},
				Description: "SecurityGroupRune Description",
				EtherType:   ipversion.IPv4,
				Direction:   securitygroupruledirection.Egress,
				Protocol:    "tcp",
				PortFrom:    42,
				PortTo:      43,
				Sources:     []string{"Source1", "Source2", "Source3"},
				Targets:     []string{"Target1", "Target2", "Target3"},
			},
		},
		DefaultForSubnet: "SecurityGroup DefaultForSubnet",
		DefaultForHost:   "SecurityGroup DefaultForHost",
	}

	psgr = SecurityGroupFromAbstractToProtocol(asg)

	require.EqualValues(t, asg.ID, psgr.Id)
	require.EqualValues(t, asg.Name, psgr.Name)
	require.EqualValues(t, asg.Description, psgr.Description)
	require.EqualValues(t, SecurityGroupRulesFromAbstractToProtocol(asg.Rules), psgr.Rules)

}

func Test_ClusterStateFromAbstractToProtocol(t *testing.T) {

	csr := ClusterStateFromAbstractToProtocol(clusterstate.Initializing)
	if reflect.TypeOf(csr).String() != "*protocol.ClusterStateResponse" {
		t.Error("Expect type *protocol.ClusterStateResponse")
		t.Fail()
	}

}
