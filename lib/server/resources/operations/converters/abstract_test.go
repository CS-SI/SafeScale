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

package converters

import (
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetstate"
	"github.com/stretchr/testify/require"
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

func Test_HostEffectiveSizingFromAbstractToProtocol(t *testing.T) {

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
	ahf.Networking.DefaultSubnetID = "Networking DefaultSubnetID"
	ahf.Networking.SubnetsByID = map[string]string{"ID1": "SubnetID1", "ID2": "SubnetID2"}
	ahf.Networking.SubnetsByName = map[string]string{"Name1": "SubnetID1", "Name2": "SubnetID2"}
	ahf.Networking.PublicIPv4 = "Networking PublicIPv4"
	ahf.Networking.PublicIPv6 = "Networking PublicIPv6"
	ahf.Networking.IPv4Addresses = map[string]string{"ID1": "ipV4_1", "ID2": "ipV4_2"}
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
