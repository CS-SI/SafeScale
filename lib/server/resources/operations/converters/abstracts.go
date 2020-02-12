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

package converters

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
)

// Contains the function used to convert from abstracts structures

// HostTemplateToHostEffectiveSizing converts an abstracts.HostTemplate to an abstracts.HostEffectiveSizing
func HostTemplateToHostEffectiveSizing(ht *abstracts.HostTemplate) *abstracts.HostEffectiveSizing {
	hes := abstracts.NewHostEffectiveSizing()
	hes.Cores = ht.Cores
	hes.RAMSize = ht.RAMSize
	hes.DiskSize = ht.DiskSize
	hes.GPUNumber = ht.GPUNumber
	hes.CPUFreq = ht.CPUFreq
	return hes
}

// ToProtocolVolume converts an api.Volume to a *Volume
func VolumeFromAbstractsToProtocol(in *abstracts.Volume) *protocol.Volume {
	return &protocol.Volume{
		Id:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: protocol.VolumeSpeed(in.Speed),
	}
}

// VolumeAttachmentFromAbstractsToProtocol ...
func VolumeAttachmentFromAbstractsToProtocol(in *abstracts.VolumeAttachment) *protocol.VolumeAttachment {
	return &protocol.VolumeAttachment{
		Volume:    &protocol.Reference{Id: in.VolumeID},
		Host:      &protocol.Reference{Id: in.ServerID},
		MountPath: in.MountPoint,
		Device:    in.Device,
	}
}

// ToProtocolVolumeInfo converts an api.Volume to a *VolumeInfo
func VolumeInfoFromAbstractsToProtocol(volume *abstracts.Volume, mounts map[string]*propertiesv1.HostLocalMount) *protocol.VolumeInfo {
	pbvi := &protocol.VolumeInfo{
		Id:    volume.ID,
		Name:  volume.Name,
		Size:  int32(volume.Size),
		Speed: protocol.VolumeSpeed(volume.Speed),
	}
	if len(mounts) > 0 {
		for k, mount := range mounts {
			pbvi.Host = &protocol.Reference{Name: k}
			pbvi.MountPath = mount.Path
			pbvi.Device = mount.Device
			pbvi.Format = mount.FileSystem

			break
		}
	}
	return pbvi
}

// ToProtocolHostDefinition ...
func HostEffectiveSizingFromAbstractsToProtocol(in *abstracts.HostEffectiveSizing) *protocol.HostDefinition {
	return &protocol.HostDefinition{
		ImageId: in.ImageID,
		Sizing: &protocol.HostSizing{
			MinCpuCount: int32(in.Cores),
			MaxCpuCount: int32(in.Cores),
			MinRamSize:  in.RAMSize,
			MaxRamSize:  in.RAMSize,
			MinDiskSize: int32(in.DiskSize),
			GpuCount:    int32(in.GPUNumber),
			MinCpuFreq:  in.CPUFreq,
		},
	}
}

// GatewayDefinitionFromAbstractsToProtocol ...
func GatewayDefinitionFromAbstractsToProtocol(in *abstracts.HostEffectiveSizing) *protocol.GatewayDefinition {
	return &protocol.GatewayDefinition{
		Cpu:      int32(in.Cores),
		Ram:      in.RAMSize,
		Disk:     int32(in.DiskSize),
		ImageId:  in.ImageID,
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}
}

// HostStatusFromAbstractsToProtocol ...
func HostStatusFromAbstractsToProtocol(in *abstracts.HostCore) *protocol.HostStatus {
	return &protocol.HostStatus{
		Name:   in.Name,
		Status: protocol.HostState(in.LastState).String(),
	}
}

// HostTemplateFromAbstractsToProtocol ...
func HostTemplateFromAbstractsToProtocol(in *abstracts.HostTemplate) *protocol.HostTemplate {
	return &protocol.HostTemplate{
		Id:       in.ID,
		Name:     in.Name,
		Cores:    int32(in.Cores),
		Ram:      int32(in.RAMSize),
		Disk:     int32(in.DiskSize),
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}
}

// ImageFromAbstractsToProtocol ...
func ImageFromAbstractsToProtocol(in *abstracts.Image) *protocol.Image {
	return &protocol.Image{
		Id:   in.ID,
		Name: in.Name,
	}
}

// NetworkFromAbstractsToProtocol ...
func NetworkFromAbstractsToProtocol(in *abstracts.Network) *protocol.Network {
	var pbVIP protocol.VirtualIp
	if in.VIP != nil {
		pbVIP = VirtualIPFromAbstractsToProtocol(*in.VIP)
	}
	return &protocol.Network{
		Id:                 in.ID,
		Name:               in.Name,
		Cidr:               in.CIDR,
		GatewayId:          in.GatewayID,
		SecondaryGatewayId: in.SecondaryGatewayID,
		VirtualIp:          &pbVIP,
		Failover:           in.SecondaryGatewayID != "",
		State:              protocol.NetworkState(in.NetworkState),
	}
}

// HostSizingRequirementsFromAbstractsToProtocol converts a protobuf HostSizing message to abstracts.HostSizingRequirements
func HostSizingRequirementsFromAbstractsToProtocol(src abstracts.HostSizingRequirements) protocol.HostSizing {
	return protocol.HostSizing{
		MinCpuCount: int32(src.MinCores),
		MaxCpuCount: int32(src.MaxCores),
		MinCpuFreq:  src.MinCPUFreq,
		GpuCount:    int32(src.MinGPU),
		MinRamSize:  src.MinRAMSize,
		MaxRamSize:  src.MaxRAMSize,
		MinDiskSize: int32(src.MinDiskSize),
	}
}

// VirtualIPFromAbstractsToProtocol converts a *abstracts.VirtualIP to a protocol.VirtualIp
func VirtualIPFromAbstractsToProtocol(in abstracts.VirtualIP) protocol.VirtualIp {
	out := protocol.VirtualIp{
		Id:        in.ID,
		NetworkId: in.NetworkID,
		PrivateIp: in.PrivateIP,
		PublicIp:  in.PublicIP,
	}
	out.Hosts = make([]*protocol.Host, len(in.Hosts))
	for _, i := range in.Hosts {
		out.Hosts = append(out.Hosts, HostCoreFromAbstractsToProtocol(i))
	}
	return out
}

// HostEffectiveSizingFromAbstractsToProperty ...
func HostEffectiveSizingFromAbstractsToProperty(ahes *abstracts.HostEffectiveSizing) *propertiesv1.HostEffectiveSizing {
	phes := propertiesv1.NewHostEffectiveSizing()
	phes.Cores = ahes.Cores
	phes.RAMSize = ahes.RAMSize
	phes.DiskSize = ahes.DiskSize
	phes.GPUNumber = ahes.GPUNumber
	phes.CPUFreq = ahes.CPUFreq
	return phes
}

// HostCoreFromAbstractsToProtocol ...
func HostCoreFromAbstractsToProtocol(in *abstracts.HostCore) *protocol.Host {
	ph := &protocol.Host{
		Id:         in.ID,
		Name:       in.Name,
		State:      HostStateFromAbstractsToProtocol(in.LastState),
		PrivateKey: in.PrivateKey,
	}
	return ph
}

// HostFullFromAbstractsToProtocol ...
func HostFullFromAbstractsToProtocol(in *abstracts.HostFull) *protocol.Host {
	ph := &protocol.Host{
		Id:         in.Core.ID,
		Name:       in.Core.Name,
		PublicIp:   in.Network.PublicIPv4,
		PrivateIp:  in.Network.IPv4Addresses[in.Network.DefaultNetworkID],
		State:      HostStateFromAbstractsToProtocol(in.Core.LastState),
		PrivateKey: in.Core.PrivateKey,
		GatewayId:  in.Network.DefaultGatewayID,
	}
	return ph
}
