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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
)

// Contains the function used to convert from abstract structures

// HostTemplateToHostEffectiveSizing converts an abstract.HostTemplate to an abstract.HostEffectiveSizing
func HostTemplateToHostEffectiveSizing(ht *abstract.HostTemplate) *abstract.HostEffectiveSizing {
	hes := abstract.NewHostEffectiveSizing()
	hes.Cores = ht.Cores
	hes.RAMSize = ht.RAMSize
	hes.DiskSize = ht.DiskSize
	hes.GPUNumber = ht.GPUNumber
	hes.CPUFreq = ht.CPUFreq
	return hes
}

// VolumeFromAbstractToProtocol converts an api.Volume to a *Volume
func VolumeFromAbstractToProtocol(in *abstract.Volume) *protocol.Volume {
	return &protocol.Volume{
		Id:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: protocol.VolumeSpeed(in.Speed),
	}
}

// VolumeAttachmentFromAbstractToProtocol ...
func VolumeAttachmentFromAbstractToProtocol(in *abstract.VolumeAttachment) *protocol.VolumeAttachment {
	return &protocol.VolumeAttachment{
		Volume:    &protocol.Reference{Id: in.VolumeID},
		Host:      &protocol.Reference{Id: in.ServerID},
		MountPath: in.MountPoint,
		Device:    in.Device,
	}
}

// VolumeInfoFromAbstractToProtocol converts an api.Volume to a *VolumeInfo
func VolumeInfoFromAbstractToProtocol(volume *abstract.Volume, mounts map[string]*propertiesv1.HostLocalMount) *protocol.VolumeInfo {
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

// HostEffectiveSizingFromAbstractToProtocol ...
func HostEffectiveSizingFromAbstractToProtocol(in *abstract.HostEffectiveSizing) *protocol.HostDefinition {
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

// GatewayDefinitionFromAbstractToProtocol ...
func GatewayDefinitionFromAbstractsToProtocol(in *abstract.HostEffectiveSizing) *protocol.GatewayDefinition {
	return &protocol.GatewayDefinition{
		Cpu:      int32(in.Cores),
		Ram:      in.RAMSize,
		Disk:     int32(in.DiskSize),
		ImageId:  in.ImageID,
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}
}

// HostStatusFromAbstractToProtocol ...
func HostStatusFromAbstractsToProtocol(in *abstract.HostCore) *protocol.HostStatus {
	return &protocol.HostStatus{
		Name:   in.Name,
		Status: protocol.HostState(in.LastState).String(),
	}
}

// HostTemplateFromAbstractToProtocol ...
func HostTemplateFromAbstractToProtocol(in *abstract.HostTemplate) *protocol.HostTemplate {
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

// ImageFromAbstractToProtocol ...
func ImageFromAbstractToProtocol(in *abstract.Image) *protocol.Image {
	return &protocol.Image{
		Id:   in.ID,
		Name: in.Name,
	}
}

// NetworkFromAbstractToProtocol ...
func NetworkFromAbstractToProtocol(in *abstract.Network) *protocol.Network {
	var pbVIP protocol.VirtualIp
	if in.VIP != nil {
		pbVIP = VirtualIPFromAbstractToProtocol(*in.VIP)
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

// HostSizingRequirementsFromAbstractToProtocol converts a protobuf HostSizing message to abstract.HostSizingRequirements
func HostSizingRequirementsFromAbstractToProtocol(src abstract.HostSizingRequirements) protocol.HostSizing {
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

// HostSizingRequirementsFromAbstractToPropertyV2 ...
func HostSizingRequirementsFromAbstractToPropertyV2(src abstract.HostSizingRequirements) *propertiesv2.HostSizingRequirements {
	return &propertiesv2.HostSizingRequirements{
		MinCores:    src.MinCores,
		MaxCores:    src.MaxCores,
		MinRAMSize:  src.MinRAMSize,
		MaxRAMSize:  src.MaxRAMSize,
		MinDiskSize: src.MinDiskSize,
		MinGPU:      src.MinGPU,
		MinCPUFreq:  src.MinCPUFreq,
		Replaceable: src.Replaceable,
	}
}

// VirtualIPFromAbstractToProtocol converts a *abstract.VirtualIP to a protocol.VirtualIp
func VirtualIPFromAbstractToProtocol(in abstract.VirtualIP) protocol.VirtualIp {
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

// HostEffectiveSizingFromAbstractToPropertyV2 ...
func HostEffectiveSizingFromAbstractToPropertyV2(ahes *abstract.HostEffectiveSizing) *propertiesv2.HostEffectiveSizing {
	phes := propertiesv2.NewHostEffectiveSizing()
	phes.Cores = ahes.Cores
	phes.RAMSize = ahes.RAMSize
	phes.DiskSize = ahes.DiskSize
	phes.GPUNumber = ahes.GPUNumber
	phes.CPUFreq = ahes.CPUFreq
	return phes
}

// HostCoreFromAbstractToProtocol ...
func HostCoreFromAbstractsToProtocol(in *abstract.HostCore) *protocol.Host {
	ph := &protocol.Host{
		Id:         in.ID,
		Name:       in.Name,
		State:      HostStateFromAbstractsToProtocol(in.LastState),
		PrivateKey: in.PrivateKey,
	}
	return ph
}

// HostFullFromAbstractsToProtocol ...
func HostFullFromAbstractsToProtocol(in *abstract.HostFull) *protocol.Host {
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

// HostCoreToHostFull ...
func HostCoreToHostFull(in abstract.HostCore) *abstract.HostFull {
	return &abstract.HostFull{Core: in}
}

// HostDescriptionFromAbstractToProperty
func HostDescriptionFromAbstractToPropertyV1(src abstract.HostDescription) *propertiesv1.HostDescription {
	return &propertiesv1.HostDescription{
		Created: src.Created,
		Creator: src.Creator,
		Updated: src.Updated,
		Purpose: src.Purpose,
		Tenant:  src.Tenant,
	}
}

// HostNetworkFromAbstractToPropertyV1
func HostNetworkFromAbstractToPropertyV1(src abstract.HostNetwork) *propertiesv1.HostNetwork {
	return &propertiesv1.HostNetwork{
		IsGateway:               src.IsGateway,
		DefaultGatewayID:        src.DefaultGatewayID,
		DefaultGatewayPrivateIP: src.DefaultGatewayPrivateIP,
		DefaultNetworkID:        src.DefaultNetworkID,
		NetworksByID:            src.NetworksByID,
		NetworksByName:          src.NetworksByName,
		PublicIPv4:              src.PublicIPv4,
		PublicIPv6:              src.PublicIPv6,
		IPv4Addresses:           src.IPv4Addresses,
		IPv6Addresses:           src.IPv6Addresses,
	}
}
