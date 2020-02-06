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

package payloads

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
)

// ToProtocolSSHConfig converts a system.SSHConfig into a SshConfig
func ToProtocolSSHConfig(from *system.SSHConfig) *protocol.SshConfig {
	var gw *protocol.SshConfig
	if from.GatewayConfig != nil {
		gw = ToProtocolSSHConfig(from.GatewayConfig)
	}
	return &protocol.SshConfig{
		Gateway:    gw,
		Host:       from.Host,
		Port:       int32(from.Port),
		PrivateKey: from.PrivateKey,
		User:       from.User,
	}
}

// ToSystemSSHConfig converts a protocol.SshConfig into a system.SSHConfig
func ToSystemSSHConfig(from *protocol.SshConfig) *system.SSHConfig {
	var gw *system.SSHConfig
	if from.Gateway != nil {
		gw = ToSystemSSHConfig(from.Gateway)
	}
	return &system.SSHConfig{
		User:          from.User,
		Host:          from.Host,
		PrivateKey:    from.PrivateKey,
		Port:          int(from.Port),
		GatewayConfig: gw,
	}
}

// ToProtocolVolume converts an api.Volume to a *Volume
func ToProtocolVolume(in *abstracts.Volume) *protocol.Volume {
	return &protocol.Volume{
		Id:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: protocol.VolumeSpeed(in.Speed),
	}
}

// ToProtocolVolumeAttachment converts an api.Volume to a *Volume
func ToProtocolVolumeAttachment(in *abstracts.VolumeAttachment) *protocol.VolumeAttachment {
	return &protocol.VolumeAttachment{
		Volume:    &protocol.Reference{Id: in.VolumeID},
		Host:      &protocol.Reference{Id: in.ServerID},
		MountPath: in.MountPoint,
		Device:    in.Device,
	}
}

// ToProtocolVolumeInfo converts an api.Volume to a *VolumeInfo
func ToProtocolVolumeInfo(volume *abstracts.Volume, mounts map[string]*propertiesv1.HostLocalMount) *protocol.VolumeInfo {
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

// ToProtocolBucketList convert a list of string into a *ContainerLsit
func ToProtocolBucketList(in []string) *protocol.BucketList {
	var buckets []*protocol.Bucket
	for _, name := range in {
		buckets = append(buckets, &protocol.Bucket{Name: name})
	}
	return &protocol.BucketList{
		Buckets: buckets,
	}
}

// ToProtocolBucketMountPoint convert a Bucket into a BucketMountingPoint
func ToProtocolBucketMountPoint(in *abstracts.Bucket) *protocol.BucketMountingPoint {
	return &protocol.BucketMountingPoint{
		Bucket: in.Name,
		Path:   in.MountPoint,
		Host:   &protocol.Reference{Name: in.Host},
	}
}

// ToProtocolShare convert a share from model to protocolbuffer format
func ToProtocolShare(hostName string, share *propertiesv1.HostShare) *protocol.ShareDefinition {
	return &protocol.ShareDefinition{
		Id:   share.ID,
		Name: share.Name,
		Host: &protocol.Reference{Name: hostName},
		Path: share.Path,
		Type: "nfs",
	}
}

// ToProtocolShareMount convert share mount on host to protocolbuffer format
func ToProtocolShareMount(shareName string, hostName string, mount *propertiesv1.HostRemoteMount) *protocol.ShareMountDefinition {
	return &protocol.ShareMountDefinition{
		Share: &protocol.Reference{Name: shareName},
		Host:  &protocol.Reference{Name: hostName},
		Path:  mount.Path,
		Type:  mount.FileSystem,
	}
}

// ToProtocolShareMountList converts share mounts to protocol buffer
func ToProtocolShareMountList(hostName string, share *propertiesv1.HostShare, mounts map[string]*propertiesv1.HostRemoteMount) *protocol.ShareMountList {
	var pbMounts []*protocol.ShareMountDefinition
	for k, v := range mounts {
		pbMounts = append(pbMounts, &protocol.ShareMountDefinition{
			Host:  &protocol.Reference{Name: k},
			Share: &protocol.Reference{Name: share.Name},
			Path:  v.Path,
			Type:  "nfs",
		})
	}
	return &protocol.ShareMountList{
		Share:     ToProtocolShare(hostName, share),
		MountList: pbMounts,
	}
}

// ToProtocolHostDefinition ...
func ToProtocolHostDefinition(in *abstracts.HostDefinition) *protocol.HostDefinition {
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

// ToProtocolGatewayDefinition converts a abstracts.HostDefinition tp .GatewayDefinition
func ToProtocolGatewayDefinition(in *abstracts.HostDefinition) *protocol.GatewayDefinition {
	return &protocol.GatewayDefinition{
		Cpu:      int32(in.Cores),
		Ram:      in.RAMSize,
		Disk:     int32(in.DiskSize),
		ImageId:  in.ImageID,
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}
}

// FromProtocolHostDefinitionToProtocolGatewayDefinition converts a protocol.HostDefinition to protocol.GatewayDefinition
func FromProtocolHostDefinitionToProtocolGatewayDefinition(in protocol.HostDefinition) protocol.GatewayDefinition {
	def := protocol.GatewayDefinition{
		ImageId:  in.ImageId,
		Cpu:      in.CpuCount,
		Ram:      in.Ram,
		Disk:     in.Disk,
		GpuCount: in.GpuCount,
		Sizing:   &protocol.HostSizing{},
	}
	*def.Sizing = *in.Sizing
	return def
}

// ToProtocolHostStatus ...
func ToProtocolHostStatus(in *abstracts.Host) *protocol.HostStatus {
	return &protocol.HostStatus{
		Name:   in.Name,
		Status: protocol.HostState(in.LastState).String(),
	}
}

// ToProtocolHostTemplate convert an template from api to protocolbuffer format
func ToProtocolHostTemplate(in *abstracts.HostTemplate) *protocol.HostTemplate {
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

// ToProtocolImage convert an image from api to protocolbuffer format
func ToProtocolImage(in *abstracts.Image) *protocol.Image {
	return &protocol.Image{
		Id:   in.ID,
		Name: in.Name,
	}
}

// ToProtocolNetwork convert a network from api to protocolbuffer format
func ToProtocolNetwork(in *abstracts.Network) *protocol.Network {
	var pbVIP protocol.VirtualIp
	if in.VIP != nil {
		pbVIP = ToProtocolVirtualIP(*in.VIP)
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

// VPL: data stuff disabled
// // ToProtocolFileList convert a list of file names from api to protocolbuffer FileList format
// func ToProtocolFileList(fileNames []string, uploadDates []string, fileSizes []int64, fileBuckets [][]string) *protocol.FileList {
// 	files := []*protocol.File{}
// 	nbFiles := int(math.Min(math.Min(math.Min(float64(len(fileNames)), float64(len(uploadDates))), float64(len(fileSizes))), float64(len(fileBuckets))))
// 	for i := 0; i < nbFiles; i++ {
// 		files = append(files, &protocol.File{Name: fileNames[i], Date: uploadDates[i], Size: fileSizes[i], Buckets: fileBuckets[i]})
// 	}
// 	return &protocol.FileList{Files: files}
// }

// ToProtocolHostSizing converts a protobuf HostSizing message to abstracts.SizingRequirements
func ToProtocolHostSizing(src abstracts.SizingRequirements) protocol.HostSizing {
	return protocol.HostSizing{
		MinCpuCount: int32(src.MinCores),
		MaxCpuCount: int32(src.MaxCores),
		MinCpuFreq:  src.MinFreq,
		GpuCount:    int32(src.MinGPU),
		MinRamSize:  src.MinRAMSize,
		MaxRamSize:  src.MaxRAMSize,
		MinDiskSize: int32(src.MinDiskSize),
	}
}

// FromProtocolHostSizing converts a protobuf HostSizing message to abstracts.SizingRequirements
func FromProtocolHostSizing(src protocol.HostSizing) abstracts.SizingRequirements {
	return abstracts.SizingRequirements{
		MinCores:    int(src.MinCpuCount),
		MaxCores:    int(src.MaxCpuCount),
		MinFreq:     src.MinCpuFreq,
		MinGPU:      int(src.GpuCount),
		MinRAMSize:  src.MinRamSize,
		MaxRAMSize:  src.MaxRamSize,
		MinDiskSize: int(src.MinDiskSize),
	}
}

// ToProtocolVirtualIP converts a *anstracts.VIP to a protocol.VirtualIp
func ToProtocolVirtualIP(in abstracts.VIP) protocol.VirtualIp {
	out := protocol.VirtualIp{
		Id:        in.ID,
		NetworkId: in.NetworkID,
		PrivateIp: in.PrivateIP,
		PublicIp:  in.PublicIP,
	}
	out.Hosts = make([]*protocol.Host, len(in.Hosts))
	for _, i := range in.Hosts {
		out.Hosts = append(out.Hosts, ToProtocolHost(i))
	}
	return out
}

// HostTemplateToHostSizeProperty ...
func HostTemplateToHostSizeProperty(ht *abstracts.HostTemplate) *propertiesv1.HostSize {
	hs := propertiesv1.NewHostSize()
	hs.Cores = ht.Cores
	hs.RAMSize = ht.RAMSize
	hs.DiskSize = ht.DiskSize
	hs.GPUNumber = ht.GPUNumber
	hs.CPUFreq = ht.CPUFreq
	return hs
}

// HostDefinitionToHostSizeProperty ...
func HostDefinitionToHostSizeProperty(hd *abstracts.HostDefinition) *propertiesv1.HostSize {
	hs := propertiesv1.NewHostSize()
	hs.Cores = hd.Cores
	hs.RAMSize = hd.RAMSize
	hs.DiskSize = hd.DiskSize
	hs.GPUNumber = hd.GPUNumber
	hs.CPUFreq = hd.CPUFreq
	return hs
}
