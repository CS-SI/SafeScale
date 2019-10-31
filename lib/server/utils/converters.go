/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package utils

import (
	"github.com/sirupsen/logrus"
	"math"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostProperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
)

// ToPBSshConfig converts a system.SSHConfig into a SshConfig
func ToPBSshConfig(from *system.SSHConfig) *pb.SshConfig {
	var gw *pb.SshConfig
	if from.GatewayConfig != nil {
		gw = ToPBSshConfig(from.GatewayConfig)
	}
	return &pb.SshConfig{
		Gateway:    gw,
		Host:       from.Host,
		Port:       int32(from.Port),
		PrivateKey: from.PrivateKey,
		User:       from.User,
	}
}

// ToSystemSSHConfig converts a pb.SshConfig into a system.SSHConfig
func ToSystemSSHConfig(from *pb.SshConfig) *system.SSHConfig {
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

// ToPBVolume converts an api.Volume to a *Volume
func ToPBVolume(in *resources.Volume) *pb.Volume {
	return &pb.Volume{
		Id:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: pb.VolumeSpeed(in.Speed),
	}
}

// ToPBVolumeAttachment converts an api.Volume to a *Volume
func ToPBVolumeAttachment(in *resources.VolumeAttachment) *pb.VolumeAttachment {
	return &pb.VolumeAttachment{
		Volume:    &pb.Reference{Id: in.VolumeID},
		Host:      &pb.Reference{Id: in.ServerID},
		MountPath: in.MountPoint,
		Device:    in.Device,
	}
}

// ToPBVolumeInfo converts an api.Volume to a *VolumeInfo
func ToPBVolumeInfo(volume *resources.Volume, mounts map[string]*propsv1.HostLocalMount) *pb.VolumeInfo {
	pbvi := &pb.VolumeInfo{
		Id:    volume.ID,
		Name:  volume.Name,
		Size:  int32(volume.Size),
		Speed: pb.VolumeSpeed(volume.Speed),
	}
	if len(mounts) > 0 {
		for k, mount := range mounts {
			pbvi.Host = &pb.Reference{Name: k}
			pbvi.MountPath = mount.Path
			pbvi.Device = mount.Device
			pbvi.Format = mount.FileSystem

			break
		}
	}
	return pbvi
}

// ToPBBucketList convert a list of string into a *ContainerLsit
func ToPBBucketList(in []string) *pb.BucketList {
	var buckets []*pb.Bucket
	for _, name := range in {
		buckets = append(buckets, &pb.Bucket{Name: name})
	}
	return &pb.BucketList{
		Buckets: buckets,
	}
}

// ToPBBucketMountPoint convert a Bucket into a BucketMountingPoint
func ToPBBucketMountPoint(in *resources.Bucket) *pb.BucketMountingPoint {
	return &pb.BucketMountingPoint{
		Bucket: in.Name,
		Path:   in.MountPoint,
		Host:   &pb.Reference{Name: in.Host},
	}
}

// ToPBShare convert a share from model to protocolbuffer format
func ToPBShare(hostName string, share *propsv1.HostShare) *pb.ShareDefinition {
	return &pb.ShareDefinition{
		Id:   share.ID,
		Name: share.Name,
		Host: &pb.Reference{Name: hostName},
		Path: share.Path,
		Type: "nfs",
	}
}

// ToPBShareMount convert share mount on host to protocolbuffer format
func ToPBShareMount(shareName string, hostName string, mount *propsv1.HostRemoteMount) *pb.ShareMountDefinition {
	return &pb.ShareMountDefinition{
		Share: &pb.Reference{Name: shareName},
		Host:  &pb.Reference{Name: hostName},
		Path:  mount.Path,
		Type:  mount.FileSystem,
	}
}

// ToPBShareMountList converts share mounts to protocol buffer
func ToPBShareMountList(hostName string, share *propsv1.HostShare, mounts map[string]*propsv1.HostRemoteMount) *pb.ShareMountList {
	var pbMounts []*pb.ShareMountDefinition
	for k, v := range mounts {
		pbMounts = append(pbMounts, &pb.ShareMountDefinition{
			Host:  &pb.Reference{Name: k},
			Share: &pb.Reference{Name: share.Name},
			Path:  v.Path,
			Type:  "nfs",
		})
	}
	return &pb.ShareMountList{
		Share:     ToPBShare(hostName, share),
		MountList: pbMounts,
	}
}

// ToPBHost convert an host from api to protocolbuffer format
func ToPBHost(in *resources.Host) (pbHost *pb.Host) {
	var (
		hostNetworkV1 *propsv1.HostNetwork
		hostSizingV1  *propsv1.HostSizing
		hostVolumesV1 *propsv1.HostVolumes
		volumes       []string
	)

	defer func() {
		if x := recover(); x != nil {
			logrus.Warnf("runtime panic occurred: %+v", x)
			pbHost = nil
		}
	}()

	err := in.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 = v.(*propsv1.HostNetwork)
		return in.Properties.LockForRead(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
			hostSizingV1 = v.(*propsv1.HostSizing)
			return in.Properties.LockForRead(HostProperty.VolumesV1).ThenUse(func(v interface{}) error {
				hostVolumesV1 = v.(*propsv1.HostVolumes)
				for k := range hostVolumesV1.VolumesByName {
					volumes = append(volumes, k)
				}
				return nil
			})
		})
	})
	if err != nil {
		return nil
	}
	return &pb.Host{
		Cpu:                 int32(hostSizingV1.AllocatedSize.Cores),
		Disk:                int32(hostSizingV1.AllocatedSize.DiskSize),
		GatewayId:           hostNetworkV1.DefaultGatewayID,
		Id:                  in.ID,
		PublicIp:            in.GetPublicIP(),
		PrivateIp:           in.GetPrivateIP(),
		Name:                in.Name,
		PrivateKey:          in.PrivateKey,
		Password:            in.Password,
		Ram:                 hostSizingV1.AllocatedSize.RAMSize,
		State:               pb.HostState(in.LastState),
		AttachedVolumeNames: volumes,
	}
}

// ToPBHostDefinition ...
func ToPBHostDefinition(in *resources.HostDefinition) *pb.HostDefinition {
	return &pb.HostDefinition{
		ImageId: in.ImageID,
		Sizing: &pb.HostSizing{
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

// ToPBGatewayDefinition converts a resources.HostDefinition tp .GatewayDefinition
func ToPBGatewayDefinition(in *resources.HostDefinition) *pb.GatewayDefinition {
	return &pb.GatewayDefinition{
		Cpu:      int32(in.Cores),
		Ram:      in.RAMSize,
		Disk:     int32(in.DiskSize),
		ImageId:  in.ImageID,
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}
}

// FromPBHostDefinitionToPBGatewayDefinition converts a pb.HostDefinition to pb.GatewayDefinition
func FromPBHostDefinitionToPBGatewayDefinition(in pb.HostDefinition) pb.GatewayDefinition {
	def := pb.GatewayDefinition{
		ImageId:  in.ImageId,
		Cpu:      in.CpuCount,
		Ram:      in.Ram,
		Disk:     in.Disk,
		GpuCount: in.GpuCount,
		Sizing:   &pb.HostSizing{},
	}
	*def.Sizing = *in.Sizing
	return def
}

// ToHostStatus ...
func ToHostStatus(in *resources.Host) *pb.HostStatus {
	return &pb.HostStatus{
		Name:   in.Name,
		Status: pb.HostState(in.LastState).String(),
	}
}

// ToPBHostTemplate convert an template from api to protocolbuffer format
func ToPBHostTemplate(in *resources.HostTemplate) *pb.HostTemplate {
	return &pb.HostTemplate{
		Id:       in.ID,
		Name:     in.Name,
		Cores:    int32(in.Cores),
		Ram:      int32(in.RAMSize),
		Disk:     int32(in.DiskSize),
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}
}

// ToPBImage convert an image from api to protocolbuffer format
func ToPBImage(in *resources.Image) *pb.Image {
	return &pb.Image{
		Id:   in.ID,
		Name: in.Name,
	}
}

// ToPBNetwork convert a network from api to protocolbuffer format
func ToPBNetwork(in *resources.Network) *pb.Network {
	var pbVIP pb.VirtualIp
	if in.VIP != nil {
		pbVIP = ToPBVirtualIP(*in.VIP)
	}
	return &pb.Network{
		Id:                 in.ID,
		Name:               in.Name,
		Cidr:               in.CIDR,
		GatewayId:          in.GatewayID,
		SecondaryGatewayId: in.SecondaryGatewayID,
		VirtualIp:          &pbVIP,
		Failover:           in.SecondaryGatewayID != "",
		State:              pb.NetworkState(in.NetworkState),
	}
}

// ToPBFileList convert a list of file names from api to protocolbuffer FileList format
func ToPBFileList(fileNames []string, uploadDates []string, fileSizes []int64, fileBuckets [][]string) *pb.FileList {
	files := []*pb.File{}
	nbFiles := int(math.Min(math.Min(math.Min(float64(len(fileNames)), float64(len(uploadDates))), float64(len(fileSizes))), float64(len(fileBuckets))))
	for i := 0; i < nbFiles; i++ {
		files = append(files, &pb.File{Name: fileNames[i], Date: uploadDates[i], Size: fileSizes[i], Buckets: fileBuckets[i]})
	}
	return &pb.FileList{Files: files}
}

// ToPBHostSizing converts a protobuf HostSizing message to resources.SizingRequirements
func ToPBHostSizing(src resources.SizingRequirements) pb.HostSizing {
	return pb.HostSizing{
		MinCpuCount: int32(src.MinCores),
		MaxCpuCount: int32(src.MaxCores),
		MinCpuFreq:  src.MinFreq,
		GpuCount:    int32(src.MinGPU),
		MinRamSize:  src.MinRAMSize,
		MaxRamSize:  src.MaxRAMSize,
		MinDiskSize: int32(src.MinDiskSize),
	}
}

// FromPBHostSizing converts a protobuf HostSizing message to resources.SizingRequirements
func FromPBHostSizing(src pb.HostSizing) resources.SizingRequirements {
	return resources.SizingRequirements{
		MinCores:    int(src.MinCpuCount),
		MaxCores:    int(src.MaxCpuCount),
		MinFreq:     src.MinCpuFreq,
		MinGPU:      int(src.GpuCount),
		MinRAMSize:  src.MinRamSize,
		MaxRAMSize:  src.MaxRamSize,
		MinDiskSize: int(src.MinDiskSize),
	}
}

// ToPBVirtualIP converts a resources.VIP to a pb.VirtualIp
func ToPBVirtualIP(src resources.VIP) pb.VirtualIp {
	dest := pb.VirtualIp{
		Id:        src.ID,
		NetworkId: src.NetworkID,
		PrivateIp: src.PrivateIP,
		PublicIp:  src.PublicIP,
		Hosts:     []*pb.Host{},
	}
	for _, i := range src.Hosts {
		dest.Hosts = append(dest.Hosts, ToPBHost(i))
	}
	return dest
}
