/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"math"

	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hostproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ToPBSshConfig converts a system.SSHConfig into a SshConfig
func ToPBSshConfig(from *system.SSHConfig) (gw *pb.SshConfig, err error) {
	if from == nil {
		return nil, fail.InvalidParameterError("from", "cannot be nil")
	}

	if from.GatewayConfig != nil {
		gw, err = ToPBSshConfig(from.GatewayConfig)
		if err != nil {
			return nil, err
		}
	}
	return &pb.SshConfig{
		Gateway:    gw,
		Host:       from.Host,
		Port:       int32(from.Port),
		PrivateKey: from.PrivateKey,
		User:       from.User,
	}, nil
}

// ToSystemSSHConfig converts a pb.SshConfig into a system.SSHConfig
func ToSystemSSHConfig(from *pb.SshConfig) (gw *system.SSHConfig, err error) {
	if from == nil {
		return nil, fail.InvalidParameterError("from", "cannot be nil")
	}
	if from.Host == "" {
		logrus.Error(fail.DecorateWithCallTrace("invalid parameter content:", "from.Host", "cannot be empty string"))
		return nil, fail.InvalidParameterError("from.Host", "cannot be empty")
	}
	if from.Gateway != nil {
		gw, err = ToSystemSSHConfig(from.Gateway)
		if err != nil {
			return nil, err
		}
	}
	return &system.SSHConfig{
		User:          from.User,
		Host:          from.Host,
		PrivateKey:    from.PrivateKey,
		Port:          int(from.Port),
		GatewayConfig: gw,
	}, nil
}

// ToPBVolume converts an api.Volume to a *Volume
func ToPBVolume(in *abstract.Volume) (*pb.Volume, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	return &pb.Volume{
		Id:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: pb.VolumeSpeed(in.Speed),
	}, nil
}

// ToPBVolumeAttachment converts an api.Volume to a *Volume
func ToPBVolumeAttachment(in *abstract.VolumeAttachment) (*pb.VolumeAttachment, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	return &pb.VolumeAttachment{
		Volume:    &pb.Reference{Id: in.VolumeID},
		Host:      &pb.Reference{Id: in.ServerID},
		MountPath: in.MountPoint,
		Device:    in.Device,
	}, nil
}

// ToPBVolumeInfo converts an api.Volume to a *VolumeInfo
func ToPBVolumeInfo(volume *abstract.Volume, mounts map[string]*propsv1.HostLocalMount) (*pb.VolumeInfo, error) {
	if volume == nil {
		return nil, fail.InvalidParameterError("volume", "cannot be nil")
	}

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
	return pbvi, nil
}

// ToPBBucketList convert a list of string into a *ContainerLsit
func ToPBBucketList(in []string) (*pb.BucketList, error) {
	var buckets []*pb.Bucket
	for _, name := range in {
		buckets = append(buckets, &pb.Bucket{Name: name})
	}
	return &pb.BucketList{
		Buckets: buckets,
	}, nil
}

// ToPBBucketMountPoint convert a Bucket into a BucketMountingPoint
func ToPBBucketMountPoint(in *abstract.Bucket) (*pb.BucketMountingPoint, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	return &pb.BucketMountingPoint{
		Bucket: in.Name,
		Path:   in.MountPoint,
		Host:   &pb.Reference{Name: in.Host},
	}, nil
}

// ToPBShare convert a share from model to protocolbuffer format
func ToPBShare(hostName string, share *propsv1.HostShare) (*pb.ShareDefinition, error) {
	if share == nil {
		return nil, fail.InvalidParameterError("share", "cannot be nil")
	}
	return &pb.ShareDefinition{
		Id:   share.ID,
		Name: share.Name,
		Host: &pb.Reference{Name: hostName},
		Path: share.Path,
		Type: "nfs",
	}, nil
}

// ToPBShareMount convert share mount on host to protocolbuffer format
func ToPBShareMount(shareName string, hostName string, mount *propsv1.HostRemoteMount) (*pb.ShareMountDefinition, error) {
	if mount == nil {
		return nil, fail.InvalidParameterError("mount", "cannot be nil")
	}

	return &pb.ShareMountDefinition{
		Share: &pb.Reference{Name: shareName},
		Host:  &pb.Reference{Name: hostName},
		Path:  mount.Path,
		Type:  mount.FileSystem,
	}, nil
}

// ToPBShareMountList converts share mounts to protocol buffer
func ToPBShareMountList(hostName string, share *propsv1.HostShare, mounts map[string]*propsv1.HostRemoteMount) (*pb.ShareMountList, error) {
	if share == nil {
		return nil, fail.InvalidParameterError("share", "cannot be nil")
	}

	var pbMounts []*pb.ShareMountDefinition
	for k, v := range mounts {
		pbMounts = append(
			pbMounts, &pb.ShareMountDefinition{
				Host:  &pb.Reference{Name: k},
				Share: &pb.Reference{Name: share.Name},
				Path:  v.Path,
				Type:  "nfs",
			},
		)
	}

	pbs, err := ToPBShare(hostName, share)
	if err != nil {
		return nil, err
	}

	return &pb.ShareMountList{
		Share:     pbs,
		MountList: pbMounts,
	}, nil
}

// ToPBHost convert an host from api to protocolbuffer format
func ToPBHost(in *abstract.Host) (*pb.Host, error) {
	var (
		hostNetworkV1 *propsv1.HostNetwork
		hostSizingV1  *propsv1.HostSizing
		hostVolumesV1 *propsv1.HostVolumes
		volumes       []string
	)

	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

	if in.Properties != nil {
		err := in.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(
			func(clonable data.Clonable) error {
				hostNetworkV1 = clonable.(*propsv1.HostNetwork)
				return in.Properties.LockForRead(hostproperty.SizingV1).ThenUse(
					func(clonable data.Clonable) error {
						hostSizingV1 = clonable.(*propsv1.HostSizing)
						return in.Properties.LockForRead(hostproperty.VolumesV1).ThenUse(
							func(clonable data.Clonable) error {
								hostVolumesV1 = clonable.(*propsv1.HostVolumes)
								for k := range hostVolumesV1.VolumesByName {
									volumes = append(volumes, k)
								}
								return nil
							},
						)
					},
				)
			},
		)
		if err != nil {
			return nil, err
		}
	}

	return &pb.Host{
		Id:                  in.ID,
		Name:                in.Name,
		Cpu:                 int32(hostSizingV1.AllocatedSize.Cores),
		Ram:                 hostSizingV1.AllocatedSize.RAMSize,
		Disk:                int32(hostSizingV1.AllocatedSize.DiskSize),
		PublicIp:            in.GetPublicIP(),
		PrivateIp:           in.GetPrivateIP(),
		PrivateKey:          in.PrivateKey,
		GatewayId:           hostNetworkV1.DefaultGatewayID,
		Password:            in.Password,
		State:               pb.HostState(in.LastState),
		AttachedVolumeNames: volumes,
	}, nil
}

// ToPBHostDefinition ...
func ToPBHostDefinition(in *abstract.HostDefinition) (*pb.HostDefinition, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}

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
	}, nil
}

// ToPBGatewayDefinition converts a abstract.HostDefinition tp .GatewayDefinition
func ToPBGatewayDefinition(in *abstract.HostDefinition) (*pb.GatewayDefinition, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	return &pb.GatewayDefinition{
		Cpu:      int32(in.Cores),
		Ram:      in.RAMSize,
		Disk:     int32(in.DiskSize),
		ImageId:  in.ImageID,
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}, nil
}

// FromPBHostDefinitionToPBGatewayDefinition converts a pb.HostDefinition to pb.GatewayDefinition
func FromPBHostDefinitionToPBGatewayDefinition(in *pb.HostDefinition) *pb.GatewayDefinition {
	if in == nil {
		return &pb.GatewayDefinition{}
	}

	def := &pb.GatewayDefinition{
		ImageId:  in.ImageId,
		Cpu:      in.CpuCount,
		Ram:      in.Ram,
		Disk:     in.Disk,
		GpuCount: in.GpuCount,
		Sizing: &pb.HostSizing{
			MinCpuCount: in.Sizing.MinCpuCount,
			MaxCpuCount: in.Sizing.MaxCpuCount,
			MinRamSize:  in.Sizing.MinRamSize,
			MaxRamSize:  in.Sizing.MaxRamSize,
			MinDiskSize: in.Sizing.MinDiskSize,
			GpuCount:    in.Sizing.GpuCount,
			MinCpuFreq:  in.Sizing.MinCpuFreq,
		},
	}
	return def
}

// ToHostStatus ...
func ToHostStatus(in *abstract.Host) (*pb.HostStatus, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	return &pb.HostStatus{
		Name:   in.Name,
		Status: pb.HostState(in.LastState).String(),
	}, nil
}

// ToPBHostTemplate convert an template from api to protocolbuffer format
func ToPBHostTemplate(in *abstract.HostTemplate) (*pb.HostTemplate, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	return &pb.HostTemplate{
		Id:       in.ID,
		Name:     in.Name,
		Cores:    int32(in.Cores),
		Ram:      int32(in.RAMSize),
		Disk:     int32(in.DiskSize),
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}, nil
}

// ToPBImage convert an image from api to protocolbuffer format
func ToPBImage(in *abstract.Image) (*pb.Image, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	return &pb.Image{
		Id:   in.ID,
		Name: in.Name,
	}, nil
}

// ToPBNetwork convert a network from api to protocolbuffer format
func ToPBNetwork(in *abstract.Network) (*pb.Network, error) {
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	var pbVIP *pb.VirtualIp
	if in.VIP != nil {
		pbVIP = ToPBVirtualIP(*in.VIP)
	}
	return &pb.Network{
		Id:                 in.ID,
		Name:               in.Name,
		Cidr:               in.CIDR,
		GatewayId:          in.GatewayID,
		SecondaryGatewayId: in.SecondaryGatewayID,
		VirtualIp:          pbVIP,
		Failover:           in.SecondaryGatewayID != "",
	}, nil
}

// ToPBFileList convert a list of file names from api to protocolbuffer FileList format
func ToPBFileList(fileNames []string, uploadDates []string, fileSizes []int64, fileBuckets [][]string) *pb.FileList {
	var files []*pb.File
	nbFiles := int(
		math.Min(
			math.Min(
				math.Min(float64(len(fileNames)), float64(len(uploadDates))), float64(len(fileSizes)),
			), float64(len(fileBuckets)),
		),
	)
	for i := 0; i < nbFiles; i++ {
		files = append(
			files, &pb.File{Name: fileNames[i], Date: uploadDates[i], Size: fileSizes[i], Buckets: fileBuckets[i]},
		)
	}
	return &pb.FileList{Files: files}
}

// ToPBHostSizing converts a protobuf HostSizing message to abstract.SizingRequirements
func ToPBHostSizing(src abstract.SizingRequirements) *pb.HostSizing {
	return &pb.HostSizing{
		MinCpuCount: int32(src.MinCores),
		MaxCpuCount: int32(src.MaxCores),
		MinCpuFreq:  src.MinFreq,
		GpuCount:    int32(src.MinGPU),
		MinRamSize:  src.MinRAMSize,
		MaxRamSize:  src.MaxRAMSize,
		MinDiskSize: int32(src.MinDiskSize),
	}
}

// FromPBHostSizing converts a protobuf HostSizing message to abstract.SizingRequirements
func FromPBHostSizing(src *pb.HostSizing) (abstract.SizingRequirements, error) {
	if src == nil {
		return abstract.SizingRequirements{}, fail.InvalidParameterError("src", "cannot be nil")
	}
	return abstract.SizingRequirements{
		MinCores:    int(src.MinCpuCount),
		MaxCores:    int(src.MaxCpuCount),
		MinFreq:     src.MinCpuFreq,
		MinGPU:      int(src.GpuCount),
		MinRAMSize:  src.MinRamSize,
		MaxRAMSize:  src.MaxRamSize,
		MinDiskSize: int(src.MinDiskSize),
	}, nil
}

// ToPBVirtualIP converts a abstract.VirtualIP to a pb.VirtualIp
func ToPBVirtualIP(src abstract.VirtualIP) *pb.VirtualIp {
	dest := &pb.VirtualIp{
		Id:        src.ID,
		NetworkId: src.NetworkID,
		PrivateIp: src.PrivateIP,
		PublicIp:  src.PublicIP,
	}
	dest.Hosts = make([]string, len(src.Hosts))
	copy(dest.Hosts, src.Hosts)
	return dest
}

// ClonePBHostSizing ...
func ClonePBHostSizing(in *pb.HostSizing) *pb.HostSizing {
	if in == nil {
		return &pb.HostSizing{}
	}
	return &pb.HostSizing{
		MinCpuCount: in.MinCpuCount,
		MaxCpuCount: in.MaxCpuCount,
		MinRamSize:  in.MinRamSize,
		MaxRamSize:  in.MaxRamSize,
		MinDiskSize: in.MinDiskSize,
		GpuCount:    in.GpuCount,
		MinCpuFreq:  in.MinCpuFreq,
	}
}

// ClonePBHostDefinition ...
func ClonePBHostDefinition(in *pb.HostDefinition) *pb.HostDefinition {
	if in == nil {
		return &pb.HostDefinition{}
	}
	return &pb.HostDefinition{
		Name:     in.Name,
		Network:  in.Network,
		CpuCount: in.CpuCount,
		Ram:      in.Ram,
		Disk:     in.Disk,
		ImageId:  in.ImageId,
		Public:   in.Public,
		GpuCount: in.GpuCount,
		CpuFreq:  in.CpuFreq,
		Force:    in.Force,
		Sizing:   ClonePBHostSizing(in.Sizing),
		Domain:   in.Domain,
	}
}
