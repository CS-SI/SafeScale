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

package utils

import (
	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system"
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

// ToSystemSshConfig converts a pb.SshConfig into a system.SSHConfig
func ToSystemSshConfig(from *pb.SshConfig) *system.SSHConfig {
	var gw *system.SSHConfig
	if from.Gateway != nil {
		gw = ToSystemSshConfig(from.Gateway)
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
func ToPBVolume(in *model.Volume) *pb.Volume {
	return &pb.Volume{
		ID:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: pb.VolumeSpeed(in.Speed),
	}
}

// ToPBVolumeAttachment converts an api.Volume to a *Volume
func ToPBVolumeAttachment(in *model.VolumeAttachment) *pb.VolumeAttachment {
	return &pb.VolumeAttachment{
		Volume:    &pb.Reference{ID: in.VolumeID},
		Host:      &pb.Reference{ID: in.ServerID},
		MountPath: in.MountPoint,
		Device:    in.Device,
	}
}

// ToPBVolumeInfo converts an api.Volume to a *VolumeInfo
func ToPBVolumeInfo(volume *model.Volume, mounts map[string]*propsv1.HostLocalMount) *pb.VolumeInfo {
	pbvi := &pb.VolumeInfo{
		ID:    volume.ID,
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
func ToPBBucketMountPoint(in *model.Bucket) *pb.BucketMountingPoint {
	return &pb.BucketMountingPoint{
		Bucket: in.Name,
		Path:   in.MountPoint,
		Host:   &pb.Reference{Name: in.Host},
	}
}

// ToPBShare convert a share from model to protocolbuffer format
func ToPBShare(hostName string, share *propsv1.HostShare) *pb.ShareDefinition {
	return &pb.ShareDefinition{
		ID:   share.ID,
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
	pbMounts := []*pb.ShareMountDefinition{}
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
func ToPBHost(in *model.Host) *pb.Host {
	hostNetworkV1 := propsv1.NewHostNetwork()
	err := in.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return nil
	}
	hostSizingV1 := propsv1.NewHostSizing()
	err = in.Properties.Get(HostProperty.SizingV1, hostSizingV1)
	if err != nil {
		return nil
	}
	return &pb.Host{
		CPU:        int32(hostSizingV1.AllocatedSize.Cores),
		Disk:       int32(hostSizingV1.AllocatedSize.DiskSize),
		GatewayID:  hostNetworkV1.DefaultGatewayID,
		ID:         in.ID,
		PublicIP:   in.GetPublicIP(),
		PrivateIP:  in.GetPrivateIP(),
		Name:       in.Name,
		PrivateKey: in.PrivateKey,
		RAM:        hostSizingV1.AllocatedSize.RAMSize,
		State:      pb.HostState(in.LastState),
	}
}

// ToHostStatus ...
func ToHostStatus(in *model.Host) *pb.HostStatus {
	return &pb.HostStatus{
		Name:   in.Name,
		Status: pb.HostState(in.LastState).String(),
	}
}

// ToPBHostTemplate convert an template from api to protocolbuffer format
func ToPBHostTemplate(in *model.HostTemplate) *pb.HostTemplate {
	return &pb.HostTemplate{
		ID:      in.ID,
		Name:    in.Name,
		Cores:   int32(in.Cores),
		Ram:     int32(in.RAMSize),
		Disk:    int32(in.DiskSize),
		GPUs:    int32(in.GPUNumber),
		GPUType: in.GPUType,
	}
}

// ToPBImage convert an image from api to protocolbuffer format
func ToPBImage(in *model.Image) *pb.Image {
	return &pb.Image{
		ID:   in.ID,
		Name: in.Name,
	}
}

//ToPBNetwork convert a network from api to protocolbuffer format
func ToPBNetwork(in *model.Network) *pb.Network {
	return &pb.Network{
		ID:        in.ID,
		Name:      in.Name,
		CIDR:      in.CIDR,
		GatewayID: in.GatewayID,
	}
}
