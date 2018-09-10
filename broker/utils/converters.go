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
	"github.com/CS-SI/SafeScale/providers/api"
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
func ToPBVolume(in *api.Volume) *pb.Volume {
	return &pb.Volume{
		ID:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: pb.VolumeSpeed(in.Speed),
	}
}

// ToPBVolumeAttachment converts an api.Volume to a *Volume
func ToPBVolumeAttachment(in *api.VolumeAttachment) *pb.VolumeAttachment {
	return &pb.VolumeAttachment{
		Volume:    &pb.Reference{ID: in.VolumeID},
		Host:      &pb.Reference{ID: in.ServerID},
		MountPath: in.MountPoint,
		Device:    in.Device,
	}
}

// ToPBVolumeInfo merges and converts an api.Volume and an api.VolumeAttachment to a *VolumeInfo
func ToPBVolumeInfo(volume *api.Volume, volumeAttch *api.VolumeAttachment) *pb.VolumeInfo {
	if volumeAttch != nil {
		return &pb.VolumeInfo{
			ID:        volume.ID,
			Name:      volume.Name,
			Size:      int32(volume.Size),
			Speed:     pb.VolumeSpeed(volume.Speed),
			Host:      &pb.Reference{ID: volumeAttch.ServerID},
			MountPath: volumeAttch.MountPoint,
			Device:    volumeAttch.Device,
			Format:    volumeAttch.Format,
		}
	}
	return &pb.VolumeInfo{
		ID:    volume.ID,
		Name:  volume.Name,
		Size:  int32(volume.Size),
		Speed: pb.VolumeSpeed(volume.Speed),
	}
}

// ToPBContainerList convert a list of string into a *ContainerLsit
func ToPBContainerList(in []string) *pb.ContainerList {

	var containers []*pb.Container
	for _, name := range in {
		containers = append(containers, &pb.Container{Name: name})
	}
	return &pb.ContainerList{
		Containers: containers,
	}
}

// ToPBContainerMountPoint convert a ContainerInfo into a ContainerMountingPoint
func ToPBContainerMountPoint(in *api.ContainerInfo) *pb.ContainerMountingPoint {
	return &pb.ContainerMountingPoint{
		Container: in.Name,
		Path:      in.MountPoint,
		Host:      &pb.Reference{Name: in.Host},
	}
}

// ToPBNas convert a Nas from api to protocolbuffer format
func ToPBNas(in *api.Nas) *pb.NasDefinition {
	return &pb.NasDefinition{
		ID:       in.ID,
		Nas:      &pb.NasName{Name: in.Name},
		Host:     &pb.Reference{Name: in.Host},
		Path:     in.Path,
		IsServer: in.IsServer,
	}
}

// ToPBHost convert an host from api to protocolbuffer format
func ToPBHost(in *api.Host) *pb.Host {
	return &pb.Host{
		CPU:        int32(in.Size.Cores),
		Disk:       int32(in.Size.DiskSize),
		GatewayID:  in.GatewayID,
		ID:         in.ID,
		PUBLIC_IP:  in.GetPublicIP(),
		PRIVATE_IP: in.GetPrivateIP(),
		Name:       in.Name,
		PrivateKey: in.PrivateKey,
		RAM:        in.Size.RAMSize,
		State:      pb.HostState(in.State),
	}
}

// ToPBHostTemplate convert an template from api to protocolbuffer format
func ToPBHostTemplate(in *api.HostTemplate) *pb.HostTemplate {
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
func ToPBImage(in *api.Image) *pb.Image {
	return &pb.Image{
		ID:   in.ID,
		Name: in.Name,
	}
}

//ToPBNetwork convert a network from api to protocolbuffer format
func ToPBNetwork(in *api.Network) *pb.Network {
	return &pb.Network{
		ID:        in.ID,
		Name:      in.Name,
		CIDR:      in.CIDR,
		GatewayID: in.GatewayID,
	}
}
