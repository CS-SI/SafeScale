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
	log "github.com/sirupsen/logrus"

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
func ToPBVolumeInfo(volume *model.Volume, host *model.Host) *pb.VolumeInfo {
	pbvi := &pb.VolumeInfo{
		ID:    volume.ID,
		Name:  volume.Name,
		Size:  int32(volume.Size),
		Speed: pb.VolumeSpeed(volume.Speed),
	}
	if host != nil {
		pbvi.Host = &pb.Reference{ID: host.ID}
		hpVolumesV1 := propsv1.BlankHostVolumes
		err := host.Properties.Get(HostProperty.VolumesV1, &hpVolumesV1)
		if err != nil {
			log.Errorf("error occured during convertion to protobuf: %s", err.Error())
			return nil
		}

		if device, ok := hpVolumesV1.DeviceByID[volume.ID]; ok {
			mounts := propsv1.BlankHostMounts
			err := host.Properties.Get(HostProperty.MountsV1, &mounts)
			if err != nil {
				log.Errorf("error occured during convertion to protobuf: %s", err.Error())
				return nil
			}
			mount := mounts.MountsByPath[mounts.MountsByDevice[device]]
			pbvi.Device = device
			pbvi.MountPath = mount.Path
			pbvi.Format = mount.FileSystem
		}
	}
	return pbvi
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
func ToPBContainerMountPoint(in *model.ContainerInfo) *pb.ContainerMountingPoint {
	return &pb.ContainerMountingPoint{
		Container: in.Name,
		Path:      in.MountPoint,
		Host:      &pb.Reference{Name: in.Host},
	}
}

// ToPBNasExport convert an export from api to protocolbuffer format
func ToPBNasExport(hostName string, export propsv1.HostExport) *pb.NasExportDefinition {
	return &pb.NasExportDefinition{
		ID:   export.ID,
		Name: &pb.NasExportName{Name: export.Name},
		Host: &pb.Reference{Name: hostName},
		Path: export.Path,
		Type: "nfs",
	}
}

// ToPBNasMount convert a host mount to protocolbuffer format
func ToPBNasMount(exportName string, hostName string, mount *propsv1.HostMount) *pb.NasMountDefinition {
	return &pb.NasMountDefinition{
		Name: &pb.NasExportName{Name: exportName},
		Host: &pb.Reference{Name: hostName},
		Path: mount.Path,
		Type: "nfs",
	}
}

// ToPBHost convert an host from api to protocolbuffer format
func ToPBHost(in *model.Host) *pb.Host {
	hpNetworkV1 := propsv1.BlankHostNetwork
	err := in.Properties.Get(HostProperty.NetworkV1, &hpNetworkV1)
	if err != nil {
		return nil
	}
	hpSizingV1 := propsv1.BlankHostSizing
	err = in.Properties.Get(HostProperty.SizingV1, &hpSizingV1)
	if err != nil {
		return nil
	}
	return &pb.Host{
		CPU:        int32(hpSizingV1.AllocatedSize.Cores),
		Disk:       int32(hpSizingV1.AllocatedSize.DiskSize),
		GatewayID:  hpNetworkV1.DefaultGatewayID,
		ID:         in.ID,
		PublicIP:   in.GetPublicIP(),
		PrivateIP:  in.GetPrivateIP(),
		Name:       in.Name,
		PrivateKey: in.PrivateKey,
		RAM:        hpSizingV1.AllocatedSize.RAMSize,
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
