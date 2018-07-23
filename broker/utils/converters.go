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

// ToPBSshconfig converts a system.SSHConfig into a SshConfig
func ToPBSshconfig(from *system.SSHConfig) *pb.SshConfig {
	var gw *pb.SshConfig
	if from.GatewayConfig != nil {
		gw = ToPBSshconfig(from.GatewayConfig)
	}
	return &pb.SshConfig{
		Gateway:    gw,
		Host:       from.Host,
		Port:       int32(from.Port),
		PrivateKey: from.PrivateKey,
		User:       from.User,
	}
}

// ToAPISshConfig converts a SshConfig into a system.SSHConfig
func ToAPISshConfig(from *pb.SshConfig) *system.SSHConfig {
	var gw *system.SSHConfig
	if from.Gateway != nil {
		gw = ToAPISshConfig(from.Gateway)
	}
	return &system.SSHConfig{
		User:          from.User,
		Host:          from.Host,
		PrivateKey:    from.PrivateKey,
		Port:          int(from.Port),
		GatewayConfig: gw,
	}
}

//ToPbVolume converts an api.Volume to a *Volume
func ToPbVolume(in api.Volume) *pb.Volume {
	return &pb.Volume{
		ID:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: pb.VolumeSpeed(in.Speed),
	}
}

//ToPBContainerList convert a list of string into a *ContainerLsit
func ToPBContainerList(in []string) *pb.ContainerList {

	var containers []*pb.Container
	for _, name := range in {
		containers = append(containers, &pb.Container{Name: name})
	}
	return &pb.ContainerList{
		Containers: containers,
	}
}

//ToPBContainerMountPoint convert a ContainerInfo into a ContainerMountingPoint
func ToPBContainerMountPoint(in *api.ContainerInfo) *pb.ContainerMountingPoint {
	return &pb.ContainerMountingPoint{
		Container: in.Name,
		Path:      in.MountPoint,
		VM: &pb.Reference{
			Name: in.VM,
		},
	}
}

// ToPBNas convert a Nas from api to protocolbuffer format
func ToPBNas(in *api.Nas) *pb.NasDefinition {
	return &pb.NasDefinition{
		Nas: &pb.NasName{
			Name: in.Name},
		VM: &pb.Reference{
			Name: in.Host},
		Path:     in.Path,
		IsServer: in.IsServer,
	}
}

// ToPBVM convert a VM from api to protocolbuffer format
func ToPBVM(in *api.VM) *pb.VM {
	return &pb.VM{
		CPU:        int32(in.Size.Cores),
		Disk:       int32(in.Size.DiskSize),
		GatewayID:  in.GatewayID,
		ID:         in.ID,
		PUBLIC_IP:  in.GetPublicIP(),
		PRIVATE_IP: in.GetPrivateIP(),
		Name:       in.Name,
		PrivateKey: in.PrivateKey,
		RAM:        in.Size.RAMSize,
		State:      pb.VMState(in.State),
	}
}
