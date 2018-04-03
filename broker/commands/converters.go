package commands

import (
	pb "github.com/SafeScale/brokerd"
	"github.com/SafeScale/providers/api"
	"github.com/SafeScale/system"
)

// ToPBSshconfig converts a system.SSHConfig into a pb.SshConfig
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

// ToAPISshConfig converts a pb.SshConfig into a system.SSHConfig
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

//ToPbVolume converts an api.Volume to a *pb.Volume
func ToPbVolume(in api.Volume) *pb.Volume {
	return &pb.Volume{
		ID:    in.ID,
		Name:  in.Name,
		Size:  int32(in.Size),
		Speed: pb.VolumeSpeed(in.Speed),
	}
}

//ToPBContainerList convert a list of string into a *pb.ContainerLsit
func ToPBContainerList(in []string) *pb.ContainerList {

	var containers []*pb.Container
	for _, name := range in {
		containers = append(containers, &pb.Container{Name: name})
	}
	return &pb.ContainerList{
		Containers: containers,
	}
}
