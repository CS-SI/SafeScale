package commands

import (
	pb "github.com/SafeScale/brokerd"
	"github.com/SafeScale/system"
)

// ToPBSshconfig Convert a system.SSHConfig into a pb.SshConfig
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

// ToAPISshConfig Convert a pb.SshConfig into a system.SSHConfig
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
