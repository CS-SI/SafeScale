package nfs

import (
	"github.com/SafeScale/system"
)

type Server struct {
	SshConfig system.SSHConfig
}

//GetHost returns the hostname or IP address of the nfs.Server
func (ns *Server) GetHost() string {
	return ns.SshConfig.Host
}

//NewServer instanciates a new nfs.Server struct
func (s *Server) NewServer(sshconfig system.SSHConfig) (*Server, error) {
	server := NFSServer{
		SshConfig: sshconfig,
	}
	return &server, nil
}

//Install installs and configure NFS server on the remote host
func (s *Server) Install() error {
	_, _, _, err := executeScript(s.SshConfig, "nfs_server_install.sh", map[string]interface{}{})
	return err
}

//MountBlockDevice mounts a local block device in the remote system
// If persistent is true, updates the system configuration to survive a reboot
func (s *Server) MountBlockDevice(device string, mountPoint string) error {
	data := map[string]interface{}{
		"Device":     device,
		"MountPoint": mountPoint,
		"FileSystem": "ext4",
	}
	_, _, _, err := executeScript(s.SshConfig, "block_device_mount.sh", data)
	return err
}

//UnmountBlockDevice unmounts a local block device on the remote system
// If persistent is true, updates the system configuration to remove the automatic mount at boot
func (s *Server) UnmountBlockDevice(device string, mountPoint string) error {
	data := map[string]interface{}{
		"Device":     device,
		"MountPoint": mountPoint,
	}
	_, _, _, err := executeScript(s.SshConfig, "block_device_unmount.sh", data)
	return err
}

//Export configures a local mountpoint to be exported by NFS
func (s *Server) AddShare(mountPoint string, acl string) error {
	data := map[string]interface{}{
		"MountPoint":   mountPoint,
		"AccessRights": acl,
	}
	_, _, _, err := executeScript(s.SshConfig, "nfs_server_path_export.sh", data)
	return err
}

//RemoveShare stops export of a local mount point by NFS on the remote server
func (s *Server) RemoveShare(mountPoint string) error {
	data := map[string]interface{}{
		"MountPoint": mountPoint,
	}
	_, _, _, err := executeScript(s.SshConfig, "nfs_server_path_unexport.sh", data)
	return err
}
