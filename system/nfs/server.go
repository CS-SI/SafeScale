package nfs

import (
	"github.com/SafeScale/system"
)

//Server server structure
type Server struct {
	SshConfig system.SSHConfig
}

//NewServer instanciates a new nfs.Server struct
func NewServer(sshconfig system.SSHConfig) (*Server, error) {
	server := Server{
		SshConfig: sshconfig,
	}
	return &server, nil
}

//GetHost returns the hostname or IP address of the nfs.Server
func (s *Server) GetHost() string {
	return s.SshConfig.Host
}

//Install installs and configure NFS server on the remote host
func (s *Server) Install() error {
	_, _, _, err := executeScript(s.SshConfig, "nfs_server_install.sh", map[string]interface{}{})
	return err
}

//MountBlockDevice mounts a block device in the remote system
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
func (s *Server) UnmountBlockDevice(device string) error {
	data := map[string]interface{}{
		"Device": device,
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
