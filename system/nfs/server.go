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

package nfs

import (
	"fmt"

	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/system/nfs/SecurityFlavor"
)

// Server structure
type Server struct {
	SshConfig *system.SSHConfig
}

// NewServer instanciates a new nfs.Server struct
func NewServer(sshconfig *system.SSHConfig) (*Server, error) {
	if sshconfig == nil {
		return nil, fmt.Errorf("invalid parameter: 'sshconfig' can't be nil")
	}

	server := Server{
		SshConfig: sshconfig,
	}
	return &server, nil
}

// GetHost returns the hostname or IP address of the nfs.Server
func (s *Server) GetHost() string {
	return s.SshConfig.Host
}

// Install installs and configure NFS service on the remote host
func (s *Server) Install() error {
	retcode, stdout, stderr, err := executeScript(*s.SshConfig, "nfs_server_install.sh", map[string]interface{}{})
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to install nfs server")
}

// AddShare configures a local path to be exported by NFS
func (s *Server) AddShare(path string, acl string) error {
	share, err := NewShare(s, path)
	if err != nil {
		return fmt.Errorf("Failed to create the share : %s", err.Error())
	}
	share.AddAcl(ExportAcl{
		Host:          "*",
		SecurityModes: []SecurityFlavor.Enum{},
		Options: ExportOptions{
			ReadOnly:       false,
			NoRootSquash:   true,
			Secure:         false,
			Async:          false,
			NoHide:         false,
			CrossMount:     false,
			NoSubtreeCheck: true,
			SetFSID:        false,
			AnonUID:        0,
			AnonGID:        0,
		},
	})

	return share.Add()
}

// RemoveShare stops export of a local mount point by NFS on the remote server
func (s *Server) RemoveShare(path string) error {
	data := map[string]interface{}{
		"Path": path,
	}
	retcode, stdout, stderr, err := executeScript(*s.SshConfig, "nfs_server_path_unexport.sh", data)
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to unexport a shared directory")
}

// MountBlockDevice mounts a block device in the remote system
func (s *Server) MountBlockDevice(device, mountPoint, format string, doNotFormat bool) (string, error) {
	data := map[string]interface{}{
		"Device":      device,
		"MountPoint":  mountPoint,
		"FileSystem":  format,
		"DoNotFormat": doNotFormat,
	}
	retcode, stdout, stderr, err := executeScript(*s.SshConfig, "block_device_mount.sh", data)
	err = handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to mount block device")
	return stdout, err
}

// UnmountBlockDevice unmounts a local block device on the remote system
func (s *Server) UnmountBlockDevice(device string) error {
	data := map[string]interface{}{
		"Device": device,
	}
	retcode, stdout, stderr, err := executeScript(*s.SshConfig, "block_device_unmount.sh", data)
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to umount block device")
}
