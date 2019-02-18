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
	SSHConfig *system.SSHConfig
}

// NewServer instanciates a new nfs.Server struct
func NewServer(sshconfig *system.SSHConfig) (*Server, error) {
	if sshconfig == nil {
		return nil, fmt.Errorf("invalid parameter: 'sshconfig' can't be nil")
	}

	server := Server{
		SSHConfig: sshconfig,
	}
	return &server, nil
}

// GetHost returns the hostname or IP address of the nfs.Server
func (s *Server) GetHost() string {
	return s.SSHConfig.Host
}

// Install installs and configure NFS service on the remote host
func (s *Server) Install() error {
	retcode, stdout, stderr, err := executeScript(*s.SSHConfig, "nfs_server_install.sh", map[string]interface{}{})
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to install nfs server")
}

// AddShare configures a local path to be exported by NFS
func (s *Server) AddShare(path string, secutityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool) error {
	share, err := NewShare(s, path)
	if err != nil {
		return fmt.Errorf("Failed to create the share : %s", err.Error())
	}

	acl := ExportACL{
		Host:          "*",
		SecurityModes: []SecurityFlavor.Enum{},
		Options: ExportOptions{
			ReadOnly:       readOnly,
			NoRootSquash:   !rootSquash,
			Secure:         secure,
			Async:          async,
			NoHide:         noHide,
			CrossMount:     crossMount,
			NoSubtreeCheck: !subtreeCheck,
			SetFSID:        false,
			AnonUID:        0,
			AnonGID:        0,
		},
	}

	for _, securityMode := range secutityModes {
		switch securityMode {
		case "sys":
			acl.SecurityModes = append(acl.SecurityModes, SecurityFlavor.Sys)
		case "krb5":
			acl.SecurityModes = append(acl.SecurityModes, SecurityFlavor.Krb5)
		case "krb5i":
			acl.SecurityModes = append(acl.SecurityModes, SecurityFlavor.Krb5i)
		case "krb5p":
			acl.SecurityModes = append(acl.SecurityModes, SecurityFlavor.Krb5p)
		default:
			return fmt.Errorf("Can't add the share, %s is not a valid security mode", securityMode)
		}
	}

	share.AddACL(acl)

	return share.Add()
}

// RemoveShare stops export of a local mount point by NFS on the remote server
func (s *Server) RemoveShare(path string) error {
	data := map[string]interface{}{
		"Path": path,
	}
	retcode, stdout, stderr, err := executeScript(*s.SSHConfig, "nfs_server_path_unexport.sh", data)
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to unexport a shared directory")
}

// MountBlockDevice mounts a block device in the remote system
func (s *Server) MountBlockDevice(deviceName, mountPoint, format string, doNotFormat bool) (string, error) {
	data := map[string]interface{}{
		"Device":      deviceName,
		"MountPoint":  mountPoint,
		"FileSystem":  format,
		"DoNotFormat": doNotFormat,
	}
	retcode, stdout, stderr, err := executeScript(*s.SSHConfig, "block_device_mount.sh", data)
	err = handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to mount block device")
	return stdout, err
}

// UnmountBlockDevice unmounts a local block device on the remote system
func (s *Server) UnmountBlockDevice(volumeUUID string) error {
	data := map[string]interface{}{
		"UUID": volumeUUID,
	}
	retcode, stdout, stderr, err := executeScript(*s.SSHConfig, "block_device_unmount.sh", data)
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to umount block device")
}
