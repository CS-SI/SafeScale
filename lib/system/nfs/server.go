/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"

	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/system/nfs/enums/securityflavor"
)

// Server structure
type Server struct {
	SSHConfig *system.SSHConfig
}

// NewServer instantiates a new nfs.Server struct
func NewServer(sshconfig *system.SSHConfig) (srv *Server, err error) {
	if sshconfig == nil {
		return nil, scerr.InvalidParameterError("sshconfig", "cannot be nil")
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
func (s *Server) Install(ctx context.Context) error {
	retcode, stdout, stderr, err := executeScript(ctx, *s.SSHConfig, "nfs_server_install.sh", map[string]interface{}{})
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to install nfs server")
}

// AddShare configures a local path to be exported by NFS
func (s *Server) AddShare(ctx context.Context, path string, secutityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool) error {
	share, err := NewShare(s, path)
	if err != nil {
		return fmt.Errorf("failed to create the share : %s", err.Error())
	}

	acl := ExportACL{
		Host:          "*",
		SecurityModes: []securityflavor.Enum{},
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
			acl.SecurityModes = append(acl.SecurityModes, securityflavor.Sys)
		case "krb5":
			acl.SecurityModes = append(acl.SecurityModes, securityflavor.Krb5)
		case "krb5i":
			acl.SecurityModes = append(acl.SecurityModes, securityflavor.Krb5i)
		case "krb5p":
			acl.SecurityModes = append(acl.SecurityModes, securityflavor.Krb5p)
		default:
			return fmt.Errorf("cannot add the share, %s is not a valid security mode", securityMode)
		}
	}

	share.AddACL(acl)

	return share.Add(ctx)
}

// RemoveShare stops export of a local mount point by NFS on the remote server
func (s *Server) RemoveShare(ctx context.Context, path string) error {
	data := map[string]interface{}{
		"Path": path,
	}
	retcode, stdout, stderr, err := executeScript(ctx, *s.SSHConfig, "nfs_server_path_unexport.sh", data)
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to unexport a shared directory")
}

// MountBlockDevice mounts a block device in the remote system
func (s *Server) MountBlockDevice(ctx context.Context, deviceName, mountPoint, format string, doNotFormat bool) (string, error) {
	data := map[string]interface{}{
		"Device":      deviceName,
		"MountPoint":  mountPoint,
		"FileSystem":  format,
		"DoNotFormat": doNotFormat,
	}
	retcode, stdout, stderr, err := executeScript(ctx, *s.SSHConfig, "block_device_mount.sh", data)
	err = handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to mount block device")
	return stdout, err
}

// UnmountBlockDevice unmounts a local block device on the remote system
func (s *Server) UnmountBlockDevice(ctx context.Context, volumeUUID string) error {
	data := map[string]interface{}{
		"UUID": volumeUUID,
	}
	retcode, stdout, stderr, err := executeScript(ctx, *s.SSHConfig, "block_device_unmount.sh", data)
	return handleExecuteScriptReturn(retcode, stdout, stderr, err, "Error executing script to umount block device")
}
