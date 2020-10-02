/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// getServer structure
type Server struct {
	SSHConfig *system.SSHConfig
}

// NewServer instantiates a new nfs.getServer struct
func NewServer(sshconfig *system.SSHConfig) (srv *Server, err fail.Error) {
	if sshconfig.IsNull() {
		return nil, fail.InvalidParameterError("sshconfig", "cannot be null value")
	}

	server := Server{
		SSHConfig: sshconfig,
	}
	return &server, nil
}

// GetHost returns the hostname or IP address of the nfs.getServer
func (s *Server) GetHost() string {
	return s.SSHConfig.Host
}

// Install installs and configure NFS service on the remote host
func (s *Server) Install(task concurrency.Task) fail.Error {
	// retcode, stdout, stderr, err := executeScript(task, *s.SSHConfig, "nfs_server_install.sh", map[string]interface{}{})
	// return fail.ReturnedValuesFromShellToError(retcode, stdout, stderr, err, "Error executing script to install nfs server")
	stdout, xerr := executeScript(task, *s.SSHConfig, "nfs_server_install.sh", map[string]interface{}{})
	if xerr != nil {
		_ = xerr.Annotate("stdout", stdout)
		return fail.Wrap(xerr, "error executing script to install nfs server")
	}
	return nil
}

// AddShare configures a local path to be exported by NFS
func (s *Server) AddShare(task concurrency.Task, path string, options string /*securityModes []string, readOnly, rootSquash, secure, async, noHide, crossMount, subtreeCheck bool*/) fail.Error {
	share, xerr := NewShare(s, path, options)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create the share")
	}

	// acl := ExportACL{
	// 	Host:          "*",
	// 	SecurityModes: []securityflavor.Enum{},
	// 	Options: ExportOptions{
	// 		ReadOnly:       readOnly,
	// 		NoRootSquash:   !rootSquash,
	// 		Secure:         secure,
	// 		Async:          async,
	// 		NoHide:         noHide,
	// 		CrossMount:     crossMount,
	// 		NoSubtreeCheck: !subtreeCheck,
	// 		SetFSID:        false,
	// 		AnonUID:        0,
	// 		AnonGID:        0,
	// 	},
	// }

	// for _, securityMode := range securityModes {
	// 	switch securityMode {
	// 	case "sys":
	// 		acl.SecurityModes = append(acl.SecurityModes, securityflavor.Sys)
	// 	case "krb5":
	// 		acl.SecurityModes = append(acl.SecurityModes, securityflavor.Krb5)
	// 	case "krb5i":
	// 		acl.SecurityModes = append(acl.SecurityModes, securityflavor.Krb5i)
	// 	case "krb5p":
	// 		acl.SecurityModes = append(acl.SecurityModes, securityflavor.Krb5p)
	// 	default:
	// 		return fmt.Errorf("cannot add the share, %s is not a valid security mode", securityMode)
	// 	}
	// }

	// share.AddACL(acl)

	return share.Add(task)
}

// RemoveShare stops export of a local mount point by NFS on the remote server
func (s *Server) RemoveShare(task concurrency.Task, path string) fail.Error {
	data := map[string]interface{}{
		"Path": path,
	}
	// retcode, stdout, stderr, err := executeScript(task, *s.SSHConfig, "nfs_server_path_unexport.sh", data)
	// return fail.ReturnedValuesFromShellToError(retcode, stdout, stderr, err, "Error executing script to unexport a shared directory")
	stdout, xerr := executeScript(task, *s.SSHConfig, "nfs_server_path_unexport.sh", data)
	if xerr != nil {
		_ = xerr.Annotate("stdout", stdout)
		return fail.Wrap(xerr, "error executing script to unexport a shared directory")
	}
	return nil
}

// MountBlockDevice mounts a block device in the remote system
func (s *Server) MountBlockDevice(task concurrency.Task, deviceName, mountPoint, format string, doNotFormat bool) (string, fail.Error) {
	data := map[string]interface{}{
		"Device":      deviceName,
		"MountPoint":  mountPoint,
		"FileSystem":  format,
		"DoNotFormat": doNotFormat,
	}
	// retcode, stdout, stderr, err := executeScript(task, *s.SSHConfig, "block_device_mount.sh", data)
	// err = fail.ReturnedValuesFromShellToError(retcode, stdout, stderr, err, "Error executing script to mount block device")
	stdout, xerr := executeScript(task, *s.SSHConfig, "block_device_mount.sh", data)
	if xerr != nil {
		_ = xerr.Annotate("stdout", stdout)
		return "", fail.Wrap(xerr, "error executing script to mount block device")
	}
	return stdout, nil
}

// UnmountBlockDevice unmounts a local block device on the remote system
func (s *Server) UnmountBlockDevice(task concurrency.Task, volumeUUID string) fail.Error {
	data := map[string]interface{}{
		"UUID": volumeUUID,
	}
	// retcode, stdout, stderr, err := executeScript(task, *s.SSHConfig, "block_device_unmount.sh", data)
	// return fail.ReturnedValuesFromShellToError(retcode, stdout, stderr, err, "Error executing script to umount block device")
	stdout, xerr := executeScript(task, *s.SSHConfig, "block_device_unmount.sh", data)
	if xerr != nil {
		_ = xerr.Annotate("stdout", stdout)
		return fail.Wrap(xerr, "error executing script to unmount block device")
	}
	return nil
}
