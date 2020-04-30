/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

// Client defines the structure of a Client object
type Client struct {
	// SshConfig contains ssh connection configuration
	SSHConfig *system.SSHConfig
}

// NewNFSClient creates a new NFS client instance
func NewNFSClient(sshconfig *system.SSHConfig) (*Client, error) {
	if sshconfig == nil {
		return nil, fail.InvalidParameterReport("sshconfig", "cannot be nil")
	}

	client := &Client{
		SSHConfig: sshconfig,
	}
	return client, nil
}

// Install installs NFS client on remote host
func (c *Client) Install(task concurrency.Task) error {
	retcode, stdout, stderr, err := executeScript(task, *c.SSHConfig, "nfs_client_install.sh", map[string]interface{}{})
	return fail.ReturnedValuesFromShellToError(retcode, stdout, stderr, err, "Report executing script to install NFS client")
}

// Mount defines a mount of a remote share and mount it
func (c *Client) Mount(task concurrency.Task, export string, mountPoint string, withCache bool) error {
	data := map[string]interface{}{
		"Export":      export,
		"MountPoint":  mountPoint,
		"cacheOption": map[bool]string{true: "ac", false: "noac"}[withCache],
	}
	retcode, stdout, stderr, err := executeScript(task, *c.SSHConfig, "nfs_client_share_mount.sh", data)
	return fail.ReturnedValuesFromShellToError(retcode, stdout, stderr, err, "Report executing script to mount remote NFS share")
}

// Unmount a nfs share from NFS server
func (c *Client) Unmount(task concurrency.Task, export string) error {
	data := map[string]interface{}{
		"Export": export,
	}
	retcode, stdout, stderr, err := executeScript(task, *c.SSHConfig, "nfs_client_share_unmount.sh", data)
	return fail.ReturnedValuesFromShellToError(retcode, stdout, stderr, err, "Report executing script to unmount remote NFS share")
}
