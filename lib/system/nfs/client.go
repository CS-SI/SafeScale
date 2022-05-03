/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	ssh2 "github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Client defines the structure of a Client object
type Client struct {
	// SshConfig contains ssh connection configuration
	SSHConfig *ssh2.SSHConfig
}

// NewNFSClient creates a new NFS client instance
func NewNFSClient(sshconfig *ssh2.SSHConfig) (*Client, fail.Error) {
	if sshconfig == nil {
		return nil, fail.InvalidParameterError("sshconfig", "cannot be nil")
	}

	return &Client{SSHConfig: sshconfig}, nil
}

// Install installs NFS client on remote host
func (c *Client) Install(ctx context.Context, svc iaas.Service) fail.Error {
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	stdout, xerr := executeScript(ctx, timings, *c.SSHConfig, "nfs_client_install.sh", map[string]interface{}{})
	if xerr != nil {
		xerr.Annotate("stdout", stdout)
		return fail.Wrap(xerr, "error executing script to install NFS client on remote host")
	}
	return nil
}

// Mount defines a mount of a remote share and mount it
func (c *Client) Mount(
	ctx context.Context, svc iaas.Service, export string, mountPoint string, withCache bool,
) fail.Error {
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	data := map[string]interface{}{
		"Export":      export,
		"MountPoint":  mountPoint,
		"cacheOption": map[bool]string{true: "ac", false: "noac"}[withCache],
	}
	stdout, xerr := executeScript(ctx, timings, *c.SSHConfig, "nfs_client_share_mount.sh", data)
	if xerr != nil {
		xerr.Annotate("stdout", stdout)
		return fail.Wrap(xerr, "error executing script to mount remote NFS share")
	}
	return nil
}

// Unmount a nfs share from NFS server
func (c *Client) Unmount(ctx context.Context, svc iaas.Service, export string) fail.Error {
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	data := map[string]interface{}{"Export": export}
	stdout, xerr := executeScript(ctx, timings, *c.SSHConfig, "nfs_client_share_unmount.sh", data)
	if xerr != nil {
		xerr.Annotate("stdout", stdout)
		return fail.Wrap(xerr, "error executing script to unmount remote NFS share")
	}
	return nil
}
