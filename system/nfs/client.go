package nfs

import (
	"fmt"

	"github.com/SafeScale/system"
)

type Client struct {
	SshConfig *system.SSHConfig
}

func NewNFSClient(sshconfig *system.SSHConfig) (*Client, error) {
	if sshconfig == nil {
		return nil, fmt.Errorf("invalid parameter: 'sshconfig' can't be nil")
	}

	client := &Client{
		SshConfig: sshconfig,
	}
	return client, nil
}

//install installs NFS client on remote host
func (c *Client) Install() error {
	_, _, _, err := executeScript(*c.SshConfig, "nfs_client_install.sh", map[string]interface{}{})
	return err
}

//MountRemoteShare defines a mount of a remote share and mount it
func (c *Client) Mount(host string, share string, mountPoint string) error {
	data := map[string]interface{}{
		"Host":       host,
		"Share":      share,
		"MountPoint": mountPoint,
	}
	_, _, _, err := executeScript(*c.SshConfig, "nfs_client_share_mount.sh", data)
	return err
}

func (c *Client) Unmount(host string, share string, mountPoint string) error {
	data := map[string]interface{}{
		"Host":       host,
		"Share":      share,
		"MountPoint": mountPoint,
	}
	_, _, _, err := executeScript(*c.SshConfig, "nfs_client_share_unmount.sh", data)
	if err != nil {
		return err
	}
	return nil
}
