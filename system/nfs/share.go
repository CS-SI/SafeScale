package nfs

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/SafeScale/system/nfs/SecurityFlavor"
)

type ExportOptions struct {
	ReadOnly       bool
	NoRootSquash   bool
	Secure         bool
	Async          bool
	NoHide         bool
	CrossMount     bool
	NoSubtreeCheck bool
	SetFSID        bool
	AnonUID        int
	AnonGID        int
}

type ExportAcl struct {
	//Host contains the pattern of hosts authorized (cf. exports man page)
	Host string
	//SecurityMode contains all the security mode allowed for the Host
	SecurityModes []SecurityFlavor.Enum
	//Options contains the options of the export ACL
	Options ExportOptions
}

//Share details the parameter of a NFS share
type Share struct {
	Server *Server
	Path   string
	ACLs   []ExportAcl
}

//NewShare creates a share struct corresponding to the export of path on server
func NewShare(server Server, path string) (*Share, error) {
	if path == "" {
		return nil, fmt.Errorf("invalid parameter: 'path' can't be empty")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("invalid parameter: 'path' must be absolute")
	}
	share := Share{
		Server: &server,
		Path:   path,
		ACLs:   []ExportAcl{},
	}
	return &share, nil
}

//AddAcl adds an ACL to the share
func (s *Share) AddAcl(acl ExportAcl) {
	acls := append(s.ACLs, acl)
	s.ACLs = acls
}

//Add configures and exports the share
func (s *Share) Add() error {
	var acls string
	for _, a := range s.ACLs {
		acl := a.Host + "("
		if len(a.SecurityModes) > 0 {
			acl += "sec="
			for _, s := range a.SecurityModes {
				acl += s.String()
			}
		} else {
			acl += "sec=sys"
		}
		if a.Options.ReadOnly {
			acl += ",ro"
		} else {
			acl += ",rw"
		}
		if a.Options.NoRootSquash {
			acl += ",no_root_squash"
		} else {
			acl += ",root_squash"
		}
		if a.Options.NoHide && !a.Options.CrossMount {
			acl += ",nohide"
		}
		if a.Options.CrossMount {
			acl += ",crossmnt"
		}
		if a.Options.SetFSID {
			acl += ",fsid=1"
		}
		if a.Options.Secure {
			acl += ",secure"
		}
		if a.Options.Async {
			acl += ",async"
		} else {
			acl += ",sync"
		}
		if a.Options.NoSubtreeCheck {
			acl += ",no_subtree_check"
		} else {
			acl += ",subtree_check"
		}
		if a.Options.AnonUID > 0 {
			acl += ",anonuid=" + strconv.Itoa(a.Options.AnonUID)
		}
		if a.Options.AnonGID > 0 {
			acl += ",anongid=" + strconv.Itoa(a.Options.AnonGID)
		}
		acl += ")"

		acls += acl + " "
	}
	data := map[string]interface{}{
		"MountPoint":   s.Path,
		"AccessRights": strings.TrimSpace(acls),
	}
	_, _, _, err := executeScript(s.Server.SshConfig, "nfs_server_path_export.sh", data)
	return err
}
