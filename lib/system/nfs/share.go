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
    "path/filepath"

    "github.com/CS-SI/SafeScale/lib/system/nfs/enums/securityflavor"
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ExportOptions ...
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

// ExportACL ...
type ExportACL struct {
    // Host contains the pattern of hosts authorized (cf. exports man page)
    Host string
    // SecurityMode contains all the security mode allowed for the Host
    SecurityModes []securityflavor.Enum
    // Options contains the options of the export ACL
    Options ExportOptions
}

// Share details the parameter of a NFS share
type Share struct {
    Server *Server
    Path   string
    // ACLs   []ExportACL
    Options string
}

// NewShare creates a share struct corresponding to the export of path on server
func NewShare(server *Server, path, options string) (*Share, fail.Error) {
    if path == "" {
        return nil, fail.InvalidParameterError("path", "cannot be empty")
    }
    if !filepath.IsAbs(path) {
        return nil, fail.InvalidParameterError("path", "must be absolute")
    }
    share := Share{
        Server: server,
        Path:   path,
        // ACLs:   []ExportACL{},
        Options: options,
    }
    return &share, nil
}

// // AddACL adds an ACL to the share
// func (s *Share) AddACL(acl ExportACL) {
// 	acls := append(s.ACLs, acl)
// 	s.ACLs = acls
// }

// Add configures and exports the share
func (s *Share) Add(task concurrency.Task) fail.Error {
    // var acls string
    // for _, a := range s.ACLs {
    // 	acl := a.Host + "("
    // 	if len(a.SecurityModes) > 0 {
    // 		acl += "sec="
    // 		for i, item := range a.SecurityModes {
    // 			acl += strings.ToLower(item.String())
    // 			if i != 0 {
    // 				acl += ","
    // 			}
    // 		}
    // 	} else {
    // 		acl += "sec=sys"
    // 	}
    // 	if a.Options.ReadOnly {
    // 		acl += ",ro"
    // 	} else {
    // 		acl += ",rw"
    // 	}
    // 	if a.Options.NoRootSquash {
    // 		acl += ",no_root_squash"
    // 	} else {
    // 		acl += ",root_squash"
    // 	}
    // 	if a.Options.NoHide && !a.Options.CrossMount {
    // 		acl += ",nohide"
    // 	}
    // 	if a.Options.CrossMount {
    // 		acl += ",crossmnt"
    // 	}
    // 	if a.Options.SetFSID {
    // 		acl += ",fsid=1"
    // 	}
    // 	if a.Options.Secure {
    // 		acl += ",secure"
    // 	}
    // 	if a.Options.Async {
    // 		acl += ",async"
    // 	} else {
    // 		acl += ",sync"
    // 	}
    // 	if a.Options.NoSubtreeCheck {
    // 		acl += ",no_subtree_check"
    // 	} else {
    // 		acl += ",subtree_check"
    // 	}
    // 	if a.Options.AnonUID > 0 {
    // 		acl += ",anonuid=" + strconv.Itoa(a.Options.AnonUID)
    // 	}
    // 	if a.Options.AnonGID > 0 {
    // 		acl += ",anongid=" + strconv.Itoa(a.Options.AnonGID)
    // 	}
    // 	acl += ")"

    // 	acls += acl + " "
    // }
    data := map[string]interface{}{
        "Path": s.Path,
        // "AccessRights": strings.TrimSpace(acls),
        "Options": s.Options,
    }

    // retcode, stdout, stderr, err := executeScript(task, *s.getServer.SSHConfig, "nfs_server_path_export.sh", data)
    // return fail.ReturnedValuesFromShellToError(retcode, stdout, stderr, err, "Error executing script to export a shared directory")
    _, xerr := executeScript(task, *s.Server.SSHConfig, "nfs_server_path_export.sh", data)
    if xerr != nil {
        return fail.Wrap(xerr, "error executing script to export a shared directory")
    }
    return nil
}
