/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	if task.Aborted() {
		return fail.AbortedError(nil, "canceled")
	}

	data := map[string]interface{}{
		"Path": s.Path,
		// "AccessRights": strings.TrimSpace(acls),
		"Options": s.Options,
	}

	if _, xerr := executeScript(task, *s.Server.SSHConfig, "nfs_server_path_export.sh", data); xerr != nil {
		return fail.Wrap(xerr, "failed to export a shared directory")
	}
	return nil
}
