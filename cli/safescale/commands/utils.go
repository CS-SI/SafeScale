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

package commands

import (
	"fmt"
	"os"
	"strconv"

	"github.com/denisbrodbeck/machineid"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// GenerateClientIdentity builds a string identifying the client
func GenerateClientIdentity() string {
	id, _ := machineid.ProtectedID("safescale:" + strconv.Itoa(os.Getuid()))
	return id
}

// RemoteFileItem is a helper struct to ease the copy of local files to remote
type RemoteFileItem struct {
	Local        string
	Remote       string
	RemoteOwner  string
	RemoteRights string
}

// Upload transfers the local file to the hostname
func (rfc RemoteFileItem) Upload(hostname string) error {
	if rfc.Local == "" {
		return scerr.InvalidInstanceContentError("rfc.Local", "cannot be empty string")
	}
	if rfc.Remote == "" {
		return scerr.InvalidInstanceContentError("rfc.Remote", "cannot be empty string")

	}
	SSHClient := client.New().SSH

	// Copy the file
	retcode, _, _, err := SSHClient.Copy(rfc.Local, hostname+":"+rfc.Remote, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to copy file '%s'", rfc.Local)
	}

	// Updates owner and access rights if asked for
	cmd := ""
	if rfc.RemoteOwner != "" {
		cmd += "chown " + rfc.RemoteOwner + " " + rfc.Remote
	}
	if rfc.RemoteRights != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "chmod " + rfc.RemoteRights + " " + rfc.Remote
	}
	retcode, _, _, err = SSHClient.Run(hostname, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to update owner and/or access rights of the remote file")
	}

	return nil
}

// RemoveRemote deletes the remote file from host
func (rfc RemoteFileItem) RemoveRemote(hostname string) error {
	SSHClient := client.New().SSH
	cmd := "rm -rf " + rfc.Remote
	retcode, _, _, err := SSHClient.Run(hostname, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to remove file '%s:%s'", hostname, rfc.Remote)
	}
	return nil
}

// RemoteFilesHandler handles the copy of files and cleanup
type RemoteFilesHandler struct {
	items []*RemoteFileItem
}

// Add adds a RemoteFileItem in the handler
func (rfh *RemoteFilesHandler) Add(file *RemoteFileItem) {
	rfh.items = append(rfh.items, file)
}

// Count returns the number of files in the handler
func (rfh *RemoteFilesHandler) Count() uint {
	return uint(len(rfh.items))
}

// Upload executes the copy of files
func (rfh *RemoteFilesHandler) Upload(hostname string) error {
	for _, v := range rfh.items {
		err := v.Upload(hostname)
		if err != nil {
			return err
		}
	}
	return nil
}

// Cleanup executes the removal of remote files.
// Note: Removal of local files is the responsability of the caller, not the RemoteFilesHandler.
func (rfh *RemoteFilesHandler) Cleanup(hostname string) {
	for _, v := range rfh.items {
		err := v.RemoveRemote(hostname)
		if err != nil {
			logrus.Warnf(err.Error())
		}
	}
}
