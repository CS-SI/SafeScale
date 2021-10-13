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

package client

import (
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// RemoteFileItem is a helper struct to ease the copy of local files to remote
type RemoteFileItem struct {
	Local        string
	Remote       string
	RemoteOwner  string
	RemoteRights string
}

// Upload transfers the local file to the hostname
func (rfc RemoteFileItem) Upload(clientSession *Session, hostname string) error {
	if rfc.Local == "" {
		return fail.InvalidInstanceContentError("rfc.Local", "cannot be empty string")
	}
	if rfc.Remote == "" {
		return fail.InvalidInstanceContentError("rfc.Remote", "cannot be empty string")

	}

	// Copy the file
	retcode, _, _, xerr := clientSession.SSH.Copy(rfc.Local, hostname+":"+rfc.Remote, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if xerr != nil {
		return xerr
	}
	if retcode != 0 {
		return fail.NewError("failed to copy file '%s'", rfc.Local)
	}

	// Updates owner and access rights if asked for
	cmd := ""
	if rfc.RemoteOwner != "" {
		cmd += "sudo chown " + rfc.RemoteOwner + " " + rfc.Remote
	}
	if rfc.RemoteRights != "" {
		if cmd != "" {
			cmd += " && "
		}
		cmd += "sudo chmod " + rfc.RemoteRights + " " + rfc.Remote
	}
	if cmd != "" {
		retcode, _, _, xerr = clientSession.SSH.Run(hostname, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
		if xerr != nil {
			return xerr
		}
		if retcode != 0 {
			return fail.NewError("failed to update owner and/or access rights of the remote file")
		}
	}

	return nil
}

// UploadString transfers a string as file to the remote host
func (rfc RemoteFileItem) UploadString(clientSession *Session, content string, hostname string) error {
	if rfc.Remote == "" {
		return fail.InvalidInstanceContentError("rfc.Remote", "cannot be empty string")

	}

	// Copy the file
	retcode, _, _, err := clientSession.SSH.Copy(rfc.Local, hostname+":"+rfc.Remote, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fail.NewError("failed to copy file '%s'", rfc.Local)
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
	retcode, _, _, err = clientSession.SSH.Run(hostname, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fail.NewError("failed to update owner and/or access rights of the remote file")
	}
	return nil
}

// RemoveRemote deletes the remote file from host
func (rfc RemoteFileItem) RemoveRemote(clientSession *Session, hostname string) error {
	if clientSession == nil {
		return fail.InvalidParameterCannotBeNilError("clientSession")
	}

	cmd := "rm -rf " + rfc.Remote
	retcode, _, _, err := clientSession.SSH.Run(hostname, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil || retcode != 0 {
		return fail.NewError("failed to remove file '%s:%s'", hostname, rfc.Remote)
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
func (rfh *RemoteFilesHandler) Upload(clientSession *Session, hostname string) error {
	if rfh == nil {
		return fail.InvalidInstanceError()
	}
	if clientSession == nil {
		return fail.InvalidParameterCannotBeNilError("clientSession")
	}
	if hostname == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostname")
	}

	for _, v := range rfh.items {
		err := v.Upload(clientSession, hostname)
		if err != nil {
			return err
		}
	}
	return nil
}

// Cleanup executes the removal of remote files.
// Note: Removal of local files is the responsability of the caller, not the RemoteFilesHandler.
func (rfh *RemoteFilesHandler) Cleanup(clientSession *Session, hostname string) {
	for _, v := range rfh.items {
		xerr := v.RemoveRemote(clientSession, hostname)
		if xerr != nil {
			logrus.Warnf(xerr.Error())
		}
	}
}
