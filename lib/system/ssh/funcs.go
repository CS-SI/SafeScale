//go:build !tunnel
// +build !tunnel

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

package ssh

import (
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

var (
	sshErrorMap = map[int]string{
		1:  "Malformed configuration or invalid cli options",
		2:  "Connection failed",
		65: "Host not allowed to connect",
		66: "General error in ssh protocol",
		67: "Key exchange failed",
		69: "MAC error",
		70: "Compression error",
		71: "Service not available",
		72: "Protocol version not supported",
		73: "Host key not verifiable",
		74: "Connection failed",
		75: "Disconnected by application",
		76: "Too many connections",
		77: "Authentication canceled by user",
		78: "No more authentication methods available",
		79: "Invalid user name",
	}
	scpErrorMap = map[int]string{
		1:  "General error in file copy",
		2:  "Destination is not directory, but it should be",
		3:  "Maximum symlink level exceeded",
		4:  "Connecting to host failed",
		5:  "Connection broken",
		6:  "File does not exist",
		7:  "No permission to access file",
		8:  "General error in sftp protocol",
		9:  "File transfer protocol mismatch",
		10: "No file matches a given criteria",
		65: "Host not allowed to connect",
		66: "General error in ssh protocol",
		67: "Key exchange failed",
		69: "MAC error",
		70: "Compression error",
		71: "Service not available",
		72: "Protocol version not supported",
		73: "Host key not verifiable",
		74: "Connection failed",
		75: "Disconnected by application",
		76: "Too many connections",
		77: "Authentication canceled by user",
		78: "No more authentication methods available",
		79: "Invalid user name",
	}
)

// SSHErrorString returns if possible the string corresponding to SSH execution
func SSHErrorString(retcode int) string {
	if msg, ok := sshErrorMap[retcode]; ok {
		return msg
	}
	return "Unqualified error"
}

// SCPErrorString returns if possible the string corresponding to SCP execution
func SCPErrorString(retcode int) string {
	if msg, ok := scpErrorMap[retcode]; ok {
		return msg
	}
	return "Unqualified error"
}

// CloseConnector is an helper function to close a connector (useable directly with defer)
func CloseConnector(conn api.Connector, err *fail.Error) {
	if valid.IsNull(conn) {
		return
	}

	derr := conn.Close()
	if err != nil {
		if *err != nil {
			_ = (*err).AddConsequence(fail.Wrap(derr, "failed to close tunnels"))
		} else {
			*err = derr
		}
	}
}
