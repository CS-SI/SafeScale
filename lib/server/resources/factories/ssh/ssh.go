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

package share

import (
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

var (
	currentSSHConnectorFactory = defaultSSHConnectorFactory
)

// defaultSSHConnectorFactory is the default factory to create SSH Connector, based on ssh.cliconnector
func defaultSSHConnectorFactory(config sshapi.Config) (sshapi.Connector, fail.Error) {
	return ssh.NewCliConnector(config)
}

// ReplaceConnectorFactory replaces the default SSH Connector factory by the one provided
func ReplaceConnectorFactory(cb func(sshapi.Config) (sshapi.Connector, fail.Error)) fail.Error {
	if cb == nil {
		return fail.InvalidParameterCannotBeEmptyStringError("cb")
	}

	currentSSHConnectorFactory = cb
	return nil
}

// ResetConnectorFactory resets the Connector Factory to the default factory function
func ResetConnectorFactory() {
	currentSSHConnectorFactory = defaultSSHConnectorFactory
}

// NewConnector creates a connector using the factory
func NewConnector(conf sshapi.Config) (sshapi.Connector, fail.Error) {
	if valid.IsNull(conf) {
		return nil, fail.InvalidParameterError("conf", "cannot be null value of 'ssh.Config'")
	}

	return currentSSHConnectorFactory(conf)
}
