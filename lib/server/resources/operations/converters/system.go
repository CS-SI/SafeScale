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

package converters

// Contains functions that are used to convert from system

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/system"
)

// ToProtocolSSHConfig converts a system.SSHConfig into a SshConfig
func SSHConfigFromSystemToProtocol(from *system.SSHConfig) *protocol.SshConfig {
	var gw *protocol.SshConfig
	if from.GatewayConfig != nil {
		gw = SSHConfigFromSystemToProtocol(from.GatewayConfig)
	}
	return &protocol.SshConfig{
		Gateway:    gw,
		Host:       from.Host,
		Port:       int32(from.Port),
		PrivateKey: from.PrivateKey,
		User:       from.User,
	}
}
