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

// Contains functions that are used to convert from Protocol

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/system"
)

// SSHConfigFromProtocolToSystem converts a protocol.SshConfig into a system.SSHConfig
func SSHConfigFromProtocolToSystem(from *protocol.SshConfig) *system.SSHConfig {
	var gw *system.SSHConfig
	if from.Gateway != nil {
		gw = SSHConfigFromProtocolToSystem(from.Gateway)
	}
	return &system.SSHConfig{
		User:          from.User,
		Host:          from.Host,
		PrivateKey:    from.PrivateKey,
		Port:          int(from.Port),
		GatewayConfig: gw,
	}
}

// FromProtocolHostDefinitionToProtocolGatewayDefinition converts a protocol.HostDefinition to protocol.GatewayDefinition
func FromProtocolHostDefinitionToProtocolGatewayDefinition(in protocol.HostDefinition) protocol.GatewayDefinition {
	def := protocol.GatewayDefinition{
		ImageId:  in.ImageId,
		Cpu:      in.CpuCount,
		Ram:      in.Ram,
		Disk:     in.Disk,
		GpuCount: in.GpuCount,
		Sizing:   &protocol.HostSizing{},
	}
	*def.Sizing = *in.Sizing
	return def
}
