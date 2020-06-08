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
	"strings"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
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

// // FromProtocolHostDefinitionToProtocolGatewayDefinition converts a protocol.HostDefinition to protocol.GatewayDefinition
// func FromProtocolHostDefinitionToProtocolGatewayDefinition(in protocol.HostDefinition) protocol.GatewayDefinition {
// 	def := protocol.GatewayDefinition{
// 		ImageId:  in.ImageId,
// 		Cpu:      in.CpuCount,
// 		Ram:      in.Ram,
// 		Disk:     in.Disk,
// 		GpuCount: in.GpuCount,
// 		Sizing:   &protocol.HostSizing{},
// 	}
// 	*def.Sizing = *in.Sizing
// 	return def
// }

// FeatureSettingsFromProtocolToResource ...
func FeatureSettingsFromProtocolToResource(in *protocol.FeatureSettings) resources.FeatureSettings {
	if in == nil {
		return resources.FeatureSettings{}
	}
	return resources.FeatureSettings{
		SkipProxy:               in.SkipProxy,
		Serialize:               in.Serialize,
		SkipFeatureRequirements: in.IgnoreFeatureRequirements,
		SkipSizingRequirements:  in.IgnoreSizingRequirements,
		AddUnconditionally:      in.AddUnconditionally,
	}
}

func HostSizingRequirementsFromProtocolToAbstract(in *protocol.HostSizing) *abstract.HostSizingRequirements {
	if in == nil {
		return &abstract.HostSizingRequirements{}
	}
	return &abstract.HostSizingRequirements{
		MinCores:    int(in.MinCpuCount),
		MaxCores:    int(in.MaxCpuCount),
		MinRAMSize:  in.MinRamSize,
		MaxRAMSize:  in.MaxRamSize,
		MinDiskSize: int(in.MinDiskSize),
		MinGPU:      int(in.GpuCount),
		MinCPUFreq:  in.MinCpuFreq,
	}
}

func NFSExportOptionsFromProtocolToString(in *protocol.NFSExportOptions) string {
	if in == nil {
		return "rw,async"
	}

	var out string
	if in.ReadOnly {
		out += "ro,"
	} else {
		out += "rw,"
	}
	if !in.RootSquash {
		out += "no_root_squash,"
	}
	if in.Secure {
		out += "secure,"
	} else {
		out += "insecure,"
	}
	if in.Async {
		out += "async,"
	} else {
		out += "sync,"
	}
	if in.NoHide {
		out += "nohide,"
	}
	if in.CrossMount {
		out += "crossmnt,"
	}
	if !in.SubtreeCheck {
		out += "no_subtree_check,"
	}
	out = strings.TrimRight(out, ",")
	return out
}
