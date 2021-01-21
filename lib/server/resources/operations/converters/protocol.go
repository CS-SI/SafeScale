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

package converters

// Contains functions that are used to convert from Protocol

import (
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"strings"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// SSHConfigFromProtocolToSystem converts a protocol.SshConfig into a system.SSHConfig
func SSHConfigFromProtocolToSystem(from *protocol.SshConfig) *system.SSHConfig {
	var gw *system.SSHConfig
	if from.Gateway != nil {
		gw = SSHConfigFromProtocolToSystem(from.Gateway)
	}
	return &system.SSHConfig{
		User:          from.User,
		Hostname:      from.HostName,
		IPAddress:     from.Host,
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

// ClusterRequestFromProtocolToAbstract ...
func ClusterRequestFromProtocolToAbstract(in *protocol.ClusterCreateRequest) (_ abstract.ClusterRequest, xerr fail.Error) {
	nullCR := abstract.ClusterRequest{}

	var (
		gatewaySizing *abstract.HostSizingRequirements
		masterSizing  *abstract.HostSizingRequirements
		nodeSizing    *abstract.HostSizingRequirements
	)
	if in.GatewaySizing != "" {
		gatewaySizing, _, xerr = HostSizingRequirementsFromStringToAbstract(in.GatewaySizing)
		if xerr != nil {
			return nullCR, xerr
		}
	}
	if gatewaySizing == nil {
		gatewaySizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}

	if in.MasterSizing != "" {
		masterSizing, _, xerr = HostSizingRequirementsFromStringToAbstract(in.MasterSizing)
		if xerr != nil {
			return nullCR, xerr
		}
	}
	if masterSizing == nil {
		masterSizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}

	if in.NodeSizing != "" {
		nodeSizing, _, xerr = HostSizingRequirementsFromStringToAbstract(in.NodeSizing)
		if xerr != nil {
			return nullCR, xerr
		}
	}
	if nodeSizing == nil {
		nodeSizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}

	disabled := map[string]struct{}{}
	for _, v := range in.Disabled {
		disabled[v] = struct{}{}
	}

	out := abstract.ClusterRequest{
		Name:                    in.Name,
		CIDR:                    in.Cidr,
		Domain:                  in.Domain,
		Complexity:              clustercomplexity.Enum(in.Complexity),
		Flavor:                  clusterflavor.Enum(in.Flavor),
		GatewaysDef:             *gatewaySizing,
		MastersDef:              *masterSizing,
		NodesDef:                *nodeSizing,
		OS:                      in.Os,
		KeepOnFailure:           in.KeepOnFailure,
		DisabledDefaultFeatures: disabled,
		InitialNodeCount:        uint(in.NodeCount),
	}
	return out, nil
}

// SecurityGroupRuleFromProtocolToAbstract does what the name says
func SecurityGroupRuleFromProtocolToAbstract(in *protocol.SecurityGroupRule) (abstract.SecurityGroupRule, fail.Error) {
	var out abstract.SecurityGroupRule
	if in == nil {
		return out, fail.InvalidParameterError("in", "cannot be nil")
	}
	out.IDs = in.Ids
	out.Description = in.Description
	out.Direction = securitygroupruledirection.Enum(in.Direction)
	out.Protocol = in.Protocol
	out.EtherType = ipversion.Enum(in.EtherType)
	out.PortFrom = in.PortFrom
	out.PortTo = in.PortTo
	out.Targets = in.Involved
	return out, nil
}

// SecurityGroupRulesFromProtocolToAbstract does what the name says
func SecurityGroupRulesFromProtocolToAbstract(in []*protocol.SecurityGroupRule) ([]abstract.SecurityGroupRule, fail.Error) {
	out := make([]abstract.SecurityGroupRule, 0, len(in))
	for _, v := range in {
		rule, xerr := SecurityGroupRuleFromProtocolToAbstract(v)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to convert '*protocol.SecurityGroupRule' to 'abstract.SecurityGroupRule'")
		}
		out = append(out, rule)
	}
	return out, nil
}

// SecurityGroupFromProtocolToAbstract ...
func SecurityGroupFromProtocolToAbstract(in *protocol.SecurityGroupResponse) (abstract.SecurityGroup, fail.Error) {
	if in == nil {
		return abstract.SecurityGroup{}, fail.InvalidParameterError("in", "cannot be nil")
	}

	rules, xerr := SecurityGroupRulesFromProtocolToAbstract(in.Rules)
	if xerr != nil {
		return abstract.SecurityGroup{}, xerr
	}

	out := abstract.SecurityGroup{
		ID:          in.GetId(),
		Name:        in.GetName(),
		Description: in.GetDescription(),
		Rules:       rules,
	}
	return out, nil
}
