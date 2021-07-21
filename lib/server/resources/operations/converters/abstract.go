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

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/system"
)

// Contains the function used to convert from abstract structures

// HostTemplateToHostEffectiveSizing converts an abstract.HostTemplate to an abstract.HostEffectiveSizing
func HostTemplateToHostEffectiveSizing(ht abstract.HostTemplate) *abstract.HostEffectiveSizing {
	hes := abstract.NewHostEffectiveSizing()
	hes.Cores = ht.Cores
	hes.RAMSize = ht.RAMSize
	hes.DiskSize = ht.DiskSize
	hes.GPUNumber = ht.GPUNumber
	hes.CPUFreq = ht.CPUFreq
	return hes
}

// VolumeAttachmentFromAbstractToProtocol ...
func VolumeAttachmentFromAbstractToProtocol(in *abstract.VolumeAttachment) *protocol.VolumeAttachmentResponse {
	return &protocol.VolumeAttachmentResponse{
		Host:      &protocol.Reference{Id: in.ServerID},
		MountPath: in.MountPoint,
		Format:    in.Format,
		Device:    in.Device,
	}
}

// HostEffectiveSizingFromAbstractToProtocol ...
func HostEffectiveSizingFromAbstractToProtocol(in *abstract.HostEffectiveSizing) *protocol.HostDefinition {
	return &protocol.HostDefinition{
		ImageId: in.ImageID,
		Sizing: &protocol.HostSizing{
			MinCpuCount: int32(in.Cores),
			MaxCpuCount: int32(in.Cores),
			MinRamSize:  in.RAMSize,
			MaxRamSize:  in.RAMSize,
			MinDiskSize: int32(in.DiskSize),
			GpuCount:    int32(in.GPUNumber),
			MinCpuFreq:  in.CPUFreq,
		},
	}
}

// HostTemplateFromAbstractToProtocol ...
func HostTemplateFromAbstractToProtocol(in abstract.HostTemplate) *protocol.HostTemplate {
	return &protocol.HostTemplate{
		Id:       in.ID,
		Name:     in.Name,
		Cores:    int32(in.Cores),
		Ram:      int32(in.RAMSize),
		Disk:     int32(in.DiskSize),
		GpuCount: int32(in.GPUNumber),
		GpuType:  in.GPUType,
	}
}

// ImageFromAbstractToProtocol ...
func ImageFromAbstractToProtocol(in *abstract.Image) *protocol.Image {
	return &protocol.Image{
		Id:   in.ID,
		Name: in.Name,
	}
}

// NetworkFromAbstractToProtocol ...
func NetworkFromAbstractToProtocol(in *abstract.Network) *protocol.Network {
	out := &protocol.Network{
		Id:         in.ID,
		Name:       in.Name,
		Cidr:       in.CIDR,
		DnsServers: in.DNSServers,
	}
	return out
}

// SubnetFromAbstractToProtocol ...
func SubnetFromAbstractToProtocol(in *abstract.Subnet) *protocol.Subnet {
	var pbVIP *protocol.VirtualIp
	if in.VIP != nil {
		pbVIP = VirtualIPFromAbstractToProtocol(*(in.VIP))
	}
	return &protocol.Subnet{
		Id:         in.ID,
		Name:       in.Name,
		Cidr:       in.CIDR,
		GatewayIds: in.GatewayIDs,
		VirtualIp:  pbVIP,
		Failover:   len(in.GatewayIDs) > 1,
		State:      protocol.SubnetState(in.State),
	}
}

// HostSizingRequirementsFromAbstractToProtocol converts a protobuf HostSizing message to abstract.HostSizingRequirements
func HostSizingRequirementsFromAbstractToProtocol(src abstract.HostSizingRequirements) protocol.HostSizing {
	return protocol.HostSizing{
		MinCpuCount: int32(src.MinCores),
		MaxCpuCount: int32(src.MaxCores),
		MinCpuFreq:  src.MinCPUFreq,
		GpuCount:    int32(src.MinGPU),
		MinRamSize:  src.MinRAMSize,
		MaxRamSize:  src.MaxRAMSize,
		MinDiskSize: int32(src.MinDiskSize),
	}
}

// HostSizingRequirementsFromAbstractToPropertyV2 ...
func HostSizingRequirementsFromAbstractToPropertyV2(src abstract.HostSizingRequirements) *propertiesv2.HostSizingRequirements {
	return &propertiesv2.HostSizingRequirements{
		MinCores:    src.MinCores,
		MaxCores:    src.MaxCores,
		MinRAMSize:  src.MinRAMSize,
		MaxRAMSize:  src.MaxRAMSize,
		MinDiskSize: src.MinDiskSize,
		MinGPU:      src.MinGPU,
		MinCPUFreq:  src.MinCPUFreq,
		Replaceable: src.Replaceable,
	}
}

// VirtualIPFromAbstractToProtocol converts a *abstract.VirtualIP to a protocol.VirtualIp
func VirtualIPFromAbstractToProtocol(in abstract.VirtualIP) *protocol.VirtualIp {
	out := protocol.VirtualIp{
		Id:        in.ID,
		NetworkId: in.NetworkID,
		PrivateIp: in.PrivateIP,
		PublicIp:  in.PublicIP,
	}
	out.Hosts = make([]*protocol.Host, 0, len(in.Hosts))
	for _, i := range in.Hosts {
		out.Hosts = append(out.Hosts, HostCoreFromAbstractToProtocol(i))
	}
	return &out
}

// HostEffectiveSizingFromAbstractToPropertyV2 ...
func HostEffectiveSizingFromAbstractToPropertyV2(ahes *abstract.HostEffectiveSizing) *propertiesv2.HostEffectiveSizing {
	phes := propertiesv2.NewHostEffectiveSizing()
	phes.Cores = ahes.Cores
	phes.RAMSize = ahes.RAMSize
	phes.DiskSize = ahes.DiskSize
	phes.GPUNumber = ahes.GPUNumber
	phes.CPUFreq = ahes.CPUFreq
	return phes
}

// HostCoreFromAbstractToProtocol ...
func HostCoreFromAbstractToProtocol(in *abstract.HostCore) *protocol.Host {
	ph := &protocol.Host{
		Id:         in.ID,
		Name:       in.Name,
		PrivateKey: in.PrivateKey,
	}
	return ph
}

// HostFullFromAbstractToProtocol ...
func HostFullFromAbstractToProtocol(in *abstract.HostFull) *protocol.Host {
	state := in.Core.LastState
	if in.CurrentState != hoststate.Unknown {
		state = in.CurrentState
	}
	ph := &protocol.Host{
		Id:         in.Core.ID,
		Name:       in.Core.Name,
		State:      HostStateFromAbstractToProtocol(state),
		PrivateKey: in.Core.PrivateKey,
	}
	if in.Networking != nil {
		ph.PublicIp = in.Networking.PublicIPv4
		if ip, ok := in.Networking.IPv4Addresses[in.Networking.DefaultSubnetID]; ok {
			ph.PrivateIp = ip
		}
		ph.GatewayId = in.Networking.DefaultGatewayID
	}
	return ph
}

// HostCoreToHostFull ...
func HostCoreToHostFull(in abstract.HostCore) *abstract.HostFull {
	return &abstract.HostFull{Core: &in}
}

// HostDescriptionFromAbstractToPropertyV1 ...
func HostDescriptionFromAbstractToPropertyV1(src abstract.HostDescription) *propertiesv1.HostDescription {
	return &propertiesv1.HostDescription{
		Created: src.Created,
		Creator: src.Creator,
		Updated: src.Updated,
		Purpose: src.Purpose,
		Tenant:  src.Tenant,
	}
}

// HostNetworkingFromAbstractToPropertyV2 ...
func HostNetworkingFromAbstractToPropertyV2(src abstract.HostNetworking) *propertiesv2.HostNetworking {
	return &propertiesv2.HostNetworking{
		IsGateway:       src.IsGateway,
		DefaultSubnetID: src.DefaultSubnetID,
		SubnetsByID:     src.SubnetsByID,
		SubnetsByName:   src.SubnetsByName,
		PublicIPv4:      src.PublicIPv4,
		PublicIPv6:      src.PublicIPv6,
		IPv4Addresses:   src.IPv4Addresses,
		IPv6Addresses:   src.IPv6Addresses,
	}
}

// HostStateFromAbstractToProtocol ...
func HostStateFromAbstractToProtocol(in hoststate.Enum) protocol.HostState {
	return protocol.HostState(in)
}

// BucketListFromAbstractToProtocol ...
func BucketListFromAbstractToProtocol(in []string) *protocol.BucketList {
	out := protocol.BucketList{Buckets: []*protocol.Bucket{}}
	for _, v := range in {
		b := protocol.Bucket{
			Name: v,
		}
		out.Buckets = append(out.Buckets, &b)
	}
	return &out
}

// SSHConfigFromAbstractToProtocol ...
func SSHConfigFromAbstractToProtocol(in system.SSHConfig) *protocol.SshConfig {
	var pbPrimaryGateway, pbSecondaryGateway *protocol.SshConfig
	if in.GatewayConfig != nil {
		pbPrimaryGateway = SSHConfigFromAbstractToProtocol(*in.GatewayConfig)
	}
	if in.SecondaryGatewayConfig != nil {
		pbSecondaryGateway = SSHConfigFromAbstractToProtocol(*in.SecondaryGatewayConfig)
	}
	if in.Port == 0 {
		in.Port = 22
	}
	return &protocol.SshConfig{
		HostName:         in.Hostname,
		User:             in.User,
		Host:             in.IPAddress,
		Port:             int32(in.Port),
		PrivateKey:       in.PrivateKey,
		Gateway:          pbPrimaryGateway,
		SecondaryGateway: pbSecondaryGateway,
	}
}

// HostStatusFromAbstractToProtocol ...
func HostStatusFromAbstractToProtocol(name string, status hoststate.Enum) *protocol.HostStatus {
	return &protocol.HostStatus{
		Name:   name,
		Status: protocol.HostState(status),
	}
}

// VolumeSpeedFromAbstractToProtocol ...
func VolumeSpeedFromAbstractToProtocol(in volumespeed.Enum) protocol.VolumeSpeed {
	switch in {
	case volumespeed.Cold:
		return protocol.VolumeSpeed_VS_COLD
	case volumespeed.Ssd:
		return protocol.VolumeSpeed_VS_SSD
	case volumespeed.Hdd:
		fallthrough
	default:
		return protocol.VolumeSpeed_VS_HDD
	}
}

// ClusterIdentityFromAbstractToProtocol converts an abstract.ClusterIdentity to protocol.ClusterIdentity
func ClusterIdentityFromAbstractToProtocol(in abstract.ClusterIdentity) *protocol.ClusterIdentity {
	return &protocol.ClusterIdentity{
		Name:          in.Name,
		Complexity:    protocol.ClusterComplexity(in.Complexity),
		Flavor:        protocol.ClusterFlavor(in.Flavor),
		AdminPassword: in.AdminPassword,
	}
}

// ClusterListFromAbstractToProtocol converts list of cluster identity to protocol.ClusterListResponse
func ClusterListFromAbstractToProtocol(in []abstract.ClusterIdentity) *protocol.ClusterListResponse {
	out := &protocol.ClusterListResponse{}
	out.Clusters = make([]*protocol.ClusterResponse, 0, len(in))
	for _, v := range in {
		cr := &protocol.ClusterResponse{
			Identity: ClusterIdentityFromAbstractToProtocol(v),
		}
		out.Clusters = append(out.Clusters, cr)
	}
	return out
}

// SecurityGroupRulesFromAbstractToProtocol converts a []abstract.SecurityGroupRule to a []*protocol.SecurityGroupRule
func SecurityGroupRulesFromAbstractToProtocol(in abstract.SecurityGroupRules) []*protocol.SecurityGroupRule {
	out := make([]*protocol.SecurityGroupRule, 0, len(in))
	for _, v := range in {
		out = append(out, SecurityGroupRuleFromAbstractToProtocol(*v))
	}
	return out
}

// SecurityGroupRuleFromAbstractToProtocol converts an abstract.SecurityGroupRule to a *protocol.SecurityGroupRule
func SecurityGroupRuleFromAbstractToProtocol(in abstract.SecurityGroupRule) *protocol.SecurityGroupRule {
	out := &protocol.SecurityGroupRule{
		Ids:         in.IDs,
		Description: in.Description,
		Direction:   protocol.SecurityGroupRuleDirection(in.Direction),
		Protocol:    in.Protocol,
		EtherType:   protocol.SecurityGroupRuleEtherType(in.EtherType),
		PortFrom:    in.PortFrom,
		PortTo:      in.PortTo,
		Involved:    in.Targets,
	}
	return out
}

// SecurityGroupFromAbstractToProtocol converts a abstract.SecurityGroup to a *protocol.SecurityGroup
func SecurityGroupFromAbstractToProtocol(in abstract.SecurityGroup) *protocol.SecurityGroupResponse {
	return &protocol.SecurityGroupResponse{
		Id:          in.ID,
		Name:        in.Name,
		Description: in.Description,
		Rules:       SecurityGroupRulesFromAbstractToProtocol(in.Rules),
	}
}

// ClusterStateFromAbstractToProtocol ...
func ClusterStateFromAbstractToProtocol(in clusterstate.Enum) *protocol.ClusterStateResponse {
	return &protocol.ClusterStateResponse{
		State: protocol.ClusterState(in),
	}
}
