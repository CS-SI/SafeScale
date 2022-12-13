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

package converters

// Contains functions that are used to convert from property

import (
	"strings"

	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
)

// ShareFromPropertyToProtocol convert a share from host to protocol message
func ShareFromPropertyToProtocol(hostName string, share *propertiesv1.HostShare) *protocol.ShareDefinition {
	return &protocol.ShareDefinition{
		Id:              share.ID,
		Name:            share.Name,
		Host:            &protocol.Reference{Name: hostName},
		Path:            share.Path,
		Type:            "nfs",
		OptionsAsString: share.ShareOptions,
	}
}

// ShareMountFromPropertyToProtocol convert share mount on host to protocol message
func ShareMountFromPropertyToProtocol(shareName string, hostName string, mount *propertiesv1.HostRemoteMount) *protocol.ShareMountDefinition {
	return &protocol.ShareMountDefinition{
		Share: &protocol.Reference{Name: shareName},
		Host:  &protocol.Reference{Name: hostName},
		Path:  mount.Path,
		Type:  mount.FileSystem,
	}
}

// ShareMountListFromPropertyToProtocol converts share mounts from host to protocol message
func ShareMountListFromPropertyToProtocol(hostName string, share *propertiesv1.HostShare, mounts map[string]*propertiesv1.HostRemoteMount) *protocol.ShareMountList {
	var pbMounts []*protocol.ShareMountDefinition
	for k, v := range mounts {
		pbMounts = append(pbMounts, &protocol.ShareMountDefinition{
			Host:  &protocol.Reference{Name: k},
			Share: &protocol.Reference{Name: share.Name},
			Path:  v.Path,
			Type:  "nfs",
		})
	}
	return &protocol.ShareMountList{
		Share:     ShareFromPropertyToProtocol(hostName, share),
		MountList: pbMounts,
	}
}

// HostSizingRequirementsFromPropertyToProtocol ...
func HostSizingRequirementsFromPropertyToProtocol(in propertiesv2.HostSizingRequirements) *protocol.HostSizing {
	return &protocol.HostSizing{
		MinCpuCount: int32(in.MinCores),
		MaxCpuCount: int32(in.MaxCores),
		MinRamSize:  in.MinRAMSize,
		MaxRamSize:  in.MaxRAMSize,
		MinDiskSize: int32(in.MinDiskSize),
		GpuCount:    int32(in.MinGPU),
		MinCpuFreq:  in.MinCPUFreq,
	}
}

// ClusterControlplaneFromPropertyToProtocol does what the name says
func ClusterControlplaneFromPropertyToProtocol(in propertiesv1.ClusterControlplane) *protocol.ClusterControlplane {
	out := protocol.ClusterControlplane{}
	if in.VirtualIP != nil {
		out.Vip = VirtualIPFromAbstractToProtocol(*in.VirtualIP)
	}
	return &out
}

// ClusterCompositeFromPropertyToProtocol does what the name says
func ClusterCompositeFromPropertyToProtocol(in propertiesv1.ClusterComposite) *protocol.ClusterComposite {
	out := protocol.ClusterComposite{}
	out.Tenants = make([]string, len(in.Tenants))
	copy(out.Tenants, in.Tenants)
	return &out
}

// ClusterDefaultsFromPropertyV2ToProtocol does what the name says
func ClusterDefaultsFromPropertyV2ToProtocol(in propertiesv2.ClusterDefaults) *protocol.ClusterDefaults {
	return &protocol.ClusterDefaults{
		GatewaySizing: HostSizingRequirementsFromPropertyToProtocol(in.GatewaySizing),
		MasterSizing:  HostSizingRequirementsFromPropertyToProtocol(in.MasterSizing),
		NodeSizing:    HostSizingRequirementsFromPropertyToProtocol(in.NodeSizing),
		Image:         in.Image,
	}
}

// ClusterDefaultsFromPropertyV3ToProtocol does what the name says
func ClusterDefaultsFromPropertyV3ToProtocol(in propertiesv3.ClusterDefaults) *protocol.ClusterDefaults {
	return &protocol.ClusterDefaults{
		GatewaySizing:     HostSizingRequirementsFromPropertyToProtocol(in.GatewaySizing),
		MasterSizing:      HostSizingRequirementsFromPropertyToProtocol(in.MasterSizing),
		NodeSizing:        HostSizingRequirementsFromPropertyToProtocol(in.NodeSizing),
		Image:             in.Image,
		FeatureParameters: in.FeatureParameters,
	}
}

// ClusterNetworkFromPropertyToProtocol does what the name says
func ClusterNetworkFromPropertyToProtocol(in propertiesv3.ClusterNetwork) *protocol.ClusterNetwork {
	return &protocol.ClusterNetwork{
		NetworkId:          in.NetworkID,
		SubnetId:           in.SubnetID,
		Cidr:               in.CIDR,
		Domain:             in.Domain,
		GatewayId:          in.GatewayID,
		GatewayIp:          in.GatewayIP,
		SecondaryGatewayId: in.SecondaryGatewayID,
		SecondaryGatewayIp: in.SecondaryGatewayIP,
		DefaultRouteIp:     in.DefaultRouteIP,
		PrimaryPublicIp:    in.PrimaryPublicIP,
		SecondaryPublicIp:  in.SecondaryPublicIP,
		EndpointIp:         in.EndpointIP,
	}
}

// ClusterFeaturesFromPropertyToProtocol does what the name says
func ClusterFeaturesFromPropertyToProtocol(in propertiesv1.ClusterFeatures) (*protocol.FeatureListResponse, *protocol.FeatureListResponse) {
	installed := &protocol.FeatureListResponse{}
	for k, v := range in.Installed {
		var requiredBy []string
		if len(v.RequiredBy) > 0 {
			for k := range v.RequiredBy {
				requiredBy = append(requiredBy, k)
			}
		}

		var requires []string
		if len(v.Requires) > 0 {
			for k := range v.Requires {
				requires = append(requires, k)
			}
		}

		item := &protocol.FeatureResponse{
			Name:       k,
			FileName:   v.FileName,
			RequiredBy: requiredBy,
			Requires:   requires,
		}
		installed.Features = append(installed.Features, item)
	}

	disabled := &protocol.FeatureListResponse{}
	for k := range in.Disabled {
		item := &protocol.FeatureResponse{
			Name: k,
		}
		disabled.Features = append(disabled.Features, item)
	}

	return installed, disabled
}

// SecurityGroupBondsFromPropertyToProtocol does what the name says
func SecurityGroupBondsFromPropertyToProtocol(in []*propertiesv1.SecurityGroupBond, target string) *protocol.SecurityGroupBondsResponse {
	out := &protocol.SecurityGroupBondsResponse{}
	switch strings.ToLower(target) {
	case "host", "hosts":
		out.Hosts = make([]*protocol.SecurityGroupBond, 0, len(in))
		for _, v := range in {
			item := &protocol.SecurityGroupBond{
				Id:       v.ID,
				Name:     v.Name,
				Disabled: v.Disabled,
			}
			out.Hosts = append(out.Hosts, item)
		}
	case "subnets", "subnet":
		out.Subnets = make([]*protocol.SecurityGroupBond, 0, len(in))
		for _, v := range in {
			item := &protocol.SecurityGroupBond{
				Id:       v.ID,
				Name:     v.Name,
				Disabled: v.Disabled,
			}
			out.Subnets = append(out.Subnets, item)
		}
	default:
	}
	return out
}

// SliceOfSecurityGroupBondFromPropertyToProtocol does what the name says
func SliceOfSecurityGroupBondFromPropertyToProtocol(in []*propertiesv1.SecurityGroupBond) []*protocol.SecurityGroupBond {
	out := make([]*protocol.SecurityGroupBond, 0, len(in))
	for _, v := range in {
		item := &protocol.SecurityGroupBond{
			Id:       v.ID,
			Name:     v.Name,
			Disabled: v.Disabled,
		}
		out = append(out, item)
	}
	return out
}

// ClusterNodeFromPropertyToProtocol converts a propertiesv3.ClusterNode to a protocol.Host
func ClusterNodeFromPropertyToProtocol(in propertiesv3.ClusterNode) *protocol.Host {
	return &protocol.Host{
		Id:        in.ID,
		Name:      in.Name,
		PublicIp:  in.PublicIP,
		PrivateIp: in.PrivateIP,
	}
}

// ClusterDefaultsPropertyV1ToV2 converts propertiesv1.ClusterDefaults to propertiesv2.ClusterDefaults
func ClusterDefaultsPropertyV1ToV2(in *propertiesv1.ClusterDefaults) *propertiesv2.ClusterDefaults {
	out := &propertiesv2.ClusterDefaults{
		Image: in.Image,
		GatewaySizing: propertiesv2.HostSizingRequirements{
			MinCores:    in.GatewaySizing.Cores,
			MinCPUFreq:  in.GatewaySizing.CPUFreq,
			MinGPU:      in.GatewaySizing.GPUNumber,
			MinRAMSize:  in.GatewaySizing.RAMSize,
			MinDiskSize: in.GatewaySizing.DiskSize,
			Replaceable: in.GatewaySizing.Replaceable,
		},
		MasterSizing: propertiesv2.HostSizingRequirements{
			MinCores:    in.MasterSizing.Cores,
			MinCPUFreq:  in.MasterSizing.CPUFreq,
			MinGPU:      in.MasterSizing.GPUNumber,
			MinRAMSize:  in.MasterSizing.RAMSize,
			MinDiskSize: in.MasterSizing.DiskSize,
			Replaceable: in.MasterSizing.Replaceable,
		},
		NodeSizing: propertiesv2.HostSizingRequirements{
			MinCores:    in.NodeSizing.Cores,
			MinCPUFreq:  in.NodeSizing.CPUFreq,
			MinGPU:      in.NodeSizing.GPUNumber,
			MinRAMSize:  in.NodeSizing.RAMSize,
			MinDiskSize: in.NodeSizing.DiskSize,
			Replaceable: in.NodeSizing.Replaceable,
		},
	}
	return out
}
