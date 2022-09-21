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

import (
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/stretchr/testify/require"
)

func Test_ShareFromPropertyToProtocol(t *testing.T) {

	hs := &propertiesv1.HostShare{
		ID:            "Host ID",
		Name:          "Nost Name",
		Path:          "Host Path",
		PathAcls:      "Host PathAcls",
		Type:          "Host Type",
		ShareAcls:     "Host ShareAcls",
		ShareOptions:  "Host ShareOptions",
		ClientsByID:   map[string]string{},
		ClientsByName: map[string]string{},
	}
	psd := ShareFromPropertyToProtocol("HostDefinition", hs)
	if reflect.TypeOf(psd).String() != "*protocol.ShareCreateRequest" {
		t.Error("Expect type *protocol.ShareCreateRequest")
		t.Fail()
	}
	require.EqualValues(t, hs.ID, psd.Id)
	require.EqualValues(t, hs.Name, psd.Name)
	require.EqualValues(t, hs.Path, psd.Path)
	require.EqualValues(t, psd.Host.Name, "HostDefinition")
	require.EqualValues(t, hs.ShareOptions, psd.OptionsAsString)

}

func Test_ShareMountFromPropertyToProtocol(t *testing.T) {

	hrm := &propertiesv1.HostRemoteMount{
		ShareID:    "HostRemoteMount ShareID",
		Export:     "HostRemoteMount Export",
		Path:       "HostRemoteMount Path",
		FileSystem: "HostRemoteMount FileSystem",
		Options:    "HostRemoteMount Options",
	}
	smp := ShareMountFromPropertyToProtocol("ShareName", "HostName", hrm)

	if reflect.TypeOf(smp).String() != "*protocol.ShareMountRequest" {
		t.Error("Expect type *protocol.ShareMountRequest")
		t.Fail()
	}

	require.EqualValues(t, smp.Share.Name, "ShareName")
	require.EqualValues(t, smp.Host.Name, "HostName")
	require.EqualValues(t, smp.Path, hrm.Path)
	require.EqualValues(t, smp.Type, hrm.FileSystem)

}

func Test_ShareMountListFromPropertyToProtocol(t *testing.T) {

	hs := &propertiesv1.HostShare{
		ID:            "Host ID",
		Name:          "Nost Name",
		Path:          "Host Path",
		PathAcls:      "Host PathAcls",
		Type:          "Host Type",
		ShareAcls:     "Host ShareAcls",
		ShareOptions:  "Host ShareOptions",
		ClientsByID:   map[string]string{},
		ClientsByName: map[string]string{},
	}
	mounts := map[string]*propertiesv1.HostRemoteMount{
		"remote": {
			ShareID:    "HostRemoteMount ShareID",
			Export:     "HostRemoteMount Export",
			Path:       "HostRemoteMount Path",
			FileSystem: "HostRemoteMount FileSystem",
			Options:    "HostRemoteMount Options",
		},
	}

	smp := ShareMountListFromPropertyToProtocol("HostName", hs, mounts)

	if reflect.TypeOf(smp).String() != "*protocol.ShareMountListRequest" {
		t.Error("Expect type *protocol.ShareMountListRequest")
		t.Fail()
	}

}

func Test_HostSizingRequirementsFromPropertyToProtocol(t *testing.T) {

	hsr := propertiesv2.HostSizingRequirements{
		MinCores:    1,
		MaxCores:    4,
		MinRAMSize:  1024,
		MaxRAMSize:  2048,
		MinDiskSize: 50,
		MinGPU:      1,
		MinCPUFreq:  1833,
		Replaceable: false,
	}
	hs := HostSizingRequirementsFromPropertyToProtocol(hsr)
	if reflect.TypeOf(hs).String() != "*protocol.HostSizing" {
		t.Error("Expect type *protocol.HostSizing")
		t.Fail()
	}

	require.EqualValues(t, hs.MinCpuCount, hsr.MinCores)
	require.EqualValues(t, hs.MaxCpuCount, hsr.MaxCores)
	require.EqualValues(t, hs.MinRamSize, hsr.MinRAMSize)
	require.EqualValues(t, hs.MaxRamSize, hsr.MaxRAMSize)
	require.EqualValues(t, hs.MinDiskSize, hsr.MinDiskSize)
	require.EqualValues(t, hs.GpuCount, hsr.MinCores)
	require.EqualValues(t, hs.MinCpuCount, hsr.MinGPU)
	require.EqualValues(t, hs.MinCpuFreq, hsr.MinCPUFreq)

}

func Test_ClusterControlplaneFromPropertyToProtocol(t *testing.T) {

	ccp := ClusterControlplaneFromPropertyToProtocol(propertiesv1.ClusterControlplane{
		VirtualIP: &abstract.VirtualIP{
			ID:        "VIP ID",
			Name:      "VIP Name",
			SubnetID:  "VIP SubnetID",
			PrivateIP: "VIP PrivateIP",
			PublicIP:  "VIP PublicIP",
			Hosts:     []*abstract.HostCore{},
			NetworkID: "VIP NetworkID",
		},
	})
	if reflect.TypeOf(ccp).String() != "*protocol.ClusterControlplane" {
		t.Error("Expect type *protocol.ClusterControlplane")
		t.Fail()
	}

}

func Test_ClusterCompositeFromPropertyToProtocol(t *testing.T) {

	cc := ClusterCompositeFromPropertyToProtocol(propertiesv1.ClusterComposite{
		Tenants: []string{},
	})
	if reflect.TypeOf(cc).String() != "*protocol.ClusterComposite" {
		t.Error("Expect type *protocol.ClusterComposite")
		t.Fail()
	}

}

func Test_ClusterDefaultsFromPropertyV2ToProtocol(t *testing.T) {

	cc := ClusterDefaultsFromPropertyV2ToProtocol(propertiesv2.ClusterDefaults{
		GatewaySizing: propertiesv2.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    1,
			MinRAMSize:  64,
			MaxRAMSize:  128,
			MinDiskSize: 50,
			MinGPU:      1,
			MinCPUFreq:  3200,
			Replaceable: false,
		},
		GatewayTemplateID: "",
		MasterSizing: propertiesv2.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    1,
			MinRAMSize:  64,
			MaxRAMSize:  128,
			MinDiskSize: 50,
			MinGPU:      1,
			MinCPUFreq:  3200,
			Replaceable: false,
		},
		MasterTemplateID: "",
		NodeSizing: propertiesv2.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    1,
			MinRAMSize:  64,
			MaxRAMSize:  128,
			MinDiskSize: 50,
			MinGPU:      1,
			MinCPUFreq:  3200,
			Replaceable: false,
		},
		NodeTemplateID: "NodeTemplateID",
		Image:          "Image",
		ImageID:        "ImageID",
	})
	if reflect.TypeOf(cc).String() != "*protocol.ClusterDefaults" {
		t.Error("Expect type *protocol.ClusterDefaults")
		t.Fail()
	}

}

func Test_ClusterDefaultsFromPropertyV3ToProtocol(t *testing.T) {

	cc := ClusterDefaultsFromPropertyV3ToProtocol(propertiesv3.ClusterDefaults{
		GatewaySizing: propertiesv2.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    1,
			MinRAMSize:  64,
			MaxRAMSize:  128,
			MinDiskSize: 50,
			MinGPU:      1,
			MinCPUFreq:  3200,
			Replaceable: false,
		},
		GatewayTemplateID: "",
		MasterSizing: propertiesv2.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    1,
			MinRAMSize:  64,
			MaxRAMSize:  128,
			MinDiskSize: 50,
			MinGPU:      1,
			MinCPUFreq:  3200,
			Replaceable: false,
		},
		MasterTemplateID: "",
		NodeSizing: propertiesv2.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    1,
			MinRAMSize:  64,
			MaxRAMSize:  128,
			MinDiskSize: 50,
			MinGPU:      1,
			MinCPUFreq:  3200,
			Replaceable: false,
		},
		NodeTemplateID: "NodeTemplateID",
		Image:          "Image",
		ImageID:        "ImageID",
	})
	if reflect.TypeOf(cc).String() != "*protocol.ClusterDefaults" {
		t.Error("Expect type *protocol.ClusterDefaults")
		t.Fail()
	}

}

func Test_ClusterNetworkFromPropertyToProtocol(t *testing.T) {

	pcn := propertiesv3.ClusterNetwork{
		NetworkID:          "ClusterNetwork NetworkID",
		CreatedNetwork:     true,
		SubnetID:           "ClusterNetwork SubnetID",
		CIDR:               "ClusterNetwork CIDR",
		GatewayID:          "ClusterNetworkv GatewayID",
		GatewayIP:          "ClusterNetwork GatewayIP",
		SecondaryGatewayID: "ClusterNetwork SecondaryGatewayID",
		SecondaryGatewayIP: "ClusterNetwork SecondaryGatewayIP",
		DefaultRouteIP:     "ClusterNetwork DefaultRouteIP",
		PrimaryPublicIP:    "ClusterNetwork PrimaryPublicIP",
		SecondaryPublicIP:  "ClusterNetwork SecondaryPublicIP",
		EndpointIP:         "ClusterNetwork EndpointIP",
		SubnetState:        subnetstate.Unknown,
		Domain:             "ClusterNetwork Domain",
	}
	cn := ClusterNetworkFromPropertyToProtocol(pcn)
	if reflect.TypeOf(cn).String() != "*protocol.ClusterNetwork" {
		t.Error("Expect type *protocol.ClusterNetwork")
		t.Fail()
	}

	require.EqualValues(t, cn.NetworkId, pcn.NetworkID)
	require.EqualValues(t, cn.SubnetId, pcn.SubnetID)
	require.EqualValues(t, cn.Cidr, pcn.CIDR)
	require.EqualValues(t, cn.Domain, pcn.Domain)
	require.EqualValues(t, cn.GatewayId, pcn.GatewayID)
	require.EqualValues(t, cn.GatewayIp, pcn.GatewayIP)
	require.EqualValues(t, cn.SecondaryGatewayId, pcn.SecondaryGatewayID)
	require.EqualValues(t, cn.SecondaryGatewayIp, pcn.SecondaryGatewayIP)
	require.EqualValues(t, cn.DefaultRouteIp, pcn.DefaultRouteIP)
	require.EqualValues(t, cn.PrimaryPublicIp, pcn.PrimaryPublicIP)
	require.EqualValues(t, cn.SecondaryPublicIp, pcn.SecondaryPublicIP)
	require.EqualValues(t, cn.EndpointIp, pcn.EndpointIP)

}

func Test_ClusterFeaturesFromPropertyToProtocol(t *testing.T) {

	featList, featResponse := ClusterFeaturesFromPropertyToProtocol(propertiesv1.ClusterFeatures{
		Installed: map[string]*propertiesv1.ClusterInstalledFeature{
			"Ansible": {
				Name:       "Ansible",
				FileName:   "ansible.yml",
				RequiredBy: map[string]struct{}{},
				Requires: map[string]struct{}{
					"Python3": {},
				},
			},
			"Python3": {
				Name:     "Python3",
				FileName: "python3.yml",
				RequiredBy: map[string]struct{}{
					"Ansible": {},
				},
				Requires: map[string]struct{}{},
			},
		},
		Disabled: map[string]struct{}{
			"Ansible": {},
		},
	})
	if reflect.TypeOf(featList).String() != "*protocol.FeatureListResponse" {
		t.Error("Expect type *protocol.FeatureListResponse")
		t.Fail()
	}
	if reflect.TypeOf(featResponse).String() != "*protocol.FeatureListResponse" {
		t.Error("Expect type *protocol.FeatureListResponse")
		t.Fail()
	}

}

func Test_SecurityGroupBondsFromPropertyToProtocol(t *testing.T) {

	sgbr := SecurityGroupBondsFromPropertyToProtocol([]*propertiesv1.SecurityGroupBond{
		{
			Name:       "Name",
			ID:         "ID   ",
			Disabled:   false,
			FromSubnet: false,
		},
	}, "host")
	if reflect.TypeOf(sgbr).String() != "*protocol.SecurityGroupBondsResponse" {
		t.Error("Expect type *protocol.SecurityGroupBondsResponse")
		t.Fail()
	}
	sgbr = SecurityGroupBondsFromPropertyToProtocol([]*propertiesv1.SecurityGroupBond{
		{
			Name:       "Name",
			ID:         "ID   ",
			Disabled:   false,
			FromSubnet: false,
		},
	}, "subnet")
	if reflect.TypeOf(sgbr).String() != "*protocol.SecurityGroupBondsResponse" {
		t.Error("Expect type *protocol.SecurityGroupBondsResponse")
		t.Fail()
	}

}

func Test_SliceOfSecurityGroupBondFromPropertyToProtocol(t *testing.T) {

	sgbs := []*propertiesv1.SecurityGroupBond{
		{
			Name:       "SG1 Name",
			ID:         "SG1 ID",
			Disabled:   false,
			FromSubnet: false,
		},
		{
			Name:       "SG2 Name",
			ID:         "SG2 ID",
			Disabled:   false,
			FromSubnet: false,
		},
		{
			Name:       "SG3 Name",
			ID:         "SG3 ID",
			Disabled:   false,
			FromSubnet: false,
		},
	}
	sgb := SliceOfSecurityGroupBondFromPropertyToProtocol(sgbs)
	if reflect.TypeOf(sgb).String() != "[]*protocol.SecurityGroupBond" {
		t.Error("Expect type []*protocol.SecurityGroupBond")
		t.Fail()
	}
	for i := range sgbs {
		require.EqualValues(t, sgbs[i].ID, sgb[i].Id)
		require.EqualValues(t, sgbs[i].Name, sgb[i].Name)
		require.EqualValues(t, sgbs[i].Disabled, sgb[i].Disabled)
	}

}

func Test_ClusterNodeFromPropertyToProtocol(t *testing.T) {

	cn := propertiesv3.ClusterNode{
		ID:          "ID",
		NumericalID: 0,
		Name:        "Name",
		PublicIP:    "PublicIP",
		PrivateIP:   "PrivateIP",
	}
	host := ClusterNodeFromPropertyToProtocol(cn)
	if reflect.TypeOf(host).String() != "*protocol.Host" {
		t.Error("Expect type *protocol.Host")
		t.Fail()
	}

	require.EqualValues(t, host.Id, cn.ID)
	require.EqualValues(t, host.Name, cn.Name)
	require.EqualValues(t, host.PublicIp, cn.PublicIP)
	require.EqualValues(t, host.PrivateIp, cn.PrivateIP)

}

func Test_ClusterDefaultsPropertyV1ToV2(t *testing.T) {

	cdv1 := &propertiesv1.ClusterDefaults{
		GatewaySizing: abstract.HostEffectiveSizing{
			Cores:       1,
			RAMSize:     1024,
			DiskSize:    64,
			GPUNumber:   1,
			GPUType:     "RTX 3080 TI",
			CPUFreq:     4800,
			ImageID:     "ImageID",
			Replaceable: false,
		},
		MasterSizing: abstract.HostEffectiveSizing{
			Cores:       1,
			RAMSize:     1024,
			DiskSize:    64,
			GPUNumber:   1,
			GPUType:     "RTX 3080 TI",
			CPUFreq:     4800,
			ImageID:     "ImageID",
			Replaceable: false,
		},
		NodeSizing: abstract.HostEffectiveSizing{
			Cores:       1,
			RAMSize:     1024,
			DiskSize:    64,
			GPUNumber:   1,
			GPUType:     "RTX 3080 TI",
			CPUFreq:     4800,
			ImageID:     "ImageID",
			Replaceable: false,
		},
		Image: "Image",
	}
	cdv2 := ClusterDefaultsPropertyV1ToV2(cdv1)

	require.EqualValues(t, cdv1.GatewaySizing.Cores, cdv2.GatewaySizing.MinCores)
	require.EqualValues(t, cdv1.GatewaySizing.CPUFreq, cdv2.GatewaySizing.MinCPUFreq)
	require.EqualValues(t, cdv1.GatewaySizing.GPUNumber, cdv2.GatewaySizing.MinGPU)
	require.EqualValues(t, cdv1.GatewaySizing.RAMSize, cdv2.GatewaySizing.MinRAMSize)
	require.EqualValues(t, cdv1.GatewaySizing.DiskSize, cdv2.GatewaySizing.MinDiskSize)
	require.EqualValues(t, cdv1.GatewaySizing.Replaceable, cdv2.GatewaySizing.Replaceable)

	require.EqualValues(t, cdv1.MasterSizing.Cores, cdv2.MasterSizing.MinCores)
	require.EqualValues(t, cdv1.MasterSizing.CPUFreq, cdv2.MasterSizing.MinCPUFreq)
	require.EqualValues(t, cdv1.MasterSizing.GPUNumber, cdv2.MasterSizing.MinGPU)
	require.EqualValues(t, cdv1.MasterSizing.RAMSize, cdv2.MasterSizing.MinRAMSize)
	require.EqualValues(t, cdv1.MasterSizing.DiskSize, cdv2.MasterSizing.MinDiskSize)
	require.EqualValues(t, cdv1.MasterSizing.Replaceable, cdv2.MasterSizing.Replaceable)

	require.EqualValues(t, cdv1.NodeSizing.Cores, cdv2.NodeSizing.MinCores)
	require.EqualValues(t, cdv1.NodeSizing.CPUFreq, cdv2.NodeSizing.MinCPUFreq)
	require.EqualValues(t, cdv1.NodeSizing.GPUNumber, cdv2.NodeSizing.MinGPU)
	require.EqualValues(t, cdv1.NodeSizing.RAMSize, cdv2.NodeSizing.MinRAMSize)
	require.EqualValues(t, cdv1.NodeSizing.DiskSize, cdv2.NodeSizing.MinDiskSize)
	require.EqualValues(t, cdv1.NodeSizing.Replaceable, cdv2.NodeSizing.Replaceable)

}
