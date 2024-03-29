/*
* Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/stretchr/testify/require"
)

func Test_SSHConfigFromProtocolToSystem(t *testing.T) {

	sc := &protocol.SshConfig{
		User:       "User",
		HostName:   "HostName",
		Host:       "127.0.0.1",
		PrivateKey: "PrivateKey",
		Port:       0,
		Gateway: &protocol.SshConfig{
			User:       "Gateway User",
			HostName:   "Gateway HostName",
			Host:       "127.0.0.1",
			PrivateKey: "Gateway PrivateKey",
			Port:       0,
		},
		SecondaryGateway: &protocol.SshConfig{
			User:       "SecondaryGateway User",
			HostName:   "SecondaryGateway HostName",
			Host:       "127.0.0.1",
			PrivateKey: "SecondaryGateway PrivateKey",
			Port:       0,
		},
	}

	ssc := SSHConfigFromProtocolToSystem(sc)
	user, xerr := ssc.GetUser()
	require.Nil(t, xerr)
	require.EqualValues(t, sc.User, user)
	host, xerr := ssc.GetHostname()
	require.Nil(t, xerr)
	require.EqualValues(t, sc.HostName, host)
	ipaddr, xerr := ssc.GetIPAddress()
	require.Nil(t, xerr)
	require.EqualValues(t, sc.Host, ipaddr)
	pkey, xerr := ssc.GetPrivateKey()
	require.Nil(t, xerr)
	require.EqualValues(t, sc.PrivateKey, pkey)
	port, xerr := ssc.GetPort()
	require.Nil(t, xerr)
	require.EqualValues(t, 0, port)

	rfs := FeatureSettingsFromProtocolToResource(nil)
	require.EqualValues(t, reflect.TypeOf(rfs).String(), "resources.FeatureSettings")

	pfs := &protocol.FeatureSettings{
		SkipProxy:                 false,
		Serialize:                 false,
		IgnoreFeatureRequirements: false,
		IgnoreSizingRequirements:  false,
		AddUnconditionally:        false,
	}
	rfs = FeatureSettingsFromProtocolToResource(pfs)

	require.EqualValues(t, rfs.SkipProxy, pfs.SkipProxy)
	require.EqualValues(t, rfs.Serialize, pfs.Serialize)
	require.EqualValues(t, rfs.SkipFeatureRequirements, pfs.IgnoreFeatureRequirements)
	require.EqualValues(t, rfs.SkipSizingRequirements, pfs.IgnoreSizingRequirements)
	require.EqualValues(t, rfs.AddUnconditionally, pfs.AddUnconditionally)

}

func Test_HostSizingRequirementsFromProtocolToAbstract(t *testing.T) {

	ahsr := HostSizingRequirementsFromProtocolToAbstract(nil)
	require.EqualValues(t, reflect.TypeOf(ahsr).String(), "*abstract.HostSizingRequirements")

	phs := &protocol.HostSizing{
		MinCpuCount: 1,
		MaxCpuCount: 5,
		MinRamSize:  1024.0,
		MaxRamSize:  2048.0,
		MinDiskSize: 64,
		GpuCount:    1,
		MinCpuFreq:  4800.0,
	}
	ahsr = HostSizingRequirementsFromProtocolToAbstract(phs)

	require.EqualValues(t, ahsr.MinCores, phs.MinCpuCount)
	require.EqualValues(t, ahsr.MaxCores, phs.MaxCpuCount)
	require.EqualValues(t, ahsr.MinRAMSize, phs.MinRamSize)
	require.EqualValues(t, ahsr.MaxRAMSize, phs.MaxRamSize)
	require.EqualValues(t, ahsr.MinDiskSize, phs.MinDiskSize)
	require.EqualValues(t, ahsr.MinGPU, phs.GpuCount)
	require.EqualValues(t, ahsr.MinCPUFreq, phs.MinCpuFreq)

}

type NFSExportTest struct {
	NFSExportOptions *protocol.NFSExportOptions
	expectResult     string
}

func Test_NFSExportOptionsFromProtocolToString(t *testing.T) {

	tests := []NFSExportTest{
		{
			NFSExportOptions: nil,
			expectResult:     "rw,async",
		},
		{
			NFSExportOptions: &protocol.NFSExportOptions{ReadOnly: true},
			expectResult:     "ro,no_root_squash,insecure,sync,no_subtree_check",
		},
		{
			NFSExportOptions: &protocol.NFSExportOptions{ReadOnly: false},
			expectResult:     "rw,no_root_squash,insecure,sync,no_subtree_check",
		},
		{
			NFSExportOptions: &protocol.NFSExportOptions{Secure: false},
			expectResult:     "rw,no_root_squash,insecure,sync,no_subtree_check",
		},
		{
			NFSExportOptions: &protocol.NFSExportOptions{Secure: true},
			expectResult:     "rw,no_root_squash,secure,sync,no_subtree_check",
		},
		{
			NFSExportOptions: &protocol.NFSExportOptions{Async: true},
			expectResult:     "rw,no_root_squash,insecure,async,no_subtree_check",
		},
		{
			NFSExportOptions: &protocol.NFSExportOptions{NoHide: true},
			expectResult:     "rw,no_root_squash,insecure,sync,nohide,no_subtree_check",
		},
		{
			NFSExportOptions: &protocol.NFSExportOptions{CrossMount: true},
			expectResult:     "rw,no_root_squash,insecure,sync,crossmnt,no_subtree_check",
		},
		{
			NFSExportOptions: &protocol.NFSExportOptions{SubtreeCheck: true},
			expectResult:     "rw,no_root_squash,insecure,sync",
		},
	}

	for i := range tests {
		test := tests[i]
		result := NFSExportOptionsFromProtocolToString(test.NFSExportOptions)
		require.EqualValues(t, result, test.expectResult)
	}

}

type ClusterRequest struct {
	ClusterCreateRequest *protocol.ClusterCreateRequest
	expectError          string
}

func Test_ClusterRequestFromProtocolToAbstract(t *testing.T) {

	tests := []ClusterRequest{
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "cpu <= 1, ram <= 1, disk = 10",
				MasterSizing:   "cpu <= 1, ram <= 1, disk = 30",
				NodeSizing:     "cpu <= 1, ram <= 1, disk = 40",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "",
		},
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "",
				MasterSizing:   "cpu <= 1, ram <= 1, disk = 30",
				NodeSizing:     "cpu <= 1, ram <= 1, disk = 40",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "",
		},
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "cpu <= 1, ram <= 1, disk = 10",
				MasterSizing:   "",
				NodeSizing:     "cpu <= 1, ram <= 1, disk = 40",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "",
		},
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "cpu <= 1, ram <= 1, disk = 10",
				MasterSizing:   "cpu <= 1, ram <= 1, disk = 30",
				NodeSizing:     "",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "",
		},
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "cpu <= 1, ram <= 1, disk = 10",
				MasterSizing:   "cpu <= 1, ram <= 1, disk = 30",
				NodeSizing:     "count = a",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "isn't a valid number",
		},
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "cpu <= 1, ram <= 1, disk = 10, count ~ 1",
				MasterSizing:   "cpu <= 1, ram <= 1, disk = 30",
				NodeSizing:     "cpu <= 1, ram <= 1, disk = 40",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "'count' can only use '='",
		},
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "cpu <= 1, ram <= 1, disk = 10",
				MasterSizing:   "cpu <= 1, ram <= 1, disk = 30, count ~ 1",
				NodeSizing:     "cpu <= 1, ram <= 1, disk = 40",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "'count' can only use '='",
		},
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "cpu <= 1, ram <= 1, disk = 10",
				MasterSizing:   "cpu <= 1, ram <= 1, disk = 30",
				NodeSizing:     "cpu <= 1, ram <= 1, disk = 40, count ~ 1",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "'count' can only use '='",
		},
		{
			ClusterCreateRequest: &protocol.ClusterCreateRequest{
				Name:           "",
				Complexity:     protocol.ClusterComplexity(clustercomplexity.Small),
				Flavor:         protocol.ClusterFlavor(clusterflavor.K8S),
				KeepOnFailure:  false,
				Cidr:           "192.178.0.0/28",
				Disabled:       []string{"A", "B", "C"},
				Os:             "Ubtuntu 20.04",
				GlobalSizing:   "cpu <= 4, ram <= 3, disk = 80",
				GatewaySizing:  "cpu <= 1, ram <= 1, disk = 10",
				MasterSizing:   "cpu <= 1, ram <= 1, disk = 30",
				NodeSizing:     "cpu <= 1, ram <= 1, disk = 40",
				Domain:         "Domain",
				TenantId:       "TestOVH@GRA5",
				GatewayOptions: "",
				MasterOptions:  "",
				NodeOptions:    "",
				Force:          false,
				DefaultSshPort: 22,
			},
			expectError: "",
		},
	}

	for i := range tests {
		test := tests[i]
		_, xerr := ClusterRequestFromProtocolToAbstract(test.ClusterCreateRequest)
		if test.expectError == "" && xerr != nil {
			t.Errorf("test %d failed: %v", i, xerr)
		}
		if test.expectError != "" && xerr == nil {
			t.Errorf(fmt.Sprintf("test %d failed: Expect error: %s", i, test.expectError))
		}
		if test.expectError != "" && xerr != nil {
			if !strings.Contains(xerr.Error(), test.expectError) {
				t.Errorf("test %d failed: expected %s and happened %s", i, test.expectError, xerr.Error())
			}
		}
	}

}

func Test_SecurityGroupRuleFromProtocolToAbstract(t *testing.T) {

	_, xerr := SecurityGroupRuleFromProtocolToAbstract(nil)
	if xerr == nil {
		t.Error("Can't SecurityGroupRuleFromProtocolToAbstract to nil pointer")
		t.Fail()
	}

	sgr := &protocol.SecurityGroupRule{
		Ids:       []string{"ID1", "ID2", "ID3 "},
		EtherType: protocol.SecurityGroupRuleEtherType(ipversion.IPv4),
		Direction: protocol.SecurityGroupRuleDirection(securitygroupruledirection.Ingress),
		Protocol:  "Protocol",
		PortFrom:  0,
		PortTo:    0,
		Involved:  []string{"Involve1"},
	}
	result, xerr := SecurityGroupRuleFromProtocolToAbstract(sgr)
	if xerr != nil {
		t.Error(xerr)
		t.Fail()
	}
	require.EqualValues(t, result.IDs, sgr.Ids)
	require.EqualValues(t, result.Description, sgr.Description)
	require.EqualValues(t, result.Direction, securitygroupruledirection.Ingress)
	require.EqualValues(t, result.Protocol, sgr.Protocol)
	require.EqualValues(t, result.EtherType, ipversion.IPv4)
	require.EqualValues(t, result.PortFrom, sgr.PortFrom)
	require.EqualValues(t, result.PortTo, sgr.PortTo)
	require.EqualValues(t, result.Sources, sgr.Involved)

	sgr = &protocol.SecurityGroupRule{
		Ids:       []string{"ID1", "ID2", "ID3 "},
		EtherType: protocol.SecurityGroupRuleEtherType(ipversion.IPv4),
		Direction: protocol.SecurityGroupRuleDirection(securitygroupruledirection.Egress),
		Protocol:  "Protocol",
		PortFrom:  0,
		PortTo:    0,
		Involved:  []string{"Involve1"},
	}
	result, xerr = SecurityGroupRuleFromProtocolToAbstract(sgr)
	if xerr != nil {
		t.Error(xerr)
		t.Fail()
	}
	require.EqualValues(t, result.Targets, sgr.Involved)

}

func Test_SecurityGroupRulesFromProtocolToAbstract(t *testing.T) {

	sgrs := []*protocol.SecurityGroupRule{
		{
			Ids:       []string{"ID1", "ID2", "ID3 "},
			EtherType: protocol.SecurityGroupRuleEtherType(ipversion.IPv4),
			Direction: protocol.SecurityGroupRuleDirection(securitygroupruledirection.Ingress),
			Protocol:  "Protocol",
			PortFrom:  0,
			PortTo:    0,
			Involved:  []string{"Involve1"},
		},
		{
			Ids:       []string{"ID1", "ID2", "ID3 "},
			EtherType: protocol.SecurityGroupRuleEtherType(ipversion.IPv4),
			Direction: protocol.SecurityGroupRuleDirection(securitygroupruledirection.Egress),
			Protocol:  "Protocol",
			PortFrom:  0,
			PortTo:    0,
			Involved:  []string{"Involve1"},
		},
	}
	asgrs, xerr := SecurityGroupRulesFromProtocolToAbstract(sgrs)
	if xerr != nil {
		t.Error(xerr)
		t.Fail()
	}
	for i := range sgrs {
		require.EqualValues(t, asgrs[i].IDs, sgrs[i].Ids)
		require.EqualValues(t, asgrs[i].Description, sgrs[i].Description)
		require.EqualValues(t, asgrs[i].Protocol, sgrs[i].Protocol)
		require.EqualValues(t, asgrs[i].EtherType, ipversion.IPv4)
		require.EqualValues(t, asgrs[i].PortFrom, sgrs[i].PortFrom)
		require.EqualValues(t, asgrs[i].PortTo, sgrs[i].PortTo)
		switch asgrs[i].Direction {
		case securitygroupruledirection.Ingress:
			require.EqualValues(t, asgrs[i].Sources, sgrs[i].Involved)
		case securitygroupruledirection.Egress:
			require.EqualValues(t, asgrs[i].Targets, sgrs[i].Involved)
		}

	}

}

func Test_SecurityGroupFromProtocolToAbstract(t *testing.T) {

	_, xerr := SecurityGroupFromProtocolToAbstract(nil)
	if xerr == nil {
		t.Error("Expect error: in can't be nil")
		t.Fail()
	}

	sgr := &protocol.SecurityGroupResponse{
		Id:          "SecurityGroupResponse ID",
		Name:        "SecurityGroupResponse Name",
		Description: "SecurityGroupResponse Description",
		Rules:       []*protocol.SecurityGroupRule{nil},
	}
	if xerr == nil {
		t.Error("Expect error: securitygrouprule can't be nil")
		t.Fail()
	}

	sgr = &protocol.SecurityGroupResponse{
		Id:          "SecurityGroupResponse ID",
		Name:        "SecurityGroupResponse Name",
		Description: "SecurityGroupResponse Description",
		Rules: []*protocol.SecurityGroupRule{
			{
				Ids:       []string{"ID1", "ID2", "ID3 "},
				EtherType: protocol.SecurityGroupRuleEtherType(ipversion.IPv4),
				Direction: protocol.SecurityGroupRuleDirection(securitygroupruledirection.Ingress),
				Protocol:  "Protocol",
				PortFrom:  0,
				PortTo:    0,
				Involved:  []string{"Involve1"},
			},
		},
	}
	asg, xerr := SecurityGroupFromProtocolToAbstract(sgr)
	if xerr != nil {
		t.Error(xerr)
		t.Fail()
	}

	require.EqualValues(t, asg.ID, sgr.GetId())
	require.EqualValues(t, asg.Name, sgr.GetName())
	require.EqualValues(t, asg.Description, sgr.GetDescription())

}

type HostStateMapping struct {
	in  protocol.HostState
	out hoststate.Enum
}

func Test_HostStateFromProtocolToEnum(t *testing.T) {

	tests := []HostStateMapping{
		{
			in:  protocol.HostState_HS_STOPPED,
			out: hoststate.Stopped,
		},
		{
			in:  protocol.HostState_HS_STARTING,
			out: hoststate.Starting,
		},
		{
			in:  protocol.HostState_HS_STARTED,
			out: hoststate.Started,
		},
		{
			in:  protocol.HostState_HS_STOPPING,
			out: hoststate.Stopping,
		},
		{
			in:  protocol.HostState_HS_ERROR,
			out: hoststate.Error,
		},
		{
			in:  protocol.HostState_HS_TERMINATED,
			out: hoststate.Terminated,
		},
		{
			in:  protocol.HostState_HS_UNKNOWN,
			out: hoststate.Unknown,
		},
		{
			in:  protocol.HostState_HS_ANY,
			out: hoststate.Any,
		},
		{
			in:  protocol.HostState_HS_FAILED,
			out: hoststate.Failed,
		},
		{
			in:  protocol.HostState_HS_DELETED,
			out: hoststate.Deleted,
		},
		{
			in:  protocol.HostState(666),
			out: hoststate.Unknown,
		},
	}
	for i := range tests {
		result := HostStateFromProtocolToEnum(tests[i].in)
		require.EqualValues(t, result, tests[i].out)
	}

}
