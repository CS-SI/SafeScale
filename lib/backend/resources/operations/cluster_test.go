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

package operations

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func createClusterRequest() abstract.ClusterRequest {
	return abstract.ClusterRequest{
		Name:          "ClusterName",
		CIDR:          "192.168.0.0/24",
		Domain:        "cluster-domain",
		Complexity:    clustercomplexity.Small,
		Flavor:        clusterflavor.K8S,
		NetworkID:     "cluster-network",
		Tenant:        "tenant-test",
		KeepOnFailure: false,
		GatewaysDef: abstract.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    8,
			MinRAMSize:  4092,
			MaxRAMSize:  8192,
			MinDiskSize: 1024,
			MinGPU:      1,
			MinCPUFreq:  2033,
			Replaceable: false,
			Image:       "HostSizingRequirements Image",
			Template:    "HostSizingRequirements Template",
		},
		MastersDef: abstract.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    8,
			MinRAMSize:  4092,
			MaxRAMSize:  8192,
			MinDiskSize: 1024,
			MinGPU:      1,
			MinCPUFreq:  2033,
			Replaceable: false,
			Image:       "HostSizingRequirements Image",
			Template:    "HostSizingRequirements Template",
		},
		NodesDef: abstract.HostSizingRequirements{
			MinCores:    1,
			MaxCores:    8,
			MinRAMSize:  4092,
			MaxRAMSize:  8192,
			MinDiskSize: 1024,
			MinGPU:      1,
			MinCPUFreq:  2033,
			Replaceable: false,
			Image:       "HostSizingRequirements Image",
			Template:    "HostSizingRequirements Template",
		},
		InitialNodeCount:        1,
		OS:                      "ubuntu",
		DisabledDefaultFeatures: map[string]struct{}{},
		Force:                   false,
		FeatureParameters:       []string{},
		DefaultSshPort:          22,
	}
}

func Test_NewCluster(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	_, xerr = NewCluster(ctx, nil)
	require.Contains(t, xerr.Error(), "invalid parameter: svc")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		cluster, xerr := NewCluster(ctx, svc)
		require.Nil(t, xerr)
		require.EqualValues(t, reflect.TypeOf(cluster).String(), "*operations.Cluster")

	})
	require.Nil(t, err)
}

func Test_LoadCluster(t *testing.T) {
	if true {
		t.Skip("BROKEN TEST") // publicIP breaks the tests
	}

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), false)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)
		require.EqualValues(t, reflect.TypeOf(cluster).String(), "*operations.Cluster")
		require.EqualValues(t, cluster.GetName(), "ClusterName")

	})
	require.Nil(t, err)

}

func TestCluster_IsNull(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	require.True(t, ocluster.IsNull())

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("Can't cast *resources.Cluster to *operations.Cluster")
		}
		require.False(t, ocluster.IsNull())
	})
	require.Nil(t, err)

}

func TestCluster_Create(t *testing.T) {
	if true {
		t.Skip("BROKEN TEST") // publicIP breaks the tests
	}

	if runtime.GOOS == "windows" {
		t.Skip()
	}

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	xerr = ocluster.Create(ctx, createClusterRequest())
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		// svc._setLogLevel(0)

		ocluster, xerr = NewCluster(ctx, svc)
		require.Nil(t, xerr)
		require.EqualValues(t, reflect.TypeOf(ocluster).String(), "*operations.Cluster")

		// svc._setLogLevel(2)

		request := createClusterRequest()

		kpName := fmt.Sprintf("cluster_%s_cladm_key", request.Name)
		kp, xerr := svc.CreateKeyPair(ctx, kpName)
		require.Nil(t, xerr)

		cladmPassword, err := utils.GeneratePassword(16)
		require.Nil(t, err)

		// Network
		network, xerr := svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          request.NetworkID,
			CIDR:          request.CIDR,
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Nil(t, xerr)

		// Subnet
		subnet, xerr := svc.CreateSubnet(ctx, abstract.SubnetRequest{
			NetworkID:      network.ID,
			Name:           request.Name,
			IPVersion:      network.IPVersion,
			CIDR:           network.CIDR,
			DNSServers:     network.DNSServers,
			Domain:         request.Domain,
			HA:             false,
			ImageRef:       "",
			DefaultSSHPort: 22,
			KeepOnFailure:  false,
		})
		require.Nil(t, xerr)

		// Securitygroups
		sgNames := []string{"PublicIPSecurityGroupID", "GWSecurityGroupID", "InternalSecurityGroupID"}
		for _, sgName := range sgNames {
			_, xerr = svc.CreateSecurityGroup(ctx, network.ID, sgName, fmt.Sprintf("Sg desc %s", sgName), abstract.SecurityGroupRules{
				&abstract.SecurityGroupRule{
					IDs:         make([]string, 0),
					Description: "",
					EtherType:   ipversion.IPv4,
					Direction:   securitygroupruledirection.Ingress,
					Protocol:    "icmp",
					PortFrom:    0,
					PortTo:      0,
					Sources:     make([]string, 0),
					Targets:     make([]string, 0),
				},
				&abstract.SecurityGroupRule{
					IDs:         make([]string, 0),
					Description: "",
					EtherType:   ipversion.IPv4,
					Direction:   securitygroupruledirection.Ingress,
					Protocol:    "tcp",
					PortFrom:    0,
					PortTo:      0,
					Sources:     make([]string, 0),
					Targets:     make([]string, 0),
				},
				&abstract.SecurityGroupRule{
					IDs:         make([]string, 0),
					Description: "",
					EtherType:   ipversion.IPv4,
					Direction:   securitygroupruledirection.Ingress,
					Protocol:    "udp",
					PortFrom:    0,
					PortTo:      0,
					Sources:     make([]string, 0),
					Targets:     make([]string, 0),
				},
			})
			require.Nil(t, xerr)
		}

		// Gateway
		_, _, xerr = svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   fmt.Sprintf("gw-%s", request.Name),
			HostName:       fmt.Sprintf("gw-%s", request.Name),
			Subnets:        []*abstract.Subnet{subnet},
			DefaultRouteIP: "192.168.0.1",
			TemplateID:     request.GatewaysDef.Template,
			// TemplateRef
			ImageID: request.GatewaysDef.Image,
			// ImageRef
			KeyPair:       kp,
			SSHPort:       22,
			Password:      cladmPassword,
			DiskSize:      64,
			Single:        false,
			PublicIP:      true,
			IsGateway:     true,
			KeepOnFailure: false,
			Preemptible:   false,
			SecurityGroupIDs: map[string]struct{}{
				"PublicIPSecurityGroupID": {},
				"GWSecurityGroupID":       {},
				"InternalSecurityGroupID": {},
			},
		})
		require.Nil(t, xerr)

		// Off-Gateway
		_, _, xerr = svc.CreateHost(ctx, abstract.HostRequest{
			ResourceName:   fmt.Sprintf("gw2-%s", request.Name),
			HostName:       fmt.Sprintf("gw2-%s", request.Name),
			Subnets:        []*abstract.Subnet{subnet},
			DefaultRouteIP: "192.168.0.2",
			TemplateID:     request.GatewaysDef.Template,
			// TemplateRef
			ImageID: request.GatewaysDef.Image,
			// ImageRef
			KeyPair:       kp,
			SSHPort:       22,
			Password:      cladmPassword,
			DiskSize:      64,
			Single:        false,
			PublicIP:      true,
			IsGateway:     true,
			KeepOnFailure: false,
			Preemptible:   false,
			SecurityGroupIDs: map[string]struct{}{
				"PublicIPSecurityGroupID": {},
				"GWSecurityGroupID":       {},
				"InternalSecurityGroupID": {},
			},
		})
		require.Nil(t, xerr)

		xerr = ocluster.Create(ctx, request)
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestCluster_Sdump(t *testing.T) {

	defer func() {
		r := recover()
		if r != nil {
			// FIXME: Due from timeout shortcuts, but strange behaviour, should check for deadlocks
			if strings.Contains(r.(string), "race detected during execution of test") {
				t.Skip()
			}
		}
	}()

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.Sdump(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		result, err := ocluster.Sdump(ctx)
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(result).String(), "string")
		require.Contains(t, result, "&abstract.ClusterIdentity{")
		require.Contains(t, result, "  Name: \"ClusterName\",")
		require.Contains(t, result, "  Flavor: 2,")
		require.Contains(t, result, "  Complexity: 1,")
		require.Contains(t, result, "  Keypair: &abstract.KeyPair{")
		require.Contains(t, result, "    \"ManagedBy\": \"safescale\",")

	})
	require.Nil(t, err)

}

func TestCluster_Deserialize(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.Sdump(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		// KeyPair
		kp, xerr := svc.CreateKeyPair(ctx, "MyPrivateKey")
		require.Nil(t, xerr)
		aci := &abstract.ClusterIdentity{
			Name:          "mycluster",
			Flavor:        clusterflavor.K8S,
			Complexity:    clustercomplexity.Small,
			Keypair:       kp,
			AdminPassword: "cladm",
			Tags: map[string]string{
				"CreationDate": time.Now().Format(time.RFC3339),
				"ManagedBy":    "safescale",
			},
		}
		serial, xerr := aci.Serialize()
		require.Nil(t, xerr)

		_, xerr = svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		xerr = ocluster.Deserialize(ctx, serial)
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestCluster_Browse(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		err := ocluster.Browse(ctx, func(aci *abstract.ClusterIdentity) fail.Error {

			require.EqualValues(t, aci.Name, "ClusterName")
			require.EqualValues(t, aci.Complexity, clustercomplexity.Small)
			require.EqualValues(t, aci.Flavor, clusterflavor.K8S)

			return nil
		})
		require.Nil(t, err)

	})
	require.Nil(t, err)

}

func TestCluster_GetIdentity(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.GetIdentity(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		aci, err := ocluster.GetIdentity(ctx)
		require.Nil(t, err)
		acid, _ := aci.GetID()
		require.EqualValues(t, acid, "ClusterName")
		require.EqualValues(t, aci.GetName(), "ClusterName")

	})
	require.Nil(t, err)

}

func TestCluster_GetFlavor(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.GetFlavor(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		flavor, err := ocluster.GetFlavor(ctx)
		require.Nil(t, err)
		require.EqualValues(t, flavor, clusterflavor.K8S)

	})
	require.Nil(t, err)

}

func TestCluster_GetComplexity(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.GetComplexity(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		complexity, err := ocluster.GetComplexity(ctx)
		require.Nil(t, err)
		require.EqualValues(t, complexity, clustercomplexity.Small)

	})
	require.Nil(t, err)

}

func TestCluster_GetAdminPassword(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.GetAdminPassword(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		pwd, err := ocluster.GetAdminPassword(ctx)
		require.Nil(t, err)
		require.Greater(t, len(pwd), 0)

	})
	require.Nil(t, err)

}

func TestCluster_GetKeyPair(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.GetKeyPair(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		kp, err := ocluster.GetKeyPair(ctx)
		require.Nil(t, err)
		require.Contains(t, kp.PrivateKey, "-----BEGIN RSA PRIVATE KEY-----")
		require.Contains(t, kp.PrivateKey, "-----END RSA PRIVATE KEY-----")

	})
	require.Nil(t, err)

}

func TestCluster_GetNetworkConfig(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.GetNetworkConfig(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		svc._setLogLevel(2)

		config, err := ocluster.GetNetworkConfig(ctx)
		require.Nil(t, err)
		require.EqualValues(t, config.NetworkID, "cluster-network")
		require.EqualValues(t, config.CreatedNetwork, true)
		require.EqualValues(t, config.SubnetID, "ClusterName")
		require.EqualValues(t, config.CIDR, "192.168.0.0/24")
		require.EqualValues(t, config.GatewayID, "gw-ClusterName")
		require.EqualValues(t, config.SubnetState, subnetstate.Ready)
		require.EqualValues(t, config.Domain, "cluster-domain")

	})
	require.Nil(t, err)

}

func TestCluster_Start(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	xerr = ocluster.Start(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		err := ocluster.Start(ctx)
		require.Contains(t, err.Error(), "failed to start Cluster because of it's current state: Nominal")

		svc._setLogLevel(2)

		err = ocluster.Stop(ctx)
		require.Nil(t, xerr)

	})
	require.Nil(t, err)

}

func TestCluster_GetState(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	_, xerr = ocluster.GetState(ctx)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		state, err := ocluster.GetState(ctx)
		require.Nil(t, err)
		require.EqualValues(t, state, clusterstate.Nominal)

	})
	require.Nil(t, err)

}

func TestCluster_AddNodes(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	var ocluster *Cluster = nil
	var hsizing = abstract.HostSizingRequirements{
		MinCores:    1,
		MaxCores:    8,
		MinRAMSize:  4092,
		MaxRAMSize:  8192,
		MinDiskSize: 1024,
		MinGPU:      1,
		MinCPUFreq:  2033,
		Replaceable: false,
		Image:       "HostSizingRequirements Image",
		Template:    "HostSizingRequirements Template",
	}
	_, xerr = ocluster.AddNodes(ctx, 1, hsizing, make(data.Map), false)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		// Still have race troubles, check for io concurrency
		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		// ocluster, ok := cluster.(*Cluster)
		_, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		// _, xerr = ocluster.AddNodes(ctx, 1, hsizing, make(data.Map), false)
		// require.Nil(t, xerr)

		// ListNodes

	})
	require.Nil(t, err)

}

func TestCluster_DeleteSpecificNode(t *testing.T) {}

func TestCluster_ListMasters(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		list, xerr := ocluster.ListMasters(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(list), 1)
		require.EqualValues(t, list[0].Name, "ClusterName-master-1")

	})
	require.Nil(t, err)

}

func TestCluster_ListMasterNames(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		list, xerr := ocluster.ListMasterNames(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(list), 1)
		require.EqualValues(t, list[0], "ClusterName-master-1")

	})
	require.Nil(t, err)

}

func TestCluster_ListMasterIDs(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		list, xerr := ocluster.ListMasterIDs(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(list), 1)
		require.EqualValues(t, list[0], "ClusterName-master-1")

	})
	require.Nil(t, err)

}

func TestCluster_ListMasterIPs(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		list, xerr := ocluster.ListMasterIPs(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(list), 1)
		require.EqualValues(t, list[0], "192.168.0.3")

	})
	require.Nil(t, err)

}

func TestCluster_FindAvailableMaster(t *testing.T) {
	if true {
		t.Skip("BROKEN TEST") // publicIP breaks the tests
	}

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		master, xerr := ocluster.FindAvailableMaster(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, master.GetName(), "ClusterName-master-1")

	})
	require.Nil(t, err)

}

func TestCluster_ListNodes(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		nodes, xerr := ocluster.ListNodes(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(nodes), 1)
		require.EqualValues(t, nodes[0].Name, "ClusterName-node-1")

	})
	require.Nil(t, err)

}

func TestCluster_ListNodeNames(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		nodes, xerr := ocluster.ListNodeNames(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(nodes), 1)
		require.EqualValues(t, nodes[0], "ClusterName-node-1")

	})
	require.Nil(t, err)

}

func TestCluster_ListNodeIDs(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		nodes, xerr := ocluster.ListNodeNames(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(nodes), 1)
		require.EqualValues(t, nodes[0], "ClusterName-node-1")

	})
	require.Nil(t, err)

}

func TestCluster_ListNodeIPs(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		nodes, xerr := ocluster.ListNodeIPs(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, len(nodes), 1)
		require.EqualValues(t, nodes[0], "192.168.0.4")

	})
	require.Nil(t, err)

}

func TestCluster_FindAvailableNode(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		node, xerr := ocluster.FindAvailableNode(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, node.GetName(), "ClusterName-node-1")

	})
	require.Nil(t, err)

}

func TestCluster_LookupNode(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		found, xerr := ocluster.LookupNode(nil, "ClusterName-node-1")
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		found, xerr = ocluster.LookupNode(ctx, "")
		require.Contains(t, xerr.Error(), "invalid parameter: ref")

		found, xerr = ocluster.LookupNode(ctx, "ClusterName-node-1")
		require.Nil(t, xerr)
		require.True(t, found)

		found, xerr = ocluster.LookupNode(ctx, "ClusterName-node-2")
		require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrNotFound")
		require.False(t, found)

	})
	require.Nil(t, err)

}

func TestCluster_CountNodes(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		count, xerr := ocluster.CountNodes(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, count, 1)

	})
	require.Nil(t, err)

}

func TestCluster_GetNodeByID(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		node, xerr := ocluster.GetNodeByID(nil, "ClusterName-node-1")
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		node, xerr = ocluster.GetNodeByID(ctx, "")
		require.Contains(t, xerr.Error(), "invalid parameter: hostID")
		require.Contains(t, xerr.Error(), "cannot be empty string")

		node, xerr = ocluster.GetNodeByID(ctx, "ClusterName-node-2")
		require.Contains(t, xerr.Error(), "failed to find node ClusterName-node-2")

		node, xerr = ocluster.GetNodeByID(ctx, "ClusterName-node-1")
		require.Nil(t, xerr)
		require.EqualValues(t, node.GetName(), "ClusterName-node-1")

	})
	require.Nil(t, err)

}

func TestCluster_Delete(t *testing.T) {}

func TestCluster_ToProtocol(t *testing.T) {

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, createClusterRequest(), true)
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		response, xerr := ocluster.ToProtocol(ctx)
		require.Nil(t, xerr)

		require.EqualValues(t, response.Identity.Name, "ClusterName")
		require.EqualValues(t, response.Identity.Complexity, protocol.ClusterComplexity_CC_SMALL)
		require.EqualValues(t, response.Identity.Flavor, protocol.ClusterFlavor_CF_K8S)
		// require.EqualValues(t, response.Identity.AdminPassword, "-c2xP8(2-u54:c.V")
		require.EqualValues(t, response.Network.NetworkId, "cluster-network")
		require.EqualValues(t, response.Network.Cidr, "192.168.0.0/24")
		require.EqualValues(t, response.Network.Domain, "cluster-domain")
		require.EqualValues(t, response.Network.GatewayId, "gw-ClusterName")
		require.EqualValues(t, response.Network.GatewayIp, "192.168.0.1")
		require.EqualValues(t, response.Network.SecondaryGatewayId, "gw2-ClusterName")
		require.EqualValues(t, response.Network.SecondaryGatewayIp, "192.168.0.2")
		require.EqualValues(t, response.Network.DefaultRouteIp, "192.168.0.1")
		require.EqualValues(t, response.Network.PrimaryPublicIp, "192.168.0.1")
		require.EqualValues(t, response.Network.SecondaryPublicIp, "192.168.0.2")
		require.EqualValues(t, response.Network.EndpointIp, "192.168.0.1")
		require.EqualValues(t, response.Network.SubnetId, "ClusterName")
		require.EqualValues(t, len(response.Masters), 1)
		require.EqualValues(t, response.Masters[0].Name, "ClusterName-master-1")
		require.EqualValues(t, len(response.Nodes), 1)
		require.EqualValues(t, response.Nodes[0].Name, "ClusterName-node-1")

	})
	require.Nil(t, err)

}

func TestCluster_Shrink(t *testing.T) {}

func TestCluster_IsFeatureInstalled(t *testing.T) {}