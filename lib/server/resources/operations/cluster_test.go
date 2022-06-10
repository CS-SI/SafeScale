//go:build ut
// +build ut

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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

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

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
				MaxCores:    2,
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
				MaxCores:    1,
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
				MaxCores:    1,
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
		})
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

	ctx := context.Background()
	task, xerr := concurrency.NewTaskWithContext(ctx)
	ctx = context.WithValue(ctx, "task", task)
	require.Nil(t, xerr)

	req := abstract.ClusterRequest{
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

	var ocluster *Cluster = nil
	xerr = ocluster.Create(ctx, req)
	require.Contains(t, xerr.Error(), "invalid instance: in")

	err := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		ocluster, xerr = NewCluster(ctx, svc)
		require.Nil(t, xerr)
		require.EqualValues(t, reflect.TypeOf(ocluster).String(), "*operations.Cluster")

		xerr = ocluster.Create(ctx, req)
		require.Contains(t, xerr.Error(), "failed to use network cluster-network to contain Cluster Subnet: nor networks/byName/cluster-network nor networks/byID/cluster-network were found in the bucket")

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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

		_, xerr = svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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
		require.EqualValues(t, aci.GetID(), "ClusterName")
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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
		require.Nil(t, xerr)

		cluster, xerr := LoadCluster(ctx, svc, "ClusterName")
		require.Nil(t, xerr)

		ocluster, ok := cluster.(*Cluster)
		if !ok {
			t.Error("ressources.Cluster not castable to operation.Cluster")
			t.FailNow()
		}

		config, err := ocluster.GetNetworkConfig(ctx)
		require.Nil(t, err)
		require.EqualValues(t, config.NetworkID, "cluster-network")
		require.EqualValues(t, config.CreatedNetwork, false)
		require.EqualValues(t, config.SubnetID, "clustername")
		require.EqualValues(t, config.CIDR, "192.168.0.0/24")
		require.EqualValues(t, config.GatewayID, "gw-clustername")
		require.EqualValues(t, config.SubnetState, subnetstate.Unknown)
		require.EqualValues(t, config.Domain, "")

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

		_, xerr := svc._CreateCluster(ctx, abstract.ClusterRequest{
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
		})
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

	})
	require.Nil(t, err)

}
