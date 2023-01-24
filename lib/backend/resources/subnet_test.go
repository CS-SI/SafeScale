//go:build fixme
// +build fixme

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

package resources

import (
	"context"
	"reflect"
	"testing"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/stretchr/testify/require"
)

func subnetRequest() abstract.SubnetRequest {
	return abstract.SubnetRequest{
		NetworkID:      "MyNetwork",
		Name:           "MySubnet",
		IPVersion:      ipversion.IPv4,
		CIDR:           "192.168.1.1/26",
		DNSServers:     []string{"8.8.8.8", "8.8.4.4"},
		Domain:         "MyDomain",
		HA:             false,
		ImageRef:       "",
		DefaultSSHPort: 22,
		KeepOnFailure:  false,
	}
}

func Test_NewSubnet(t *testing.T) {

	var svc iaasapi.Service

	subnet, err := NewSubnet(svc)
	require.Nil(t, subnet)
	require.Contains(t, err.Error(), "cannot be nil")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		subnet, err = NewSubnet(svc)
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(subnet).String(), "*resources.Subnet")

	})
	if xerr != nil {
		t.Error(xerr)
	}
	require.Nil(t, xerr)

}

func Test_LoadSubnet(t *testing.T) {

	var svc iaasapi.Service
	ctx := context.Background()

	// Wrong service
	bucket, err := LoadSubnet(ctx, svc, "mynetwork", "mysubnet")
	require.Nil(t, bucket)
	require.Contains(t, err.Error(), "cannot be nil")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		// Load unnamed Bucket
		subnet, err := LoadSubnet(ctx, svc, "", "mysubnet") // FIXME: no cares about network ?!?
		require.Nil(t, subnet)
		require.Contains(t, err.Error(), "ither subnets/byName/mysubnet nor subnets/byID/mysubnet were found in the Bucket")

		svc._reset()

		// Subnet, but not a subnet
		asubnet := abstract.NewSubnet()
		asubnet.ID = "mysubnet"
		asubnet.Name = "mysubnet"
		asubnet.CIDR = "192.168.0.1/24"
		asubnet.IPVersion = ipversion.IPv4
		asubnet.Network = "mynetwork"

		_ = svc._setInternalData("subnets/byID/mysubnet", asubnet)
		_ = svc._setInternalData("subnets/byName/mysubnet", asubnet)

		subnet, xerr := LoadSubnet(ctx, svc, "", "mysubnet")
		require.Nil(t, xerr)
		require.EqualValues(t, reflect.TypeOf(bucket).String(), "*resources.Subnet")

	})
	require.Nil(t, xerr)

}

func TestSubnet_Exists(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, err := svc.CreateSubnet(nil, subnetRequest())
		require.Contains(t, err.Error(), "cannot create context from nil parent")

		_, err = svc.CreateSubnet(ctx, subnetRequest())
		require.Contains(t, err.Error(), "neither networks/byName/MyNetwork nor networks/byID/MyNetwork were found in the Bucket")

		_, xerr := svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          "MyNetwork",
			CIDR:          "127.0.0.1/28",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Nil(t, xerr)

		_, err = svc.CreateSubnet(ctx, subnetRequest())
		require.Nil(t, err)

		subnet, err := LoadSubnet(ctx, svc, "MyNetwork", "MySubnet")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(subnet).String(), "*resources.Subnet")
		require.False(t, subnet.IsNull())

		exists, err := subnet.Exists(ctx)
		require.True(t, exists)
		require.Nil(t, err)

	})
	if xerr != nil {
		t.Error(xerr.Error())
	}
	require.Nil(t, xerr)

}

func TestSubnet_IsNull(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, xerr := svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          "MyNetwork",
			CIDR:          "127.0.0.1/28",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Nil(t, xerr)

		_, err := svc.CreateSubnet(ctx, subnetRequest())
		require.Nil(t, err)

		subnet, err := LoadSubnet(ctx, svc, "MyNetwork", "MySubnet")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(subnet).String(), "*resources.Subnet")
		require.False(t, subnet.IsNull())

	})
	require.Nil(t, xerr)

}

func Test_ListSubnets(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		svc._setLogLevel(0)

		_, xerr := svc.CreateSubnet(nil, subnetRequest())
		require.Contains(t, xerr.Error(), "cannot create context from nil parent")

		_, xerr = svc.CreateSubnet(ctx, subnetRequest())
		require.Contains(t, xerr.Error(), "neither networks/byName/MyNetwork nor networks/byID/MyNetwork were found in the Bucket")

		_, xerr = svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          "MyNetwork",
			CIDR:          "127.0.0.1/28",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Nil(t, xerr)

		_, xerr = svc.CreateSubnet(ctx, subnetRequest())
		require.Nil(t, xerr)

		svc._setLogLevel(0)

		subnets, xerr := ListSubnets(ctx, svc, "MyNetwork", true)
		require.Nil(t, xerr)
		require.EqualValues(t, len(subnets), 1)

		id, err := subnets[0].GetID()
		require.Nil(t, err)
		require.EqualValues(t, id, "MySubnet")
		require.EqualValues(t, subnets[0].Network, "MyNetwork")

	})
	if xerr != nil {
		t.Error(xerr.Error())
	}
	require.Nil(t, xerr)

}

func TestSubnet_Carry(t *testing.T) {

	ctx := context.Background()

	anetwork := abstract.NewNetwork()
	anetwork.ID = "Network_ID"
	anetwork.Name = "Network Name"

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, xerr := svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          "MyNetwork",
			CIDR:          "127.0.0.1/28",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Nil(t, xerr)

		_, xerr = svc.CreateSubnet(ctx, subnetRequest())
		require.Nil(t, xerr)

		subnet, err := LoadSubnet(ctx, svc, "MyNetwork", "MySubnet")
		require.Nil(t, err)

		asubnet := abstract.NewSubnet()
		asubnet.ID = "mysubnet"
		asubnet.Name = "mysubnet"
		asubnet.CIDR = "192.168.0.1/24"
		asubnet.IPVersion = ipversion.IPv4
		asubnet.Network = "mynetwork"

		xerr = subnet.Carry(ctx, asubnet)
		require.Contains(t, xerr.Error(), "cannot carry, already carries something")

		svc._reset()

		mdc, xerr := NewCore(svc, "subnet", "subnets", &abstract.Subnet{})
		require.Nil(t, xerr)

		xerr = mdc.Carry(ctx, asubnet)
		require.Nil(t, xerr)

	})
	require.Nil(t, xerr)

}

// CreateSecurityGroups
// AttachHost
// DetachHost
// ListHosts
// InspectGateway
// GetGatewayPublicIP
// GetGatewayPublicIPs
// Delete
// InspectNetwork
// GetDefaultRouteIP
// GetEndpointIP
// HasVirtualIP
// GetVirtualIP
// GetCIDR
// GetState
// ToProtocol
// BindSecurityGroup
// UnbindSecurityGroup
// ListSecurityGroups
// EnableSecurityGroup
// DisableSecurityGroup
// InspectGatewaySecurityGroup
// InspectInternalSecurityGroup
// InspectPublicIPSecurityGroup
// CreateSubnetWithoutGateway
