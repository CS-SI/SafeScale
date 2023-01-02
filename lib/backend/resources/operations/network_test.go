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

package operations

import (
	"context"
	"fmt"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	serializer "github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/stretchr/testify/require"
)

func Test_NewNetwork(t *testing.T) {

	var svc iaas.Service
	_, err := NewNetwork(svc)
	require.Contains(t, err.Error(), "invalid parameter: svc")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		svc._updateOption("metadatakey", "")
		svc._updateOption("metadatakeyErr", fail.NewError("No metadata key"))

		_, err := NewNetwork(svc)
		require.Contains(t, err.Error(), "No metadata key")

		svc._reset()

		network, err := NewNetwork(svc)
		require.Nil(t, err)

		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")

	})
	require.Nil(t, xerr)

}

func Test_LoadNetwork(t *testing.T) {

	var svc iaas.Service
	ctx := context.Background()

	network, err := LoadNetwork(ctx, svc, "mynetwork")

	fmt.Println(network, err)

	require.EqualValues(t, network, nil)
	require.Contains(t, err.Error(), "invalid parameter: svc")

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		network, xerr := LoadNetwork(ctx, svc, "")
		require.EqualValues(t, network, nil)
		require.Contains(t, xerr.Error(), "cannot be empty string")

		svc._updateOption("getcacheErr", fail.NotFoundError("no cache !"))

		network, xerr = LoadNetwork(ctx, svc, "mynetwork")
		require.EqualValues(t, network, nil)
		require.Contains(t, xerr.Error(), "neither networks/byName/mynetwork nor networks/byID/mynetwork were found in the bucket")

		svc._reset()
		svc._updateOption("timingsErr", fail.NotFoundError("no timings !"))

		_, xerr = svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "127.0.0.1/28",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Contains(t, xerr.Error(), "no timings !")

		svc._reset()

		_, xerr = svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "127.0.0.1/28",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Nil(t, xerr)

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

	})
	require.Nil(t, xerr)

}

func TestNetwork_Create(t *testing.T) {

	var onetwork *Network
	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.EqualValues(t, network, nil)
		require.EqualValues(t, reflect.TypeOf(err).String(), "*fail.ErrNotFound")
		require.Contains(t, err.Error(), "neither networks/byName/mynetwork nor networks/byID/mynetwork were found in the bucket")

		xerr := onetwork.Create(ctx, abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Contains(t, xerr.Error(), "calling method from a nil pointer")

		anetwork := &abstract.Network{
			ID:         "mynetwork",
			Name:       "mynetwork",
			CIDR:       "127.0.0.1/28",
			DNSServers: []string{"8.8.8.8", "8.8.4.4"},
			Imported:   false,
			Tags: map[string]string{
				"CreationDate": time.Now().Format(time.RFC3339),
				"ManagedBy":    "safescale",
			},
			// Domain: "domain",
			// GatewayID: "gatewayid",
			// SecondaryGatewayID: "SecondaryGatewayID"
		}

		mc, xerr := NewCore(svc, "network", "networks", anetwork)
		require.Nil(t, xerr)

		xerr = mc.Carry(ctx, anetwork)
		require.Nil(t, xerr)

		onetwork = &Network{MetadataCore: mc}
		xerr = onetwork.Create(nil, abstract.NetworkRequest{ // nolint
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})

	})
	require.Nil(t, xerr)
}

func TestNetwork_Carry(t *testing.T) {

	ctx := context.Background()

	anetwork := abstract.NewNetwork()
	anetwork.ID = "Network_ID"
	anetwork.Name = "Network Name"

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		networkReq := abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		}

		_, xerr := svc.CreateNetwork(ctx, networkReq)
		require.Nil(t, xerr)

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

		onetwork := network.(*Network)
		xerr = onetwork.carry(ctx, anetwork)
		require.Contains(t, xerr.Error(), "is not null value, cannot overwrite")

		svc._reset()

		network, xerr = NewNetwork(svc)
		require.Nil(t, xerr)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")

		onetwork = network.(*Network)

		defer func() {
			r := recover()
			if r != nil {
				t.Error(r)
			}
		}()

		xerr = onetwork.carry(ctx, anetwork)
		require.Nil(t, xerr)

	})
	require.Nil(t, xerr)

}

func TestNetwork_Import(t *testing.T) {

	network := abstract.NewNetwork()
	network.ID = "Network_ID"
	network.Name = "Network_Name"

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		fld, xerr := NewMetadataFolder(svc, "networks")
		xerr = debug.InjectPlannedFail(xerr)
		require.Nil(t, xerr)

		props, xerr := serializer.NewJSONProperties("resources.network")
		xerr = debug.InjectPlannedFail(xerr)
		require.Nil(t, xerr)

		onetwork := &Network{
			MetadataCore: &MetadataCore{
				kind:       "network",
				folder:     fld,
				properties: props,
			},
		}

		err := svc._setInternalData("networks/byID/Network_ID", network)
		require.Nil(t, err)
		err = svc._setInternalData("networks/byName/Network_Name", network)
		require.Nil(t, err)

		// @TODO: check about this behaviour, not sure that is correct
		xerr = onetwork.Import(ctx, "Network_ID")
		require.Contains(t, xerr.Error(), "cannot import Network")
		require.Contains(t, xerr.Error(), "is already such a Network in metadata")

	})
	require.Nil(t, xerr)

}

func TestNetwork_Browse(t *testing.T) {

	var callback func(storageBucket *abstract.Network) fail.Error
	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		networkReq := abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		}

		_, xerr := svc.CreateNetwork(ctx, networkReq)
		require.Nil(t, xerr)

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

		xerr = network.Browse(nil, func(network *abstract.Network) fail.Error { // nolint
			return nil
		})
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		xerr = network.Browse(ctx, callback)
		require.Contains(t, xerr.Error(), "invalid parameter: callback")

		/*
			xerr = network.Browse(ctx, func(network *abstract.Network) fail.Error {
				require.EqualValues(t, reflect.TypeOf(network).String(), "*abstract.Network")
				return nil
			})
			require.Contains(t, xerr.Error(), "cannot find a value for 'task' in context")

			task, err := concurrency.NewTaskWithContext(ctx)
			ctx = context.WithValue(ctx, "task", task)
			require.Nil(t, err)
		*/

		xerr = network.Browse(ctx, func(network *abstract.Network) fail.Error {
			require.EqualValues(t, reflect.TypeOf(network).String(), "*abstract.Network")
			require.EqualValues(t, skip(network.GetID()), "mynetwork")
			require.EqualValues(t, network.GetName(), "mynetwork")
			return nil
		})
		require.Nil(t, xerr)

	})
	require.Nil(t, xerr)

}

func TestNetwork_Delete(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		_, xerr := svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Nil(t, xerr)

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

		xerr = network.Delete(nil) // nolint
		require.Contains(t, xerr.Error(), "invalid parameter: ctx")

		func() {

			// FIXME: it panic here, it MUST not
			defer func() {
				if e := recover(); e != nil {
					switch e := e.(type) {
					case string:
						require.Contains(t, e, "invalid memory address or nil pointer dereference")
					case runtime.Error:
						require.Contains(t, e.Error(), "invalid memory address or nil pointer dereference")
					case error:
						require.Contains(t, e.Error(), "invalid memory address or nil pointer dereference")
					default:
						t.Error(e)
					}
				}
			}()

			xerr = network.Delete(ctx)
			require.Contains(t, xerr.Error(), "cannot find a value for 'task' in context")

		}()

		svc._reset()

		_, xerr = svc.CreateNetwork(ctx, abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		})
		require.Nil(t, xerr)

		network, err = LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

		xerr = network.Delete(ctx)
		require.Nil(t, xerr)

	})
	require.Nil(t, xerr)

}

func TestNetwork_GetCIDR(t *testing.T) {

	ctx := context.Background()

	// No task ? hum ...

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		networkReq := abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		}

		_, xerr := svc.CreateNetwork(ctx, networkReq)
		require.Nil(t, xerr)

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

		onetwork := network.(*Network)
		cidr, xerr := onetwork.GetCIDR(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, networkReq.CIDR, cidr)

	})
	require.Nil(t, xerr)

}

func TestNetwork_ToProtocol(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		networkReq := abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		}

		_, xerr := svc.CreateNetwork(ctx, networkReq)
		require.Nil(t, xerr)

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

		onetwork := network.(*Network)
		proto, xerr := onetwork.ToProtocol(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, reflect.TypeOf(proto).String(), "*protocol.Network")

	})
	require.Nil(t, xerr)

}

func TestNetwork_InspectSubnet(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		networkReq := abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		}

		_, xerr := svc.CreateNetwork(ctx, networkReq)
		require.Nil(t, xerr)

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

		onetwork := network.(*Network)
		_, xerr = onetwork.InspectSubnet(ctx, "mynetwork")
		require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrNotFound")

		subnetReq := abstract.SubnetRequest{
			Name:           "mynetwork",
			NetworkID:      "mynetwork",
			IPVersion:      ipversion.IPv4,
			CIDR:           "192.168.16.4/32",
			DefaultSSHPort: 22,
		}
		_, xerr = svc.CreateSubnet(ctx, subnetReq)
		require.Nil(t, xerr)

		osubnet, err := LoadSubnet(ctx, svc, "", "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(osubnet).String(), "*operations.Subnet")
		require.EqualValues(t, skip(osubnet.GetID()), "mynetwork")

		xerr = onetwork.AdoptSubnet(ctx, osubnet)
		require.Nil(t, xerr)

		subnet, xerr := onetwork.InspectSubnet(ctx, "mynetwork")
		require.Nil(t, xerr)
		require.EqualValues(t, osubnet, subnet)

		xerr = onetwork.AbandonSubnet(ctx, "mynetwork")
		require.Nil(t, xerr)

		_, xerr = onetwork.InspectSubnet(ctx, "mynetwork")
		require.EqualValues(t, reflect.TypeOf(xerr).String(), "*fail.ErrNotFound")

	})
	require.Nil(t, xerr)

}

func Test_FreeCIDRForSingleHost(t *testing.T) {

	ctx := context.Background()

	xerr := NewServiceTest(t, func(svc *ServiceTest) {

		networkReq := abstract.NetworkRequest{
			Name:          "mynetwork",
			CIDR:          "192.168.16.4/32",
			DNSServers:    []string{"8.8.8.8", "8.8.4.4"},
			KeepOnFailure: false,
		}

		_, xerr := svc.CreateNetwork(ctx, networkReq)
		require.Nil(t, xerr)

		network, err := LoadNetwork(ctx, svc, "mynetwork")
		require.Nil(t, err)
		require.EqualValues(t, reflect.TypeOf(network).String(), "*operations.Network")
		require.EqualValues(t, skip(network.GetID()), "mynetwork")

		xerr = FreeCIDRForSingleHost(ctx, network, 21)
		require.Nil(t, xerr)

		onetwork := network.(*Network)

		cidr, xerr := onetwork.GetCIDR(ctx)
		require.Nil(t, xerr)
		require.EqualValues(t, cidr, "192.168.16.4/32")

	})
	require.Nil(t, xerr)

}
