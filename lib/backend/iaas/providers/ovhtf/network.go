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

package ovhtf

import (
	"context"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers/terraformer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/global"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	networkResourceSnippetPath = "snippets/resource_network.tf.template"
)

type (
	networkResource struct {
		ResourceCore
	}
)

func newNetworkResource(name string) terraformer.Resource {
	out := &networkResource{NewResourceCore(name)}
	out.ResourceCore.snippet = networkResourceSnippetPath
	return out
}

// ToMap returns a map of networkResource field to be used where needed
func (nr *networkResource) ToMap() map[string]any {
	return map[string]any{
		"Name": nr.Name(),
	}
}

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (p provider) HasDefaultNetwork(context.Context) (bool, fail.Error) {
	return false, nil
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (p provider) GetDefaultNetwork(context.Context) (*abstract.Network, fail.Error) {
	// FIXME: support default network
	return nil, fail.NotFoundError("no default network for this provider")
}

// CreateNetwork creates a network named name
func (p provider) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (newNet *abstract.Network, ferr fail.Error) {
	var xerr fail.Error
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Special treatment for OVH : no dnsServers means __NO__ DNS servers, not default ones
	// The way to do so, accordingly to OVH support, is to set DNS servers to 0.0.0.0
	if len(req.DNSServers) == 0 {
		req.DNSServers = []string{"0.0.0.0"}
	}

	// Checks if CIDR is valid...
	if req.CIDR != "" {
		_, _, err := net.ParseCIDR(req.CIDR)
		if err != nil {
			return nil, fail.Wrap(err, "failed to create subnet '%s (%s)': %s", req.Name, req.CIDR)
		}
	} else { // CIDR is empty, choose the first Class C one possible
		tracer.Trace("CIDR is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
	}

	netRsc := newNetworkResource(req.Name)

	summoner, xerr := terraformer.NewSummoner(p.tfWorkdir, global.Settings.Backend.Terraform.ExecPath)
	if xerr != nil {
		return nil, xerr
	}

	xerr = summoner.Build(p, netRsc)
	if xerr != nil {
		return nil, xerr
	}

	// // We specify a name and that it should forward packets
	// state := true
	// basicOpts := networks.CreateOpts{
	// 	Name:         req.Name,
	// 	AdminStateUp: &state,
	// }
	//
	// opts := portsecurity.NetworkCreateOptsExt{
	// 	CreateOptsBuilder:   basicOpts,
	// 	PortSecurityEnabled: gophercloud.Enabled,
	// }
	//
	// // Creates the network
	// var network *networks.Network
	// xerr = stacks.RetryableRemoteCall(ctx,
	// 	func() (innerErr error) {
	// 		network, innerErr = networks.Create(s.NetworkClient, opts).Extract()
	// 		return innerErr
	// 	},
	// 	NormalizeError,
	// )
	outputs, xerr := summoner.Apply(ctx)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create network '%s'", req.Name)
	}
	_ = outputs

	// Starting from here, delete network if exit with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := summoner.Destroy(ctx)
			if derr != nil {
				logrus.WithContext(ctx).Errorf("failed to delete Network '%s': %v", req.Name, derr)
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	newNet = abstract.NewNetwork()
	// FIXME: how to recover outputs from terraform apply?
	// newNet.ID = outputs.ID
	// newNet.Name = outputs.Name
	newNet.CIDR = req.CIDR
	return newNet, nil
}

// InspectNetworkByName ...
func (p *provider) InspectNetworkByName(ctx context.Context, name string) (*abstract.Network, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", name).WithStopwatch().Entering().Exiting()

	return nil, fail.NotImplementedError()

	/*
		// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
		r := networks.GetResult{}
		xerr := stacks.RetryableRemoteCall(ctx,
			func() error {
				_, r.Err = s.ComputeClient.Get(s.NetworkClient.ServiceURL("networks?name="+name), &r.Body, &gophercloud.RequestOpts{
					OkCodes: []int{200, 203},
				})
				return r.Err
			},
			NormalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrForbidden:
				return nil, abstract.ResourceForbiddenError("network", name)
			default:
				return nil, fail.NewError("query for network '%s' failed: %v", name, r.Err)
			}
		}

		nets, found := r.Body.(map[string]interface{})["networks"].([]interface{})
		if found && len(nets) > 0 {
			entry, ok := nets[0].(map[string]interface{})
			if !ok {
				return nil, fail.InvalidParameterError("Body['networks']", "is not a map[string]")
			}
			id, ok := entry["id"].(string)
			if !ok {
				return nil, fail.InvalidParameterError("entry['id']", "is not a string")
			}
			return s.InspectNetwork(ctx, id)
		}
		return nil, abstract.ResourceNotFoundError("network", name)
	*/
}

// InspectNetwork returns the network identified by id
func (p *provider) InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	return nil, fail.NotImplementedError()

	/*
		// If not found, we look for any network from provider
		// 1st try with id
		var network *networks.Network
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (innerErr error) {
				network, innerErr = networks.Get(s.NetworkClient, id).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
				debug.IgnoreError(xerr)
			default:
				return nil, xerr
			}
		}
		if network != nil && network.ID != "" {
			newNet := abstract.NewNetwork()
			newNet.ID = network.ID
			newNet.Name = network.Name
			return newNet, nil
		}

		// At this point, no network has been found with given reference
		errNotFound := abstract.ResourceNotFoundError("network", id)
		// logrus.Debug(errNotFound)
		return nil, errNotFound
	*/
}

// ListNetworks lists available networks
func (p *provider) ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error) {
	var emptySlice []*abstract.Network
	if valid.IsNull(p) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "").WithStopwatch().Entering().Exiting()

	return nil, fail.NotImplementedError()

	/*
		// Retrieve a pager (i.e. a paginated collection)
		var netList []*abstract.Network
		xerr := stacks.RetryableRemoteCall(ctx,
			func() error {
				innerErr := networks.List(s.NetworkClient, networks.ListOpts{}).EachPage(
					func(page pagination.Page) (bool, error) {
						networkList, err := networks.ExtractNetworks(page)
						if err != nil {
							return false, err
						}

						for _, n := range networkList {
							if n.ID == s.ProviderNetworkID {
								continue
							}

							newNet := abstract.NewNetwork()
							newNet.ID = n.ID
							newNet.Name = n.Name

							netList = append(netList, newNet)
						}
						return true, nil
					},
				)
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return emptySlice, xerr
		}

		return netList, nil
	*/
}

// DeleteNetwork deletes the network identified by id
func (p *provider) DeleteNetwork(ctx context.Context, id string) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	return fail.NotImplementedError()

	/*
		var network *networks.Network
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (innerErr error) {
				network, innerErr = networks.Get(s.NetworkClient, id).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			logrus.WithContext(ctx).Errorf("failed to get Network '%s': %+v", id, xerr)
			return xerr
		}

		sns, xerr := s.ListSubnets(ctx, id)
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to list Subnets of Network '%s'", network.Name)
			logrus.WithContext(ctx).Debugf(strprocess.Capitalize(xerr.Error()))
			return xerr
		}
		if len(sns) > 0 {
			return fail.InvalidRequestError("cannot delete a Network '%s': there are Subnets in it", network.Name)
		}

		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				return networks.Delete(s.NetworkClient, id).ExtractErr()
			},
			NormalizeError,
		)
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to delete Network '%s'", network.Name)
			logrus.WithContext(ctx).Debugf(strprocess.Capitalize(xerr.Error()))
			return xerr
		}

		return nil
	*/
}

// ToGophercloudIPVersion converts ipversion.Enum (corresponding to SafeScale abstract) to gophercloud.IPVersion
// if v is invalid, returns gophercloud.IPv4
func ToGophercloudIPVersion(v ipversion.Enum) gophercloud.IPVersion {
	switch v {
	case ipversion.IPv6:
		return gophercloud.IPv6
	case ipversion.IPv4:
		fallthrough
	default:
		return gophercloud.IPv4
	}
}

// ToAbstractIPVersion converts an int representation of IPVersion to an ipversion.Enum
// if v is invalid, returns ipversion.sIPv4
func ToAbstractIPVersion(v int) ipversion.Enum {
	switch v {
	case 6:
		return ipversion.IPv6
	case 4:
		fallthrough
	default:
		return ipversion.IPv4
	}
}

// // createRouter creates a router satisfying req
// func (p *provider) createRouter(ctx context.Context, req RouterRequest) (*Router, fail.Error) {
// 	// Create a router to connect external provider network
// 	gi := routers.GatewayInfo{
// 		NetworkID: req.NetworkID,
// 	}
// 	state := true
// 	opts := routers.CreateOpts{
// 		Name:         req.Name,
// 		AdminStateUp: &state,
// 		GatewayInfo:  &gi,
// 	}
// 	var router *routers.Router
// 	xerr := stacks.RetryableRemoteCall(ctx,
// 		func() (innerErr error) {
// 			router, innerErr = routers.Create(s.NetworkClient, opts).Extract()
// 			return innerErr
// 		},
// 		NormalizeError,
// 	)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	logrus.WithContext(ctx).Debugf("Openstack router '%s' (%s) successfully created", router.Name, router.ID)
// 	return &Router{
// 		ID:        router.ID,
// 		Name:      router.Name,
// 		NetworkID: router.GatewayInfo.NetworkID,
// 	}, nil
// }

// // ListRouters lists available routers
// func (p *provider) ListRouters(ctx context.Context) ([]Router, fail.Error) {
// 	var emptySlice []Router
// 	if valid.IsNull(p) {
// 		return emptySlice, fail.InvalidInstanceError()
// 	}
//
// 	var ns []Router
// 	xerr := stacks.RetryableRemoteCall(ctx,
// 		func() error {
// 			return routers.List(s.NetworkClient, routers.ListOpts{}).EachPage(
// 				func(page pagination.Page) (bool, error) {
// 					list, err := routers.ExtractRouters(page)
// 					if err != nil {
// 						return false, err
// 					}
// 					for _, r := range list {
// 						an := Router{
// 							ID:        r.ID,
// 							Name:      r.Name,
// 							NetworkID: r.GatewayInfo.NetworkID,
// 						}
// 						ns = append(ns, an)
// 					}
// 					return true, nil
// 				},
// 			)
// 		},
// 		NormalizeError,
// 	)
// 	return ns, xerr
// }
//
// // deleteRouter deletes the router identified by id
// func (p *provider) deleteRouter(ctx context.Context, id string) fail.Error {
// 	return stacks.RetryableRemoteCall(ctx,
// 		func() error {
// 			return routers.Delete(s.NetworkClient, id).ExtractErr()
// 		},
// 		NormalizeError,
// 	)
// }
//
// // addSubnetToRouter attaches subnet to router
// func (p *provider) addSubnetToRouter(ctx context.Context, routerID string, subnetID string) fail.Error {
// 	return stacks.RetryableRemoteCall(ctx,
// 		func() error {
// 			_, innerErr := routers.AddInterface(s.NetworkClient, routerID, routers.AddInterfaceOpts{
// 				SubnetID: subnetID,
// 			}).Extract()
// 			return innerErr
// 		},
// 		NormalizeError,
// 	)
// }
//
// // removeSubnetFromRouter detaches a subnet from router interface
// func (p *provider) removeSubnetFromRouter(ctx context.Context, routerID string, subnetID string) fail.Error {
// 	return stacks.RetryableRemoteCall(ctx,
// 		func() error {
// 			_, innerErr := routers.RemoveInterface(s.NetworkClient, routerID, routers.RemoveInterfaceOpts{
// 				SubnetID: subnetID,
// 			}).Extract()
// 			return innerErr
// 		},
// 		NormalizeError,
// 	)
// }
