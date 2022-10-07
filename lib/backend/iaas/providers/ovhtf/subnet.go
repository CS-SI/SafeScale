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

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/terraformer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	createSubnetResourceSnippetPath = "snippets/resource_subnet_create.tf"
	createRouterResourceSnippetPath = "snippets/resource_router_create.tf"
)

type subnetResource struct {
	terraformer.ResourceCore

	id             string
	networkID      string
	cidr           string
	ipVersion      ipversion.Enum
	dnsNameServers []string
}

func newSubnetResource(name string, snippet string) *subnetResource {
	out := &subnetResource{ResourceCore: terraformer.NewResourceCore(name, snippet)}
	return out
}

// ToMap returns a map of networkResource field to be used where needed
func (nr *subnetResource) ToMap() map[string]any {
	return map[string]any{
		"Name":       nr.Name(),
		"ID":         nr.networkID,
		"CIDR":       nr.cidr,
		"IPVersion":  nr.ipVersion,
		"NetworkID":  nr.networkID,
		"DNSServers": nr.dnsNameServers,
	}
}

type routerResource struct {
	terraformer.ResourceCore

	id string
}

func newRouterResource(name string, snippet string) *routerResource {
	out := &routerResource{ResourceCore: terraformer.NewResourceCore(name, snippet)}
	return out
}

// ToMap returns a map of networkResource field to be used where needed
func (rr *routerResource) ToMap() map[string]any {
	return map[string]any{
		"Name": rr.Name(),
		"ID":   rr.id,
	}
}

// CreateSubnet creates a subnet
func (p *provider) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (newNet *abstract.Subnet, ferr fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Checks if CIDR is valid...
	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		return nil, fail.ConvertError(err)
	}

	subnetRsc := newSubnetResource(req.Name, createSubnetResourceSnippetPath)
	subnetRsc.cidr = req.CIDR
	subnetRsc.ipVersion = req.IPVersion
	subnetRsc.dnsNameServers = req.DNSServers

	// // If req.IPVersion contains invalid value, force to IPv4
	// var ipVersion gophercloud.IPVersion
	// switch ToGophercloudIPVersion(req.IPVersion) {
	// case gophercloud.IPv6:
	// 	ipVersion = gophercloud.IPv6
	// case gophercloud.IPv4:
	// 	fallthrough
	// default:
	// 	ipVersion = gophercloud.IPv4
	// }
	//

	// // You must associate a new subnet with an existing network - to do this you
	// // need its UUID. You must also provide a well-formed CIDR value.
	// dhcp := true
	// opts := subnets.CreateOpts{
	// 	NetworkID:  req.NetworkID,
	// 	CIDR:       req.CIDR,
	// 	IPVersion:  ipVersion,
	// 	Name:       req.Name,
	// 	EnableDHCP: &dhcp,
	// }
	if len(req.DNSServers) > 0 {
		subnetRsc.dnsNameServers = req.DNSServers
	}

	// FIXME: is it necessary?
	// if !p.configOptions.UseLayer3Networking {
	// 	// noGateway := ""
	// 	// opts.GatewayIP = &noGateway
	// }

	summoner, xerr := p.Terraformer()
	if xerr != nil {
		return nil, xerr
	}

	xerr = summoner.Build(subnetRsc)
	if xerr != nil {
		return nil, xerr
	}

	outputs, xerr := summoner.Apply(ctx)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: think about it: not deleting may allow to rerun to finalize creation...
	// defer func() {
	// 	if ferr != nil {
	// 		derr := summoner.Destroy(ctx)
	// 		if derr != nil {
	// 			_ = ferr.AddConsequence(derr)
	// 		}
	// 	}
	// }()

	out := &abstract.Subnet{
		Name:      req.Name,
		Network:   req.NetworkID,
		IPVersion: req.IPVersion,
		Domain:    req.Domain,
		CIDR:      req.CIDR,
	}
	out.ID, xerr = unmarshalOutput[string](outputs["subnet_id"])
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}

func (p *provider) validateCIDR(req abstract.SubnetRequest, network *abstract.Network) fail.Error {
	_, _ /*subnetDesc*/, err := net.ParseCIDR(req.CIDR)
	if err != nil {
		return fail.Wrap(err, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
	}
	return nil
}

// InspectSubnet returns the subnet identified by id
func (p *provider) InspectSubnet(ctx context.Context, id string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	return nil, fail.NotImplementedError()

	/*
		as := abstract.NewSubnet()
		var sn *subnets.Subnet
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (innerErr error) {
				sn, innerErr = subnets.Get(s.NetworkClient, id).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return nil, xerr
		}

		as.ID = sn.ID
		as.Name = sn.Name
		as.Network = sn.NetworkID
		as.IPVersion = ToAbstractIPVersion(sn.IPVersion)
		as.CIDR = sn.CIDR
		as.DNSServers = sn.DNSNameservers

		return as, nil
	*/
}

// InspectSubnetByName ...
func (p *provider) InspectSubnetByName(ctx context.Context, networkRef, name string) (subnet *abstract.Subnet, ferr fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", name).WithStopwatch().Entering().Exiting()

	return nil, fail.NotImplementedError()

	/*
		listOpts := subnets.ListOpts{
			Name: name,
		}
		var an *abstract.Network
		if networkRef != "" {
			var xerr fail.Error
			an, xerr = s.InspectNetwork(ctx, networkRef)
			if xerr != nil {
				switch xerr.(type) { // nolint
				case *fail.ErrNotFound:
					an, xerr = s.InspectNetworkByName(ctx, networkRef)
					if xerr != nil {
						return nil, xerr
					}
				default:
					return nil, xerr
				}
			}

			listOpts.NetworkID = an.ID
		}

		var resp []subnets.Subnet
		xerr := stacks.RetryableRemoteCall(ctx,
			func() error {
				var allPages pagination.Page
				var innerErr error
				if allPages, innerErr = subnets.List(s.NetworkClient, listOpts).AllPages(); innerErr != nil {
					return innerErr
				}
				resp, innerErr = subnets.ExtractSubnets(allPages)
				if innerErr != nil {
					return innerErr
				}
				return nil
			},
			NormalizeError,
		)
		if xerr != nil {
			return nil, xerr
		}

		switch len(resp) {
		case 0:
			msg := "failed to find a Subnet named '%s'"
			if an != nil {
				msg += " in Network '%s'"
				return nil, fail.NotFoundError(msg, name, an.Name)
			}
			return nil, fail.NotFoundError(msg, name)
		case 1:
			item := resp[0]
			subnet = abstract.NewSubnet()
			subnet.ID = item.ID
			subnet.Network = item.NetworkID
			subnet.Name = name
			subnet.CIDR = item.CIDR
			subnet.DNSServers = item.DNSNameservers
			subnet.IPVersion = ToAbstractIPVersion(item.IPVersion)
			return subnet, nil
		default:
			msg := "more than one Subnet named '%s' found"
			if an != nil {
				msg += " in Network '%s'"
				return nil, fail.DuplicateError(msg, name, an.Name)
			}
			return nil, fail.DuplicateError(msg, name)
		}
	*/
}

// ListSubnets lists available subnets in a network
func (p *provider) ListSubnets(ctx context.Context, networkID string) ([]*abstract.Subnet, fail.Error) {
	var emptySlice []*abstract.Subnet
	if valid.IsNull(p) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "").WithStopwatch().Entering().Exiting()

	return nil, fail.NotImplementedError()

	/*
		listOpts := subnets.ListOpts{}
		if networkID != "" {
			listOpts.NetworkID = networkID
		}
		var subnetList []*abstract.Subnet
		xerr := stacks.RetryableRemoteCall(ctx,
			func() error {
				return subnets.List(s.NetworkClient, listOpts).EachPage(func(page pagination.Page) (bool, error) {
					list, err := subnets.ExtractSubnets(page)
					if err != nil {
						return false, NormalizeError(err)
					}

					for _, subnet := range list {
						item := abstract.NewSubnet()
						item.ID = subnet.ID
						item.Name = subnet.Name
						item.Network = subnet.ID
						item.IPVersion = ToAbstractIPVersion(subnet.IPVersion)
						subnetList = append(subnetList, item)
					}
					return true, nil
				})
			},
			NormalizeError,
		)
		if xerr != nil {
			return emptySlice, xerr
		}
		// VPL: empty subnet list is not an abnormal situation, do not log
		return subnetList, nil
	*/
}

// DeleteSubnet deletes the network identified by id
func (p *provider) DeleteSubnet(ctx context.Context, id string) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stacks.network") || tracing.ShouldTrace("stack.openstack"), "(%s)", id).WithStopwatch().Entering().Exiting()

	return fail.NotImplementedError()

	/*
		timings, xerr := s.Timings()
		if xerr != nil {
			return xerr
		}

		routerList, _ := s.ListRouters(ctx)
		var router *Router
		for _, r := range routerList {
			r := r
			if r.Name == id {
				router = &r
				break
			}
		}
		if router != nil {
			if xerr := s.removeSubnetFromRouter(ctx, router.ID, id); xerr != nil {
				return fail.Wrap(xerr, "failed to remove Subnet %s from its router %s", id, router.ID)
			}
			if xerr := s.deleteRouter(ctx, router.ID); xerr != nil {
				return fail.Wrap(xerr, "failed to delete router %s associated with Subnet %s", router.ID, id)
			}
		}

		retryErr := retry.WhileUnsuccessful(
			func() error {
				innerXErr := stacks.RetryableRemoteCall(ctx,
					func() error {
						return subnets.Delete(s.NetworkClient, id).ExtractErr()
					},
					NormalizeError,
				)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrInvalidRequest, *fail.ErrDuplicate:
						msg := "hosts or services are still attached"
						return retry.StopRetryError(fail.Wrap(innerXErr, msg))
					case *fail.ErrNotFound:
						// consider a missing Subnet as a successful deletion
						debug.IgnoreError(innerXErr)
					default:
						return innerXErr
					}
				}
				return nil
			},
			timings.NormalDelay(),
			timings.ContextTimeout(),
		)
		if retryErr != nil {
			switch retryErr.(type) {
			case *retry.ErrTimeout:
				return fail.Wrap(fail.Cause(retryErr), "timeout")
			case *retry.ErrStopRetry:
				return fail.Wrap(fail.Cause(retryErr), "stopping retries")
			default:
				return retryErr
			}
		}
		return nil
	*/
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
