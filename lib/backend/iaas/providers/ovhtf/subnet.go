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

	terraformer "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

const (
	subnetDesignResourceSnippetPath = "snippets/resource_subnet_design.tf"
)

// type subnetResource struct {
// 	terraformer.ResourceCore
//
// 	id             string
// 	networkID      string
// 	cidr           string
// 	ipVersion      string
// 	dnsNameServers []string
// }
//
// func newSubnetResource(name string, snippet string) (*subnetResource, fail.Error) {
// 	rc, xerr := terraformer.NewResourceCore(name, snippet)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	return &subnetResource{ResourceCore: rc}, nil
// }
//
// // ToMap returns a map of networkResource field to be used where needed
// func (nr *subnetResource) ToMap() map[string]any {
// 	return map[string]any{
// 		"Name":       nr.Name(),
// 		"ID":         nr.networkID,
// 		"CIDR":       nr.cidr,
// 		"IPVersion":  nr.ipVersion,
// 		"NetworkID":  nr.networkID,
// 		"DNSServers": nr.dnsNameServers,
// 	}
// }

// type routerResource struct {
// 	terraformer.ResourceCore
//
// 	id string
// }
//
// func newRouterResource(name string, snippet string) (*routerResource, fail.Error) {
// 	rc, xerr := terraformer.NewResourceCore(name, snippet)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	return &routerResource{ResourceCore: rc}, nil
// }
//
// // ToMap returns a map of networkResource field to be used where needed
// func (rr *routerResource) ToMap() map[string]any {
// 	return map[string]any{
// 		"Name": rr.Name(),
// 		"ID":   rr.id,
// 	}
// }

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

	abstractSubnet, xerr := abstract.NewSubnet(abstract.WithName(req.Name))
	if xerr != nil {
		return nil, xerr
	}

	xerr = p.ConsolidateSubnetSnippet(abstractSubnet)
	if xerr != nil {
		return nil, xerr
	}

	abstractSubnet.CIDR = req.CIDR
	abstractSubnet.IPVersion = req.IPVersion
	abstractSubnet.DNSServers = req.DNSServers
	abstractSubnet.Network = req.NetworkID
	abstractSubnet.Domain = req.Domain

	// Pass information to terraformer that we are in creation process
	xerr = abstractSubnet.AddOptions(abstract.MarkForCreation())
	if xerr != nil {
		return nil, xerr
	}

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

	// FIXME: is it necessary?
	// if !p.configOptions.UseLayer3Networking {
	// 	// noGateway := ""
	// 	// opts.GatewayIP = &noGateway
	// }

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return nil, xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: should be necessary to add local Resource for router, and add it to Assemble... Otherwise it will be difficult to remove routers during Destroy...
	def, xerr := renderer.Assemble(ctx, abstractSubnet)
	if xerr != nil {
		return nil, xerr
	}
	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			logrus.WithContext(ctx).Infof("cleaning up on failure, deleting Subnet '%s'", req.Name)
			derr := renderer.Destroy(ctx, def, terraformerapi.WithTarget(abstractSubnet))
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	abstractSubnet.ID, xerr = unmarshalOutput[string](outputs["subnet_"+req.Name+"_id"])
	if xerr != nil {
		return nil, xerr
	}

	return abstractSubnet, nil
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

	defer debug.NewTracer(ctx, tracing.ShouldTrace("providers.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	as, xerr := p.MiniStack.InspectSubnet(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	return as, p.ConsolidateSubnetSnippet(as)
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

	as, xerr := p.MiniStack.InspectSubnetByName(ctx, networkRef, name)
	if xerr != nil {
		return nil, xerr
	}

	return as, p.ConsolidateSubnetSnippet(as)
}

// ListSubnets lists available subnets in a network
func (p *provider) ListSubnets(ctx context.Context, networkID string) ([]*abstract.Subnet, fail.Error) {
	var emptySlice []*abstract.Subnet
	if valid.IsNull(p) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "").WithStopwatch().Entering().Exiting()

	return p.MiniStack.ListSubnets(ctx, networkID)
}

// DeleteSubnet deletes the network identified by id
func (p *provider) DeleteSubnet(ctx context.Context, subnetParam iaasapi.SubnetIdentifier) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	as, subnetLabel, xerr := iaasapi.ValidateSubnetIdentifier(subnetParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("providers.network") || tracing.ShouldTrace("provider.ovhtf"), "(%s)", subnetLabel).WithStopwatch().Entering().Exiting()

	if as.ID != "" {
		as, xerr = p.InspectSubnet(ctx, as.ID)
	} else {
		as, xerr = p.InspectSubnetByName(ctx, as.Network, as.Name)
	}
	if xerr != nil {
		return xerr
	}

	xerr = as.AddOptions(abstract.MarkForDestruction())
	if xerr != nil {
		return xerr
	}

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return xerr
	}

	def, xerr := renderer.Assemble(ctx, as)
	if xerr != nil {
		return xerr
	}

	xerr = renderer.Destroy(ctx, def /*, terraformerapi.WithTarget(as)*/)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete Network '%s'", as.Name)
	}

	return nil
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

func (p *provider) ConsolidateSubnetSnippet(as *abstract.Subnet) fail.Error {
	if valid.IsNil(p) || as == nil {
		return nil
	}

	return as.AddOptions(
		abstract.UseTerraformSnippet(subnetDesignResourceSnippetPath),
		abstract.WithResourceType("openstack_networking_subnet_v2"),
	)
}
