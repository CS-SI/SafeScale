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
	"reflect"

	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/sirupsen/logrus"

	terraformer "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	networkDesignResourceSnippetPath = "snippets/resource_network_design.tf"
	// networkCreateResourceSnippetPath  = "snippets/resource_network_create.tf"
	// networkDeleteResourceSnippetPath  = "snippets/resource_network_delete.tf"
	// networkInspectResourceSnippetPath = "snippets/resource_network_inspect.tf"
)

// type (
// 	networkResource struct {
// 		terraformer.ResourceCore
// 		id string
// 	}
// )

// func newNetworkResource(name string, snippet string, opts ...terraformer.ResourceOption) (*networkResource, fail.Error) {
// 	rc, xerr := terraformer.NewResourceCore(name, snippet, opts...)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	return &networkResource{ResourceCore: rc}, nil
// }
//
// // ToMap returns a map of networkResource field to be used where needed
// func (nr *networkResource) ToMap() map[string]any {
// 	return map[string]any{
// 		"Name": nr.Name(),
// 		"ID":   nr.id,
// 	}
// }
//
// // String returns a string that represents the network resource
// func (nr networkResource) String() string {
// 	out := "'" + nr.Name() + "'"
// 	if out == "''" {
// 		out = nr.id
// 	}
// 	return out
// }

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (p *provider) HasDefaultNetwork() (bool, fail.Error) {
	return false, nil
}

// DefaultNetwork returns the *abstract.Network corresponding to the default network
func (p *provider) DefaultNetwork(context.Context) (*abstract.Network, fail.Error) {
	// FIXME: support default network
	return nil, fail.NotFoundError("no default Network for this Provider")
}

// CreateNetwork creates a network named name
func (p *provider) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	var xerr fail.Error
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.network"), "(%s)", req.Name).WithStopwatch().Entering()
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
			return nil, fail.Wrap(err)
		}
	} else { // CIDR is empty, choose the first Class C one possible
		tracer.Trace("CIDR is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
	}

	abstractNetwork, xerr := p.DesignNetwork(ctx, req)
	if xerr != nil {
		return nil, xerr
	}

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return nil, xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return nil, xerr
	}

	def, xerr := renderer.Assemble(abstractNetwork)
	if xerr != nil {
		return nil, xerr
	}

	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to create network '%s'", req.Name)
	}

	// Starting from here, delete network if exit with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			logrus.WithContext(ctx).Infof("Cleaning up on failure, deleting Network '%s'", req.Name)
			derr := renderer.Destroy(ctx, def, terraformerapi.WithTarget(abstractNetwork))
			if derr != nil {
				logrus.WithContext(ctx).Errorf("failed to delete Network '%s': %v", req.Name, derr)
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	abstractNetwork.ID, xerr = unmarshalOutput[string](outputs["network_"+req.Name+"_id"])
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to recover Network id")
	}

	return abstractNetwork, nil
}

// DesignNetwork initializes a networkResource to create/inspect/destroy Network
func (p *provider) DesignNetwork(ctx context.Context, req abstract.NetworkRequest) (_ *abstract.Network, ferr fail.Error) {
	var xerr fail.Error
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.network"), "(%s)", req.Name).WithStopwatch().Entering()
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
			return nil, fail.Wrap(err)
		}
	} else { // CIDR is empty, choose the first Class C one possible
		tracer.Trace("CIDR is empty, choosing one...")
		req.CIDR = "192.168.1.0/24"
		tracer.Trace("CIDR chosen for network is '%s'", req.CIDR)
	}

	opts := []abstract.Option{
		abstract.WithName(req.Name),
		abstract.UseTerraformSnippet(networkDesignResourceSnippetPath),
		abstract.WithResourceType("openstack_networking_network_v2"),
	}
	newNet, xerr := abstract.NewNetwork(opts...)
	if xerr != nil {
		return nil, xerr
	}

	newNet.CIDR = req.CIDR

	// summoner, xerr := p.Terraformer()
	// if xerr != nil {
	// 	return nil, xerr
	// }
	// defer func() { _ = summoner.Close() }()
	//
	// xerr = summoner.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// xerr = summoner.Assemble(netRsc)
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// outputs, xerr := summoner.Apply(ctx)
	// if xerr != nil {
	// 	return nil, fail.Wrap(xerr, "failed to create network '%s'", req.Name)
	// }
	//
	// // Starting from here, delete network if exit with error
	// defer func() {
	// 	ferr = debug.InjectPlannedFail(ferr)
	// 	if ferr != nil && req.CleanOnFailure() {
	// 		logrus.WithContext(ctx).Infof("Cleaning up on failure, deleting Network '%s'", req.Name)
	// 		derr := summoner.Destroy(ctx)
	// 		if derr != nil {
	// 			logrus.WithContext(ctx).Errorf("failed to delete Network '%s': %v", req.Name, derr)
	// 			_ = ferr.AddConsequence(derr)
	// 		}
	// 	}
	// }()

	return newNet, nil
}

// InspectNetworkByName returns information about a Network identified by its name
// Note: uses MiniStack, as there is no way (as far as I know) to do that with terraform
// returns:
//   - nil, *fail.ErrInvalidParameter: one parameter is invalid
//   - nil, *fail.ErrNotFound: network not found
//   - nil, *fail.ErrDuplicate: found multiple networks with that name
//   - *abstract.Network, nil: network found and returned information
func (p *provider) InspectNetworkByName(ctx context.Context, name string) (*abstract.Network, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.network"), "(%s)", name).WithStopwatch().Entering().Exiting()

	return p.MiniStack.InspectNetworkByName(ctx, name)
}

func unmarshalOutput[T any](in tfexec.OutputMeta) (T, fail.Error) {
	var out T
	if len(in.Value) == 0 {
		return out, fail.SyntaxError("failed to unmarshal empty %s value", in.Type, in.Value, reflect.TypeOf(out).String())
	}

	err := json.Unmarshal(in.Value, &out)
	if err != nil {
		return out, fail.Wrap(err, "failed to unmarshal '%s' value in '%s'", in.Type, reflect.TypeOf(out).String())
	}

	return out, nil
}

// func (p *provider) inspectNetworkResource(ctx context.Context, rsc *networkResource) (*abstract.Network, fail.Error) {
// 	summoner, xerr := p.Terraformer()
// 	if xerr != nil {
// 		return nil, xerr
// 	}
// 	defer func() { _ = summoner.Close() }()
//
// 	xerr = summoner.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	xerr = summoner.Assemble(rsc)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	if rsc.id != "" {
// 		xerr := summoner.Import(ctx, "openstack_networking_network_v2.network_inspect", rsc.id)
// 		if xerr != nil {
// 			switch xerr.(type) {
// 			case *fail.ErrDuplicate:
// 				// continue
// 				debug.IgnoreError(xerr)
// 			default:
// 				return nil, xerr
// 			}
// 		}
// 	} else {
// 		// FIXME: List all networks and import the one we are interested in by name
// 	}
//
// 	state, xerr := summoner.State(ctx)
// 	if xerr != nil {
// 		switch xerr.(type) {
// 		case *fail.ErrNotFound:
// 			return nil, fail.NotFoundError("failed to find network %s", rsc.String())
// 		case *fail.ErrDuplicate:
// 			return nil, fail.DuplicateError("found multiple networks %s", rsc.String())
// 		default:
// 			return nil, xerr
// 		}
// 	}
//
// 	out := abstract.NewNetwork()
// 	if state.Values != nil {
// 		for _, v := range state.Values.RootModule.Resources {
// 			if v.Address == "openstack_networking_network_v2.network_inspect" {
// 				var ok bool
// 				attrs := v.AttributeValues
// 				out.ID, ok = attrs["id"].(string)
// 				if !ok {
// 					return nil, fail.SyntaxError("failed to get field 'id' of Network")
// 				}
//
// 				out.Name, ok = attrs["name"].(string)
// 				if !ok {
// 					return nil, fail.SyntaxError("failed to get field 'name' of Network")
// 				}
//
// 				tags, ok := attrs["all_tags"].([]string)
// 				if xerr != nil {
// 					return nil, fail.SyntaxError("failed to get field 'all_tags' of Network")
// 				}
//
// 				out.Tags = data.StringSliceToMap[string](tags)
// 				return out, nil
// 			}
// 		}
// 	}
// 	return nil, fail.NotFoundError()
// }

// InspectNetwork returns the network identified by id
// Note: found a way to do that with terraform (far from being simple)... Not sure we shouldn't use MiniStack instead...
// returns:
//   - nil, *fail.ErrInvalidParameter: one parameter is invalid
//   - nil, *fail.ErrNotFound: network not found
//   - nil, *fail.ErrDuplicate: found multiple networks with that name
//   - *abstract.Network, nil: network found and returned information
func (p *provider) InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.network"), "(%s)", id).WithStopwatch().Entering().Exiting()

	return p.MiniStack.InspectNetwork(ctx, id)
	//
	// netRsc, xerr := newNetworkResource("", networkInspectResourceSnippetPath, terraformer.WithLocalState())
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	// netRsc.id = id
	// return p.inspectNetworkResource(ctx, netRsc)
}

// ListNetworks lists available networks
func (p *provider) ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error) {
	var emptySlice []*abstract.Network
	if valid.IsNull(p) {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "").WithStopwatch().Entering().Exiting()

	return p.MiniStack.ListNetworks(ctx)
}

// DeleteNetwork deletes the network identified by id
func (p *provider) DeleteNetwork(ctx context.Context, parameter iaasapi.NetworkParameter) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	an, networkLabel, xerr := iaasapi.ValidateNetworkParameter(parameter)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.network"), "(%s)", networkLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	if an.ID != "" {
		an, xerr = p.InspectNetwork(ctx, an.ID)
	} else if an.Name != "" {
		an, xerr = p.InspectNetworkByName(ctx, an.Name)
	}
	if xerr != nil {
		return xerr
	}

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

	xerr = an.AddOptions(abstract.UseTerraformSnippet(networkDesignResourceSnippetPath))
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

	def, xerr := renderer.Assemble(an)
	if xerr != nil {
		return xerr
	}

	xerr = renderer.Destroy(ctx, def, terraformerapi.WithTarget(an))
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete network %s", an.ID)
	}

	return nil
}

// // ToGophercloudIPVersion converts ipversion.Enum (corresponding to SafeScale abstract) to gophercloud.IPVersion
// // if v is invalid, returns gophercloud.IPv4
// func ToGophercloudIPVersion(v ipversion.Enum) gophercloud.IPVersion {
// 	switch v {
// 	case ipversion.IPv6:
// 		return gophercloud.IPv6
// 	case ipversion.IPv4:
// 		fallthrough
// 	default:
// 		return gophercloud.IPv4
// 	}
// }

// // ToAbstractIPVersion converts an int representation of IPVersion to an ipversion.Enum
// // if v is invalid, returns ipversion.sIPv4
// func ToAbstractIPVersion(v int) ipversion.Enum {
// 	switch v {
// 	case 6:
// 		return ipversion.IPv6
// 	case 4:
// 		fallthrough
// 	default:
// 		return ipversion.IPv4
// 	}
// }

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

func (p *provider) ConsolidateNetworkSnippet(an *abstract.Network) {
	if valid.IsNil(p) || an == nil {
		return
	}

	_ = an.AddOptions(abstract.UseTerraformSnippet(networkDesignResourceSnippetPath))
}
