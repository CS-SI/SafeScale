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

package azuretf

import (
	"context"
	"net"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

const (
	NATRouteNameFormat = "sfsnet-%s-nat-allowed"
	NATRouteTagFormat  = "sfsnet-%s-nat-needed"
)

// ------ network methods ------

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
// No default network settings supported by GCP
func (s stack) HasDefaultNetwork(context.Context) (bool, fail.Error) {
	return false, nil
}

// GetDefaultNetwork returns the *abstract.Network corresponding to the default network
func (s stack) GetDefaultNetwork(context.Context) (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("no default network in gcp driver")
}

// CreateNetwork creates a new network
func (s stack) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

// InspectNetwork returns the network identified by id (actually for gcp, id here is name)
func (s stack) InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

// InspectNetworkByName returns the network identified by ref (id or name)
func (s stack) InspectNetworkByName(ctx context.Context, name string) (*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("implement me")
}

func toAbstractNetwork(in compute.Network) *abstract.Network {
	out := abstract.NewNetwork()
	out.Name = in.Name
	out.ID = strconv.FormatUint(in.Id, 10)
	out.CIDR = in.IPv4Range
	return out
}

// ListNetworks lists available networks
func (s stack) ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me") // Does it make sense with terraform ?
}

// DeleteNetwork deletes the network identified by id
func (s stack) DeleteNetwork(ctx context.Context, ref string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("implement me")
}

// ------ VIP methods ------

// CreateVIP creates a private virtual IP
func (s stack) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if networkID == "" {
		return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	return nil, fail.NotImplementedError("CreateVIP() not implemented yet") // FIXME: Technical debt
}

// AddPublicIPToVIP adds a public IP to VIP
func (s stack) AddPublicIPToVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (s stack) BindHostToVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (s stack) UnbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	return fail.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME: Technical debt
}

// DeleteVIP deletes the VIP
func (s stack) DeleteVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}

// ------ SecurityGroup methods ------

// ------ Subnet methods ------

// CreateSubnet creates a new subnet
func (s stack) CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

func (s stack) validateCIDR(req abstract.SubnetRequest, network *abstract.Network) fail.Error {
	if _, _, err := net.ParseCIDR(req.CIDR); err != nil {
		return fail.Wrap(err, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
	}
	return nil
}

// InspectSubnet returns the subnet identified by id
func (s stack) InspectSubnet(ctx context.Context, id string) (*abstract.Subnet, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

// InspectSubnetByName returns the subnet identified by name
func (s stack) InspectSubnetByName(ctx context.Context, networkID string, name string) (_ *abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

// ListSubnets lists available subnets
func (s stack) ListSubnets(ctx context.Context, networkRef string) (_ []*abstract.Subnet, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	return nil, fail.NotImplementedError("implement me")
}

func toAbstractSubnet(in compute.Subnetwork) *abstract.Subnet {
	item := abstract.NewSubnet()
	item.Name = in.Name
	item.ID = strconv.FormatUint(in.Id, 10)
	item.CIDR = in.IpCidrRange
	parts := strings.Split(in.Network, "/")
	item.Network = parts[len(parts)-1]
	return item
}

// DeleteSubnet deletes the subnet identified by id
func (s stack) DeleteSubnet(ctx context.Context, id string) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("implement me")
}
