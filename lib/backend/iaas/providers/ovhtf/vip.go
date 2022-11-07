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
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	vipResourceSnippetPath = "snippets/resource_vip.tf"
)

// type (
// 	vipResource struct {
// 		terraformer.ResourceCore
// 	}
// )
//
// func newVIPResource(name string) (*vipResource, fail.Error) {
// 	rc, xerr := terraformer.NewResourceCore(name, vipResourceSnippetPath)
// 	if xerr != nil {
// 		return nil, xerr
// 	}
//
// 	return &vipResource{ResourceCore: rc}, nil
// }
//
// // ToMap returns a map of networkResource field to be used where needed
// func (nr *vipResource) ToMap() map[string]any {
// 	return map[string]any{
// 		"Name": nr.Name(),
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

// CreateVIP creates a private virtual IP
// If public is set to true,
func (p *provider) CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	if networkID = strings.TrimSpace(networkID); networkID == "" {
		return nil, fail.InvalidParameterError("networkID", "cannot be empty string")
	}
	if subnetID = strings.TrimSpace(subnetID); subnetID == "" {
		return nil, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}
	if name = strings.TrimSpace(name); name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	return nil, fail.NotImplementedError()

	/*
		var port *ports.Port
		asu := true
		options := ports.CreateOpts{
			NetworkID:      networkID,
			AdminStateUp:   &asu,
			Name:           name,
			SecurityGroups: &securityGroups,
			FixedIPs:       []ports.IP{{SubnetID: subnetID}},
		}
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (innerErr error) {
				port, innerErr = ports.Create(s.NetworkClient, options).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return nil, xerr
		}

		// FIXME: OPP Now, and only for OVH, disable port security
		// _, _ = s.rpcChangePortSecurity(ctx, port.ID, false)

		vip := abstract.NewVirtualIP()
		vip.ID = port.ID
		vip.PrivateIP = port.FixedIPs[0].IPAddress
		return vip, nil
	*/
}

// AddPublicIPToVIP adds a public IP to VIP
func (p *provider) AddPublicIPToVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}

	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (p *provider) BindHostToVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	return fail.NotImplementedError()

	/*
		var vipPort *ports.Port
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (innerErr error) {
				vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return xerr
		}
		hostPorts, xerr := s.rpcListPorts(ctx, ports.ListOpts{
			DeviceID:  hostID,
			NetworkID: vip.NetworkID,
		})
		if xerr != nil {
			return xerr
		}
		addressPair := ports.AddressPair{
			MACAddress: vipPort.MACAddress,
			IPAddress:  vip.PrivateIP,
		}
		for _, p := range hostPorts {
			p := p
			p.AllowedAddressPairs = append(p.AllowedAddressPairs, addressPair)
			xerr = stacks.RetryableRemoteCall(ctx,
				func() error {
					_, innerErr := ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &p.AllowedAddressPairs}).Extract()
					return innerErr
				},
				NormalizeError,
			)
			if xerr != nil {
				return xerr
			}
		}
		return nil
	*/
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (p *provider) UnbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	return fail.NotImplementedError()

	/*
		var vipPort *ports.Port
		xerr := stacks.RetryableRemoteCall(ctx,
			func() (innerErr error) {
				vipPort, innerErr = ports.Get(s.NetworkClient, vip.ID).Extract()
				return innerErr
			},
			NormalizeError,
		)
		if xerr != nil {
			return xerr
		}
		hostPorts, xerr := s.rpcListPorts(ctx, ports.ListOpts{
			DeviceID:  hostID,
			NetworkID: vip.NetworkID,
		})
		if xerr != nil {
			return xerr
		}
		for _, p := range hostPorts {
			var newAllowedAddressPairs []ports.AddressPair
			for _, a := range p.AllowedAddressPairs {
				if a.MACAddress != vipPort.MACAddress {
					newAllowedAddressPairs = append(newAllowedAddressPairs, a)
				}
			}
			xerr = stacks.RetryableRemoteCall(ctx,
				func() error {
					_, innerErr := ports.Update(s.NetworkClient, p.ID, ports.UpdateOpts{AllowedAddressPairs: &newAllowedAddressPairs}).Extract()
					return innerErr
				},
				NormalizeError,
			)
			if xerr != nil {
				return xerr
			}
		}
		return nil
	*/
}

// DeleteVIP deletes the port corresponding to the VIP
func (p *provider) DeleteVIP(ctx context.Context, vip *abstract.VirtualIP) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}

	return fail.NotImplementedError()

	/*
		for _, v := range vip.Hosts {
			xerr := s.UnbindHostFromVIP(ctx, vip, v.ID)
			if xerr != nil {
				return xerr
			}
		}
		return stacks.RetryableRemoteCall(ctx,
			func() error {
				return ports.Delete(s.NetworkClient, vip.ID).ExtractErr()
			},
			NormalizeError,
		)
	*/
}
