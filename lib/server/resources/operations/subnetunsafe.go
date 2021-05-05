/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"reflect"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetstate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// UnsafeInspectGateway returns the gateway related to Subnet
// Note: a write lock of the instance (instance.lock.Lock() ) must have been called before calling this method
func (instance *Subnet) UnsafeInspectGateway(primary bool) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	gwIdx := 0
	if !primary {
		gwIdx = 1
	}
	out := instance.gateways[gwIdx]
	if out == nil {
		return nil, fail.NotFoundError("failed to find gateway")
	}

	return out, nil
}

// // unsafeInspectNetwork returns the Network instance owning the Subnet
// func (instance *Subnet) unsafeInspectNetwork() (rn resources.Network, xerr fail.Error) {
// 	defer fail.OnPanic(&xerr)
//
//
// 	return instance.parentNetwork, nil
// }

// UnsafeGetDefaultRouteIP ...
func (instance *Subnet) UnsafeGetDefaultRouteIP() (ip string, xerr fail.Error) {
	ip = ""
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if as.VIP != nil && as.VIP.PrivateIP != "" {
			ip = as.VIP.PrivateIP
			return nil
		}
		if len(as.GatewayIDs) > 0 {
			rh, innerErr := LoadHost(instance.GetService(), as.GatewayIDs[0])
			if innerErr != nil {
				return innerErr
			}
			defer rh.Released()

			ip, xerr = rh.GetPrivateIP()
			if xerr != nil {
				return xerr
			}
			return nil
		}

		return fail.NotFoundError("failed to find default route IP: no gateway defined")
	})
	return ip, xerr

}

// unsafeGetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (instance *Subnet) unsafeGetVirtualIP() (vip *abstract.VirtualIP, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		vip = as.VIP
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "cannot get Subnet virtual IP")

	}
	if vip == nil {
		return nil, fail.NotFoundError("failed to find Virtual IP binded to gateways for Subnet '%s'", instance.GetName())
	}

	return vip, nil
}

// unsafeGetCIDR returns the CIDR of the network
// Intended to be used when instance is notoriously not nil (because previously checked)
func (instance *Subnet) unsafeGetCIDR() (cidr string, xerr fail.Error) {
	cidr = ""
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		cidr = as.CIDR
		return nil
	})
	return cidr, xerr
}

// unsafeGetState returns the state of the network
// Intended to be used when rs is notoriously not null (because previously checked)
func (instance *Subnet) unsafeGetState() (state subnetstate.Enum, xerr fail.Error) {
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		state = as.State
		return nil
	})
	return state, xerr
}

// unsafeAbandonHost is the non goroutine-safe version of UnbindHost, without paramter validation, that does the real work
// Note: must be used wisely
func (instance *Subnet) unsafeAbandonHost(props *serialize.JSONProperties, hostID string) fail.Error {
	return props.Alter(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
		shV1, ok := clonable.(*propertiesv1.SubnetHosts)
		if !ok {
			return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		hostName, found := shV1.ByID[hostID]
		if found {
			delete(shV1.ByName, hostName)
			delete(shV1.ByID, hostID)
		}
		return nil
	})
}

// unsafeHasVirtualIP tells if the Subnet uses a VIP a default route
func (instance *Subnet) unsafeHasVirtualIP() (bool, fail.Error) {
	var found bool
	xerr := instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		found = as.VIP != nil
		return nil
	})
	return found, xerr
}
