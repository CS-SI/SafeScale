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
	"github.com/CS-SI/SafeScale/lib/utils/errcontrol"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// unsafeInspectGateway returns the gateway related to subnet
// Note: a write lock of the instance (instance.lock.Lock() ) must have been called before calling this method
func (instance *subnet) unsafeInspectGateway(primary bool) (_ resources.Host, xerr fail.Error) {
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

// unsafeInspectNetwork returns the Network instance owning the Subnet
func (instance *subnet) unsafeInspectNetwork() (rn resources.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	return instance.parentNetwork, nil
}

// unsafeGetDefaultRouteIP ...
func (instance *subnet) unsafeGetDefaultRouteIP() (ip string, xerr fail.Error) {
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

			ip = rh.(*host).privateIP
			return nil
		}

		return fail.NotFoundError("failed to find default route IP: no gateway defined")
	})
	return ip, xerr

}

// unsafeGetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (instance *subnet) unsafeGetVirtualIP() (vip *abstract.VirtualIP, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		vip = as.VIP
		return nil
	})
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "cannot get subnet virtual IP")

	}
	if vip == nil {
		return nil, fail.NotFoundError("failed to find Virtual IP binded to gateways for subnet '%s'", instance.GetName())
	}

	return vip, nil
}

// unsafeGetCIDR returns the CIDR of the network
// Intended to be used when instance is notoriously not nil (because previously checked)
func (instance *subnet) unsafeGetCIDR() (cidr string, xerr fail.Error) {
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
func (instance *subnet) unsafeGetState() (state subnetstate.Enum, xerr fail.Error) {
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
func (instance *subnet) unsafeAbandonHost(props *serialize.JSONProperties, hostID string) fail.Error {
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

// unsafeHasVirtualIP tells if the subnet uses a VIP a default route
func (instance *subnet) unsafeHasVirtualIP() (bool, fail.Error) {
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
