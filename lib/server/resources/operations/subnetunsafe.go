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
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// unsafeInspectGateway returns the gateway related to subnet
// Note: a write lock of the instance (instance.lock.Lock() ) must have been called before calling this method
func (instance *subnet) unsafeInspectGateway(task concurrency.Task, primary bool) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task.Aborted() {
		return nullHost(), fail.AbortedError(nil, "aborted")
	}

	primaryStr := "primary"
	gwIdx := 0
	if !primary {
		primaryStr = "secondary"
		gwIdx = 1
	}

	if instance.gateways[gwIdx] == nil {
		var gatewayID string
		xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if primary {
				if len(as.GatewayIDs) < 1 {
					return fail.NotFoundError("no gateway registered")
				}
				gatewayID = as.GatewayIDs[0]
			} else {
				if len(as.GatewayIDs) < 2 {
					return fail.NotFoundError("no secondary gateway registered")
				}
				gatewayID = as.GatewayIDs[1]
			}
			return nil
		})
		if xerr != nil {
			return nullHost(), xerr
		}

		if gatewayID == "" {
			return nullHost(), fail.NotFoundError("no %s gateway ID found in subnet properties", primaryStr)
		}

		rh, xerr := LoadHost(task, instance.GetService(), gatewayID)
		if xerr != nil {
			return nullHost(), xerr
		}

		instance.gateways[gwIdx] = rh.(*host)
	}
	return instance.gateways[gwIdx], nil
}

// unsafeInspectNetwork returns the Network instance owning the Subnet
func (instance *subnet) unsafeInspectNetwork(task concurrency.Task) (rn resources.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	return instance.parentNetwork, nil
}

// unsafeGetDefaultRouteIP ...
func (instance *subnet) unsafeGetDefaultRouteIP(task concurrency.Task) (ip string, xerr fail.Error) {
	ip = ""
	xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if as.VIP != nil && as.VIP.PrivateIP != "" {
			ip = as.VIP.PrivateIP
			return nil
		}
		if len(as.GatewayIDs) > 0 {
			rh, innerErr := LoadHost(task, instance.GetService(), as.GatewayIDs[0])
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
func (instance *subnet) unsafeGetVirtualIP(task concurrency.Task) (vip *abstract.VirtualIP, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	xerr = instance.Review(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		vip = as.VIP
		return nil
	})
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
func (instance *subnet) unsafeGetCIDR(task concurrency.Task) (cidr string, xerr fail.Error) {
	cidr = ""
	xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
func (instance *subnet) unsafeGetState(task concurrency.Task) (state subnetstate.Enum, xerr fail.Error) {
	xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
func (instance *subnet) unsafeAbandonHost(task concurrency.Task, props *serialize.JSONProperties, hostID string) fail.Error {
	return props.Alter(/*task, */subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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
