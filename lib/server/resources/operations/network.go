/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"reflect"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// networksFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
)

// network links Object Storage folder and Networking
type network struct {
	*core
}

func nullNetwork() *network {
	return &network{core: nullCore()}
}

// NewNetwork creates an instance of Networking
func NewNetwork(svc iaas.Service) (resources.Network, fail.Error) {
	if svc.IsNull() {
		return nullNetwork(), fail.InvalidParameterError("svc", "cannot be null value")
	}

	coreInstance, xerr := newCore(svc, "network", networksFolderName, &abstract.Network{})
	if xerr != nil {
		return nullNetwork(), xerr
	}

	return &network{core: coreInstance}, nil
}

// LoadNetwork loads the metadata of a subnet
func LoadNetwork(task concurrency.Task, svc iaas.Service, ref string) (resources.Network, fail.Error) {
	if task.IsNull() {
		return nullNetwork(), fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc.IsNull() {
		return nullNetwork(), fail.InvalidParameterError("svc", "cannot be null value")
	}
	if ref == "" {
		return nullNetwork(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	rn, xerr := NewNetwork(svc)
	if xerr != nil {
		return nullNetwork(), xerr
	}

	// TODO: core.Read() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
	if xerr = rn.Read(task, ref); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nullNetwork(), fail.NotFoundError("failed to find Network '%s'", ref)
		default:
			return nullNetwork(), xerr
		}
	}

	if xerr = upgradeProperties(task, rn); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			// ignore
		default:
			return nullNetwork(), fail.Wrap(xerr, "failed to upgrade Networking properties")
		}
	}
	return rn, nil
}

// upgradeProperties upgrades properties to most recent version
func upgradeProperties(task concurrency.Task, rn resources.Network) fail.Error {
	return rn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if props.Count() > 0 && !props.Lookup(networkproperty.SubnetsV1) {
			rs, xerr := NewSubnet(rn.GetService())
			if xerr != nil {
				return xerr
			}
			as := abstract.NewSubnet()
			as.Name = an.Name
			as.Network = an.ID
			//as.IPVersion = an.IPVersion
			//as.DNSServers = an.DNSServers
			//as.CIDR = as.CIDR
			//as.Domain = an.Domain
			//as.VIP = an.VIP
			//xerr = rs.Create(task, req, gwname)
			_ = rs
			return nil
		}
		return fail.AlteredNothingError()
	})
}

// IsNull tells if the instance corresponds to subnet Null Value
func (rn *network) IsNull() bool {
	return rn == nil || rn.core.IsNull()
}

// Create creates a network
func (rn *network) Create(task concurrency.Task, req abstract.NetworkRequest) (xerr fail.Error) {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(
		task,
		true,
		"('%s', '%s')", req.Name, req.CIDR,
	).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	// Check if subnet already exists and is managed by SafeScale
	svc := rn.GetService()
	if _, xerr = LoadNetwork(task, svc, req.Name); xerr == nil {
		return fail.DuplicateError("network '%s' already exists", req.Name)
	}

	// Verify if the subnet already exist and in this case is not managed by SafeScale
	if _, xerr = svc.InspectNetworkByName(req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		case *fail.ErrInvalidRequest, *fail.ErrTimeout:
			return xerr
		default:
			return xerr
		}
	} else {
		return fail.DuplicateError("network '%s' already exists (not managed by SafeScale)", req.Name)
	}

	// Verify the IPRanges is not routable
	if req.CIDR != "" {
		routable, xerr := net.IsCIDRRoutable(req.CIDR)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to determine if CIDR is not routable")
		}
		if routable {
			return fail.InvalidRequestError("cannot create such a Networking, CIDR must not be routable; please choose an appropriate CIDR (RFC1918)")
		}
	}

	// Create the network
	logrus.Debugf("Creating network '%s' with CIDR '%s'...", req.Name, req.CIDR)
	an, xerr := svc.CreateNetwork(req)
	if xerr != nil {
		return xerr
	}

	//// Starting from here, delete subnet if exiting with error
	//defer func() {
	//	if xerr != nil && an != nil && !req.KeepOnFailure {
	//		derr := svc.DeleteNetwork(an.ID)
	//		if derr != nil {
	//			switch derr.(type) {
	//			case *fail.ErrNotFound:
	//				logrus.Errorf("failed to delete NetworkID: resource not found: %+v", derr)
	//			case *fail.ErrTimeout:
	//				logrus.Errorf("failed to delete NetworkID: timeout: %+v", derr)
	//			default:
	//				logrus.Errorf("failed to delete NetworkID: %+v", derr)
	//			}
	//			_ = xerr.AddConsequence(derr)
	//		}
	//	}
	//}()

	// Write subnet object metadata
	// logrus.Debugf("Saving subnet metadata '%s' ...", subnet.GetName)
	return rn.Carry(task, an)
}

//// deleteGateway eases a gateway deletion
//// Note: doesn't use gw.Remove() because by rule a Delete on a gateway is not permitted
//func (rn subnet) deleteGateway(task concurrency.Task, gw resources.Host) (xerr fail.Error) {
//	name := gw.GetName()
//	fail.OnExitLogError(&xerr, "failed to delete gateway '%s'", name)
//
//	var errors []error
//	if xerr = rn.GetService().DeleteHost(gw.GetID()); xerr != nil {
//		switch xerr.(type) {
//		case *fail.ErrNotFound: // host resource not found, considered as a success.
//			break
//		case *fail.ErrTimeout:
//			errors = append(errors, fail.Wrap(xerr, "failed to delete host '%s', timeout", name))
//		default:
//			errors = append(errors, fail.Wrap(xerr, "failed to delete host '%s'", name))
//		}
//	}
//	if xerr = gw.(*host).core.Delete(task); xerr != nil {
//		switch xerr.(type) {
//		case *fail.ErrNotFound: // host metadata not found, considered as a success.
//			break
//		case *fail.ErrTimeout:
//			errors = append(errors, fail.Wrap(xerr, "timeout trying to delete gateway metadata", name))
//		default:
//			errors = append(errors, fail.Wrap(xerr, "failed to delete gateway '%s' metadata", name))
//		}
//	}
//	if len(errors) > 0 {
//		return fail.NewErrorList(errors)
//	}
//	return nil
//}

//func (rn subnet) unbindHostFromVIP(task concurrency.Task, vip *abstract.VirtualIP, host resources.Host) fail.Error {
//	name := host.GetName()
//	if xerr := rn.GetService().UnbindHostFromVIP(vip, host.GetID()); xerr != nil {
//		switch xerr.(type) {
//		case *fail.ErrNotFound, *fail.ErrTimeout:
//			logrus.Debugf("Cleaning up on failure, failed to remove '%s' gateway bind from VIP: %v", name, xerr)
//		default:
//			logrus.Debugf("Cleaning up on failure, failed to remove '%s' gateway bind from VIP: %v", name, xerr)
//		}
//		return xerr
//	}
//	logrus.Infof("Cleaning up on failure, host '%s' bind removed from VIP", name)
//	return nil
//}

// Browse walks through all the metadata objects in subnet
func (rn network) Browse(task concurrency.Task, callback func(*abstract.Network) fail.Error) fail.Error {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "can't be nil")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "can't be nil")
	}

	return rn.core.BrowseFolder(task, func(buf []byte) fail.Error {
		an := abstract.NewNetwork()
		xerr := an.Deserialize(buf)
		if xerr != nil {
			return xerr
		}
		return callback(an)
	})
}

//// AttachHost links host ID to the subnet
//func (rn *subnet) BindHost(task concurrency.Task, host resources.Host) (xerr fail.Error) {
//	if rn.IsNull() {
//		return fail.InvalidInstanceError()
//	}
//	if task.IsNull() {
//		return fail.InvalidParameterError("task", "cannot be nil")
//	}
//	if host == nil {
//		return fail.InvalidParameterError("host", "cannot be nil")
//	}
//
//	tracer := debug.NewTracer(nil, true, "("+host.GetName()+")").Entering()
//	defer tracer.Exiting()
//	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
//	defer fail.OnPanic(&xerr)
//
//	hostID := host.GetID()
//	hostName := host.GetName()
//
//	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
//		return props.Alter(task, networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
//			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
//			if !ok {
//				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
//			}
//			networkHostsV1.ByID[hostID] = hostName
//			networkHostsV1.ByName[hostName] = hostID
//			return nil
//		})
//	})
//}

//// DetachHost unlinks host ID from subnet
//func (rn *subnet) UnbindHost(task concurrency.Task, hostID string) (xerr fail.Error) {
//	if rn.IsNull() {
//		return fail.InvalidInstanceError()
//	}
//	if task.IsNull() {
//		return fail.InvalidParameterError("task", "cannot be nil")
//	}
//	if hostID == "" {
//		return fail.InvalidParameterError("hostID", "cannot be empty string")
//	}
//
//	tracer := debug.NewTracer(nil, true, "('"+hostID+"')").Entering()
//	defer tracer.Exiting()
//	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
//	defer fail.OnPanic(&xerr)
//
//	return rn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
//		return props.Alter(task, networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
//			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
//			if !ok {
//				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
//			}
//			hostName, found := networkHostsV1.ByID[hostID]
//			if found {
//				delete(networkHostsV1.ByName, hostName)
//				delete(networkHostsV1.ByID, hostID)
//			}
//			return nil
//		})
//	})
//}

//// ListHosts returns the list of Host attached to the subnet (excluding gateway)
//func (rn subnet) ListHosts(task concurrency.Task) (_ []resources.Host, xerr fail.Error) {
//	if rn.IsNull() {
//		return nil, fail.InvalidInstanceError()
//	}
//	if task.IsNull() {
//		return nil, fail.InvalidParameterError("task", "cannot be nil")
//	}
//
//	defer debug.NewTracer(task, tracing.ShouldTrace("resources.subnet")).Entering().Exiting()
//	defer fail.OnExitLogError(&xerr, "error listing hosts")
//	defer fail.OnPanic(&xerr)
//
//	var list []resources.Host
//	xerr = rn.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
//		return props.Inspect(task, networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
//			networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
//			if !ok {
//				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
//			}
//			svc := rn.GetService()
//			for id := range networkHostsV1.ByID {
//				host, innerErr := LoadHost(task, svc, id)
//				if innerErr != nil {
//					return innerErr
//				}
//				list = append(list, host)
//			}
//			return nil
//		})
//	})
//	return list, xerr
//}

//// GetGateway returns the gateway related to subnet
//func (rn subnet) GetGateway(task concurrency.Task, primary bool) (_ resources.Host, xerr fail.Error) {
//	if rn.IsNull() {
//		return nil, fail.InvalidInstanceError()
//	}
//	if task.IsNull() {
//		return nil, fail.InvalidParameterError("task", "cannot be nil")
//	}
//
//	defer fail.OnPanic(&xerr)
//
//	primaryStr := "primary"
//	if !primary {
//		primaryStr = "secondary"
//	}
//	tracer := debug.NewTracer(nil, true, "(%s)", primaryStr).Entering()
//	defer tracer.Exiting()
//	// defer fail.OnExitLogError(&err, tracer.TraceMessage())
//	defer fail.OnPanic(&xerr)
//
//	var gatewayID string
//	xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
//		an, ok := clonable.(*abstract.Networking)
//		if !ok {
//			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
//		}
//		if primary {
//			gatewayID = an.GatewayID
//		} else {
//			gatewayID = an.SecondaryGatewayID
//		}
//		return nil
//	})
//	if xerr != nil {
//		return nil, xerr
//	}
//	if gatewayID == "" {
//		return nil, fail.NotFoundError("no %s gateway ID found in subnet properties", primaryStr)
//	}
//	return LoadHost(task, rn.GetService(), gatewayID)
//}

//// getGateway returns a resources.Host corresponding to the gateway requested. May return HostNull if no gateway exists.
//func (rn subnet) getGateway(task concurrency.Task, primary bool) resources.Host {
//	host, _ := rn.GetGateway(task, primary)
//	return host
//}

// Delete deletes subnet
func (rn *network) Delete(task concurrency.Task) (xerr fail.Error) {
	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
	defer fail.OnPanic(&xerr)

	rn.SafeLock(task)
	defer rn.SafeUnlock(task)

	xerr = rn.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := rn.GetService()

		var subnets map[string]string
		innerXErr := props.Inspect(task, networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			subnets = subnetsV1.ByName
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		subnetsLen := len(subnets)
		switch subnetsLen {
		case 0:
			// no subnet, continue to delete the network
		case 1:
			var found bool
			for k, v := range subnets {
				if k == rn.GetName() {
					found = true
					// the single subnet present is a subnet named like the network, delete it first
					rs, xerr := LoadSubnet(task, svc, "", v)
					if xerr != nil {
						return xerr
					}
					if xerr = rs.Delete(task); xerr != nil {
						return xerr
					}
				}
			}
			if !found {
				return fail.InvalidRequestError("failed to delete Network '%s', 1 Subnet still inside", rn.GetName())
			}
		default:
			return fail.InvalidRequestError("failed to delete Network '%s', %d Subnets still inside", rn.GetName(), subnetsLen)
		}

		waitMore := false
		// delete Network, with tolerance
		innerXErr = svc.DeleteNetwork(an.ID)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// If subnet doesn't exist anymore on the provider infrastructure, don't fail to cleanup the metadata
				logrus.Warnf("network not found on provider side, cleaning up metadata.")
				return innerXErr
			case *fail.ErrTimeout:
				logrus.Error("cannot delete subnet due to a timeout")
				waitMore = true
			default:
				logrus.Error("cannot delete subnet, other reason")
			}
		}
		if waitMore {
			errWaitMore := retry.WhileUnsuccessfulDelay1Second(
				func() error {
					recNet, recErr := svc.InspectNetwork(an.ID)
					if recNet != nil {
						return fmt.Errorf("still there")
					}
					if _, ok := recErr.(*fail.ErrNotFound); ok {
						return nil
					}
					return fail.Wrap(recErr, "another kind of error")
				},
				temporal.GetContextTimeout(),
			)
			if errWaitMore != nil {
				_ = innerXErr.AddConsequence(errWaitMore)
			}
		}
		return innerXErr
	})
	if xerr != nil {
		return xerr
	}

	// Remove metadata
	return rn.core.Delete(task)
}

//// GetDefaultRouteIP returns the IP of the LAN default route
//func (rn subnet) GetDefaultRouteIP(task concurrency.Task) (ip string, xerr fail.Error) {
//	if rn.IsNull() {
//		return "", fail.InvalidInstanceError()
//	}
//	if task.IsNull() {
//		return "", fail.InvalidParameterError("task", "cannot be nil")
//	}
//
//	ip = ""
//	xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
//		an, ok := clonable.(*abstract.Networking)
//		if !ok {
//			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
//		}
//		if an.VIP != nil && an.VIP.PrivateIP != "" {
//			ip = an.VIP.PrivateIP
//		} else {
//			objpgw, innerErr := LoadHost(task, rn.GetService(), an.GatewayID)
//			if innerErr != nil {
//				return innerErr
//			}
//			ip = objpgw.(*host).getPrivateIP(task)
//			return nil
//		}
//		return nil
//	})
//	return ip, xerr
//}
//
//// getDefaultRouteIP ...
//func (rn subnet) getDefaultRouteIP(task concurrency.Task) string {
//	if rn.IsNull() {
//		return ""
//	}
//	ip, _ := rn.GetDefaultRouteIP(task)
//	return ip
//}
//
//// GetEndpointIP returns the IP of the internet IP to reach the subnet
//func (rn subnet) GetEndpointIP(task concurrency.Task) (ip string, xerr fail.Error) {
//	ip = ""
//	if rn.IsNull() {
//		return ip, fail.InvalidInstanceError()
//	}
//	if task.IsNull() {
//		return ip, fail.InvalidParameterError("task", "cannot be nil")
//	}
//
//	xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
//		an, ok := clonable.(*abstract.Networking)
//		if !ok {
//			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
//		}
//		if an.VIP != nil && an.VIP.PublicIP != "" {
//			ip = an.VIP.PublicIP
//		} else {
//			objpgw, inErr := LoadHost(task, rn.GetService(), an.GatewayID)
//			if inErr != nil {
//				return inErr
//			}
//			ip = objpgw.(*host).getPublicIP(task)
//			return nil
//		}
//		return nil
//	})
//	return ip, xerr
//}
//
//// getEndpointIP ...
//func (rn subnet) getEndpointIP(task concurrency.Task) string {
//	if rn.IsNull() {
//		return ""
//	}
//	ip, _ := rn.GetEndpointIP(task)
//	return ip
//}
//
//// HasVirtualIP tells if the subnet uses a VIP a default route
//func (rn subnet) HasVirtualIP(task concurrency.Task) bool {
//	if rn.IsNull() {
//		logrus.Errorf(fail.InvalidInstanceError().Error())
//		return false
//	}
//
//	var found bool
//	xerr := rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
//		an, ok := clonable.(*abstract.Networking)
//		if !ok {
//			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
//		}
//		found = an.VIP != nil
//		return nil
//	})
//	return xerr == nil && found
//}
//
//// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
//func (rn subnet) GetVirtualIP(task concurrency.Task) (vip *abstract.VirtualIP, xerr fail.Error) {
//	if rn.IsNull() {
//		return nil, fail.InvalidInstanceError()
//	}
//	if task.IsNull() {
//		return nil, fail.InvalidParameterError("task", "cannot be nil")
//	}
//
//	xerr = rn.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
//		an, ok := clonable.(*abstract.Networking)
//		if !ok {
//			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
//		}
//		vip = an.VIP
//		return nil
//	})
//	if xerr != nil {
//		return nil, fail.Wrap(xerr, "cannot get subnet virtual IP")
//
//	}
//	if vip == nil {
//		return nil, fail.NotFoundError("failed to find Virtual IP binded to gateways for subnet '%s'", rn.GetName())
//	}
//	return vip, nil
//}

// GetCIDR returns the CIDR of the subnet
func (rn network) GetCIDR(task concurrency.Task) (cidr string, xerr fail.Error) {
	if rn.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return "", fail.InvalidParameterError("task", "cannot be nil")
	}

	cidr = ""
	xerr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		cidr = an.CIDR
		return nil
	})
	return cidr, xerr
}

// CIDR returns the CIDR of the subnet
// Intended to be used when objn is notoriously not nil (because previously checked)
func (rn network) CIDR(task concurrency.Task) string {
	cidr, _ := rn.GetCIDR(task)
	return cidr
}

// ToProtocol converts resources.Network to protocol.Network
func (rn network) ToProtocol(task concurrency.Task) (_ *protocol.Network, xerr fail.Error) {
	if rn.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, true, "").Entering()
	defer tracer.Exiting()

	var pn *protocol.Network
	xerr = rn.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())

		}

		pn = &protocol.Network{
			Id:   an.ID,
			Name: an.Name,
			Cidr: an.CIDR,
		}

		return props.Inspect(task, networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for k := range nsV1.ByName {
				pn.Subnets = append(pn.Subnets, k)
			}
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}
	return pn, nil
}

//// BindSecurityGroup binds a security group to the host; if enabled is true, apply it immediately
//func (rs *subnet) BindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup, enabled resources.SecurityGroupActivation) fail.Error {
//	if rn.IsNull() {
//		return fail.InvalidInstanceError()
//	}
//	if task == nil {
//		return fail.InvalidParameterError("task", "cannot be nil")
//	}
//	if sg.IsNull() {
//		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
//	}
//
//	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
//		return props.Alter(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
//			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
//			if !ok {
//				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
//			}
//
//			sgID := sg.GetID()
//			// First check if the security group is not already registered for the host with the exact same state
//			for k, v := range nsgV1.ByID {
//				if k == sgID && v.Disabled == (bool)(!enabled) {
//					return fail.DuplicateError("security group '%s' already bound to host")
//				}
//			}
//
//			// Bind the security group to the subnet (does the security group side of things)
//			if innerXErr := sg.BindToSubnet(task, rn, !enabled); innerXErr != nil {
//				return innerXErr
//			}
//
//			// Updates subnet metadata
//			nsgV1.ByID[sgID].Disabled = !enabled
//			nsgV1.ByName[sg.GetName()].Disabled = !enabled
//			return nil
//		})
//	})
//}
//
//// UnbindSecurityGroup unbinds a security group from the host
//func (rn *subnet) UnbindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
//	if rn.IsNull() {
//		return fail.InvalidInstanceError()
//	}
//	if task == nil {
//		return fail.InvalidParameterError("task", "cannot be nil")
//	}
//	if sg.IsNull() {
//		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
//	}
//
//	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
//		return props.Alter(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
//			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
//			if !ok {
//				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
//			}
//
//			sgID := sg.GetID()
//			// Check if the security group is listed for the host, inot already registered for the host with the exact same state
//			found := false
//			for k := range nsgV1.ByID {
//				if k == sgID {
//					found = true
//					break
//				}
//			}
//			// If not found, consider request successful
//			if !found {
//				return nil
//			}
//
//			// unbind security group from subnet on cloud provider side
//			if innerXErr := sg.UnbindFromSubnet(task, rn); innerXErr != nil {
//				return innerXErr
//			}
//
//			// updates the metadata
//			delete(nsgV1.ByID, sgID)
//			delete(nsgV1.ByName, sg.GetName())
//			return nil
//
//		})
//	})
//}
//
//// ListSecurityGroups returns a slice of security groups binded to host
//func (rn *subnet) ListSecurityGroups(task concurrency.Task, kind string) (list []*propertiesv1.SecurityGroupBond, _ fail.Error) {
//	var nullList []*propertiesv1.SecurityGroupBond
//	if rn.IsNull() {
//		return nullList, fail.InvalidInstanceError()
//	}
//	if task == nil {
//		return nullList, fail.InvalidParameterError("task", "cannot be nil")
//	}
//
//	if kind == "" {
//		kind = "all"
//	}
//	loweredKind := strings.ToLower(kind)
//	switch loweredKind {
//	case "all", "enabled", "disabled":
//		// continue
//	default:
//		return nil, fail.InvalidParameterError("kind", fmt.Sprintf("invalid value '%s'", kind))
//	}
//
//	return list, rn.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
//		return props.Inspect(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
//			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
//			if !ok {
//				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
//			}
//			list = filterBondsByKind(nsgV1.ByID, loweredKind)
//			return nil
//		})
//	})
//}
//
//// EnableSecurityGroup enables a binded security group to subnet
//func (rn *subnet) EnableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
//	if rn.IsNull() {
//		return fail.InvalidInstanceError()
//	}
//	if task == nil {
//		return fail.InvalidParameterError("task", "cannot be nil")
//	}
//	if sg.IsNull() {
//		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
//	}
//
//	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
//		return props.Inspect(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
//			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
//			if !ok {
//				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
//			}
//
//			sgID := sg.GetID()
//			// First check if the security group is not already registered for the host with the exact same state
//			var found bool
//			for k := range nsgV1.ByID {
//				if k == sgID {
//					found = true
//				}
//			}
//			if !found {
//				return fail.NotFoundError("security group '%s' is not binded to subnet '%s'", sg.GetName(), rn.GetID())
//			}
//
//			// Do security group stuff to enable it
//			if innerXErr := sg.BindToSubnet(task, rn, resources.SecurityGroupEnable); innerXErr != nil {
//				switch innerXErr.(type) {
//				case *fail.ErrDuplicate:
//					// security group already bound to subnet with the same state, consider as a success
//				default:
//					return innerXErr
//				}
//			}
//
//			// update metadata
//			nsgV1.ByID[sgID].Disabled = false
//			nsgV1.ByName[sg.GetName()].Disabled = false
//			return nil
//		})
//	})
//}
//
//// DisableSecurityGroup disables an already binded security group on subnet
//func (rn *subnet) DisableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) fail.Error {
//	if rn.IsNull() {
//		return fail.InvalidInstanceError()
//	}
//	if task == nil {
//		return fail.InvalidParameterError("task", "cannot be nil")
//	}
//	if sg.IsNull() {
//		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
//	}
//
//	return rn.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
//		return props.Inspect(task, networkproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
//			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
//			if !ok {
//				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
//			}
//
//			sgID := sg.GetID()
//			// First check if the security group is not already registered for the host with the exact same state
//			var found bool
//			for k := range nsgV1.ByID {
//				if k == sgID {
//					found = true
//				}
//			}
//			if !found {
//				return fail.NotFoundError("security group '%s' is not binded to subnet '%s'", sg.GetName(), rn.GetID())
//			}
//
//			// Do security group stuff to enable it
//			if innerXErr := sg.BindToSubnet(task, rn, true); innerXErr != nil {
//				switch innerXErr.(type) {
//				case *fail.ErrNotFound:
//				// security group not bound to subnet, consider as a success
//				default:
//					return innerXErr
//				}
//			}
//
//			// update metadata
//			nsgV1.ByID[sgID].Disabled = true
//			nsgV1.ByName[sg.GetName()].Disabled = true
//			return nil
//		})
//	})
//}

// InspectSubnet returns the instance of resources.Subnet corresponding to the subnet referenced by 'ref' attached to
// the subnet
func (rn network) InspectSubnet(task concurrency.Task, ref string) (resources.Subnet, fail.Error) {
	if rn.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	return LoadSubnet(task, rn.GetService(), rn.GetID(), ref)
}
