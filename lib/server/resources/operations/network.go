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

func nullNetwork() resources.Network {
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
		return nullNetwork(), fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
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

	if xerr = upgradeNetworkPropertyIfNeeded(task, rn); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			// ignore
		default:
			return nullNetwork(), fail.Wrap(xerr, "failed to upgrade Networking properties")
		}
	}
	return rn, nil
}

// upgradeNetworkPropertyIfNeeded upgrades properties to most recent version
func upgradeNetworkPropertyIfNeeded(task concurrency.Task, rn resources.Network) fail.Error {
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
			as.CIDR = an.CIDR
			as.DNSServers = an.DNSServers
			return rs.Carry(task, as)
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
	defer fail.OnPanic(&xerr)

	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	tracer := debug.NewTracer(
		task,
		true,
		"('%s', '%s')", req.Name, req.CIDR,
	).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	// Check if subnet already exists and is managed by SafeScale
	svc := rn.GetService()
	if _, xerr = LoadNetwork(task, svc, req.Name); xerr == nil {
		return fail.DuplicateError("network '%s' already exists", req.Name)
	}

	// Verify if the subnet already exist and in this case is not managed by SafeScale
	if _, xerr = svc.InspectNetworkByName(req.Name); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return xerr
		}
	} else {
		return fail.DuplicateError("network '%s' already exists (not managed by SafeScale)", req.Name)
	}

	// Verify the CIDR is not routable
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

	// Write subnet object metadata
	// logrus.Debugf("Saving subnet metadata '%s' ...", subnet.GetName)
	return rn.Carry(task, an)
}

// Browse walks through all the metadata objects in subnet
func (rn network) Browse(task concurrency.Task, callback func(*abstract.Network) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

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

// Delete deletes subnet
func (rn *network) Delete(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rn.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	tracer := debug.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

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
						switch xerr.(type) {
						case *fail.ErrNotFound:
							// Subnet is already deleted, consider as a success and continue
						default:
							return xerr
						}
					} else {
						subnetName := rs.GetName()
						if xerr = rs.Delete(task); xerr != nil {
							return fail.Wrap(xerr, "failed to delete Subnet '%s'", subnetName)
						}
					}
				}
			}
			if !found {
				return fail.InvalidRequestError("failed to delete Network '%s', 1 Subnet still inside", rn.GetName())
			}
		default:
			return fail.InvalidRequestError("failed to delete Network '%s', %d Subnets still inside", rn.GetName(), subnetsLen)
		}

		// delete Network, with tolerance
		if innerXErr = svc.DeleteNetwork(an.ID); innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// If Network doesn't exist anymore on the provider side, do not fail to cleanup the metadata: log but continue
				logrus.Warnf("failed to find Network on provider side, cleaning up metadata.")
			case *fail.ErrTimeout:
				logrus.Error("cannot delete Network due to a timeout")
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
					return innerXErr
				}
			default:
				logrus.Errorf("cannot delete Network, other reason (%s: %s)", reflect.TypeOf(innerXErr).String(), innerXErr.Error())
			}
		}
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// Remove metadata
	return rn.core.Delete(task)
}

// GetCIDR returns the CIDR of the subnet
func (rn network) GetCIDR(task concurrency.Task) (cidr string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rn.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return "", fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
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
	defer fail.OnPanic(&xerr)

	if rn.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
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

// InspectSubnet returns the instance of resources.Subnet corresponding to the subnet referenced by 'ref' attached to
// the subnet
func (rn network) InspectSubnet(task concurrency.Task, ref string) (_ resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rn.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	return LoadSubnet(task, rn.GetService(), rn.GetID(), ref)
}
