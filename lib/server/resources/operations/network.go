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
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	networkKind = "network"
	// networksFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
)

// network links Object Storage folder and Networking
type network struct {
	*core

	lock sync.RWMutex
}

func nullNetwork() resources.Network {
	return &network{core: nullCore()}
}

// NewNetwork creates an instance of Networking
func NewNetwork(svc iaas.Service) (resources.Network, fail.Error) {
	if svc == nil {
		return nullNetwork(), fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := newCore(svc, networkKind, networksFolderName, &abstract.Network{})
	if xerr != nil {
		return nullNetwork(), xerr
	}

	instance := &network{
		core: coreInstance,
	}
	return instance, nil
}

// LoadNetwork loads the metadata of a subnet
func LoadNetwork(svc iaas.Service, ref string) (rn resources.Network, xerr fail.Error) {
	if svc == nil {
		return nullNetwork(), fail.InvalidParameterError("svc", "cannot be null value")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nullNetwork(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	networkCache, xerr := svc.GetCache(networkKind)
	if xerr != nil {
		return nil, xerr
	}

	options := []data.ImmutableKeyValue{
		data.NewImmutableKeyValue("onMiss", func() (cache.Cacheable, fail.Error) {
			rn, innerXErr := NewNetwork(svc)
			if innerXErr != nil {
				return nil, innerXErr
			}

			// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
			if innerXErr = rn.Read(ref); innerXErr != nil {
				return nil, innerXErr
			}

			// Deal with legacy
			if xerr = rn.(*network).upgradeNetworkPropertyIfNeeded(); xerr != nil {
				switch xerr.(type) {
				case *fail.ErrAlteredNothing:
					// ignore
				default:
					return nil, fail.Wrap(xerr, "failed to upgrade Network properties")
				}
			}

			return rn, nil
		}),
	}
	cacheEntry, xerr := networkCache.Get(ref, options...)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nullNetwork(), fail.NotFoundError("failed to find Network '%s'", ref)
		default:
			return nullNetwork(), xerr
		}
	}

	if rn = cacheEntry.Content().(resources.Network); rn == nil {
		return nullNetwork(), fail.InconsistentError("nil value found in Network cache for key '%s'", ref)
	}
	_ = cacheEntry.LockContent()
	defer func() {
		if xerr != nil {
			_ = cacheEntry.UnlockContent()
		}
	}()

	return rn, nil
}

// upgradeNetworkPropertyIfNeeded upgrades properties to most recent version
func (instance *network) upgradeNetworkPropertyIfNeeded() fail.Error {
	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if props.Count() > 0 && !props.Lookup(networkproperty.SubnetsV1) {
			rs, xerr := NewSubnet(instance.GetService())
			if xerr != nil {
				return xerr
			}

			as := abstract.NewSubnet()
			as.Name = an.Name
			as.Network = an.ID
			as.CIDR = an.CIDR
			as.DNSServers = an.DNSServers
			return rs.Carry(as)
		}
		return fail.AlteredNothingError()
	})
}

// isNull tells if the instance corresponds to subnet Null Value
func (instance *network) isNull() bool {
	return instance == nil || instance.core.isNull()
}

// Create creates a network
func (instance *network) Create(ctx context.Context,req abstract.NetworkRequest) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, true, "('%s', '%s')", req.Name, req.CIDR).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if subnet already exists and is managed by SafeScale
	svc := instance.GetService()
	if existing, xerr := LoadNetwork(task, svc, req.Name); xerr == nil {
		existing.Released()
		return fail.DuplicateError("network '%s' already exists", req.Name)
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
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

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Create the network
	logrus.Debugf("Creating network '%s' with CIDR '%s'...", req.Name, req.CIDR)
	an, xerr := svc.CreateNetwork(req)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := svc.DeleteNetwork(an.ID); xerr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network"))
			}
		}
	}()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Write subnet object metadata
	// logrus.Debugf("Saving subnet metadata '%s' ...", subnet.GetName)
	return instance.Carry(/*task, */an)
}

// carry registers clonable as core value and deals with cache
func (instance *network) carry(/*ctx context.Context, */clonable data.Clonable) (xerr fail.Error) {
	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.core.kind)
	if xerr != nil {
		return xerr
	}

	if xerr := kindCache.ReserveEntry(identifiable.GetID()); xerr != nil {
		return xerr
	}
	defer func() {
		if xerr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.core.kind, identifiable.GetID()))
			}

		}
	}()

	// Note: do not validate parameters, this call will do it
	if xerr := instance.core.Carry(task, clonable); xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(identifiable.GetID(), instance)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()

	return nil
}

// Browse walks through all the metadata objects in subnet
func (instance *network) Browse(ctx context.Context,callback func(*abstract.Network) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value of network, so do not validate rn
	// if rn.IsNull() {
	//     return fail.InvalidInstanceError()
	// }
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.core.BrowseFolder(task, func(buf []byte) fail.Error {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		an := abstract.NewNetwork()
		xerr := an.Deserialize(buf)
		if xerr != nil {
			return xerr
		}

		return callback(an)
	})
}

// Delete deletes subnet
func (instance *network) Delete(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.Alter(/*task,  */func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := instance.GetService()

		var subnets map[string]string
		innerXErr := props.Inspect(/*task, */networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if k == instance.GetName() {
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
				return fail.InvalidRequestError("failed to delete Network '%s', 1 Subnet still inside", instance.GetName())
			}
		default:
			return fail.InvalidRequestError("failed to delete Network '%s', %d Subnets still inside", instance.GetName(), subnetsLen)
		}

		// Cannot abort starting from here
		defer task.DisarmAbortSignal()()

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
				logrus.Errorf(innerXErr.Error())
				return innerXErr
			}
		}
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// Remove metadata
	return instance.core.Delete(task)
}

// GetCIDR returns the CIDR of the subnet
func (instance *network) GetCIDR(ctx context.Context) (cidr string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return "", fail.InvalidInstanceError()
	}
	if task == nil {
		return "", fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	cidr = ""
	xerr = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		cidr = an.CIDR
		return nil
	})
	return cidr, xerr
}

// ToProtocol converts resources.Network to protocol.Network
func (instance *network) ToProtocol(ctx context.Context) (_ *protocol.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, true, "").Entering()
	defer tracer.Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var pn *protocol.Network
	xerr = instance.Review(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())

		}

		pn = &protocol.Network{
			Id:   an.ID,
			Name: an.Name,
			Cidr: an.CIDR,
		}

		return props.Inspect(/*task, */networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for k := range nsV1.ByName {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

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
func (instance *network) InspectSubnet(ctx context.Context,ref string) (_ resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	return LoadSubnet(task, instance.GetService(), instance.GetID(), ref)
}

// AdoptSubnet registers a Subnet to the Network metadata
func (instance *network) AdoptSubnet(ctx context.Context,subnet resources.Subnet) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if subnet == nil {
		return fail.InvalidParameterCannotBeNilError("subnet")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	parentNetwork, xerr := subnet.InspectNetwork(task)
	if xerr != nil {
		return xerr
	}
	if parentNetwork.GetName() != instance.GetName() {
		return fail.InvalidRequestError("cannot adopt Subnet '%s' because Network '%s' does not own it", subnet.GetName(), instance.GetName())
	}

	return instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(/*task, */networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			name := subnet.GetName()
			id := subnet.GetID()
			nsV1.ByID[id] = name
			nsV1.ByName[name] = id
			return nil
		})
	})
}

// AbandonSubnet unregisters a Subnet from the Network (does not imply the Subnet is deleted)
func (instance *network) AbandonSubnet(ctx context.Context,subnetID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(/*task, */networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			id := subnetID
			name, ok := nsV1.ByID[subnetID]
			if !ok {
				if id, ok = nsV1.ByName[subnetID]; !ok {
					return fail.NotFoundError("failed to find a Subnet identified by %s in Network '%s'", subnetID, instance.GetName())
				}
			}

			delete(nsV1.ByID, id)
			delete(nsV1.ByName, name)
			return nil
		})
	})
}
