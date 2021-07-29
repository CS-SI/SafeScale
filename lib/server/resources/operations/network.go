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
	"golang.org/x/net/context"

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
	netretry "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	networkKind = "network"
	// networksFolderName is the technical name of the container used to store networks info
	networksFolderName = "networks"
)

// Network links Object Storage MetadataFolder and Networking
type Network struct {
	*MetadataCore

	lock sync.RWMutex
}

// NullValue returns a *Network representing a null value
func NullValue() *Network {
	return &Network{MetadataCore: NullCore()}
}

// NewNetwork creates an instance of Networking
func NewNetwork(svc iaas.Service) (resources.Network, fail.Error) {
	if svc == nil {
		return NullValue(), fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, networkKind, networksFolderName, &abstract.Network{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return NullValue(), xerr
	}

	instance := &Network{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// LoadNetwork loads the metadata of a subnet
func LoadNetwork(svc iaas.Service, ref string) (rn resources.Network, xerr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be null value")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	networkCache, xerr := svc.GetCache(networkKind)
	xerr = debug.InjectPlannedFail(xerr)
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

			// VPL: disabled silent metadata upgrade; will be implemented in a global one-pass migration
			// // Deal with legacy
			// xerr = rn.(*network).upgradeNetworkMetadataIfNeeded()
			// xerr = debug.InjectPlannedFail(xerr)
			// if xerr != nil {
			// 	switch xerr.(type) {
			// 	case *fail.ErrAlteredNothing:
			// 		// ignore
			// 	default:
			// 		return nil, fail.Wrap(xerr, "failed to upgrade Network properties")
			// 	}
			// }

			return rn, nil
		}),
	}
	cacheEntry, xerr := networkCache.Get(ref, options...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nil, fail.NotFoundError("failed to find Network '%s'", ref)
		default:
			return nil, xerr
		}
	}

	if rn = cacheEntry.Content().(resources.Network); rn == nil {
		return nil, fail.InconsistentError("nil value found in Network cache for key '%s'", ref)
	}
	_ = cacheEntry.LockContent()
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			_ = cacheEntry.UnlockContent()
		}
	}()

	return rn, nil
}

// IsNull tells if the instance corresponds to subnet Null Value
func (instance *Network) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || instance.MetadataCore.IsNull()
}

// Create creates a Network
func (instance *Network) Create(ctx context.Context, req abstract.NetworkRequest) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		networkName := instance.GetName()
		if networkName != "" {
			return fail.NotAvailableError("already carrying Network '%s'", networkName)
		}
		return fail.InvalidInstanceContentError("instance", "is not null value")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, true, "('%s', '%s')", req.Name, req.CIDR).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if subnet already exists and is managed by SafeScale
	svc := instance.GetService()
	if existing, xerr := LoadNetwork(svc, req.Name); xerr == nil {
		existing.Released()
		return fail.DuplicateError("Network '%s' already exists", req.Name)
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Verify if the subnet already exist and in this case is not managed by SafeScale
	_, xerr = svc.InspectNetworkByName(req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	} else {
		return fail.DuplicateError("Network '%s' already exists (not managed by SafeScale)", req.Name)
	}

	// Verify the CIDR is not routable
	if req.CIDR != "" {
		routable, xerr := netretry.IsCIDRRoutable(req.CIDR)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to determine if CIDR is not routable")
		}

		if routable {
			return fail.InvalidRequestError("cannot create such a Networking, CIDR must not be routable; please choose abstractNetwork appropriate CIDR (RFC1918)")
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Create the Network
	logrus.Debugf("Creating Network '%s' with CIDR '%s'...", req.Name, req.CIDR)
	abstractNetwork, xerr := svc.CreateNetwork(req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			derr := svc.DeleteNetwork(abstractNetwork.ID)
			derr = debug.InjectPlannedFail(derr)
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network"))
			}
		}
	}()

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Write subnet object metadata
	// logrus.Debugf("Saving subnet metadata '%s' ...", subnet.GetName)
	abstractNetwork.Imported = false
	return instance.carry(abstractNetwork)
}

// carry registers clonable as core value and deals with cache
func (instance *Network) carry(clonable data.Clonable) (xerr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.MetadataCore.GetKind())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = kindCache.ReserveEntry(identifiable.GetID())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if derr := kindCache.FreeEntry(identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.MetadataCore.GetKind(), identifiable.GetID()))
			}
		}
	}()

	// Note: do not validate parameters, this call will do it
	xerr = instance.MetadataCore.Carry(clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(identifiable.GetID(), instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()

	return nil
}

// Import imports an existing Network in SafeScale metadata
func (instance *Network) Import(ctx context.Context, ref string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, true, "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	// Check if Network already exists and is managed by SafeScale
	svc := instance.GetService()
	if existing, xerr := LoadNetwork(svc, ref); xerr == nil {
		existing.Released()
		return fail.DuplicateError("cannot import Network '%s': there is already such a Network in metadata", ref)
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Verify if the subnet already exist and in this case is not managed by SafeScale
	abstractNetwork, xerr := svc.InspectNetworkByName(ref)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			abstractNetwork, xerr = svc.InspectNetwork(ref)
		default:
			return xerr
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Write subnet object metadata
	// logrus.Debugf("Saving subnet metadata '%s' ...", subnet.GetName)
	abstractNetwork.Imported = true
	return instance.carry(abstractNetwork)
}

// Browse walks through all the metadata objects in subnet
func (instance *Network) Browse(ctx context.Context, callback func(*abstract.Network) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value, so do not validate instance with .IsNull()
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.MetadataCore.BrowseFolder(func(buf []byte) fail.Error {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		an := abstract.NewNetwork()
		xerr := an.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return callback(an)
	})
}

// Delete deletes subnet
func (instance *Network) Delete(ctx context.Context) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(nil, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		abstractNetwork, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := instance.GetService()

		var subnets map[string]string
		innerXErr := props.Inspect(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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
			// no subnet, continue to delete the Network
		case 1:
			var found bool
			for k, v := range subnets {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if k == instance.GetName() {
					found = true
					// the single subnet present is a subnet named like the Network, delete it first
					rs, xerr := LoadSubnet(svc, "", v)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							// Subnet is already deleted, considered as a success and continue
							debug.IgnoreError(xerr)
						default:
							return xerr
						}
					} else {
						subnetName := rs.GetName()
						xerr = rs.Delete(ctx)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
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

		// delete Network if not imported, with tolerance
		if !abstractNetwork.Imported {
			innerXErr = svc.DeleteNetwork(abstractNetwork.ID)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// If Network does not exist anymore on the provider side, do not fail to cleanup the metadata: log and continue
					logrus.Debugf("failed to find Network on provider side, cleaning up metadata.")
				case *fail.ErrTimeout:
					logrus.Error("cannot delete Network due to a timeout")
					errWaitMore := retry.WhileUnsuccessfulDelay1Second(
						func() error {
							recNet, recErr := svc.InspectNetwork(abstractNetwork.ID)
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
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Remove metadata
	return instance.MetadataCore.Delete()
}

// GetCIDR returns the CIDR of the subnet
func (instance *Network) GetCIDR() (cidr string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return "", fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	cidr = ""
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
func (instance *Network) ToProtocol() (_ *protocol.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var pn *protocol.Network
	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		an, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())

		}

		pn = &protocol.Network{
			Id:   an.ID,
			Name: an.Name,
			Cidr: an.CIDR,
		}

		return props.Inspect(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return pn, nil
}

// InspectSubnet returns the instance of resources.Subnet corresponding to the subnet referenced by 'ref' attached to
// the subnet
func (instance *Network) InspectSubnet(ref string) (_ resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	return LoadSubnet(instance.GetService(), instance.GetID(), ref)
}

// AdoptSubnet registers a Subnet to the Network metadata
func (instance *Network) AdoptSubnet(ctx context.Context, subnet resources.Subnet) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnet == nil {
		return fail.InvalidParameterCannotBeNilError("subnet")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	parentNetwork, xerr := subnet.InspectNetwork()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer parentNetwork.Released()

	if parentNetwork.GetName() != instance.GetName() {
		return fail.InvalidRequestError("cannot adopt Subnet '%s' because Network '%s' does not own it", subnet.GetName(), instance.GetName())
	}

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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
func (instance *Network) AbandonSubnet(ctx context.Context, subnetID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
		default:
		}
	}
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
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

// FreeCIDRForSingleHost frees the CIDR index inside the Network 'Network'
func FreeCIDRForSingleHost(network resources.Network, index uint) fail.Error {
	return network.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SingleHostsV1, func(clonable data.Clonable) fail.Error {
			nshV1, ok := clonable.(*propertiesv1.NetworkSingleHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSingleHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nshV1.FreeSlot(index)
			return nil
		})
	})
}
