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

package operations

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	networkKind = "network"
	// networksFolderName is the technical name of the Object Storage container used to store networks info
	networksFolderName = "networks"
)

// Network links Object Storage MetadataFolder and Networking
type Network struct {
	*metadata.Core
}

// NewNetwork creates an instance of Networking
func NewNetwork(ctx context.Context) (resources.Network, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, networkKind, networksFolderName, abstract.NewEmptyNetwork())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Network{
		Core: coreInstance,
	}
	return instance, nil
}

// LoadNetwork loads the metadata of a subnet
func LoadNetwork(inctx context.Context, ref string) (resources.Network, fail.Error) {
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return nil, xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Network
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Network, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *Network
			cacheref := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := myjob.Service().Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Network)
					if ok {
						return casted, nil
					}
				}
			}

			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onNetworkCacheMiss(ctx, ref) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// do not want to propagate the reason that let us know the Network was not found to the caller... but we want to log it
					logrus.Debugf(xerr.Error())
					return nil, fail.NotFoundError("failed to find Network %s", ref)
				default:
					return nil, xerr
				}
			}

			networkInstance, ok := anon.(resources.Network)
			if !ok {
				return nil, fail.InconsistentError("cache content should be a resources.Network", ref)
			}
			if networkInstance == nil {
				return nil, fail.InconsistentError("nil value found in Network cache for key '%s'", ref)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = networkInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, networkInstance.GetName()), networkInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				hid, err := networkInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), networkInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(10 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cacheref); xerr == nil {
					casted, ok := val.(resources.Network)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Network")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			return networkInstance, nil

		}()
		chRes <- result{ga, gerr}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// onNetworkCacheMiss is called when there is no instance in cache of Network 'ref'
func onNetworkCacheMiss(ctx context.Context, ref string) (data.Identifiable, fail.Error) {
	networkInstance, innerXErr := NewNetwork(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	blank, innerXErr := NewNetwork(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if innerXErr = networkInstance.Read(ctx, ref); innerXErr != nil {
		return nil, innerXErr
	}

	if strings.Compare(fail.IgnoreError(networkInstance.String(ctx)).(string), fail.IgnoreError(blank.String(ctx)).(string)) == 0 {
		return nil, fail.NotFoundError("network with ref '%s' does NOT exist", ref)
	}

	return networkInstance, nil
}

// IsNull tells if the instance corresponds to subnet Null Value
func (instance *Network) IsNull() bool {
	return instance == nil || valid.IsNull(instance.Core)
}

// Kind returns the kind of resource
func (instance *Network) Kind() string {
	return networkKind
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Network) Exists(ctx context.Context) (bool, fail.Error) {
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.ConvertError(err)
	}
	_, xerr := instance.Service().InspectNetwork(ctx, theID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return false, nil
		default:
			return false, xerr
		}
	}

	return true, nil
}

// Create creates a Network
// returns:
//   - *fail.ErrInvalidParameter: one parameter is invalid
//   - *failErrInvalidInstance: Create() is called from bad instance (nil or null value)
//   - *fail.ErrNotAvailable: a Network with the same name is currently created
//   - *fail.ErrDuplicate: a Network with the same name already exist on Provider Side (managed or not by SafeScale)
//   - *fail.ErrAborted: abort signal has been received
func (instance *Network) Create(inctx context.Context, req abstract.NetworkRequest) (_ fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.IsTaken() {
		return fail.NotAvailableError("already carrying information")
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(inctx, true, "('%s', '%s')", req.Name, req.CIDR).WithStopwatch().Entering()
	defer tracer.Exiting()

	svc := instance.Service()

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// Check if Network already exists and is managed by SafeScale
			_, xerr := LoadNetwork(ctx, req.Name)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					ar := result{xerr}
					return ar, ar.rErr
				}
			} else {
				xerr := fail.DuplicateError("Network '%s' already exists", req.Name)
				_ = xerr.Annotate("managed", true)
				ar := result{xerr}
				return ar, ar.rErr
			}

			// Verify if the network already exist and in this case is not managed by SafeScale
			_, xerr = svc.InspectNetworkByName(ctx, req.Name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					ar := result{xerr}
					return ar, ar.rErr
				}
			} else {
				xerr := fail.DuplicateError("Network '%s' already exists ", req.Name)
				_ = xerr.Annotate("managed", false)
				ar := result{xerr}
				return ar, ar.rErr
			}

			// Verify the CIDR is not routable
			if req.CIDR != "" {
				routable, xerr := netretry.IsCIDRRoutable(req.CIDR)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					rv := fail.Wrap(xerr, "failed to determine if CIDR is not routable")
					ar := result{rv}
					return ar, ar.rErr
				}

				if routable {
					rv := fail.InvalidRequestError("cannot create such a Networking, CIDR must not be routable; please choose abstractNetwork appropriate CIDR (RFC1918)")
					ar := result{rv}
					return ar, ar.rErr
				}
			}

			var abstractNetwork *abstract.Network

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() && !valid.IsNull(abstractNetwork) {
					derr := svc.DeleteNetwork(cleanupContextFrom(ctx), abstractNetwork.ID)
					derr = debug.InjectPlannedFail(derr)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network"))
					}
				}
			}()

			// Create the Network
			logrus.WithContext(ctx).Debugf("Creating Network '%s' with CIDR '%s'...", req.Name, req.CIDR)
			abstractNetwork, xerr = svc.CreateNetwork(ctx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				rv := fail.Wrap(xerr, "failure creating provider network")
				ar := result{rv}
				return ar, ar.rErr
			}

			// Write subnet object metadata
			logrus.WithContext(ctx).Debugf("Saving Subnet metadata '%s' ...", abstractNetwork.Name)
			abstractNetwork.Imported = false
			xerr = instance.carry(ctx, abstractNetwork)
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			ar := result{nil}
			return ar, ar.rErr
		}()
		chRes <- gres
	}() // nolint

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes // wait for cleanup
		return fail.ConvertError(inctx.Err())
	}
}

// carry registers clonable as core value and deals with cache
func (instance *Network) carry(ctx context.Context, clonable clonable.Clonable) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.Core.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Import imports an existing Network in SafeScale metadata
func (instance *Network) Import(ctx context.Context, ref string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.Core.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, true, "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	// Check if Network already exists and is managed by SafeScale
	svc := instance.Service()
	_, xerr := LoadNetwork(ctx, ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			debug.IgnoreErrorWithContext(ctx, xerr)
		default:
			return xerr
		}
	} else {
		return fail.DuplicateError("cannot import Network '%s': there is already such a Network in metadata", ref)
	}

	// Verify if the subnet already exist and in this case is not managed by SafeScale
	abstractNetwork, xerr := svc.InspectNetworkByName(ctx, ref)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			abstractNetwork, xerr = svc.InspectNetwork(ctx, ref)
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	// Write subnet object metadata
	// logrus.WithContext(ctx).Debugf("Saving subnet metadata '%s' ...", subnet.GetName)
	abstractNetwork.Imported = true
	return instance.carry(ctx, abstractNetwork)
}

// Browse walks through all the metadata objects in subnet
func (instance *Network) Browse(ctx context.Context, callback func(*abstract.Network) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: Do not test with Isnull here, as Browse may be used from null value
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	return instance.Core.BrowseFolder(ctx, func(buf []byte) fail.Error {
		an, _ := abstract.NewNetwork()
		xerr := an.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return callback(an)
	})
}

var (
	CurrentNetworkAbstractContextKey   = "current_network_abstract"
	CurrentNetworkPropertiesContextKey = "current_network_properties"
)

// Delete deletes subnet
func (instance *Network) Delete(inctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		var outprops *serialize.JSONProperties
		var networkAbstract *abstract.Network

		xerr := instance.Review(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			var innerErr error
			networkAbstract, innerErr = clonable.Cast[*abstract.Network](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			outprops = props
			return nil
		})
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		ctx := context.WithValue(ctx, CurrentNetworkAbstractContextKey, networkAbstract) // nolint
		ctx = context.WithValue(ctx, CurrentNetworkPropertiesContextKey, outprops)       // nolint

		tracer := debug.NewTracer(ctx, true, "").WithStopwatch().Entering()
		defer tracer.Exiting()

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		var abstractNetwork *abstract.Network
		xerr = instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			var innerErr error
			abstractNetwork, innerErr = clonable.Cast[*abstract.Network](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			svc := instance.Service()

			var subnets map[string]string
			innerXErr := props.Inspect(networkproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
				subnetsV1, innerErr := clonable.Cast[*propertiesv1.NetworkSubnets](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
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
					if k == instance.GetName() {
						found = true
						deleted := false
						// the single subnet present is a subnet named like the Network, delete it first
						subnetInstance, xerr := LoadSubnet(ctx, "", v)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							switch xerr.(type) {
							case *fail.ErrNotFound:
								// Subnet is already deleted, considered as a success and continue
								debug.IgnoreErrorWithContext(ctx, xerr)
								deleted = true
							default:
								return xerr
							}
						}

						if !deleted {
							subnetName := subnetInstance.GetName()
							xerr = subnetInstance.Delete(ctx)
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
				innerXErr = props.Alter(networkproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
					nsgV1, innerErr := clonable.Cast[*propertiesv1.NetworkSecurityGroups](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					for k := range nsgV1.ByID {
						sgInstance, propsXErr := LoadSecurityGroup(ctx, k)
						if propsXErr != nil {
							switch propsXErr.(type) {
							case *fail.ErrNotFound:
								debug.IgnoreErrorWithContext(ctx, propsXErr)
								continue
							default:
								return propsXErr
							}
						}

						sgid, err := sgInstance.GetID()
						if err != nil {
							return fail.ConvertError(err)
						}

						propsXErr = sgInstance.unsafeDelete(ctx, true)
						if propsXErr != nil {
							return propsXErr
						}

						// -- delete reference to Security Group in Network
						delete(nsgV1.ByID, sgid)
						delete(nsgV1.ByName, sgInstance.GetName())
					}
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				maybeDeleted := false
				innerXErr = svc.DeleteNetwork(ctx, abstractNetwork.ID)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						// If Network does not exist anymore on the provider side, do not fail to cleanup the metadata: log and continue
						logrus.WithContext(ctx).Debugf("failed to find Network on provider side, cleaning up metadata.")
						maybeDeleted = true
					case *fail.ErrTimeout:
						logrus.WithContext(ctx).Error("cannot delete Network due to a timeout")
						errWaitMore := retry.WhileUnsuccessful(
							func() error {
								select {
								case <-ctx.Done():
									return retry.StopRetryError(ctx.Err())
								default:
								}

								recNet, recErr := svc.InspectNetwork(ctx, abstractNetwork.ID)
								if _, ok := recErr.(*fail.ErrNotFound); ok {
									return nil
								}
								if recNet != nil {
									return fmt.Errorf("still there")
								}

								return fail.Wrap(recErr, "another kind of error")
							},
							timings.SmallDelay(),
							timings.ContextTimeout(),
						)
						if errWaitMore != nil {
							_ = innerXErr.AddConsequence(errWaitMore)
							return innerXErr
						}
					default:
						logrus.WithContext(ctx).Errorf(innerXErr.Error())
						return innerXErr
					}
				}

				if maybeDeleted {
					logrus.WithContext(ctx).Debugf("The network %s should be deleted already, if not errors will follow", abstractNetwork.ID)
				}
				iterations := 6
				for {
					_, ierr := svc.InspectNetwork(ctx, abstractNetwork.ID)
					if ierr != nil {
						if _, ok := ierr.(*fail.ErrNotFound); ok {
							break
						}
					}
					iterations--
					if iterations < 0 {
						logrus.WithContext(ctx).Debugf("The network '%s' is still there", abstractNetwork.ID)
						break
					}
					time.Sleep(timings.NormalDelay())
				}
			}
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreErrorWithContext(ctx, xerr)
				// continue
			default:
				xerr.WithContext(ctx)
				chRes <- result{xerr}
				return
			}
		}

		// Remove metadata
		xerr = instance.Core.Delete(ctx)
		if xerr != nil {
			xerr.WithContext(ctx)
			chRes <- result{xerr}
			return
		}

		chRes <- result{nil}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return fail.ConvertError(inctx.Err())
	}
}

// GetCIDR returns the CIDR of the subnet
func (instance *Network) GetCIDR(ctx context.Context) (cidr string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	cidr = ""
	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		an, innerErr := clonable.Cast[*abstract.Network](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		cidr = an.CIDR
		return nil
	})
	return cidr, xerr
}

// ToProtocol converts resources.Network to protocol.Network
func (instance *Network) ToProtocol(ctx context.Context) (out *protocol.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	xerr := instance.Review(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		an, innerErr := clonable.Cast[*abstract.Network](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)

		}

		out = &protocol.Network{
			Id:   an.ID,
			Name: an.Name,
			Cidr: an.CIDR,
		}

		return props.Inspect(networkproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
			nsV1, innerErr := clonable.Cast[*propertiesv1.NetworkSubnets](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			for k := range nsV1.ByName {
				out.Subnets = append(out.Subnets, k)
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}

// InspectSubnet returns the instance of resources.Subnet corresponding to the subnet referenced by 'ref' attached to
// the subnet
func (instance *Network) InspectSubnet(ctx context.Context, ref string) (_ resources.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	nid, err := instance.GetID()
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	sn, xerr := LoadSubnet(ctx, nid, ref)
	return sn, xerr
}

// AdoptSubnet registers a Subnet to the Network metadata
func (instance *Network) AdoptSubnet(ctx context.Context, subnet resources.Subnet) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if subnet == nil {
		return fail.InvalidParameterCannotBeNilError("subnet")
	}

	parentNetwork, xerr := subnet.InspectNetwork(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if parentNetwork.GetName() != instance.GetName() {
		return fail.InvalidRequestError("cannot adopt Subnet '%s' because Network '%s' does not own it", subnet.GetName(), instance.GetName())
	}

	return instance.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
			nsV1, innerErr := clonable.Cast[*propertiesv1.NetworkSubnets](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			name := subnet.GetName()
			id, err := subnet.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}
			nsV1.ByID[id] = name
			nsV1.ByName[name] = id
			return nil
		})
	})
}

// AbandonSubnet unregisters a Subnet from the Network (does not imply the Subnet is deleted)
func (instance *Network) AbandonSubnet(ctx context.Context, subnetID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	return instance.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
			nsV1, innerErr := clonable.Cast[*propertiesv1.NetworkSubnets](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			id := subnetID
			name, ok := nsV1.ByID[subnetID]
			if !ok {
				id, ok = nsV1.ByName[subnetID]
				if !ok {
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
func FreeCIDRForSingleHost(ctx context.Context, network resources.Network, index uint) fail.Error {
	return network.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SingleHostsV1, func(p clonable.Clonable) fail.Error {
			nshV1, innerErr := clonable.Cast[*propertiesv1.NetworkSingleHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			nshV1.FreeSlot(index)
			return nil
		})
	})
}
