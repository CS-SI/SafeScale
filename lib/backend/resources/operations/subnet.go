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
	"net"
	"strings"
	"sync"
	"time"

	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	subnetKind = "subnet"
	// networksFolderName is the technical name of the container used to store networks info
	subnetsFolderName = "subnets"

	subnetInternalSecurityGroupNamePattern        = "safescale-sg_subnet_internals.%s.%s"
	subnetInternalSecurityGroupDescriptionPattern = "SG for internal access in Subnet %s of Network %s"
	subnetGWSecurityGroupNamePattern              = "safescale-sg_subnet_gateways.%s.%s"
	subnetGWSecurityGroupDescriptionPattern       = "SG for gateways in Subnet %s of Network %s"
	subnetPublicIPSecurityGroupNamePattern        = "safescale-sg_subnet_publicip.%s.%s"
	subnetPublicIPSecurityGroupDescriptionPattern = "SG for hosts with public IP in Subnet %s of Network %s"

	virtualIPNamePattern = "safescale-vip_gateways_subnet.%s.%s"
)

// Subnet links Object Storage MetadataFolder and Subnet
type Subnet struct {
	*metadata.Core

	localCache struct {
		sync.RWMutex
		gateways [2]*Host
		// parentNetwork resources.Network
	}
}

// ListSubnets returns a list of available subnets
func ListSubnets(ctx context.Context, frame *scope.Frame, networkID string, all bool) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if frame == nil {
		return nil, fail.InvalidParameterCannotBeNilError("frame")
	}

	if all {
		return frame.Service().ListSubnets(ctx, networkID)
	}

	subnetInstance, xerr := NewSubnet(frame)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// recover Subnets from metadata
	var list []*abstract.Subnet
	xerr = subnetInstance.Browse(ctx, func(abstractSubnet *abstract.Subnet) fail.Error {
		if networkID == "" || abstractSubnet.Network == networkID {
			list = append(list, abstractSubnet)
		}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return list, nil
}

// NewSubnet creates an instance of Subnet used as resources.Subnet
func NewSubnet(frame *scope.Frame) (_ *Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(frame) {
		return nil, fail.InvalidParameterCannotBeNilError("frame")
	}

	coreInstance, xerr := metadata.NewCore(frame, metadata.MethodObjectStorage, subnetKind, subnetsFolderName, &abstract.Subnet{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Subnet{
		Core: coreInstance,
	}
	return instance, nil
}

// LoadSubnet loads the metadata of a Subnet
func LoadSubnet(inctx context.Context, frame *scope.Frame, networkRef, subnetRef string) (*Subnet, fail.Error) {
	if valid.IsNull(frame) {
		return nil, fail.InvalidParameterCannotBeNilError("frame")
	}
	if subnetRef = strings.TrimSpace(subnetRef); subnetRef == "" {
		return nil, fail.InvalidParameterError("subnetRef", "cannot be empty string")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *Subnet
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ *Subnet, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *Subnet
			cachesubnetRef := fmt.Sprintf("%T/%s", kt, subnetRef)

			cache, xerr := frame.Service().GetCache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				if val, xerr := cache.Get(ctx, cachesubnetRef); xerr == nil {
					casted, ok := val.(*Subnet)
					if ok {
						return casted, nil
					}
				}
			}

			// -- First step: identify subnetID from (networkRef, subnetRef) --
			var (
				subnetID        string
				networkInstance resources.Network
			)

			networkRef = strings.TrimSpace(networkRef)
			switch networkRef {
			case "":
				// If networkRef is empty, subnetRef must be subnetID
				subnetID = subnetRef
			default:
				// Try to load Network metadata
				networkInstance, xerr = LoadNetwork(ctx, frame, networkRef)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						debug.IgnoreError(xerr)
						// Network metadata can be missing if it's the default Network, so continue
					default:
						return nil, xerr
					}
				}

				withDefaultSubnetwork, err := frame.Service().HasDefaultNetwork()
				if err != nil {
					return nil, err
				}

				if networkInstance != nil { // nolint
					// Network metadata loaded, find the ID of the Subnet (subnetRef may be ID or Name)
					xerr = metadata.InspectProperty[*propertiesv1.NetworkSubnets](ctx, networkInstance, networkproperty.SubnetsV1, func(subnetsV1 *propertiesv1.NetworkSubnets) fail.Error {
						var found bool
						for k, v := range subnetsV1.ByName {
							if k == subnetRef || v == subnetRef {
								subnetID = v
								found = true
								break
							}
						}
						if !found {
							return fail.NotFoundError("failed to find a Subnet referenced by '%s' in network '%s'", subnetRef, networkInstance.GetName())
						}
						return nil
					})
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return nil, xerr
					}
				} else if withDefaultSubnetwork {
					// No Network Metadata, try to use the default Network if there is one
					an, xerr := frame.Service().DefaultNetwork(ctx)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return nil, xerr
					}

					if an.Name == networkRef || an.ID == networkRef {
						// We are in default Network context, query Subnet list and search for the one requested
						list, xerr := ListSubnets(ctx, frame, an.ID, false)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							return nil, xerr
						}

						for _, v := range list {
							if v.ID == subnetRef || v.Name == subnetRef {
								subnetID = v.ID
								break
							}
						}
					}
				} else {
					// failed to identify the Network owning the Subnets
					return nil, fail.NotFoundError("failed to find Network '%s'", networkRef)
				}
			}

			if subnetID == "" {
				return nil, fail.NotFoundError("failed to find a Subnet '%s' in Network '%s'", subnetRef, networkRef)
			}

			// -- second step: search instance in service cache
			cacheMissLoader := func() (data.Identifiable, fail.Error) { return onSubnetCacheMiss(ctx, frame, subnetID) }
			anon, xerr := cacheMissLoader()
			if xerr != nil {
				return nil, xerr
			}

			var ok bool
			subnetInstance, ok := anon.(*Subnet)
			if !ok {
				return nil, fail.InconsistentError("cache entry for %s is not a *Subnet", subnetID)
			}
			if subnetInstance == nil {
				return nil, fail.InconsistentError("nil found in cache for Subnet with id %s", subnetID)
			}

			// if cache failed we are here, so we better retrieve updated information...
			xerr = subnetInstance.Reload(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if cache != nil {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, subnetInstance.GetName()), subnetInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				hid, err := subnetInstance.GetID()
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), subnetInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.ConvertError(err)
				}
				time.Sleep(10 * time.Millisecond) // consolidate cache.Set

				if val, xerr := cache.Get(ctx, cachesubnetRef); xerr == nil {
					casted, ok := val.(*Subnet)
					if ok {
						return casted, nil
					} else {
						logrus.WithContext(ctx).Warnf("wrong type of resources.Subnet")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			return subnetInstance, nil
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

// onSubnetCacheMiss is called when there is no instance in cache of Subnet 'subnetID'
func onSubnetCacheMiss(ctx context.Context, frame *scope.Frame, subnetID string) (data.Identifiable, fail.Error) {
	subnetInstance, innerXErr := NewSubnet(frame)
	if innerXErr != nil {
		return nil, innerXErr
	}

	if innerXErr = subnetInstance.Read(ctx, subnetID); innerXErr != nil {
		return nil, innerXErr
	}

	xerr := subnetInstance.updateCachedInformation(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return subnetInstance, nil
}

// updateCachedInformation updates the information cached in instance because will be frequently used and will not be changed over time
func (instance *Subnet) updateCachedInformation(ctx context.Context) fail.Error {
	instance.localCache.Lock()
	defer instance.localCache.Unlock()

	var primaryGatewayID, secondaryGatewayID string
	xerr := instance.Inspect(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		if len(as.GatewayIDs) > 0 {
			primaryGatewayID = as.GatewayIDs[0]
		}
		if len(as.GatewayIDs) > 1 {
			secondaryGatewayID = as.GatewayIDs[1]
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if primaryGatewayID != "" {
		hostInstance, xerr := LoadHost(ctx, instance.Frame(), primaryGatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
				// Network metadata can be missing if it's the default Network, so continue
			default:
				return xerr
			}
		} else {
			var ok bool
			instance.localCache.gateways[0], ok = hostInstance.(*Host)
			if !ok {
				return fail.NewError("hostInstance should be a *Host")
			}
		}
	}

	if secondaryGatewayID != "" {
		hostInstance, xerr := LoadHost(ctx, instance.Frame(), secondaryGatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
				// Network metadata can be missing if it's the default Network, so continue
			default:
				return xerr
			}
		} else {
			var ok bool
			instance.localCache.gateways[1], ok = hostInstance.(*Host)
			if !ok {
				return fail.InconsistentError("hostInstance should be a *Host")
			}
		}
	}

	return nil
}

// IsNull tells if the instance is a null value
func (instance *Subnet) IsNull() bool {
	return instance == nil || valid.IsNil(instance.Core)
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Subnet) Exists(ctx context.Context) (bool, fail.Error) {
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.ConvertError(err)
	}
	_, xerr := instance.Service().InspectSubnet(ctx, theID)
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

// Carry wraps rv.core.Carry() to add Volume to service cache
func (instance *Subnet) Carry(ctx context.Context, clonable clonable.Clonable) (ferr fail.Error) {
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}

	xerr := instance.Core.Carry(ctx, clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Create creates a Subnet
func (instance *Subnet) Create(ctx context.Context, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.Core) {
		if instance.Core.IsTaken() {
			return fail.InconsistentError("already carrying information")
		}
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet"), "('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.ImageRef, req.HA).WithStopwatch().Entering()
	defer tracer.Exiting()

	xerr := instance.unsafeCreateSubnet(ctx, req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failure in 'unsafe' creating subnet")
	}

	snid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	// Starting from here, delete Subnet if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			if derr := instance.deleteSubnetThenWaitCompletion(context.Background(), snid); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", ActionFromError(ferr)))
			} else {
				logrus.WithContext(ctx).Infof("the subnet '%s' should be gone by now", snid)
			}
		}
	}()

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if instance != nil {
				derr := instance.unsafeUpdateSubnetStatus(context.Background(), subnetstate.Error)
				if derr != nil {
					_ = ferr.AddConsequence(derr)
				}
			}
		}
	}()

	// --- Create the gateway(s) ---
	xerr = instance.unsafeCreateGateways(ctx, req, gwname, gwSizing, nil)
	if xerr != nil {
		return fail.Wrap(xerr, "failure in 'unsafe' creating gateways")
	}

	// --- Updates Subnet state in metadata ---
	xerr = instance.unsafeFinalizeSubnetCreation(ctx)
	if xerr != nil {
		return fail.Wrap(xerr, "failure in 'unsafe' finalizing subnet creation")
	}

	return nil
}

// CreateSecurityGroups ...
func (instance *Subnet) CreateSecurityGroups(ctx context.Context, networkInstance resources.Network, keepOnFailure bool, defaultSSHPort int32) (subnetGWSG, subnetInternalSG, subnetPublicIPSG resources.SecurityGroup, ferr fail.Error) {
	// instance.lock.Lock()
	// defer instance.lock.Unlock()
	return instance.unsafeCreateSecurityGroups(ctx, networkInstance, keepOnFailure, defaultSSHPort)
}

// bindInternalSecurityGroupToGateway does what its name says
func (instance *Subnet) bindInternalSecurityGroupToGateway(ctx context.Context, host resources.Host) fail.Error {
	return instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		sg, innerXErr := LoadSecurityGroup(ctx, instance.Frame(), as.InternalSecurityGroupID)
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to load Subnet '%s' internal Security Group %s", as.Name, as.InternalSecurityGroupID)
		}

		if innerXErr = sg.BindToHost(ctx, host, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to apply Subnet '%s' internal Security Group '%s' to Host '%s'", as.Name, sg.GetName(), host.GetName())
		}

		return nil
	})
}

// undoBindInternalSecurityGroupToGateway does what its name says
func (instance *Subnet) undoBindInternalSecurityGroupToGateway(ctx context.Context, host resources.Host, keepOnFailure bool, xerr *fail.Error) fail.Error {
	if ctx != context.Background() {
		return fail.InvalidParameterError("ctx", "has to be context.Background()")
	}

	if xerr != nil && *xerr != nil && keepOnFailure {
		_ = instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, innerErr := lang.Cast[*abstract.Subnet](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			sg, derr := LoadSecurityGroup(ctx, instance.Frame(), as.InternalSecurityGroupID)
			if derr != nil {
				_ = (*xerr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind External Security Group of Subnet '%s' from Host '%s'", as.Name, host.GetName()))
				return derr
			}

			derr = sg.UnbindFromHost(ctx, host)
			if derr != nil {
				_ = (*xerr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind External Security Group of Subnet '%s' from Host '%s'", as.Name, host.GetName()))
				return derr
			}

			return nil
		})
	}

	return nil
}

// deleteSubnetThenWaitCompletion deletes the Subnet identified by 'id' and wait for deletion confirmation
func (instance *Subnet) deleteSubnetThenWaitCompletion(ctx context.Context, id string) fail.Error {
	svc := instance.Service()

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	xerr = svc.DeleteSubnet(ctx, id)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If Subnet doesn't exist anymore on the provider infrastructure, do not fail
			debug.IgnoreError(xerr)
			return nil
		default:
			return xerr
		}
	}
	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			_, xerr := svc.InspectSubnet(ctx, id)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Subnet not found, good
					debug.IgnoreError(xerr)
					return nil
				default:
					return xerr
				}
			}
			return nil
		},
		timings.SmallDelay(),
		timings.ContextTimeout(),
	)
	return xerr
}

// validateCIDR tests if CIDR requested is valid, or select one if no CIDR is provided
func (instance *Subnet) validateCIDR(ctx context.Context, req *abstract.SubnetRequest, network abstract.Network) fail.Error {
	_, networkDesc, _ := net.ParseCIDR(network.CIDR)
	if req.CIDR != "" {
		routable, xerr := netutils.IsCIDRRoutable(req.CIDR)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to determine if CIDR is not routable")
		}

		if routable {
			return fail.InvalidRequestError("cannot create such a Subnet, CIDR must NOT be routable; please choose an appropriate CIDR (RFC1918)")
		}

		_, subnetDesc, err := net.ParseCIDR(req.CIDR)
		err = debug.InjectPlannedError(err)
		if err != nil {
			return fail.ConvertError(err)
		}

		// ... and if CIDR is inside VPC's one
		if !netutils.CIDROverlap(*networkDesc, *subnetDesc) {
			return fail.InvalidRequestError("not inside Network CIDR '%s'", network.CIDR)
		}
		return nil
	}

	// CIDR is empty, choose the first Class C available one
	logrus.WithContext(ctx).Debugf("CIDR is empty, choosing one...")

	subnets, xerr := instance.Service().ListSubnets(ctx, network.ID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	var (
		newIPNet net.IPNet
		found    bool
	)
	mask, _ := networkDesc.Mask.Size()
	maxBitShift := uint(30 - mask)

	for bs := uint(1); bs <= maxBitShift && !found; bs++ {
		limit := uint(1 << maxBitShift)
		for i := uint(1); i <= limit; i++ {
			newIPNet, xerr = netutils.NthIncludedSubnet(*networkDesc, uint8(bs), i)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to choose a CIDR for the Subnet")
			}
			if wouldOverlap(subnets, newIPNet) == nil {
				found = true
				break
			}
		}
	}
	if !found {
		return fail.OverflowError(nil, maxBitShift, "failed to find a free available CIDR ")
	}

	req.CIDR = newIPNet.String()
	logrus.WithContext(ctx).Debugf("CIDR chosen for Subnet '%s' is '%s'", req.Name, req.CIDR)
	return nil
}

// wouldOverlap returns fail.ErrOverloadError if Subnet overlaps one of the subnets in allSubnets
// TODO: there is room for optimization here, 'allSubnets' is walked through at each call...
func wouldOverlap(allSubnets []*abstract.Subnet, subnet net.IPNet) fail.Error {
	for _, s := range allSubnets {
		_, sDesc, xerr := net.ParseCIDR(s.CIDR)
		if xerr != nil {
			return fail.ConvertError(xerr)
		}
		if netutils.CIDROverlap(subnet, *sDesc) {
			return fail.OverloadError("would intersect with '%s (%s)'", s.Name, s.CIDR)
		}
	}
	return nil
}

// checkUnicity checks if the Subnet name is not already used
func (instance *Subnet) checkUnicity(ctx context.Context, req abstract.SubnetRequest) fail.Error {
	_, xerr := LoadSubnet(ctx, instance.Frame(), req.NetworkID, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil
		default:
			return xerr
		}
	}

	return fail.DuplicateError("Subnet '%s' already exists", req.Name)
}

// validateNetwork verifies the Network exists and make sure req.Network field is an ID
func (instance *Subnet) validateNetwork(ctx context.Context, req *abstract.SubnetRequest) (resources.Network, *abstract.Network, fail.Error) {
	var an *abstract.Network
	networkInstance, xerr := LoadNetwork(ctx, instance.Frame(), req.NetworkID)
	if xerr != nil {
		switch xerr.(type) { // nolint
		case *fail.ErrNotFound:
			withDefaultSubnetwork, err := instance.Service().HasDefaultNetwork()
			if err != nil {
				return nil, nil, err
			}

			if !withDefaultSubnetwork {
				return nil, nil, xerr
			}

			an, xerr = instance.Service().DefaultNetwork(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, nil, xerr
			}
		}
	} else {
		xerr = networkInstance.Inspect(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
			var innerErr error
			an, innerErr = lang.Cast[*abstract.Network](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			// check the network exists on provider side
			_, innerXErr := instance.Service().InspectNetwork(ctx, an.ID)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// TODO: automatic metadata cleanup ?
					return fail.InconsistentError("inconsistent metadata detected for Network '%s': it does not exist anymore on provider side", an.Name)
				default:
					return innerXErr
				}
			}
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, xerr
		}
	}

	req.NetworkID = an.ID
	if len(req.DNSServers) == 0 {
		req.DNSServers = an.DNSServers
	}

	return networkInstance, an, nil
}

// unbindHostFromVIP unbinds a Host from VIP
// Actually does nothing in aws for now
func (instance *Subnet) unbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, host resources.Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	hid, err := host.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	xerr := instance.Service().UnbindHostFromVIP(ctx, vip, hid)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "cleaning up on %s, failed to unbind gateway '%s' from VIP", ActionFromError(xerr), host.GetName())
	}

	return nil
}

// Browse walks through all the metadata objects in Subnet
func (instance *Subnet) Browse(ctx context.Context, callback func(*abstract.Subnet) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: Do not test with Isnull here, as Browse may be used from null value
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "can't be nil")
	}

	return instance.Core.BrowseFolder(ctx, func(buf []byte) fail.Error {
		as, innerXErr := abstract.NewSubnet("unknown")
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = as.Deserialize(buf)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		return callback(as)
	})
}

// AttachHost links Host to the Subnet
func (instance *Subnet) AttachHost(ctx context.Context, host resources.Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	tracer := debug.NewTracer(ctx, true, "("+host.GetName()+")").Entering()
	defer tracer.Exiting()

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	hostName := host.GetName()
	snid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	// To apply the request, the instance must be one of the Subnets of the Host
	xerr := host.InspectProperty(ctx, hostproperty.NetworkV2, func(p clonable.Clonable) fail.Error {
		hnV2, innerErr := lang.Cast[*propertiesv2.HostNetworking](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		found := false
		for k := range hnV2.SubnetsByID {
			if k == snid {
				found = true
				break
			}
		}
		if !found {
			return fail.InvalidRequestError("failed to adopt Host '%s' in Subnet '%s' as Host is not connected to it", hostName, snid)
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		subnetAbstract, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		if subnetAbstract.InternalSecurityGroupID != "" {
			sgInstance, innerXErr := LoadSecurityGroup(ctx, instance.Frame(), subnetAbstract.InternalSecurityGroupID)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = sgInstance.BindToHost(ctx, host, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark)
			if innerXErr != nil {
				return innerXErr
			}
		}

		pubIP, innerXErr := host.GetPublicIP(ctx)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				break
			default:
				return innerXErr
			}
		}

		isGateway, innerXErr := host.IsGateway(ctx)
		if innerXErr != nil {
			return innerXErr
		}

		if !isGateway && pubIP != "" && subnetAbstract.PublicIPSecurityGroupID != "" {
			sgInstance, innerXErr := LoadSecurityGroup(ctx, instance.Frame(), subnetAbstract.PublicIPSecurityGroupID)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = sgInstance.BindToHost(ctx, host, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark)
			if innerXErr != nil {
				return innerXErr
			}
		}

		return props.Alter(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			subnetHostsV1, innerErr := lang.Cast[*propertiesv1.SubnetHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			hostID, err := host.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			subnetHostsV1.ByID[hostID] = hostName
			subnetHostsV1.ByName[hostName] = hostID
			return nil
		})
	})
}

// DetachHost unlinks host ID from Subnet
func (instance *Subnet) DetachHost(ctx context.Context, hostID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet"), "('"+hostID+"')").Entering()
	defer tracer.Exiting()

	return instance.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return instance.unsafeAbandonHost(props, hostID)
	})
}

// ListHosts returns the list of Hosts attached to the Subnet (excluding gateway)
func (instance *Subnet) ListHosts(ctx context.Context) (_ []resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet")).Entering().Exiting()

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	var list []resources.Host
	xerr := instance.ReviewProperty(ctx, subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
		shV1, innerErr := lang.Cast[*propertiesv1.SubnetHosts](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		frame := instance.Frame()
		for id := range shV1.ByID {
			hostInstance, innerErr := LoadHost(ctx, frame, id)
			if innerErr != nil {
				return innerErr
			}
			list = append(list, hostInstance)
		}
		return nil
	})
	return list, xerr
}

// InspectGateway returns the gateway related to Subnet
func (instance *Subnet) InspectGateway(ctx context.Context, primary bool) (_ resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	return instance.unsafeInspectGateway(ctx, primary)
}

// GetGatewayPublicIP returns the Public IP of a particular gateway
func (instance *Subnet) GetGatewayPublicIP(ctx context.Context, primary bool) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	var ip string
	xerr := metadata.Inspect(ctx, instance, func(as *abstract.Subnet, _ *serialize.JSONProperties) fail.Error {
		var (
			id  string
			rgw resources.Host
		)

		if primary {
			id = as.GatewayIDs[0]
		} else {
			if len(as.GatewayIDs) < 2 {
				return fail.InvalidRequestError("there is no secondary gateway in Subnet '%s'", instance.GetName())
			}

			id = as.GatewayIDs[1]
		}
		var inErr fail.Error
		if rgw, inErr = LoadHost(ctx, instance.Frame(), id); inErr != nil {
			return inErr
		}

		if ip, inErr = rgw.GetPublicIP(ctx); inErr != nil {
			return inErr
		}

		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	return ip, nil
}

// GetGatewayPublicIPs returns a slice of public IP of gateways
func (instance *Subnet) GetGatewayPublicIPs(ctx context.Context) (_ []string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []string
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	var gatewayIPs []string
	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		gatewayIPs = make([]string, 0, len(as.GatewayIDs))
		for _, v := range as.GatewayIDs {
			rgw, inErr := LoadHost(ctx, instance.Frame(), v)
			if inErr != nil {
				return inErr
			}

			ip, inErr := rgw.GetPublicIP(ctx)
			if inErr != nil {
				return inErr
			}

			gatewayIPs = append(gatewayIPs, ip)
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return []string{}, xerr
	}

	return gatewayIPs, nil
}

var (
	currentSubnetAbstractContextKey   = "removing_subnet_abstract"
	currentSubnetPropertiesContextKey = "removing_subnet_properties"
)

// Delete deletes a Subnet
func (instance *Subnet) Delete(inctx context.Context) fail.Error {
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
	go func() (ferr fail.Error) { //nolint
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		var force bool
		var ok bool
		if cv := ctx.Value("force"); cv != nil {
			force, ok = cv.(bool)
			if !ok {
				ar := result{fail.InvalidRequestError("force flag must be a bool")}
				chRes <- ar
				return nil
			}
		}

		if force {
			logrus.WithContext(ctx).Tracef("forcing subnet deletion")
		}

		var (
			subnetAbstract *abstract.Subnet
			subnetHosts    *propertiesv1.SubnetHosts
			outprops       *serialize.JSONProperties
		)
		xerr := instance.Review(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			var innerErr error
			subnetAbstract, innerErr = lang.Cast[*abstract.Subnet](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			outprops = props
			return props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
				var innerErr error
				subnetHosts, innerErr = lang.Cast[*propertiesv1.SubnetHosts](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				return nil
			})
		})
		if xerr != nil {
			ar := result{xerr}
			chRes <- ar
			return
		}

		ctx := context.WithValue(ctx, currentSubnetAbstractContextKey, subnetAbstract) // nolint
		ctx = context.WithValue(ctx, currentSubnetPropertiesContextKey, outprops)      // nolint

		tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("operations.Subnet")*/).WithStopwatch().Entering()
		defer tracer.Exiting()

		// Lock Subnet instance
		// instance.lock.Lock()
		// defer instance.lock.Unlock()

		svc := instance.Service()
		subnetName := instance.GetName()
		xerr = instance.Inspect(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			as, innerErr := lang.Cast[*abstract.Subnet](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			// Check if hosts are still attached to Subnet according to metadata
			var errorMsg string
			return props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
				shV1, innerErr := lang.Cast[*propertiesv1.SubnetHosts](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				hostsLen := uint(len(shV1.ByName))
				hostList := make([]string, 0, hostsLen)
				if hostsLen > 0 {
					for k := range shV1.ByName {
						// Check if Host still has metadata and count it if yes
						if hess, innerXErr := LoadHost(ctx, instance.Frame(), k); innerXErr != nil {
							debug.IgnoreError(innerXErr)
						} else {
							if _, innerXErr := hess.ForceGetState(ctx); innerXErr != nil {
								debug.IgnoreError(innerXErr)
							} else {
								hostList = append(hostList, k)
							}
						}
					}
				}
				hostsLen = uint(len(hostList))
				if hostsLen > 0 {
					var verb string
					if hostsLen == 1 {
						verb = "is"
					} else {
						verb = "are"
					}
					errorMsg = fmt.Sprintf("cannot delete Subnet '%s': %d host%s %s still attached to it: %s", as.Name, hostsLen, strprocess.Plural(hostsLen), verb, strings.Join(hostList, ", "))
					return fail.NotAvailableError(errorMsg)
				}
				return nil
			})
		})
		if xerr != nil {
			ar := result{xerr}
			chRes <- ar
			return
		}

		xerr = instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			as, innerErr := lang.Cast[*abstract.Subnet](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			// 1st delete gateway(s)
			gwIDs, innerXErr := instance.deleteGateways(ctx, as)
			if innerXErr != nil {
				return innerXErr
			}

			// FIXME: see if we can adapt relaxedDeleteHost to use context values and prevent duplicated code...
			// Unbind Host from current Subnet (not done by relaxedDeleteHost as Hosts are gateways, to avoid deadlock as Subnet instance may already be locked)
			if len(gwIDs) > 0 {
				for _, v := range gwIDs {
					innerXErr = instance.unsafeAbandonHost(props, v)
					if innerXErr != nil {
						return innerXErr
					}
				}
			}

			// 2nd delete VIP if needed
			if as.VIP != nil {
				if innerXErr := svc.DeleteVIP(ctx, as.VIP); innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to delete VIP for gateways")
				}
			}

			// 3rd delete security groups associated to Subnet by users (do not include SG created with Subnet, they will be deleted later)
			innerXErr = props.Alter(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
				ssgV1, innerErr := lang.Cast[*propertiesv1.SubnetSecurityGroups](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				return instance.onRemovalUnbindSecurityGroups(ctx, subnetHosts, ssgV1)
			})
			if innerXErr != nil {
				return innerXErr
			}

			// 4st free CIDR index if the Subnet has been created for a single Host
			if as.SingleHostCIDRIndex > 0 {
				// networkInstance, innerXErr := instance.unsafeInspectNetwork()
				networkInstance, innerXErr := LoadNetwork(ctx, instance.Frame(), as.Network)
				if innerXErr != nil {
					return innerXErr
				}

				innerXErr = FreeCIDRForSingleHost(ctx, networkInstance, as.SingleHostCIDRIndex)
				if innerXErr != nil {
					return innerXErr
				}
			}

			// finally delete Subnet
			logrus.WithContext(ctx).Debugf("Deleting Subnet '%s'...", as.Name)
			if innerXErr = instance.deleteSubnetThenWaitCompletion(ctx, as.ID); innerXErr != nil {
				return innerXErr
			}

			// Delete Subnet's own Security Groups
			innerXErr = instance.deleteSecurityGroups(ctx, [3]string{as.GWSecurityGroupID, as.InternalSecurityGroupID, as.PublicIPSecurityGroupID})
			return innerXErr
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			ar := result{xerr}
			chRes <- ar
			return
		}

		// Remove metadata
		xerr = instance.Core.Delete(ctx)
		if xerr != nil {
			ar := result{xerr}
			chRes <- ar
			return
		}

		logrus.WithContext(ctx).Infof("Subnet '%s' successfully deleted.", subnetName)
		ar := result{nil}
		chRes <- ar
		return
	}() // nolint
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

// deleteSecurityGroups deletes the Security Groups created for the Subnet
func (instance *Subnet) deleteSecurityGroups(ctx context.Context, sgs [3]string) (ferr fail.Error) {
	for _, v := range sgs {
		if v == "" {
			return fail.NewError("unexpected empty security group")
		}

		sgInstance, xerr := LoadSecurityGroup(ctx, instance.Frame(), v)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Security Group not found, consider this as a success
				debug.IgnoreError(xerr)
				continue
			default:
				return xerr
			}
		}

		sgName := sgInstance.GetName()
		sgID, err := sgInstance.GetID()
		if err != nil {
			return fail.ConvertError(err)
		}
		logrus.WithContext(ctx).Debugf("Deleting Security Group '%s' (%s)...", sgName, sgID)
		xerr = sgInstance.Delete(ctx, true)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Security Group not found, consider this as a success
				debug.IgnoreError(xerr)
				continue
			default:
				return xerr
			}
		}
		logrus.WithContext(ctx).Debugf("Deleted Security Group '%s' (%s)...", sgName, sgID)
	}
	return nil
}

// InspectNetwork returns the Network instance owning the Subnet
func (instance *Subnet) InspectNetwork(ctx context.Context) (rn resources.Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var as *abstract.Subnet
	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		var innerErr error
		as, innerErr = lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return LoadNetwork(ctx, instance.Frame(), as.Network)
}

// deleteGateways deletes all the gateways of the Subnet
// A gateway host that is not found must be considered as a success
func (instance *Subnet) deleteGateways(ctx context.Context, subnet *abstract.Subnet) (ids []string, ferr fail.Error) {
	if subnet.GatewayIDs == nil { // unlikely, either is an input error or we are dealing with metadata corruption
		subnet.GatewayIDs = []string{}
	}

	if len(subnet.GatewayIDs) == 0 { // unlikely, either is an input error or we are dealing with metadata corruption
		gwInstance, xerr := LoadHost(ctx, instance.Frame(), fmt.Sprintf("gw-%s", subnet.Name))
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
			default:
				return subnet.GatewayIDs, xerr
			}
		}

		if gwInstance != nil {
			if gid, err := gwInstance.GetID(); err == nil {
				if gid != "" {
					subnet.GatewayIDs = append(subnet.GatewayIDs, gid)
				}
			}
		}

		gw2Instance, xerr := LoadHost(ctx, instance.Frame(), fmt.Sprintf("gw2-%s", subnet.Name))
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
			default:
				return subnet.GatewayIDs, xerr
			}
		}

		if gw2Instance != nil {
			if g2id, err := gw2Instance.GetID(); err == nil { // valid id
				if g2id != "" {
					subnet.GatewayIDs = append(subnet.GatewayIDs, g2id)
				}
			}
		}
	}

	if len(subnet.GatewayIDs) > 0 {
		for _, v := range subnet.GatewayIDs {
			hostInstance, xerr := LoadHost(ctx, instance.Frame(), v)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// missing gateway is considered as a successful deletion, continue
					logrus.WithContext(ctx).Tracef("host instance not found, gateway deletion considered as a success")
					debug.IgnoreError(xerr)
				default:
					return subnet.GatewayIDs, xerr
				}
			} else {
				name := hostInstance.GetName()
				logrus.WithContext(ctx).Debugf("Deleting gateway '%s'...", name)

				// delete Host
				hostInstanceImpl, err := lang.Cast[*Host](hostInstance)
				if err != nil {
					return subnet.GatewayIDs, fail.Wrap(err)
				}

				xerr := hostInstanceImpl.RelaxedDeleteHost(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// missing gateway is considered as a successful deletion, continue
						logrus.WithContext(ctx).Tracef("host instance not found, relaxed gateway deletion considered as a success")
						debug.IgnoreError(xerr)
					default:
						return subnet.GatewayIDs, xerr
					}
				}

				logrus.WithContext(ctx).Debugf("Gateway '%s' successfully deleted.", name)
			}

			// Remove current entry from gateways to delete
			subnet.GatewayIDs = subnet.GatewayIDs[1:]
		}
	} else {
		logrus.WithContext(ctx).Warnf("no gateways were detected")
	}
	return subnet.GatewayIDs, nil
}

// onRemovalUnbindSecurityGroups makes sure the security groups bound to Subnet are unbound
func (instance *Subnet) onRemovalUnbindSecurityGroups(ctx context.Context, subnetHosts *propertiesv1.SubnetHosts, sgs *propertiesv1.SubnetSecurityGroups) (ferr fail.Error) {
	snid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	unbindParams := taskUnbindFromHostsAttachedToSubnetParams{
		subnetID:    snid,
		subnetName:  instance.GetName(),
		subnetHosts: subnetHosts,
		onRemoval:   true,
	}
	for k := range sgs.ByID {
		sgInstance, xerr := LoadSecurityGroup(ctx, instance.Frame(), k)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// consider a Security Group not found as a successful unbind
				debug.IgnoreError(xerr)
			default:
				return xerr
			}
		} else {
			xerr = sgInstance.unbindFromSubnetHosts(ctx, unbindParams)
			if xerr != nil {
				return xerr
			}

			// VPL: no need to update SubnetSecurityGroups property, the Subnet is being removed
			// delete(sgs.ByID, v)
			// delete(sgs.ByName, k)
		}
	}
	return nil
}

// GetDefaultRouteIP returns the IP of the LAN default route
func (instance *Subnet) GetDefaultRouteIP(ctx context.Context) (ip string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeGetDefaultRouteIP(ctx)
}

// GetEndpointIP returns the internet (public) IP to reach the Subnet
func (instance *Subnet) GetEndpointIP(ctx context.Context) (ip string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ip = ""
	if valid.IsNil(instance) {
		return ip, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		if as.VIP != nil && as.VIP.PublicIP != "" {
			ip = as.VIP.PublicIP
		} else {
			objpgw, innerXErr := LoadHost(ctx, instance.Frame(), as.GatewayIDs[0])
			if innerXErr != nil {
				return innerXErr
			}

			ip, innerXErr = objpgw.(*Host).GetPublicIP(ctx)
			return innerXErr
		}
		return nil
	})
	return ip, xerr
}

// HasVirtualIP tells if the Subnet uses a VIP a default route
func (instance *Subnet) HasVirtualIP(ctx context.Context) (bool, fail.Error) {
	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeHasVirtualIP(ctx)
}

// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (instance *Subnet) GetVirtualIP(ctx context.Context) (vip *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeGetVirtualIP(ctx)
}

// GetCIDR returns the CIDR of the Subnet
func (instance *Subnet) GetCIDR(ctx context.Context) (cidr string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeGetCIDR(ctx)
}

// GetState returns the current state of the Subnet
func (instance *Subnet) GetState(ctx context.Context) (state subnetstate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return subnetstate.Unknown, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return instance.unsafeGetState(ctx)
}

// ToProtocol converts resources.Network to protocol.Network
func (instance *Subnet) ToProtocol(ctx context.Context) (_ *protocol.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var (
		gw  resources.Host
		vip *abstract.VirtualIP
	)

	// Get primary gateway ID
	var xerr fail.Error
	gw, xerr = instance.unsafeInspectGateway(ctx, true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	primaryGatewayID, err := gw.GetID()
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	// Get secondary gateway id if such a gateway exists
	gwIDs := []string{primaryGatewayID}

	gw, xerr = instance.unsafeInspectGateway(ctx, false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return nil, xerr
		}
	} else {
		sgid, err := gw.GetID()
		if err != nil {
			return nil, fail.ConvertError(err)
		}

		gwIDs = append(gwIDs, sgid)
	}

	snid, err := instance.GetID()
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	pn := &protocol.Subnet{
		Id:         snid,
		Name:       instance.GetName(),
		Cidr:       func() string { out, _ := instance.unsafeGetCIDR(ctx); return out }(),
		GatewayIds: gwIDs,
		Failover:   func() bool { out, _ := instance.unsafeHasVirtualIP(ctx); return out }(),
		State:      protocol.SubnetState(func() int32 { out, _ := instance.unsafeGetState(ctx); return int32(out) }()),
	}

	vip, xerr = instance.unsafeGetVirtualIP(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return nil, xerr
		}
	}
	if vip != nil {
		pn.VirtualIp = converters.VirtualIPFromAbstractToProtocol(*vip)
	}

	return pn, nil
}

// BindSecurityGroup binds a security group to the Subnet; if enabled is true, apply it immediately
func (instance *Subnet) BindSecurityGroup(ctx context.Context, sgInstance resources.SecurityGroup, enabled resources.SecurityGroupActivation) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgInstance == nil {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	snid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet"), "(%s)", snid).Entering()
	defer tracer.Exiting()

	return instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		abstractSubnet, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		var subnetHosts *propertiesv1.SubnetHosts
		innerXErr := props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			subnetHosts, innerErr = lang.Cast[*propertiesv1.SubnetHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
			nsgV1, innerErr := lang.Cast[*propertiesv1.SubnetSecurityGroups](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			sgID, err := sgInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			// First check if the security group is not already registered for the host with the exact same state
			for k, v := range nsgV1.ByID {
				if k == sgID && v.Disabled == bool(!enabled) {
					return fail.DuplicateError("security group '%s' already bound to Subnet", sgInstance.GetName())
				}
			}

			// Bind the security group to the Subnet (does the security group side of things)
			sgInstanceImpl, innerErr := lang.Cast[*SecurityGroup](sgInstance)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			innerXErr := sgInstanceImpl.unsafeBindToSubnet(ctx, abstractSubnet, subnetHosts, enabled, resources.MarkSecurityGroupAsSupplemental)
			if innerXErr != nil {
				return innerXErr
			}

			// Updates Subnet metadata
			if _, ok := nsgV1.ByID[sgID]; !ok {
				nsgV1.ByID[sgID] = &propertiesv1.SecurityGroupBond{
					ID:       sgID,
					Name:     sgInstance.GetName(),
					Disabled: bool(!enabled),
				}
			} else {
				nsgV1.ByID[sgID].Disabled = bool(!enabled)
			}
			return nil
		})
	})
}

// UnbindSecurityGroup unbinds a security group from the host
func (instance *Subnet) UnbindSecurityGroup(ctx context.Context, sgInstance resources.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgInstance == nil {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	return instance.unsafeUnbindSecurityGroup(ctx, sgInstance)
}

// ListSecurityGroups returns a slice of security groups bound to Subnet
func (instance *Subnet) ListSecurityGroups(ctx context.Context, state securitygroupstate.Enum) (list []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptyList []*propertiesv1.SecurityGroupBond
	if valid.IsNil(instance) {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet"), "(%s)", state.String()).Entering()
	defer tracer.Exiting()

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	return list, instance.InspectProperty(ctx, subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
		ssgV1, innerErr := lang.Cast[*propertiesv1.SubnetSecurityGroups](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		list = FilterBondsByKind(ssgV1.ByID, state)
		return nil
	})
}

// EnableSecurityGroup enables a binded security group to Subnet
func (instance *Subnet) EnableSecurityGroup(ctx context.Context, sgInstance resources.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgInstance == nil {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	snid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	svc := instance.Service()
	return instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		abstractSubnet, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		var subnetHosts *propertiesv1.SubnetHosts
		innerXErr := props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			subnetHosts, innerErr = lang.Cast[*propertiesv1.SubnetHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
			nsgV1, innerErr := lang.Cast[*propertiesv1.SubnetSecurityGroups](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			var asg *abstract.SecurityGroup
			innerXErr := sgInstance.Inspect(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
				var innerErr error
				asg, innerErr = lang.Cast[*abstract.SecurityGroup](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// First check if the security group is not already registered for the host with the exact same state
			var found bool
			for k := range nsgV1.ByID {
				if k == asg.ID {
					found = true
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not binded to Subnet '%s'", sgInstance.GetName(), snid)
			}

			// Do security group stuff to enable it
			caps := svc.Capabilities()
			if caps.CanDisableSecurityGroup {
				if innerXErr = svc.EnableSecurityGroup(ctx, asg); innerXErr != nil {
					return innerXErr
				}
			} else {
				sgInstanceImpl, err := lang.Cast[*SecurityGroup](sgInstance)
				if err != nil {
					return fail.Wrap(err)
				}

				innerXErr = sgInstanceImpl.unsafeBindToSubnet(ctx, abstractSubnet, subnetHosts, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrDuplicate:
						// security group already bound to Subnet with the same state, considered as a success
						debug.IgnoreError(innerXErr)
					default:
						return innerXErr
					}
				}
			}

			// update metadata
			nsgV1.ByID[asg.ID].Disabled = false
			return nil
		})
	})
}

// DisableSecurityGroup disables an already binded security group on Subnet
func (instance *Subnet) DisableSecurityGroup(ctx context.Context, sgInstance resources.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgInstance == nil {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	snid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	svc := instance.Service()
	return instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		abstractSubnet, innerErr := lang.Cast[*abstract.Subnet](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		var subnetHosts *propertiesv1.SubnetHosts
		innerXErr := props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			subnetHosts, innerErr = lang.Cast[*propertiesv1.SubnetHosts](p)
			return fail.Wrap(innerErr)
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
			nsgV1, innerErr := lang.Cast[*propertiesv1.SubnetSecurityGroups](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			var abstractSG *abstract.SecurityGroup
			innerXErr := sgInstance.Inspect(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
				var innerErr error
				abstractSG, innerErr = lang.Cast[*abstract.SecurityGroup](p)
				return fail.Wrap(innerErr)
			})
			if innerXErr != nil {
				return innerXErr
			}

			// First check if the security group is not already registered for the host with the exact same state
			if _, ok := nsgV1.ByID[abstractSG.ID]; !ok {
				return fail.NotFoundError("security group '%s' is not bound to Subnet '%s'", sgInstance.GetName(), snid)
			}

			caps := svc.Capabilities()
			if caps.CanDisableSecurityGroup {
				if innerXErr = svc.DisableSecurityGroup(ctx, abstractSG); innerXErr != nil {
					return innerXErr
				}
			} else {
				// Do security group stuff to disable it
				sgInstanceImpl, err := lang.Cast[*SecurityGroup](sgInstance)
				if err != nil {
					return fail.Wrap(err)
				}

				innerXErr = sgInstanceImpl.unsafeBindToSubnet(ctx, abstractSubnet, subnetHosts, resources.SecurityGroupDisable, resources.KeepCurrentSecurityGroupMark)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						// security group not bound to Subnet, considered as a success
						debug.IgnoreError(innerXErr)
					default:
						return innerXErr
					}
				}
			}

			// update metadata
			nsgV1.ByID[abstractSG.ID].Disabled = true
			return nil
		})
	})
}

// InspectGatewaySecurityGroup returns the instance of SecurityGroup in Subnet related to external access on gateways
func (instance *Subnet) InspectGatewaySecurityGroup(ctx context.Context) (_ resources.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var abstractSubnet *abstract.Subnet
	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		var innerErr error
		abstractSubnet, innerErr = lang.Cast[*abstract.Subnet](p)
		return fail.Wrap(innerErr)
	})
	if xerr != nil {
		return nil, xerr
	}

	return LoadSecurityGroup(ctx, instance.Frame(), abstractSubnet.GWSecurityGroupID)
}

// InspectInternalSecurityGroup returns the instance of SecurityGroup for internal security inside the Subnet
func (instance *Subnet) InspectInternalSecurityGroup(ctx context.Context) (_ resources.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var abstractSubnet *abstract.Subnet
	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		var innerErr error
		abstractSubnet, innerErr = lang.Cast[*abstract.Subnet](p)
		return fail.Wrap(innerErr)
	})
	if xerr != nil {
		return nil, xerr
	}

	return LoadSecurityGroup(ctx, instance.Frame(), abstractSubnet.InternalSecurityGroupID)
}

// InspectPublicIPSecurityGroup returns the instance of SecurityGroup in Subnet for Hosts with Public IP (which does not apply on gateways)
func (instance *Subnet) InspectPublicIPSecurityGroup(ctx context.Context) (_ resources.SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var abstractSubnet *abstract.Subnet
	xerr := instance.Review(ctx, func(p clonable.Clonable, _ *serialize.JSONProperties) fail.Error {
		var innerErr error
		abstractSubnet, innerErr = lang.Cast[*abstract.Subnet](p)
		return fail.Wrap(innerErr)
	})
	if xerr != nil {
		return nil, xerr
	}

	return LoadSecurityGroup(ctx, instance.Frame(), abstractSubnet.PublicIPSecurityGroupID)
}

// CreateSubnetWithoutGateway creates a Subnet named like 'singleHostName', without gateway
func (instance *Subnet) CreateSubnetWithoutGateway(ctx context.Context, req abstract.SubnetRequest) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: do not use .isNull() here
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet"),
		"('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.ImageRef, req.HA).WithStopwatch().Entering()
	defer tracer.Exiting()

	xerr := instance.unsafeCreateSubnet(ctx, req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// --- Updates Subnet state in metadata ---
	xerr = instance.unsafeFinalizeSubnetCreation(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}
