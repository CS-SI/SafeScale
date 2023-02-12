/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package resources

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/consts"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	subnetKind = "subnet"
	// networksFolderName is the technical name of the container used to store networks info
	subnetsFolderName = "subnets"

	subnetInternalSecurityGroupNamePattern        = "safescale-sg_subnet_internals_%s_%s"
	subnetInternalSecurityGroupDescriptionPattern = "SG for internal access in Subnet %s of Network %s"
	subnetGWSecurityGroupNamePattern              = "safescale-sg_subnet_gateways_%s_%s"
	subnetGWSecurityGroupDescriptionPattern       = "SG for gateways in Subnet %s of Network %s"
	subnetPublicIPSecurityGroupNamePattern        = "safescale-sg_subnet_publicip_%s_%s"
	subnetPublicIPSecurityGroupDescriptionPattern = "SG for hosts with public IP in Subnet %s of Network %s"

	virtualIPNamePattern = "safescale-vip_gateways_subnet_%s_%s"
)

// Subnet links Object Storage MetadataFolder and Subnet
type Subnet struct {
	*metadata.Core[*abstract.Subnet]

	localCache struct {
		sync.RWMutex
		gateways [2]*Host
		// parentNetwork *Network
	}
}

// ListSubnets returns a list of available subnets
func ListSubnets(ctx context.Context, networkID string, all bool) (_ []*abstract.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if all {
		return myjob.Service().ListSubnets(ctx, networkID)
	}

	subnetInstance, xerr := NewSubnet(ctx)
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

// NewSubnet creates an instance of Subnet used as *Subnet
func NewSubnet(ctx context.Context) (_ *Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, subnetKind, subnetsFolderName, abstract.NewEmptySubnet())
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
func LoadSubnet(inctx context.Context, networkRef, subnetRef string) (*Subnet, fail.Error) {
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if subnetRef = strings.TrimSpace(subnetRef); subnetRef == "" {
		return nil, fail.InvalidParameterError("subnetRef", "cannot be empty string")
	}

	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return nil, xerr
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
			refcache := fmt.Sprintf("%T/%s", kt, subnetRef)

			cache, xerr := myjob.Service().Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			var (
				subnetInstance  *Subnet
				inCache         bool
				err             error
				subnetID        string
				networkInstance *Network
			)

			if cache != nil {
				entry, err := cache.Get(ctx, refcache)
				if err == nil {
					subnetInstance, err = lang.Cast[*Subnet](entry)
					if err != nil {
						return nil, fail.Wrap(err)
					}

					inCache = true

					// -- reload from metadata storage
					xerr := subnetInstance.Core.Reload(ctx)
					if xerr != nil {
						return nil, xerr
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			if subnetInstance == nil {
				// -- First step: identify subnetID from (networkRef, subnetRef) --
				networkRef = strings.TrimSpace(networkRef)
				switch networkRef {
				case "":
					// If networkRef is empty, subnetRef must be subnetID
					subnetID = subnetRef
				default:
					// Try to load Network resource
					networkInstance, xerr = LoadNetwork(ctx, networkRef)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							debug.IgnoreErrorWithContext(ctx, xerr)
							// Network metadata can be missing if it's the default Network, so continue
						default:
							return nil, xerr
						}
					}

					withDefaultSubnetwork, err := myjob.Service().HasDefaultNetwork()
					if err != nil {
						return nil, err
					}

					if networkInstance != nil { // nolint
						networkTrx, xerr := newNetworkTransaction(ctx, networkInstance)
						if xerr != nil {
							return nil, xerr
						}
						defer networkTrx.TerminateFromError(ctx, &ferr)

						// Network metadata loaded, find the ID of the Subnet (subnetRef may be ID or Name)
						xerr = inspectNetworkMetadataProperty(ctx, networkTrx, networkproperty.SubnetsV1, func(subnetsV1 *propertiesv1.NetworkSubnets) fail.Error {
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
						an, xerr := myjob.Service().DefaultNetwork(ctx)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							return nil, xerr
						}

						if an.Name == networkRef || an.ID == networkRef {
							// We are in default Network context, query Subnet list and search for the one requested
							list, xerr := ListSubnets(ctx, an.ID, false)
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

				anon, xerr := onSubnetCacheMiss(ctx, subnetID)
				if xerr != nil {
					return nil, xerr
				}

				subnetInstance, err = lang.Cast[*Subnet](anon)
				if err != nil {
					return nil, fail.Wrap(err)
				}
			}

			if cache != nil && !inCache {
				err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, subnetInstance.GetName()), subnetInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				hid, err := subnetInstance.GetID()
				if err != nil {
					return nil, fail.Wrap(err)
				}

				err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), subnetInstance, &store.Options{Expiration: 1 * time.Minute})
				if err != nil {
					return nil, fail.Wrap(err)
				}

				time.Sleep(10 * time.Millisecond) // consolidate cache.Set
				val, xerr := cache.Get(ctx, refcache)
				if xerr == nil {
					if _, ok := val.(*Subnet); !ok {
						logrus.WithContext(ctx).Warnf("wrong type of *Subnet")
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}

			if myjob.Service().Capabilities().UseTerraformer {
				subnetTrx, xerr := newSubnetTransaction(ctx, subnetInstance)
				if xerr != nil {
					return nil, xerr
				}
				defer subnetTrx.TerminateFromError(ctx, &ferr)

				xerr = inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
					prov, innerXErr := myjob.Service().ProviderDriver()
					if innerXErr != nil {
						return innerXErr
					}

					castedProv, innerErr := lang.Cast[providers.ReservedForTerraformerUse](prov)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					innerXErr = castedProv.ConsolidateSubnetSnippet(as)
					if innerXErr != nil {
						return innerXErr
					}

					_, innerXErr = myjob.Scope().RegisterAbstractIfNeeded(as)
					return innerXErr
				})
				if xerr != nil {
					return nil, xerr
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
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// onSubnetCacheMiss is called when there is no instance in cache of Subnet 'subnetID'
func onSubnetCacheMiss(ctx context.Context, subnetID string) (_ data.Identifiable, ferr fail.Error) {
	subnetInstance, innerXErr := NewSubnet(ctx)
	if innerXErr != nil {
		return nil, innerXErr
	}

	innerXErr = subnetInstance.Read(ctx, subnetID)
	if innerXErr != nil {
		return nil, innerXErr
	}

	trx, xerr := newSubnetTransaction(ctx, subnetInstance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = subnetInstance.updateCachedInformation(ctx, trx)
	if xerr != nil {
		return nil, xerr
	}

	return subnetInstance, nil
}

// updateCachedInformation updates the information cached in instance because will be frequently used and will not be changed over time
func (instance *Subnet) updateCachedInformation(ctx context.Context, trx subnetTransaction) fail.Error {
	instance.localCache.Lock()
	defer instance.localCache.Unlock()

	var primaryGatewayID, secondaryGatewayID string
	xerr := inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
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
		hostInstance, xerr := LoadHost(ctx, primaryGatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreErrorWithContext(ctx, xerr)
				// Network metadata can be missing if it's the default Network, so continue
			default:
				return xerr
			}
		} else {
			instance.localCache.gateways[0] = hostInstance
		}
	}

	if secondaryGatewayID != "" {
		hostInstance, xerr := LoadHost(ctx, secondaryGatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreErrorWithContext(ctx, xerr)
				// Network metadata can be missing if it's the default Network, so continue
			default:
				return xerr
			}
		} else {
			var ok bool
			instance.localCache.gateways[1] = hostInstance
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

func (instance *Subnet) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newInstance, err := newBulkSubnet()
	if err != nil {
		return nil, err
	}

	return newInstance, newInstance.Replace(instance)
}

// newBulkSubnet ...
func newBulkSubnet() (*Subnet, fail.Error) {
	protected, err := abstract.NewSubnet()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	core, err := metadata.NewEmptyCore(abstract.SubnetKind, protected)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	instance := &Subnet{Core: core}
	return instance, nil
}

func (instance *Subnet) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Subnet](in)
	if err != nil {
		return err
	}

	err = instance.Core.Replace(src.Core)
	if err != nil {
		return err
	}

	for i := 0; i < 2; i++ {
		instance.localCache.gateways[i] = src.localCache.gateways[i]
	}

	return nil
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Subnet) Exists(ctx context.Context) (bool, fail.Error) {
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.Wrap(err)
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

// Create creates a Subnet
func (instance *Subnet) Create(ctx context.Context, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements, extra interface{}) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.Core) && instance.Core.IsTaken() {
		return fail.InconsistentError("already carrying information")
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet"), "('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.ImageRef, req.HA).WithStopwatch().Entering()
	defer tracer.Exiting()

	subnetTrx, xerr := instance.buildSubnet(ctx, req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	snid, err := instance.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	// Starting from here, Delete Subnet if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && req.CleanOnFailure() {
			derr := subnetTrx.deleteSubnetThenWaitCompletion(cleanupContextFrom(ctx))
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Subnet", ActionFromError(ferr)))
				return
			}
			subnetTrx.SilentTerminate(ctx)
			derr = instance.Core.Delete(ctx)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Subnet", ActionFromError(ferr)))
				return
			}

			logrus.WithContext(ctx).Infof("the subnet '%s' should be gone by now", snid)
		}
	}()

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := instance.updateSubnetStatus(cleanupContextFrom(ctx), subnetTrx, subnetstate.Error)
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	// --- Create the gateway(s) ---
	if req.DefaultSSHPort <= 0 {
		req.DefaultSSHPort = 22
	}
	xerr = instance.createGateways(ctx, subnetTrx, req, gwname, gwSizing, nil, extra)
	if xerr != nil {
		gateway := "gateway"
		if req.HA {
			gateway += "s"
		}
		return fail.Wrap(xerr, "failed to create %s", gateway)
	}

	// --- Updates Subnet state in metadata ---
	xerr = instance.finalizeSubnetCreation(ctx, subnetTrx)
	if xerr != nil {
		return fail.Wrap(xerr, "failure in 'unsafe' finalizing subnet creation")
	}

	return nil
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
			return fail.Wrap(err)
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
			return fail.Wrap(xerr)
		}
		if netutils.CIDROverlap(subnet, *sDesc) {
			return fail.OverloadError("would intersect with '%s (%s)'", s.Name, s.CIDR)
		}
	}
	return nil
}

// checkUnicity checks if the Subnet name is not already used
// FIXME: optimization opportunity: use scope resource list to prevent remote read?
func (instance *Subnet) checkUnicity(ctx context.Context, req abstract.SubnetRequest) fail.Error {
	_, xerr := LoadSubnet(ctx, req.NetworkID, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// Check if a subnet with this name already exist globally
			xerr = instance.LookupByName(ctx, req.Name)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					myjob, xerr := jobapi.FromContext(ctx)
					if xerr != nil {
						return xerr
					}

					_, xerr = myjob.Service().InspectSubnetByName(ctx, req.NetworkID, req.Name)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return nil
						default:
							return fail.DuplicateError("found a Subnet named '%s' (not managed by SafeScale)", req.Name)
						}
					}

					return nil
				default:
					return xerr
				}
			}

		default:
			return xerr
		}
	}

	return fail.DuplicateError("found an existing Subnet named '%s'", req.Name)
}

// validateNetwork verifies the Network exists and make sure req.Network field is an ID
// Note: caller has the responsibility to terminate returned networkTransaction
func (instance *Subnet) validateNetwork(ctx context.Context, req *abstract.SubnetRequest) (_ *abstract.Network, _ networkTransaction, ferr fail.Error) {
	var (
		abstractNetwork *abstract.Network
		networkTrx      networkTransaction
	)
	networkInstance, xerr := LoadNetwork(ctx, req.NetworkID)
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

			abstractNetwork, xerr = instance.Service().DefaultNetwork(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, nil, xerr
			}

			networkInstance, xerr = LoadNetwork(ctx, abstractNetwork.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, nil, xerr
			}

		default:
			return nil, nil, xerr
		}
	}

	networkTrx, xerr = newNetworkTransaction(ctx, networkInstance)
	if xerr != nil {
		return nil, nil, xerr
	}

	xerr = inspectNetworkMetadataAbstract(ctx, networkTrx, func(an *abstract.Network) fail.Error {
		abstractNetwork = an

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

	req.NetworkID = abstractNetwork.ID
	if len(req.DNSServers) == 0 {
		req.DNSServers = abstractNetwork.DNSServers
	}

	return abstractNetwork, networkTrx, nil
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
		as, _ := abstract.NewSubnet()
		innerXErr := as.Deserialize(buf)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		return callback(as)
	})
}

// AttachHost links Host to the Subnet
func (instance *Subnet) AttachHost(ctx context.Context, host *Host) (ferr fail.Error) {
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

	hostName := host.GetName()
	snid, err := instance.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	isGateway, xerr := host.IsGateway(ctx)
	if xerr != nil {
		return xerr
	}

	hostTrx, xerr := newHostTransaction(ctx, host)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.SilentTerminate(ctx) // host is only reviewed, no way to fail

	// To apply the request, the instance must be one of the Subnets of the Host
	xerr = inspectHostMetadataProperty(ctx, hostTrx, hostproperty.NetworkV2, func(hnV2 *propertiesv2.HostNetworking) fail.Error {
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

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	subnetTrx.TerminateFromError(ctx, &ferr)

	return alterSubnetMetadata(ctx, subnetTrx, func(abstractSubnet *abstract.Subnet, props *serialize.JSONProperties) fail.Error {
		if abstractSubnet.InternalSecurityGroupID != "" {
			sgInstance, innerXErr := LoadSecurityGroup(ctx, abstractSubnet.InternalSecurityGroupID)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = sgInstance.BindToHost(ctx, host, SecurityGroupEnable, KeepCurrentSecurityGroupMark)
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

		if !isGateway && pubIP != "" && abstractSubnet.PublicIPSecurityGroupID != "" {
			sgInstance, innerXErr := LoadSecurityGroup(ctx, abstractSubnet.PublicIPSecurityGroupID)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = sgInstance.BindToHost(ctx, host, SecurityGroupEnable, KeepCurrentSecurityGroupMark)
			if innerXErr != nil {
				return innerXErr
			}
		}

		return props.Alter(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			subnetHostsV1, innerErr := clonable.Cast[*propertiesv1.SubnetHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			hostID, err := host.GetID()
			if err != nil {
				return fail.Wrap(err)
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

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	return subnetTrx.AbandonHost(ctx, hostID)
}

// ListHosts returns the list of Hosts attached to the Subnet (excluding gateway)
func (instance *Subnet) ListHosts(ctx context.Context) (_ []*Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet")).Entering().Exiting()

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var list []*Host
	xerr = inspectSubnetMetadataProperty(ctx, trx, subnetproperty.HostsV1, func(shV1 *propertiesv1.SubnetHosts) fail.Error {
		for id := range shV1.ByID {
			hostInstance, innerXErr := LoadHost(ctx, id)
			if innerXErr != nil {
				return innerXErr
			}

			list = append(list, hostInstance)
		}
		return nil
	})
	return list, xerr
}

// InspectGateway returns the gateway related to Subnet
func (instance *Subnet) InspectGateway(ctx context.Context, primary bool) (_ *Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return instance.inspectGateway(ctx, trx, primary)
}

// GetGatewayPublicIP returns the Public IP of a particular gateway
func (instance *Subnet) GetGatewayPublicIP(ctx context.Context, primary bool) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var ip string
	xerr = inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		var (
			id  string
			rgw *Host
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
		rgw, inErr = LoadHost(ctx, id)
		if inErr != nil {
			return inErr
		}

		ip, inErr = rgw.GetPublicIP(ctx)
		if inErr != nil {
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

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return emptySlice, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var gatewayIPs []string
	xerr = inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		gatewayIPs = make([]string, 0, len(as.GatewayIDs))
		for _, v := range as.GatewayIDs {
			rgw, inErr := LoadHost(ctx, v)
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
	currentSubnetTransactionContextKey = "current_subnet_transaction"
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet")).WithStopwatch().Entering()
	defer tracer.Exiting()

	chRes := make(chan fail.Error)
	go func() {
		defer close(chRes)

		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			subnetName := instance.GetName()
			defer func() {
				if ferr == nil {
					ferr = instance.Core.Delete(ctx)
					if ferr == nil {
						logrus.WithContext(ctx).Infof("Subnet '%s' successfully deleted.", subnetName)
					}

				}
			}()

			var force bool
			var ok bool
			if cv := ctx.Value("force"); cv != nil {
				force, ok = cv.(bool)
				if !ok {
					return fail.InvalidRequestError("force flag must be a bool")
				}
			}

			if force {
				logrus.WithContext(ctx).Tracef("forcing subnet deletion")
			}

			subnetTrx, xerr := newSubnetTransaction(ctx, instance)
			if xerr != nil {
				return xerr
			}
			defer subnetTrx.TerminateFromError(ctx, &ferr)

			ctx := context.WithValue(ctx, currentSubnetTransactionContextKey, subnetTrx) // nolint
			svc := instance.Service()
			xerr = inspectSubnetMetadata(ctx, subnetTrx, func(as *abstract.Subnet, props *serialize.JSONProperties) fail.Error {
				// Check if hosts are still attached to Subnet according to metadata
				var errorMsg string
				return props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
					shV1, innerErr := clonable.Cast[*propertiesv1.SubnetHosts](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					hostsLen := uint(len(shV1.ByName))
					hostList := make([]string, 0, hostsLen)
					if hostsLen > 0 {
						for k := range shV1.ByName {
							// Check if Host still has metadata and count it if yes
							if hess, innerXErr := LoadHost(ctx, k); innerXErr != nil {
								debug.IgnoreErrorWithContext(ctx, innerXErr)
							} else {
								if _, innerXErr := hess.ForceGetState(ctx); innerXErr != nil {
									debug.IgnoreErrorWithContext(ctx, innerXErr)
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
						errorMsg = fmt.Sprintf("cannot Delete Subnet '%s': %d host%s %s still attached to it: %s", as.Name, hostsLen, strprocess.Plural(hostsLen), verb, strings.Join(hostList, ", "))
						return fail.NotAvailableError(errorMsg)
					}
					return nil
				})
			})
			if xerr != nil {
				return xerr
			}

			// Delete gateway(s)
			gwIDs, innerXErr := trxDeleteGateways(ctx, subnetTrx)
			if innerXErr != nil {
				return innerXErr
			}

			// Unbind Host from current Subnet (not done by relaxedDeleteHost as Hosts are gateways, to avoid deadlock as Subnet instance may already be locked)
			if len(gwIDs) > 0 {
				for _, v := range gwIDs {
					innerXErr = subnetTrx.AbandonHost(ctx, v)
					if innerXErr != nil {
						return innerXErr
					}
				}
			}

			var (
				abstractSubnet *abstract.Subnet
				subnetSGS      *propertiesv1.SubnetSecurityGroups
			)
			xerr = inspectSubnetMetadata(ctx, subnetTrx, func(as *abstract.Subnet, props *serialize.JSONProperties) (finnerXErr fail.Error) {
				abstractSubnet = as
				// Delete VIP if needed
				if as.VIP != nil {
					innerXErr := svc.DeleteVIP(ctx, as.VIP)
					if innerXErr != nil {
						return fail.Wrap(innerXErr, "failed to Delete VIP for gateways")
					}
				}

				// Delete security groups associated to Subnet by users (do not include SG created with Subnet, they will be deleted later)
				innerXErr = props.Inspect(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
					ssgV1, innerErr := clonable.Cast[*propertiesv1.SubnetSecurityGroups](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					subnetSGS = ssgV1
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				return subnetTrx.UnbindSecurityGroups(ctx, subnetSGS)
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			// free CIDR index if the Subnet has been created for a single Host
			if abstractSubnet.SingleHostCIDRIndex > 0 {
				// networkInstance, innerXErr := instance.unsafeInspectNetwork()
				networkInstance, xerr := LoadNetwork(ctx, abstractSubnet.Network)
				if xerr != nil {
					return xerr
				}

				networkTrx, xerr := newNetworkTransaction(ctx, networkInstance)
				if xerr != nil {
					return xerr
				}
				defer networkTrx.TerminateFromError(ctx, &ferr)

				xerr = networkTrx.FreeCIDRForSingleHost(ctx, abstractSubnet.SingleHostCIDRIndex)
				if xerr != nil {
					return xerr
				}
			}

			// Delete Subnet's own Security Groups
			xerr = instance.deleteSecurityGroups(ctx, [3]string{abstractSubnet.GWSecurityGroupID, abstractSubnet.InternalSecurityGroupID, abstractSubnet.PublicIPSecurityGroupID})
			if xerr != nil {
				return xerr
			}

			// finally Delete Subnet
			logrus.WithContext(ctx).Debugf("Deleting Subnet '%s'...", abstractSubnet.Name)
			xerr = subnetTrx.deleteSubnetThenWaitCompletion(ctx)
			if xerr != nil {
				return xerr
			}

			return nil
		}()
		chRes <- gerr
	}() // nolint

	select {
	case xerr := <-chRes:
		return xerr
	case <-ctx.Done():
		<-chRes
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return fail.Wrap(inctx.Err())
	}
}

// deleteSecurityGroups deletes the Security Groups created for the Subnet
func (instance *Subnet) deleteSecurityGroups(ctx context.Context, sgs [3]string) (ferr fail.Error) {
	for _, v := range sgs {
		if v == "" {
			logrus.Warningf("unexpected empty security group")
			continue
		}

		sgInstance, xerr := LoadSecurityGroup(ctx, v)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Security Group not found, consider this as a success
				debug.IgnoreErrorWithContext(ctx, xerr)
				continue
			default:
				return xerr
			}
		}

		sgName := sgInstance.GetName()
		sgID, err := sgInstance.GetID()
		if err != nil {
			return fail.Wrap(err)
		}
		logrus.WithContext(ctx).Debugf("Deleting Security Group '%s' (%s)...", sgName, sgID)
		xerr = sgInstance.Delete(ctx, true)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Security Group not found, consider this as a success
				debug.IgnoreErrorWithContext(ctx, xerr)
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
func (instance *Subnet) InspectNetwork(ctx context.Context) (_ *Network, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var network string
	xerr = inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		network = as.Network
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return LoadNetwork(ctx, network)
}

// deleteGateways deletes all the gateways of the Subnet
// A gateway host that is not found must be considered as a success
func trxDeleteGateways(ctx context.Context, trx subnetTransaction) (ids []string, ferr fail.Error) {
	var empty []string
	return ids, inspectSubnetMetadataAbstract(ctx, trx, func(subnet *abstract.Subnet) fail.Error {
		if subnet.GatewayIDs == nil { // unlikely, either is an input error or we are dealing with metadata corruption
			subnet.GatewayIDs = empty
		}

		if len(subnet.GatewayIDs) == 0 { // unlikely, either is an input error or we are dealing with metadata corruption
			gwInstance, xerr := LoadHost(ctx, fmt.Sprintf("gw-%s", subnet.Name))
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					ids = subnet.GatewayIDs
					return xerr
				}
			}

			if gwInstance != nil {
				if gid, err := gwInstance.GetID(); err == nil {
					if gid != "" {
						subnet.GatewayIDs = append(subnet.GatewayIDs, gid)
					}
				}
			}

			gw2Instance, xerr := LoadHost(ctx, fmt.Sprintf("gw2-%s", subnet.Name))
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError(xerr)
				default:
					ids = subnet.GatewayIDs
					return xerr
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
			deleteHostFn := func(v string) (ferr fail.Error) {
				var (
					hostInstance *Host
					innerXErr    fail.Error
				)

				defer func() {
					if ferr == nil && hostInstance != nil {
						ferr = hostInstance.Core.Delete(ctx)
					}
				}()

				hostInstance, innerXErr = LoadHost(ctx, v)
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						// missing gateway is considered as a successful deletion, continue
						logrus.WithContext(ctx).Tracef("host instance not found, gateway deletion considered as a success")

					default:
						ids = subnet.GatewayIDs
						return innerXErr
					}
				} else {
					name := hostInstance.GetName()
					logrus.WithContext(ctx).Debugf("Deleting gateway '%s'...", name)

					hostSSHConfig, innerXErr := hostInstance.GetSSHConfig(ctx)
					if innerXErr != nil {
						return innerXErr
					}

					hostSSH, innerXErr := ssh.NewConnector(hostSSHConfig)
					if innerXErr != nil {
						return innerXErr
					}

					// Delete Host
					hostTrx, innerXErr := newHostTransaction(ctx, hostInstance)
					if innerXErr != nil {
						return innerXErr
					}
					defer func(trx hostTransaction) { trx.TerminateFromError(ctx, &ferr) }(hostTrx)

					innerXErr = hostTrx.RelaxedDeleteHost(ctx, hostSSH)
					innerXErr = debug.InjectPlannedFail(innerXErr)
					if innerXErr != nil {
						switch innerXErr.(type) {
						case *fail.ErrNotFound:
							// missing gateway is considered as a successful deletion, continue
							logrus.WithContext(ctx).Tracef("host instance not found, relaxed gateway deletion considered as a success")
							debug.IgnoreErrorWithContext(ctx, innerXErr)
						default:
							ids = subnet.GatewayIDs
							return innerXErr
						}
					}

					logrus.WithContext(ctx).Debugf("Gateway '%s' successfully deleted.", name)
				}

				// Remove current entry from gateways to Delete
				subnet.GatewayIDs = subnet.GatewayIDs[1:]
				return nil
			}

			for _, v := range subnet.GatewayIDs {
				xerr := deleteHostFn(v)
				if xerr != nil {
					return xerr
				}
			}
		} else {
			logrus.WithContext(ctx).Warnf("no gateways were detected")
		}

		return nil
	})
}

// GetDefaultRouteIP returns the IP of the LAN default route
func (instance *Subnet) GetDefaultRouteIP(ctx context.Context) (ip string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	return subnetTrx.GetDefaultRouteIP(ctx)
}

// GetEndpointIP returns the internet (public) IP to reach the Subnet
func (instance *Subnet) GetEndpointIP(ctx context.Context) (ip string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ip = ""
	if valid.IsNil(instance) {
		return ip, fail.InvalidInstanceError()
	}

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		if as.VIP != nil && as.VIP.PublicIP != "" {
			ip = as.VIP.PublicIP
		} else {
			objpgw, innerXErr := LoadHost(ctx, as.GatewayIDs[0])
			if innerXErr != nil {
				return innerXErr
			}

			ip, innerXErr = objpgw.GetPublicIP(ctx)
			return innerXErr
		}
		return nil
	})
	return ip, xerr
}

// HasVirtualIP tells if the Subnet uses a VIP a default route
func (instance *Subnet) HasVirtualIP(ctx context.Context) (_ bool, ferr fail.Error) {
	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	return subnetTrx.HasVirtualIP(ctx)
}

// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (instance *Subnet) GetVirtualIP(ctx context.Context) (vip *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	return subnetTrx.GetVirtualIP(ctx)
}

// GetCIDR returns the CIDR of the Subnet
func (instance *Subnet) GetCIDR(ctx context.Context) (cidr string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	return subnetTrx.GetCIDR(ctx)
}

// GetState returns the current state of the Subnet
func (instance *Subnet) GetState(ctx context.Context) (state subnetstate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return subnetstate.Unknown, fail.InvalidInstanceError()
	}

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return subnetstate.Unknown, xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	return subnetTrx.GetState(ctx)
}

// ToProtocol converts resources.Network to protocol.Network
func (instance *Subnet) ToProtocol(ctx context.Context) (_ *protocol.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var (
		gw  *Host
		vip *abstract.VirtualIP
	)

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	// Get primary gateway
	gw, xerr = instance.inspectGateway(ctx, subnetTrx, true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	primaryGatewayID, err := gw.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	// Get secondary gateway id if such a gateway exists
	gwIDs := []string{primaryGatewayID}

	gw, xerr = instance.inspectGateway(ctx, subnetTrx, false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return nil, xerr
		}
	} else {
		sgid, err := gw.GetID()
		if err != nil {
			return nil, fail.Wrap(err)
		}

		gwIDs = append(gwIDs, sgid)
	}

	snid, err := instance.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	pn := &protocol.Subnet{
		Id:         snid,
		Name:       instance.GetName(),
		Cidr:       func() string { out, _ := subnetTrx.GetCIDR(ctx); return out }(),
		GatewayIds: gwIDs,
		Failover:   func() bool { out, _ := subnetTrx.HasVirtualIP(ctx); return out }(),
		State:      protocol.SubnetState(func() int32 { out, _ := subnetTrx.GetState(ctx); return int32(out) }()),
	}

	vip, xerr = subnetTrx.GetVirtualIP(ctx)
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
func (instance *Subnet) BindSecurityGroup(ctx context.Context, sgInstance *SecurityGroup, enabled SecurityGroupActivation) (ferr fail.Error) {
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
		return fail.Wrap(err)
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet"), "(%s)", snid).Entering()
	defer tracer.Exiting()

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	return alterSubnetMetadata(ctx, subnetTrx, func(abstractSubnet *abstract.Subnet, props *serialize.JSONProperties) fail.Error {
		var subnetHosts *propertiesv1.SubnetHosts
		innerXErr := props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			subnetHosts, innerErr = clonable.Cast[*propertiesv1.SubnetHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) (innerFErr fail.Error) {
			nsgV1, innerErr := clonable.Cast[*propertiesv1.SubnetSecurityGroups](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			sgID, err := sgInstance.GetID()
			if err != nil {
				return fail.Wrap(err)
			}

			sgTrx, innerXErr := newSecurityGroupTransaction(ctx, sgInstance)
			if innerXErr != nil {
				return innerXErr
			}
			sgTrx.TerminateFromError(ctx, &innerFErr)

			// First check if the security group is not already registered for the host with the exact same state
			for k, v := range nsgV1.ByID {
				if k == sgID && v.Disabled == bool(!enabled) {
					return fail.DuplicateError("security group '%s' already bound to Subnet", sgInstance.GetName())
				}
			}

			// Bind the security group to the Subnet (does the security group side of things)
			innerXErr = sgTrx.BindToSubnet(ctx, abstractSubnet, subnetHosts, enabled, MarkSecurityGroupAsSupplemental)
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
func (instance *Subnet) UnbindSecurityGroup(ctx context.Context, sgInstance *SecurityGroup) (ferr fail.Error) {
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
		return fail.Wrap(err)
	}

	sgID, innerErr := sgInstance.GetID()
	if innerErr != nil {
		return fail.Wrap(innerErr)
	}

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	// -- Unbind Security Group from Subnet and attached Hosts
	xerr = alterSubnetMetadataProperty(ctx, subnetTrx, subnetproperty.SecurityGroupsV1, func(ssgV1 *propertiesv1.SubnetSecurityGroups) fail.Error {
		// Check if the security group is listed for the host, is not already registered for the host with the exact same state
		found := false
		for k := range ssgV1.ByID {
			if k == sgID {
				found = true
				break
			}
		}
		// If not found, consider request successful
		if !found {
			return nil
		}

		// unbind security group from Subnet on cloud provider side
		innerXErr := sgTrx.UnbindFromSubnetHosts(ctx, subnetTrx)
		if innerXErr != nil {
			return innerXErr
		}

		// updates the metadata
		delete(ssgV1.ByID, sgID)
		delete(ssgV1.ByName, sgInstance.GetName())
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// -- Remove Subnet reference in Security Group
	return alterSecurityGroupMetadataProperty(ctx, sgTrx, securitygroupproperty.SubnetsV1, func(sgsV1 *propertiesv1.SecurityGroupSubnets) fail.Error {
		delete(sgsV1.ByID, snid)
		delete(sgsV1.ByName, instance.GetName())
		return nil
	})
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

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return emptyList, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return list, inspectSubnetMetadataProperty(ctx, trx, subnetproperty.SecurityGroupsV1, func(ssgV1 *propertiesv1.SubnetSecurityGroups) fail.Error {
		list = FilterBondsByKind(ssgV1.ByID, state)
		return nil
	})
}

// EnableSecurityGroup enables a binded security group to Subnet
func (instance *Subnet) EnableSecurityGroup(ctx context.Context, sgInstance *SecurityGroup) (ferr fail.Error) {
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
		return fail.Wrap(err)
	}

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	svc := instance.Service()
	return alterSubnetMetadata(ctx, subnetTrx, func(abstractSubnet *abstract.Subnet, props *serialize.JSONProperties) fail.Error {
		var subnetHosts *propertiesv1.SubnetHosts
		innerXErr := props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			subnetHosts, innerErr = clonable.Cast[*propertiesv1.SubnetHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
			nsgV1, innerErr := clonable.Cast[*propertiesv1.SubnetSecurityGroups](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			var abstractSG *abstract.SecurityGroup
			innerXErr := inspectSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
				abstractSG = asg
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// First check if the security group is not already registered for the host with the exact same state
			var found bool
			for k := range nsgV1.ByID {
				if k == abstractSG.ID {
					found = true
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not binded to Subnet '%s'", sgInstance.GetName(), snid)
			}

			// Do security group stuff to enable it
			caps := svc.Capabilities()
			if caps.CanDisableSecurityGroup {
				innerXErr = svc.EnableSecurityGroup(ctx, abstractSG)
				if innerXErr != nil {
					return innerXErr
				}
			} else {
				innerXErr = sgTrx.BindToSubnet(ctx, abstractSubnet, subnetHosts, SecurityGroupEnable, KeepCurrentSecurityGroupMark)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrDuplicate:
						// security group already bound to Subnet with the same state, considered as a success
						debug.IgnoreErrorWithContext(ctx, innerXErr)
					default:
						return innerXErr
					}
				}
			}

			// update metadata
			nsgV1.ByID[abstractSG.ID].Disabled = false
			return nil
		})
	})
}

// DisableSecurityGroup disables an already binded security group on Subnet
func (instance *Subnet) DisableSecurityGroup(ctx context.Context, sgInstance *SecurityGroup) (ferr fail.Error) {
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
		return fail.Wrap(err)
	}

	subnetTrx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	svc := instance.Service()
	return alterSubnetMetadata(ctx, subnetTrx, func(abstractSubnet *abstract.Subnet, props *serialize.JSONProperties) fail.Error {
		var subnetHosts *propertiesv1.SubnetHosts
		innerXErr := props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			subnetHosts, innerErr = clonable.Cast[*propertiesv1.SubnetHosts](p)
			return fail.Wrap(innerErr)
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
			nsgV1, innerErr := clonable.Cast[*propertiesv1.SubnetSecurityGroups](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			var abstractSG *abstract.SecurityGroup
			innerXErr := inspectSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
				abstractSG = asg
				return nil
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
				innerXErr = sgTrx.BindToSubnet(ctx, abstractSubnet, subnetHosts, SecurityGroupDisable, KeepCurrentSecurityGroupMark)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						// security group not bound to Subnet, considered as a success
						debug.IgnoreErrorWithContext(ctx, innerXErr)
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
func (instance *Subnet) InspectGatewaySecurityGroup(ctx context.Context) (_ *SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var abstractSubnet *abstract.Subnet
	xerr = inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		abstractSubnet = as
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return LoadSecurityGroup(ctx, abstractSubnet.GWSecurityGroupID)
}

// InspectInternalSecurityGroup returns the instance of SecurityGroup for internal security inside the Subnet
func (instance *Subnet) InspectInternalSecurityGroup(ctx context.Context) (_ *SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var sgID string
	xerr = inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		sgID = as.InternalSecurityGroupID
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return LoadSecurityGroup(ctx, sgID)
}

// InspectPublicIPSecurityGroup returns the instance of SecurityGroup in Subnet for Hosts with Public IP (which does not apply on gateways)
func (instance *Subnet) InspectPublicIPSecurityGroup(ctx context.Context) (_ *SecurityGroup, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	trx, xerr := newSubnetTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var sgID string
	xerr = inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		sgID = as.PublicIPSecurityGroupID
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	return LoadSecurityGroup(ctx, sgID)
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

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.subnet"), "('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.ImageRef, req.HA).WithStopwatch().Entering()
	defer tracer.Exiting()

	subnetTrx, xerr := instance.buildSubnet(ctx, req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer subnetTrx.TerminateFromError(ctx, &ferr)

	// --- Updates Subnet state in metadata ---
	xerr = instance.finalizeSubnetCreation(ctx, subnetTrx)
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}

// buildSubnet ...
// Note: returned subnetTransaction has to be terminated by caller.
func (instance *Subnet) buildSubnet(inctx context.Context, req abstract.SubnetRequest) (_ subnetTransaction, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if req.CIDR == "" {
		return nil, fail.InvalidRequestError("invalid empty string value for 'req.CIDR'")
	}

	if req.IPVersion == ipversion.Unknown {
		req.IPVersion = ipversion.IPv4
	}

	type localresult struct {
		rTr  subnetTransaction
		rErr fail.Error
	}
	chRes := make(chan localresult)
	go func() {
		defer close(chRes)

		gtrx, gerr := func() (_ subnetTransaction, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			logrus.WithContext(ctx).Debugf("Creating Subnet '%s' with CIDR '%s'...", req.Name, req.CIDR)

			abstractNetwork, networkTrx, xerr := instance.validateNetwork(ctx, &req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}
			defer networkTrx.TerminateFromError(ctx, &ferr)

			// Check if Subnet already exists and is managed by SafeScale
			xerr = instance.checkUnicity(ctx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// Verify the CIDR is not routable
			xerr = instance.validateCIDR(ctx, &req, *abstractNetwork)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, fail.Wrap(xerr, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
			}

			svc := instance.Service()
			abstractSubnet, xerr := svc.CreateSubnet(ctx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// Starting from here, Delete Subnet if exiting with error
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && abstractSubnet != nil && req.CleanOnFailure() {
					derr := svc.DeleteSubnet(cleanupContextFrom(ctx), abstractSubnet.ID)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Subnet", ActionFromError(ferr)))
					}
				}
			}()

			// Write Subnet object metadata and updates the service cache
			xerr = instance.Carry(ctx, abstractSubnet)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// Starting from here, Delete Subnet metadata if exiting with error
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() {
					derr := instance.Core.Delete(cleanupContextFrom(ctx))
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Subnet metadata", ActionFromError(ferr)))
					}
				}
			}()

			// attach Subnet to Network
			xerr = alterNetworkMetadataProperty(ctx, networkTrx, networkproperty.SubnetsV1, func(nsV1 *propertiesv1.NetworkSubnets) fail.Error {
				nsV1.ByID[abstractSubnet.ID] = abstractSubnet.Name
				nsV1.ByName[abstractSubnet.Name] = abstractSubnet.ID
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// commit as far as possible changes to Network
			xerr = networkTrx.Commit(ctx)
			if xerr != nil {
				return nil, xerr
			}

			subnetTrx, xerr := newSubnetTransaction(ctx, instance)
			if xerr != nil {
				return nil, xerr
			}
			defer func() {
				if ferr != nil {
					// Note: terminate subnetTrx only if error occured
					subnetTrx.TerminateFromError(ctx, &ferr)
				} else {
					ferr = subnetTrx.Commit(ctx)
				}
			}()

			xerr = instance.updateCachedInformation(ctx, subnetTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			if req.DefaultSSHPort == 0 {
				req.DefaultSSHPort = 22
			}

			subnetGWSG, subnetInternalSG, subnetPublicIPSG, xerr := subnetTrx.CreateSecurityGroups(ctx, networkTrx, req.CIDR, req.KeepOnFailure, int32(req.DefaultSSHPort))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() {
					a, _ := subnetGWSG.GetID()
					b, _ := subnetInternalSG.GetID()
					c, _ := subnetPublicIPSG.GetID()

					derr := instance.deleteSecurityGroups(cleanupContextFrom(ctx), [3]string{a, b, c})
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to Delete Security Groups"))
					}
				}
			}()

			caps := svc.Capabilities()
			failover := req.HA
			if failover {
				if caps.PrivateVirtualIP {
					logrus.Info("Driver support private Virtual IP, honoring the failover setup for gateways.")
				} else {
					logrus.WithContext(ctx).Warnf("Driver does not support private Virtual IP, cannot set up failover of Subnet default route.")
					failover = false
				}
			}

			// Creates VIP for gateways if asked for
			var avip *abstract.VirtualIP
			if failover {
				a, err := subnetGWSG.GetID()
				if err != nil {
					return nil, xerr
				}

				avip, xerr = svc.CreateVIP(ctx, abstractSubnet.Network, abstractSubnet.ID, fmt.Sprintf(virtualIPNamePattern, abstractSubnet.Name, networkTrx.GetName()), []string{a})
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return nil, fail.Wrap(xerr, "failed to create VIP")
				}

				// Starting from here, Delete VIP if exists with error
				defer func() {
					ferr = debug.InjectPlannedFail(ferr)
					if ferr != nil && abstractSubnet != nil && abstractSubnet.VIP != nil && req.CleanOnFailure() {
						derr := svc.DeleteVIP(cleanupContextFrom(ctx), abstractSubnet.VIP)
						if derr != nil {
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete VIP", ActionFromError(ferr)))
						}
					}
				}()
			}

			xerr = alterSubnetMetadata(ctx, subnetTrx, func(as *abstract.Subnet, props *serialize.JSONProperties) fail.Error {
				var innerErr error
				as.VIP = avip
				as.State = subnetstate.GatewayCreation
				as.GWSecurityGroupName = subnetGWSG.GetName()
				as.GWSecurityGroupID, innerErr = subnetGWSG.GetID()
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				as.InternalSecurityGroupName = subnetInternalSG.GetName()
				as.InternalSecurityGroupID, innerErr = subnetInternalSG.GetID()
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				as.PublicIPSecurityGroupName = subnetPublicIPSG.GetName()
				as.PublicIPSecurityGroupID, innerErr = subnetPublicIPSG.GetID()
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				// Creates the bind between the Subnet default security group and the Subnet
				return props.Alter(subnetproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
					ssgV1, innerErr := clonable.Cast[*propertiesv1.SubnetSecurityGroups](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					subnetID, innerErr := subnetGWSG.GetID()
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					item := &propertiesv1.SecurityGroupBond{
						ID:       subnetID,
						Name:     as.GWSecurityGroupName,
						Disabled: false,
					}
					ssgV1.ByID[item.ID] = item
					ssgV1.ByName[as.GWSecurityGroupName] = item.ID

					subnetID, innerErr = subnetInternalSG.GetID()
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					item = &propertiesv1.SecurityGroupBond{
						ID:       subnetID,
						Name:     as.InternalSecurityGroupName,
						Disabled: false,
					}
					ssgV1.ByID[item.ID] = item
					ssgV1.ByName[item.Name] = item.ID
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// FIXME: OPP Disable VIP SG and port security

			return subnetTrx, nil
		}()
		chRes <- localresult{gtrx, gerr}
	}() // nolint

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.Wrap(inctx.Err())
	}
}

// Carry registers 'as' as Core value of Subnet and register abstract in scope
func (instance *Subnet) Carry(ctx context.Context, as *abstract.Subnet) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if instance.Core.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if as == nil {
		return fail.InvalidParameterCannotBeNilError("as")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, as)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Job().Scope().RegisterAbstract(as)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// inspectGateway returns the gateway related to Subnet
// Note: you must take a lock (instance.lock.Lock() ) before calling this method
func (instance *Subnet) inspectGateway(ctx context.Context, subnetTrx subnetTransaction, primary bool) (_ *Host, ferr fail.Error) {
	gwIdx := 0
	if !primary {
		gwIdx = 1
	}

	instance.localCache.RLock()
	out := instance.localCache.gateways[gwIdx]
	instance.localCache.RUnlock() // nolint
	if out == nil {
		xerr := instance.updateCachedInformation(ctx, subnetTrx)
		if xerr != nil {
			return nil, xerr
		}

		instance.localCache.RLock()
		out = instance.localCache.gateways[gwIdx]
		instance.localCache.RUnlock() // nolint
		if out == nil {
			return nil, fail.NotFoundError("failed to find gateway")
		} else {
			incrementExpVar("net.cache.hit")
		}
	} else {
		incrementExpVar("net.cache.hit")
	}

	return out, nil
}

// updateSubnetStatus ...
func (instance *Subnet) updateSubnetStatus(ctx context.Context, subnetTrx subnetTransaction, target subnetstate.Enum) fail.Error {
	xerr := alterSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
		as.State = target
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.updateCachedInformation(ctx, subnetTrx)
	return debug.InjectPlannedFail(xerr)
}

// finalizeSubnetCreation ...
func (instance *Subnet) finalizeSubnetCreation(ctx context.Context, subnetTrx subnetTransaction) fail.Error {
	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	xerr := alterSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
		as.State = subnetstate.Ready
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.updateCachedInformation(ctx, subnetTrx)
	return debug.InjectPlannedFail(xerr)
}

func (instance *Subnet) createGateways(inctx context.Context, subnetTrx subnetTransaction, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements, sgs map[string]string, extra interface{}) (_ fail.Error) {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if subnetTrx == nil {
		return fail.InvalidParameterCannotBeNilError("subnetTrx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := myjob.Service()
			if gwSizing == nil {
				gwSizing = &abstract.HostSizingRequirements{MinGPU: -1}
			}

			subnetName := subnetTrx.GetName()
			template, xerr := svc.FindTemplateBySizing(ctx, *gwSizing)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{fail.Wrap(xerr, "failed to find appropriate template")}
				return ar, ar.rErr
			}

			// define image...
			imageQuery := gwSizing.Image
			if imageQuery == "" {
				imageQuery = req.ImageRef
				if imageQuery == "" {
					cfg, xerr := svc.ConfigurationOptions()
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						ar := result{xerr}
						return ar, ar.rErr
					}

					imageQuery = cfg.DefaultImage
					if imageQuery == "" {
						imageQuery = consts.DEFAULTOS
					}
				}
				img, xerr := svc.SearchImage(ctx, imageQuery)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// look for an exact match by ID
						imgs, xerr := svc.ListImages(ctx, true)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							xerr := fail.Wrap(xerr, "failure listing images")
							ar := result{xerr}
							return ar, ar.rErr
						}

						img = nil
						for _, aimg := range imgs {
							if strings.Compare(aimg.ID, imageQuery) == 0 {
								logrus.WithContext(ctx).Tracef("exact match by ID, ignoring jarowinkler results")
								img = aimg
								break
							}
						}
						if img == nil {
							xerr := fail.Wrap(xerr, "failed to find image with ID %s", imageQuery)
							ar := result{xerr}
							return ar, ar.rErr
						}

					default:
						xerr := fail.Wrap(xerr, "failed to find image '%s'", imageQuery)
						ar := result{xerr}
						return ar, ar.rErr
					}
				}

				gwSizing.Image = img.ID
			}

			var primaryGatewayName, secondaryGatewayName string
			if req.HA || gwname == "" {
				primaryGatewayName = "gw-" + subnetName
			} else {
				primaryGatewayName = gwname
			}
			if req.HA {
				secondaryGatewayName = "gw2-" + subnetName
			}

			domain := strings.Trim(req.Domain, ".")
			if domain != "" {
				domain = "." + domain
			}

			keepalivedPassword, err := utils.GeneratePassword(16)
			err = debug.InjectPlannedError(err)
			if err != nil {
				err := fail.Wrap(err)
				ar := result{err}
				return ar, ar.rErr
			}

			var abstractSubnet *abstract.Subnet
			xerr = inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				abstractSubnet = as

				// IDs of Security Groups to attach to Host used as gateway
				if len(sgs) == 0 {
					sgs = map[string]string{}
				}
				sgs[as.GWSecurityGroupID] = as.GWSecurityGroupName
				sgs[as.InternalSecurityGroupID] = as.InternalSecurityGroupName
				sgs[as.PublicIPSecurityGroupID] = as.PublicIPSecurityGroupName
				return nil
			})
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			gwRequest := abstract.HostRequest{
				ImageID:           gwSizing.Image,
				ImageRef:          imageQuery,
				Subnets:           []*abstract.Subnet{abstractSubnet},
				SSHPort:           req.DefaultSSHPort,
				TemplateID:        template.ID,
				KeepOnFailure:     req.KeepOnFailure,
				SecurityGroupByID: sgs,
				IsGateway:         true,
				DiskSize:          gwSizing.MinDiskSize,
			}

			var (
				primaryGateway, secondaryGateway   *Host
				primaryUserdata, secondaryUserdata *userdata.Content
			)

			type gwRes struct {
				num uint
				res data.Map[string, any]
				err fail.Error
			}

			gws := make(chan gwRes, 2)
			egGwCreation := new(errgroup.Group)

			// Starts primary gateway creation
			primaryRequest := gwRequest
			primaryRequest.ResourceName = primaryGatewayName
			primaryRequest.HostName = primaryGatewayName + domain

			var castedExtra map[string]string
			if extra == nil {
				castedExtra = map[string]string{}
			}
			castedExtra["gateway"] = "true"

			waitForFirstGw := make(chan struct{})
			egGwCreation.Go(func() error {
				defer func() {
					close(waitForFirstGw)
				}()
				tr, err := subnetTrx.CreateGateway(ctx, primaryRequest, *gwSizing, castedExtra)
				if err != nil {
					gws <- gwRes{
						num: 1,
						res: nil,
						err: err,
					}
					return err
				}
				gws <- gwRes{
					num: 1,
					res: tr,
					err: nil,
				}
				return nil
			})
			egGwCreation.Go(func() error {
				// Starts secondary gateway creation if asked for
				if req.HA {
					// workaround for Stein -> creating both gw at the same time don't work, so with Stein we have to wait until 1st gateway is finished
					{
						st, xerr := svc.ProviderName()
						if xerr != nil {
							return xerr
						}
						if st == "ovh" {
							<-waitForFirstGw
						}
					}

					secondaryRequest := gwRequest
					secondaryRequest.ResourceName = secondaryGatewayName
					secondaryRequest.HostName = secondaryGatewayName
					if req.Domain != "" {
						secondaryRequest.HostName = secondaryGatewayName + domain
					}
					tr, err := subnetTrx.CreateGateway(ctx, secondaryRequest, *gwSizing, castedExtra)
					if err != nil {
						gws <- gwRes{
							num: 2,
							res: nil,
							err: err,
						}
						return err
					}
					gws <- gwRes{
						num: 2,
						res: tr,
						err: nil,
					}
					return nil
				}
				return nil
			})

			xerr = fail.Wrap(egGwCreation.Wait())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			var (
				primaryMap, secondaryMap data.Map[string, any]
			)
			close(gws)
			for v := range gws {
				if v.num == 1 {
					primaryMap = v.res
				}
				if v.num == 2 {
					secondaryMap = v.res
				}
			}

			// handle primary gateway
			{
				primaryGateway, err = lang.Cast[*Host](primaryMap["host"])
				if err != nil {
					ar := result{fail.Wrap(err)}
					return ar, ar.rErr
				}

				primaryGatewaySSHConfig, xerr := primaryGateway.GetSSHConfig(ctx)
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
				}

				primaryGatewaySSH, xerr := ssh.NewConnector(primaryGatewaySSHConfig)
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
				}

				primaryGatewayTrx, xerr := newHostTransaction(ctx, primaryGateway)
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
				}
				defer primaryGatewayTrx.TerminateFromError(ctx, &ferr)

				// Starting from here, deletes the primary gateway if exiting with error
				defer func() {
					ferr = debug.InjectPlannedFail(ferr)
					if ferr != nil && !req.KeepOnFailure && primaryGateway != nil {
						logrus.WithContext(cleanupContextFrom(ctx)).Warnf("Cleaning up on failure, deleting gateway '%s'... because of '%s'", primaryGateway.GetName(), ferr.Error())
						derr := primaryGatewayTrx.RelaxedDeleteHost(cleanupContextFrom(ctx), primaryGatewaySSH)
						derr = debug.InjectPlannedFail(derr)
						if derr != nil {
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete primary gateway"))
							return
						} else {
							primaryGatewayTrx.SilentTerminate(ctx)
							derr = primaryGateway.Core.Delete(ctx)
							if derr != nil {
								_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete primary gateway metadata"))
								return
							}
						}

						if req.HA {
							derr = instance.unbindHostFromVIP(cleanupContextFrom(ctx), abstractSubnet.VIP, primaryGateway)
							if derr != nil {
								_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind primary gateway from VIP"))
								return
							}
						}

						logrus.WithContext(cleanupContextFrom(ctx)).Debugf("Cleaning up on failure, gateway '%s' deleted", primaryGateway.GetName())
					}
				}()

				primaryUserdata, err = lang.Cast[*userdata.Content](primaryMap["userdata"])
				if err != nil {
					ar := result{fail.Wrap(err)}
					return ar, ar.rErr
				}
				primaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

				// apply SG to primary gateway
				{
					safe := false

					// Fix for Stein
					{
						st, xerr := svc.ProviderName()
						if xerr != nil {
							ar := result{xerr}
							return ar, ar.rErr
						}

						if st != "ovh" {
							safe = true
						}
					}

					if cfg, xerr := svc.ConfigurationOptions(); xerr == nil {
						safe = cfg.Safe
					}

					if !safe {
						xerr = svc.ChangeSecurityGroupSecurity(ctx, false, true, req.NetworkID, "")
						if xerr != nil {
							ar := result{xerr}
							return ar, ar.rErr
						}
					}

					defer func() {
						derr := subnetTrx.undoBindInternalSecurityGroupToGateway(cleanupContextFrom(ctx), primaryGatewayTrx, req.KeepOnFailure, &ferr)
						if derr != nil {
							logrus.WithContext(ctx).Warnf(derr.Error())
						}
					}()

					// Bind Internal Security Group to gateway
					xerr = subnetTrx.BindInternalSecurityGroupToGateway(ctx, primaryGatewayTrx)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						ar := result{xerr}
						return ar, ar.rErr
					}

					if !safe {
						xerr = svc.ChangeSecurityGroupSecurity(ctx, true, false, req.NetworkID, "")
						if xerr != nil {
							ar := result{xerr}
							return ar, ar.rErr
						}
					}
				}
			}

			if req.HA {
				// apply SG to secondary gateway
				{
					safe := false

					// Fix for Stein
					{
						st, xerr := svc.ProviderName()
						if xerr != nil {
							ar := result{xerr}
							return ar, ar.rErr
						}
						if st != "ovh" {
							safe = true
						}
					}

					if cfg, xerr := svc.ConfigurationOptions(); xerr == nil {
						safe = cfg.Safe
					}

					var ok bool
					secondaryGateway, ok = secondaryMap["host"].(*Host)
					if !ok {
						xerr := fail.InconsistentError("localresult[host] should be a *Host")
						ar := result{xerr}
						return ar, ar.rErr
					}

					secondaryGatewaySSHConfig, xerr := secondaryGateway.GetSSHConfig(ctx)
					if xerr != nil {
						ar := result{xerr}
						return ar, ar.rErr
					}

					secondaryGatewaySSH, xerr := ssh.NewConnector(secondaryGatewaySSHConfig)
					if xerr != nil {
						ar := result{xerr}
						return ar, ar.rErr
					}

					secondaryGatewayTrx, xerr := newHostTransaction(ctx, secondaryGateway)
					if xerr != nil {
						ar := result{xerr}
						return ar, ar.rErr
					}
					defer secondaryGatewayTrx.TerminateFromError(ctx, &ferr)

					// Starting from here, deletes the secondary gateway if exiting with error
					defer func() {
						ferr = debug.InjectPlannedFail(ferr)
						if ferr != nil && req.CleanOnFailure() && secondaryGateway != nil {
							derr := secondaryGatewayTrx.RelaxedDeleteHost(cleanupContextFrom(ctx), secondaryGatewaySSH)
							derr = debug.InjectPlannedFail(derr)
							if derr != nil {
								_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete secondary gateway"))
								return
							} else {
								secondaryGatewayTrx.SilentTerminate(ctx)
								derr = primaryGateway.Core.Delete(ctx)
								if derr != nil {
									_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete secondary gateway metadata"))
									return
								}
							}

							derr = instance.unbindHostFromVIP(cleanupContextFrom(ctx), abstractSubnet.VIP, secondaryGateway)
							if derr != nil {
								_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind secondary gateway from VIP"))
							}
						}
					}()

					secondaryUserdata, ok = secondaryMap["userdata"].(*userdata.Content)
					if !ok {
						xerr := fail.InvalidParameterError("localresult[userdata] should be a *userdate.Content")
						ar := result{xerr}
						return ar, ar.rErr
					}
					secondaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

					defer func() {
						derr := subnetTrx.undoBindInternalSecurityGroupToGateway(cleanupContextFrom(ctx), secondaryGatewayTrx, req.KeepOnFailure, &ferr)
						if derr != nil {
							logrus.WithContext(cleanupContextFrom(ctx)).Warn(derr.Error())
						}
					}()

					// Bind Internal Security Group to gateway
					if !safe {
						xerr = svc.ChangeSecurityGroupSecurity(ctx, false, true, req.NetworkID, "")
						if xerr != nil {
							ar := result{xerr}
							return ar, ar.rErr
						}
					}

					xerr = subnetTrx.BindInternalSecurityGroupToGateway(ctx, secondaryGatewayTrx)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						ar := result{xerr}
						return ar, ar.rErr
					}

					if !safe {
						xerr = svc.ChangeSecurityGroupSecurity(ctx, true, false, req.NetworkID, "")
						if xerr != nil {
							ar := result{xerr}
							return ar, ar.rErr
						}
					}
				}
			}

			// Update userdata of gateway(s)
			xerr = inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) (innerXErr fail.Error) {
				// Updates userdatas to use later
				var inErr fail.Error
				primaryUserdata.PrimaryGatewayPrivateIP, inErr = primaryGateway.GetPrivateIP(ctx)
				if inErr != nil {
					return inErr
				}

				primaryUserdata.PrimaryGatewayPublicIP, inErr = primaryGateway.GetPublicIP(ctx)
				if inErr != nil {
					return inErr
				}

				primaryUserdata.IsPrimaryGateway = true
				if as.VIP != nil {
					primaryUserdata.DefaultRouteIP = as.VIP.PrivateIP
					primaryUserdata.EndpointIP = as.VIP.PublicIP
				} else {
					primaryUserdata.DefaultRouteIP = primaryUserdata.PrimaryGatewayPrivateIP
					primaryUserdata.EndpointIP = primaryUserdata.PrimaryGatewayPublicIP
				}

				if secondaryGateway != nil {
					// as.SecondaryGatewayID = secondaryGateway.ID()
					primaryUserdata.SecondaryGatewayPrivateIP, inErr = secondaryGateway.GetPrivateIP(ctx)
					if inErr != nil {
						return inErr
					}

					secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
					secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
					primaryUserdata.SecondaryGatewayPublicIP, inErr = secondaryGateway.GetPublicIP(ctx)
					if inErr != nil {
						return inErr
					}
					secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
					secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
					secondaryUserdata.IsPrimaryGateway = false
					if as.VIP != nil {
						secondaryUserdata.DefaultRouteIP = primaryUserdata.DefaultRouteIP
						secondaryUserdata.EndpointIP = primaryUserdata.EndpointIP
					} else {
						secondaryUserdata.DefaultRouteIP = secondaryUserdata.SecondaryGatewayPrivateIP
						secondaryUserdata.EndpointIP = secondaryUserdata.SecondaryGatewayPublicIP
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			// As hosts are marked as gateways, the configuration stopped on phase 2 'netsec', the remaining 3 phases have to be run explicitly
			xerr = alterSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				as.State = subnetstate.GatewayConfiguration
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{xerr}
				return ar, ar.rErr
			}

			egFinalizer := new(errgroup.Group)
			egFinalizer.Go(func() error {
				_, err := instance.finalizeGatewayConfiguration(ctx, primaryGateway, primaryUserdata)
				return err
			})
			egFinalizer.Go(func() error {
				if req.HA {
					_, err := instance.finalizeGatewayConfiguration(ctx, secondaryGateway, secondaryUserdata)
					return err
				}
				return nil
			})

			xerr = fail.Wrap(egFinalizer.Wait())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr := fail.Wrap(xerr, "error finalizing gateway configuration")
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
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for cleanup
		return fail.Wrap(inctx.Err())
	}
}

// unbindHostFromVIP unbinds a Host from VIP
// Actually does nothing in aws for now
func (instance *Subnet) unbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, host *Host) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	hid, err := host.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	xerr := instance.Service().UnbindHostFromVIP(ctx, vip, hid)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "cleaning up on %s, failed to unbind gateway '%s' from VIP", ActionFromError(xerr), host.GetName())
	}

	return nil
}

func (instance *Subnet) finalizeGatewayConfiguration(inctx context.Context, host *Host, ud *userdata.Content) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	gwname := host.GetName()
	tracer := debug.NewTracer(ctx, true, "(%s)", gwname).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))
			defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Starting final configuration phases on the gateway '%s' with err '%s' ...", gwname, ferr), fmt.Sprintf("Ending final configuration phases on the gateway '%s'", gwname))()

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			// Executes userdata phase2 script to finalize host installation
			waitingTime := temporal.MaxTimeout(24*timings.RebootTimeout()/10, timings.HostCreationTimeout())

			if host.thePhaseDoesSomething(ctx, userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY, ud) {
				xerr = host.runInstallPhase(ctx, userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY, ud, waitingTime)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.rErr
				}
			} else {
				logrus.WithContext(ctx).Debugf("Nothing to do for the phase '%s'", userdata.PHASE3_GATEWAY_HIGH_AVAILABILITY)
			}

			if host.thePhaseDoesSomething(ctx, userdata.PHASE4_SYSTEM_FIXES, ud) {
				// If we have an error here, we just ignore it
				xerr = host.runInstallPhase(ctx, userdata.PHASE4_SYSTEM_FIXES, ud, waitingTime)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					theCause := fail.Wrap(fail.Cause(xerr))
					if _, ok := theCause.(*fail.ErrTimeout); !ok || valid.IsNil(theCause) {
						ar := result{nil, xerr}
						return ar, ar.rErr
					}

					debug.IgnoreErrorWithContext(ctx, xerr)
				}

				// intermediate gateway reboot
				logrus.WithContext(ctx).Infof("Rebooting gateway '%s'", gwname)
				xerr = host.Reboot(ctx, true)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.rErr
				}

				time.Sleep(timings.RebootTimeout())

				_, xerr = host.waitInstallPhase(ctx, userdata.PHASE4_SYSTEM_FIXES, waitingTime)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.rErr
				}
			} else {
				logrus.WithContext(ctx).Debugf("Nothing to do for the phase '%s'", userdata.PHASE4_SYSTEM_FIXES)
			}

			// final phase...
			xerr = host.runInstallPhase(ctx, userdata.PHASE5_FINAL, ud, waitingTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			// By design, phase 5 doesn't touch network cfg, so no reboot needed
			_, xerr = host.waitInstallPhase(ctx, userdata.PHASE5_FINAL, waitingTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			ar := result{nil, nil}
			return ar, ar.rErr
		}()
		chRes <- gres
	}() // nolint

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}
