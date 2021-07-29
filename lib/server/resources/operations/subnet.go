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
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
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
	*MetadataCore

	lock     sync.RWMutex
	gateways [2]*Host
	// parentNetwork resources.Network
}

// NullSubnet returns a *Subnet representing null value
func NullSubnet() *Subnet {
	return &Subnet{MetadataCore: NullCore()}
}

// ListSubnets returns a list of available subnets
func ListSubnets(ctx context.Context, svc iaas.Service, networkID string, all bool) (_ []*abstract.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
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
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	if all {
		return svc.ListSubnets(networkID)
	}

	subnetInstance, xerr := NewSubnet(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// recover Subnets from metadata
	var list []*abstract.Subnet
	xerr = subnetInstance.Browse(ctx, func(abstractSubnet *abstract.Subnet) fail.Error {
		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

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
func NewSubnet(svc iaas.Service) (_ resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return NullSubnet(), fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, subnetKind, subnetsFolderName, &abstract.Subnet{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return NullSubnet(), xerr
	}

	instance := &Subnet{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// LoadSubnet loads the metadata of a Subnet
func LoadSubnet(svc iaas.Service, networkRef, subnetRef string) (rs resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if subnetRef = strings.TrimSpace(subnetRef); subnetRef == "" {
		return nil, fail.InvalidParameterError("subnetRef", "cannot be empty string")
	}

	// -- First step: identify subnetID from (networkRef, subnetRef) --
	var (
		subnetID string
		rn       resources.Network
	)
	networkRef = strings.TrimSpace(networkRef)
	switch networkRef {
	case "":
		// If networkRef is empty, subnetRef must be subnetID
		subnetID = subnetRef
	default:
		// Try to load Network metadata
		rn, xerr = LoadNetwork(svc, networkRef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Network metadata can be missing if it's the default Network, so continue
			default:
				return nil, xerr
			}
		}

		if rn != nil { //nolint
			// Network metadata loaded, find the ID of the Subnet (subnetRef may be ID or Name)
			xerr = rn.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Inspect(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
					subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					var found bool
					for k, v := range subnetsV1.ByName {
						if k == subnetRef || v == subnetRef {
							subnetID = v
							found = true
							break
						}
					}
					if !found {
						return fail.NotFoundError("failed to find a Subnet referenced by '%s' in network '%s'", subnetRef, rn.GetName())
					}
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}
		} else if svc.HasDefaultNetwork() {
			// No Network Metadata, try to use the default Network if there is one
			an, xerr := svc.GetDefaultNetwork()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			if an.Name == networkRef || an.ID == networkRef {
				// We are in default Network context, query Subnet list and search for the one requested
				list, xerr := ListSubnets(context.TODO(), svc, an.ID, false)
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

	// -- second step: search instance in service cache
	xerr = fail.NotFoundError()
	if subnetID != "" {
		subnetCache, xerr := svc.GetCache(subnetKind)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		options := []data.ImmutableKeyValue{
			data.NewImmutableKeyValue("onMiss", func() (cache.Cacheable, fail.Error) {
				rs, innerXErr := NewSubnet(svc)
				if innerXErr != nil {
					return nil, innerXErr
				}

				// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
				if innerXErr = rs.ReadByID(subnetID); innerXErr != nil {
					return nil, innerXErr
				}

				return rs, rs.(*Subnet).updateCachedInformation()
			}),
		}
		cacheEntry, xerr := subnetCache.Get(subnetID, options...)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		if rs = cacheEntry.Content().(*Subnet); rs == nil {
			return nil, fail.InconsistentError("nil found in cache for Subnet with id %s", subnetID)
		}
		_ = cacheEntry.LockContent()
		defer func() {
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				_ = cacheEntry.UnlockContent()
			}
		}()
	}

	// -- deal with instance not found and unable to create --
	if rs == nil {
		if networkRef != "" {
			// rewrite NotFoundError, user does not bother about metadata stuff
			return nil, fail.NotFoundError("failed to find a Subnet '%s' in Network '%s'", subnetRef, networkRef)
		}
		return nil, fail.NotFoundError("failed to find a Subnet referenced by '%s'", subnetRef)
	}
	return rs, nil
}

// updateCachedInformation updates the information cached in instance because will be frequently used and will not changed over time
func (instance *Subnet) updateCachedInformation() fail.Error {
	var primaryGatewayID, secondaryGatewayID string
	xerr := instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
		hostInstance, xerr := LoadHost(instance.GetService(), primaryGatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		instance.gateways[0] = hostInstance.(*Host)
	}
	if secondaryGatewayID != "" {
		hostInstance, xerr := LoadHost(instance.GetService(), secondaryGatewayID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		instance.gateways[1] = hostInstance.(*Host)
	}

	return nil
}

func (instance *Subnet) IsNull() bool {
	return instance == nil || (instance != nil && ((instance.MetadataCore == nil) || (instance.MetadataCore != nil && instance.MetadataCore.IsNull())))
}

// Carry wraps rv.core.Carry() to add Volume to service cache
func (instance *Subnet) Carry(clonable data.Clonable) (xerr fail.Error) {
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
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

// Create creates a Subnet
// FIXME: split up this function for readability
func (instance *Subnet) Create(ctx context.Context, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !instance.IsNull() {
		subnetName := instance.GetName()
		if subnetName != "" {
			return fail.NotAvailableError("already carrying Subnet '%s'", subnetName)
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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"),
		"('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.ImageRef, req.HA,
	).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.unsafeCreateSubnet(ctx, req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, delete Subnet if exiting with error
	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := instance.deleteSubnetAndConfirm(instance.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", ActionFromError(xerr)))
			}
		}
	}()

	// --- Create the gateway(s) ---
	xerr = instance.unsafeCreateGateways(ctx, req, gwname, gwSizing, nil)
	if xerr != nil {
		return xerr
	}

	// --- Updates Subnet state in metadata ---
	return instance.unsafeFinalizeSubnetCreation()
}

func (instance *Subnet) unsafeCreateSubnet(ctx context.Context, req abstract.SubnetRequest) fail.Error {
	if req.CIDR == "" {
		return fail.InvalidRequestError("invalid empty string value for 'req.CIDR'")
	}

	networkInstance, abstractNetwork, xerr := instance.validateNetwork(&req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Check if Subnet already exists and is managed by SafeScale
	xerr = instance.checkUnicity(req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Verify the CIDR is not routable
	xerr = instance.validateCIDR(&req, *abstractNetwork)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to validate CIDR '%s' for Subnet '%s'", req.CIDR, req.Name)
	}

	svc := instance.GetService()
	abstractSubnet, xerr := svc.CreateSubnet(req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound, *fail.ErrInvalidRequest, *fail.ErrTimeout:
			return xerr
		default:
			return xerr
		}
	}

	// Starting from here, delete Subnet if exiting with error
	defer func() {
		if xerr != nil && abstractSubnet != nil && !req.KeepOnFailure {
			if derr := instance.deleteSubnetAndConfirm(abstractSubnet.ID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", ActionFromError(xerr)))
			}
		}
	}()

	// Write Subnet object metadata and updates the service cache
	xerr = instance.Carry(abstractSubnet)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, delete Subnet metadata if exiting with error
	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := instance.MetadataCore.Delete(); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet metadata", ActionFromError(xerr)))
			}
		}
	}()
	xerr = instance.updateCachedInformation()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	subnetGWSG, subnetInternalSG, subnetPublicIPSG, xerr := instance.UnsafeCreateSecurityGroups(ctx, networkInstance, req.KeepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			derr := instance.deleteSecurityGroups(ctx, [3]string{subnetGWSG.GetID(), subnetInternalSG.GetID(), subnetPublicIPSG.GetID()})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Groups"))
			}
		}
	}()

	caps := svc.GetCapabilities()
	failover := req.HA
	if failover {
		if caps.PrivateVirtualIP {
			logrus.Info("Driver support private Virtual IP, honoring the failover setup for gateways.")
		} else {
			logrus.Warning("Driver does not support private Virtual IP, cannot set up failover of Subnet default route.")
			failover = false
		}
	}

	// Creates VIP for gateways if asked for
	var avip *abstract.VirtualIP
	if failover {
		avip, xerr = svc.CreateVIP(abstractSubnet.Network, abstractSubnet.ID, fmt.Sprintf(virtualIPNamePattern, abstractSubnet.Name, networkInstance.GetName()), []string{subnetGWSG.GetID()})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to create VIP")
		}

		// Starting from here, delete VIP if exists with error
		defer func() {
			if xerr != nil && abstractSubnet != nil && abstractSubnet.VIP != nil && !req.KeepOnFailure {
				if derr := svc.DeleteVIP(abstractSubnet.VIP); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete VIP", ActionFromError(xerr)))
				}
			}
		}()
	}

	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		as.VIP = avip
		as.State = subnetstate.GatewayCreation
		as.GWSecurityGroupID = subnetGWSG.GetID()
		as.InternalSecurityGroupID = subnetInternalSG.GetID()
		as.PublicIPSecurityGroupID = subnetPublicIPSG.GetID()

		// Creates the bind between the Subnet default security group and the Subnet
		return props.Alter(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			item := &propertiesv1.SecurityGroupBond{
				ID:       subnetGWSG.GetID(),
				Name:     subnetGWSG.GetName(),
				Disabled: false,
			}
			ssgV1.ByID[item.ID] = item
			ssgV1.ByName[subnetGWSG.GetName()] = item.ID

			item = &propertiesv1.SecurityGroupBond{
				ID:       subnetInternalSG.GetID(),
				Name:     subnetInternalSG.GetName(),
				Disabled: false,
			}
			ssgV1.ByID[item.ID] = item
			ssgV1.ByName[item.Name] = item.ID
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// attach Subnet to Network
	xerr = networkInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nsV1.ByID[abstractSubnet.ID] = abstractSubnet.Name
			nsV1.ByName[abstractSubnet.Name] = abstractSubnet.ID
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, remove Subnet from Network metadata if exiting with error
	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			derr := networkInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
					nsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					delete(nsV1.ByID, abstractSubnet.ID)
					delete(nsV1.ByName, abstractSubnet.Name)
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to detach Subnet from Network", ActionFromError(xerr)))
			}
		}
	}()

	return nil
}

func (instance *Subnet) unsafeFinalizeSubnetCreation() fail.Error {
	xerr := instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		as.State = subnetstate.Ready
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return instance.updateCachedInformation()
}

func (instance *Subnet) unsafeCreateGateways(ctx context.Context, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements, sgs map[string]struct{}) fail.Error {
	svc := instance.GetService()
	if gwSizing == nil {
		gwSizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}

	template, xerr := svc.FindTemplateBySizing(*gwSizing)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to find appropriate template")
	}

	// define image...
	imageQuery := gwSizing.Image
	if imageQuery == "" {
		imageQuery = req.ImageRef
		if imageQuery == "" {
			cfg, xerr := svc.GetConfigurationOptions()
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			imageQuery = cfg.GetString("DefaultImage")
		}
		if imageQuery == "" {
			imageQuery = "Ubuntu 20.04"
		}
		img, xerr := svc.SearchImage(imageQuery)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// look for an exact match by ID
				imgs, xerr := svc.ListImages(true)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failure listing images")
				}

				img = nil
				for _, aimg := range imgs {
					if strings.Compare(aimg.ID, imageQuery) == 0 {
						logrus.Tracef("exact match by ID, ignoring jarowinkler results")
						img = &aimg
						break
					}
				}
				if img == nil {
					return fail.Wrap(xerr, "failed to find image with ID %s", imageQuery)
				}

			default:
				return fail.Wrap(xerr, "failed to find image '%s'", imageQuery)
			}
		}

		gwSizing.Image = img.ID
	}

	subnetName := instance.GetName()
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
		return fail.ConvertError(err)
	}

	var as *abstract.Subnet
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		var ok bool
		as, ok = clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// IDs of Security Groups to attach to Host used as gateway
		if len(sgs) == 0 {
			sgs = map[string]struct{}{}
		}
		sgs[as.GWSecurityGroupID] = struct{}{}
		sgs[as.InternalSecurityGroupID] = struct{}{}
		sgs[as.PublicIPSecurityGroupID] = struct{}{}
		return nil
	})
	if xerr != nil {
		return xerr
	}

	gwRequest := abstract.HostRequest{
		ImageID:          gwSizing.Image,
		ImageRef:         imageQuery,
		Subnets:          []*abstract.Subnet{as},
		SSHPort:          req.DefaultSSHPort,
		TemplateID:       template.ID,
		KeepOnFailure:    req.KeepOnFailure,
		SecurityGroupIDs: sgs,
		IsGateway:        true,
	}

	var (
		primaryGateway, secondaryGateway   *Host
		primaryUserdata, secondaryUserdata *userdata.Content
		primaryTask, secondaryTask         concurrency.Task
	)

	tg, xerr := concurrency.NewTaskGroupWithContext(ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/creategateways"))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starts primary gateway creation
	primaryRequest := gwRequest
	primaryRequest.ResourceName = primaryGatewayName
	primaryRequest.HostName = primaryGatewayName + domain
	primaryTask, xerr = tg.Start(instance.taskCreateGateway, taskCreateGatewayParameters{
		request: primaryRequest,
		sizing:  *gwSizing,
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starts secondary gateway creation if asked for
	if req.HA {
		secondaryRequest := gwRequest
		secondaryRequest.ResourceName = secondaryGatewayName
		secondaryRequest.HostName = secondaryGatewayName
		if req.Domain != "" {
			secondaryRequest.HostName = secondaryGatewayName + domain
		}
		secondaryTask, xerr = tg.Start(instance.taskCreateGateway, taskCreateGatewayParameters{
			request: secondaryRequest,
			sizing:  *gwSizing,
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	results, groupXErr := tg.WaitGroup()
	if groupXErr != nil {
		return groupXErr
	}
	if results == nil {
		return fail.InconsistentError("task results shouldn't be nil")
	}

	id, xerr := primaryTask.ID()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		groupXErr = xerr
	} else {
		if content, ok := results[id]; !ok {
			return fail.InconsistentError("task results does not contain %s", id)
		} else {
			if content == nil {
				return fail.InconsistentError("task result with %s should not be nil", id)
			}
		}

		result, ok := results[id].(data.Map)
		if !ok {
			xerr = fail.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(results[id]).String())
			groupXErr = xerr
		} else {
			primaryGateway = result["host"].(*Host)
			primaryUserdata = result["userdata"].(*userdata.Content)
			primaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

			xerr = instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				abstractSubnet, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError("'*abstract.Subnet' expected, '%%s' provided", reflect.TypeOf(clonable).String())
				}

				abstractSubnet.GatewayIDs = append(abstractSubnet.GatewayIDs, primaryGateway.GetID())
				return nil
			})
			if xerr != nil {
				//goland:noinspection GoNilness
				if groupXErr == nil {
					groupXErr = xerr
				} else {
					_ = groupXErr.AddConsequence(xerr)
				}
			} else {
				// Starting from here, deletes the primary gateway if exiting with error
				defer func() {
					if xerr != nil && !req.KeepOnFailure {
						logrus.Debugf("Cleaning up on failure, deleting gateway '%s'...", primaryGateway.GetName())
						derr := primaryGateway.RelaxedDeleteHost(context.Background())
						derr = debug.InjectPlannedFail(derr)
						if derr != nil {
							switch derr.(type) {
							case *fail.ErrTimeout:
								logrus.Warnf("We should have waited more...") // FIXME: Wait until gateway no longer exists
							default:
							}
							_ = xerr.AddConsequence(derr)
						} else {
							logrus.Debugf("Cleaning up on failure, gateway '%s' deleted", primaryGateway.GetName())
						}
						if req.HA {
							if derr := instance.unbindHostFromVIP(as.VIP, primaryGateway); derr != nil {
								_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind VIP from gateway", ActionFromError(xerr)))
							}
						}
					}
				}()

				// Bind Internal Security Group to gateway
				xerr = instance.bindInternalSecurityGroupToGateway(ctx, primaryGateway)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					//goland:noinspection GoNilness
					if groupXErr == nil {
						groupXErr = xerr
					} else {
						_ = groupXErr.AddConsequence(xerr)
					}
				} else {
					defer instance.undoBindInternalSecurityGroupToGateway(ctx, primaryGateway, req.KeepOnFailure, &xerr)
				}
			}
		}
	}

	if req.HA {
		id, xerr := secondaryTask.ID()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if groupXErr == nil {
				groupXErr = xerr
			} else {
				_ = groupXErr.AddConsequence(xerr)
			}
		}

		if content, ok := results[id]; !ok {
			return fail.InconsistentError("task results does not contain %s", id)
		} else {
			if content == nil {
				return fail.InconsistentError("task result with %s should not be nil", id)
			}
		}

		result, ok := results[id].(data.Map)
		if !ok {
			xerr = fail.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(results[id]).String())
			if groupXErr == nil {
				groupXErr = xerr
			} else {
				_ = groupXErr.AddConsequence(xerr)
			}
		} else {
			secondaryGateway = result["host"].(*Host)
			secondaryUserdata = result["userdata"].(*userdata.Content)
			secondaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

			// register gateway id in subnet metadata
			xerr = instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				abstractSubnet, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError("'*abstract.Subnet' expected, '%%s' provided", reflect.TypeOf(clonable).String())
				}

				abstractSubnet.GatewayIDs = append(abstractSubnet.GatewayIDs, secondaryGateway.GetID())
				return nil
			})
			if xerr != nil {
				if groupXErr == nil {
					groupXErr = xerr
				} else {
					_ = groupXErr.AddConsequence(xerr)
				}
			}

			// Starting from here, deletes the secondary gateway if exiting with error
			defer func() {
				if xerr != nil && !req.KeepOnFailure {
					derr := secondaryGateway.RelaxedDeleteHost(ctx)
					derr = debug.InjectPlannedFail(derr)
					if derr != nil {
						switch derr.(type) {
						case *fail.ErrTimeout:
							logrus.Warnf("We should have waited more") // FIXME: Wait until gateway no longer exists
						default:
						}
						_ = xerr.AddConsequence(derr)
					}
					derr = instance.unbindHostFromVIP(as.VIP, secondaryGateway)
					derr = debug.InjectPlannedFail(derr)
					if derr != nil {
						_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind VIP from gateway", ActionFromError(xerr)))
					}
				}
			}()

			// Bind Internal Security Group to gateway
			xerr = instance.bindInternalSecurityGroupToGateway(ctx, secondaryGateway)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				if groupXErr == nil {
					groupXErr = xerr
				} else {
					_ = groupXErr.AddConsequence(xerr)
				}
			} else {
				defer instance.undoBindInternalSecurityGroupToGateway(ctx, secondaryGateway, req.KeepOnFailure, &xerr)
			}
		}
	}
	if groupXErr != nil {
		return groupXErr
	}

	// Update userdata of gateway(s)
	xerr = instance.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// Updates userdatas to use later
		primaryUserdata.PrimaryGatewayPrivateIP, innerXErr = primaryGateway.GetPrivateIP()
		if innerXErr != nil {
			return innerXErr
		}

		primaryUserdata.PrimaryGatewayPublicIP, innerXErr = primaryGateway.GetPublicIP()
		if innerXErr != nil {
			return innerXErr
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
			primaryUserdata.SecondaryGatewayPrivateIP, innerXErr = secondaryGateway.GetPrivateIP()
			if innerXErr != nil {
				return innerXErr
			}

			secondaryUserdata.PrimaryGatewayPrivateIP = primaryUserdata.PrimaryGatewayPrivateIP
			secondaryUserdata.SecondaryGatewayPrivateIP = primaryUserdata.SecondaryGatewayPrivateIP
			primaryUserdata.SecondaryGatewayPublicIP, innerXErr = secondaryGateway.GetPublicIP()
			if innerXErr != nil {
				return innerXErr
			}
			secondaryUserdata.PrimaryGatewayPublicIP = primaryUserdata.PrimaryGatewayPublicIP
			secondaryUserdata.SecondaryGatewayPublicIP = primaryUserdata.SecondaryGatewayPublicIP
			secondaryUserdata.IsPrimaryGateway = false
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// As hosts are marked as gateways, the configuration stopped on phase 2 'netsec', the remaining 3 phases have to be run explicitly
	xerr = instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		as.State = subnetstate.GatewayConfiguration
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	tg, xerr = concurrency.NewTaskGroupWithContext(ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/configuregateways"))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	_, xerr = tg.Start(instance.taskFinalizeGatewayConfiguration, taskFinalizeGatewayConfigurationParameters{
		host:     primaryGateway,
		userdata: primaryUserdata,
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if req.HA {
		_, xerr = tg.Start(instance.taskFinalizeGatewayConfiguration, taskFinalizeGatewayConfigurationParameters{
			host:     secondaryGateway,
			userdata: secondaryUserdata,
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	_, xerr = tg.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}

// bindInternalSecurityGroupToGateway does what its name says
func (instance *Subnet) bindInternalSecurityGroupToGateway(ctx context.Context, host resources.Host) fail.Error {
	return instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		sg, innerXErr := LoadSecurityGroup(instance.GetService(), as.InternalSecurityGroupID)
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to load Subnet '%s' internal Security Group %s", as.Name, as.InternalSecurityGroupID)
		}
		defer sg.Released()

		if innerXErr = sg.BindToHost(ctx, host, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to apply Subnet '%s' internal Security Group '%s' to Host '%s'", as.Name, sg.GetName(), host.GetName())
		}

		return nil
	})
}

// undoBindInternalSecurityGroupToGateway does what its name says
func (instance *Subnet) undoBindInternalSecurityGroupToGateway(ctx context.Context, host resources.Host, keepOnFailure bool, xerr *fail.Error) {
	if xerr != nil && *xerr != nil && keepOnFailure {
		_ = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sg, derr := LoadSecurityGroup(instance.GetService(), as.InternalSecurityGroupID)
			if derr == nil {
				derr = sg.UnbindFromHost(context.Background(), host)
				sg.Released()
			}
			if derr != nil {
				_ = (*xerr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind Internal Security Group of Subnet '%s' from Host '%s'", as.Name, host.GetName()))
			}
			return nil
		})
	}
}

// deleteSubnetAndConfirm deletes the Subnet identified by 'id' and wait for deletion confirmation
func (instance *Subnet) deleteSubnetAndConfirm(id string) fail.Error {
	svc := instance.GetService()
	xerr := svc.DeleteSubnet(id)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If Subnet doesn't exist anymore on the provider infrastructure, do not fail
			return nil
		default:
			return xerr
		}
	}
	return retry.WhileUnsuccessfulDelay1Second(
		func() error {
			_, xerr := svc.InspectSubnet(id)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Subnet not found, good
				default:
					return xerr
				}
			}
			return nil
		},
		temporal.GetContextTimeout(),
	)
}

// validateCIDR tests if CIDR requested is valid, or select one if no CIDR is provided
func (instance *Subnet) validateCIDR(req *abstract.SubnetRequest, network abstract.Network) fail.Error {
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
			return fail.InvalidRequestError("not inside Network CIDR '%s'", req.CIDR, req.Name, network.CIDR)
		}
		return nil
	}

	// CIDR is empty, choose the first Class C available one
	logrus.Debugf("CIDR is empty, choosing one...")

	subnets, xerr := instance.GetService().ListSubnets(network.ID)
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
	logrus.Debugf("CIDR chosen for Subnet '%s' is '%s'", req.Name, req.CIDR)
	return nil
}

// wouldOverlap returns fail.ErrOverloadError if Subnet overlaps one of the subnets in allSubnets
// TODO: there is room for optimization here, 'allSubnets' is walked through at each call...
func wouldOverlap(allSubnets []*abstract.Subnet, subnet net.IPNet) fail.Error {
	for _, s := range allSubnets {
		_, sDesc, _ := net.ParseCIDR(s.CIDR)
		if netutils.CIDROverlap(subnet, *sDesc) {
			return fail.OverloadError("would intersect with '%s (%s)'", s.Name, s.CIDR)
		}
	}
	return nil
}

// checkUnicity checks if the Subnet name is not already used
func (instance *Subnet) checkUnicity(req abstract.SubnetRequest) fail.Error {
	resSubnet, xerr := LoadSubnet(instance.GetService(), req.NetworkID, req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil
		default:
			return xerr
		}
	}

	resSubnet.Released()
	return fail.DuplicateError("Subnet '%s' already exists", req.Name)
}

// validateNetwork verifies the Network exists and make sure req.Network field is an ID
func (instance *Subnet) validateNetwork(req *abstract.SubnetRequest) (resources.Network, *abstract.Network, fail.Error) {
	var an *abstract.Network
	svc := instance.GetService()
	rn, xerr := LoadNetwork(svc, req.NetworkID)
	if xerr == nil {
		xerr = rn.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			var ok bool
			an, ok = clonable.(*abstract.Network)
			if !ok {
				return fail.InconsistentError("'*abstract.Networking' expected, %s' provided", reflect.TypeOf(clonable).String())
			}

			// check the network exists on provider side
			if _, innerXErr := svc.InspectNetwork(an.ID); innerXErr != nil {
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
	} else {
		rn = nil
		switch xerr.(type) { //nolint
		case *fail.ErrNotFound:
			if !svc.HasDefaultNetwork() {
				return nil, nil, xerr
			}
			an, xerr = svc.GetDefaultNetwork()
		}
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	req.NetworkID = an.ID
	if len(req.DNSServers) == 0 {
		req.DNSServers = an.DNSServers
	}

	return rn, an, nil
}

// unbindHostFromVIP unbinds a VIP from IPAddress
// Actually does nothing in aws for now
func (instance *Subnet) unbindHostFromVIP(vip *abstract.VirtualIP, host resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	xerr = instance.GetService().UnbindHostFromVIP(vip, host.GetID())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "cleaning up on %s, failed to unbind gateway '%s' from VIP", ActionFromError(xerr), host.GetName())
	}

	return nil
}

// Browse walks through all the metadata objects in Subnet
func (instance *Subnet) Browse(ctx context.Context, callback func(*abstract.Subnet) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: Browse is intended to be callable from null value, so do not validate instance with .IsNull()
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "can't be nil")
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

		as := abstract.NewSubnet()
		xerr := as.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if task.Aborted() {
			return fail.AbortedError(nil, "aborted")
		}

		return callback(as)
	})
}

// AdoptHost links host ID to the Subnet
func (instance *Subnet) AdoptHost(ctx context.Context, host resources.Host) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if host == nil {
		return fail.InvalidParameterCannotBeNilError("host")
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

	tracer := debug.NewTracer(task, true, "("+host.GetName()+")").Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	hostName := host.GetName()

	// To apply the request, the instance must be one of the Subnets of the Host
	xerr = host.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			found := false
			for k := range hnV2.SubnetsByID {
				if k == instance.GetID() {
					found = true
					break
				}
			}
			if !found {
				return fail.InvalidRequestError("failed to adopt Host '%s' in Subnet '%s' as Host is not connected to it", hostName, instance.GetID())
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hostID := host.GetID()
			subnetHostsV1.ByID[hostID] = hostName
			subnetHostsV1.ByName[hostName] = hostID
			return nil
		})
	})
}

// AbandonHost unlinks host ID from Subnet
func (instance *Subnet) AbandonHost(ctx context.Context, hostID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
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

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("resources.subnet"), "('"+hostID+"')").Entering()
	defer tracer.Exiting()

	// instance.lock.Lock()
	// defer instance.lock.Unlock()

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return instance.unsafeAbandonHost(props, hostID)
	})
}

// ListHosts returns the list of Hosts attached to the Subnet (excluding gateway)
func (instance *Subnet) ListHosts(ctx context.Context) (_ []resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
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
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	defer debug.NewTracer(task, tracing.ShouldTrace("resources.subnet")).Entering().Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var list []resources.Host
	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.NetworkHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			svc := instance.GetService()
			for id := range shV1.ByID {
				hostInstance, innerErr := LoadHost(svc, id)
				if innerErr != nil {
					return innerErr
				}
				list = append(list, hostInstance)
			}
			return nil
		})
	})
	return list, xerr
}

// InspectGateway returns the gateway related to Subnet
func (instance *Subnet) InspectGateway(primary bool) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return HostNullValue(), fail.InvalidInstanceError()
	}

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.UnsafeInspectGateway(primary)
}

// GetGatewayPublicIP returns the Public IP of a particular gateway
func (instance *Subnet) GetGatewayPublicIP(primary bool) (_ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return "", fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var ip string
	svc := instance.GetService()
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

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
		if rgw, innerXErr = LoadHost(svc, id); innerXErr != nil {
			return innerXErr
		}
		defer rgw.Released()

		if ip, innerXErr = rgw.GetPublicIP(); innerXErr != nil {
			return innerXErr
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
func (instance *Subnet) GetGatewayPublicIPs() (_ []string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var emptySlice []string
	if instance == nil || instance.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var gatewayIPs []string
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		gatewayIPs = make([]string, 0, len(as.GatewayIDs))
		svc := instance.GetService()
		for _, v := range as.GatewayIDs {
			rgw, innerXErr := LoadHost(svc, v)
			if innerXErr != nil {
				return innerXErr
			}

			//goland:noinspection ALL
			defer func(hostInstance resources.Host) {
				hostInstance.Released()
			}(rgw)

			ip, innerXErr := rgw.GetPublicIP()
			if innerXErr != nil {
				return innerXErr
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

// Delete deletes a Subnet
func (instance *Subnet) Delete(ctx context.Context) (xerr fail.Error) {
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

	tracer := debug.NewTracer(nil, true /*tracing.ShouldTrace("operations.Subnet")*/).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Lock Subnet instance
	instance.lock.Lock()
	defer instance.lock.Unlock()

	var (
		hostsLen uint
		hostList []string
	)
	svc := instance.GetService()
	xerr = instance.Inspect(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// Check if hosts are still attached to Subnet according to metadata
		var errorMsg string
		return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			shV1, ok := clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hostsLen = uint(len(shV1.ByName))
			hostList = make([]string, 0, hostsLen)
			if hostsLen > 0 {
				for k := range shV1.ByName {
					// Check if Host still has metadata and count it if yes
					if hostInstance, innerXErr := LoadHost(svc, k, HostLightOption); innerXErr == nil {
						hostInstance.Released()
						hostList = append(hostList, k)
					}
				}
			}
			if len(hostList) > 0 {
				verb := "are"
				if hostsLen == 1 {
					verb = "is"
				}
				errorMsg = fmt.Sprintf("cannot delete Subnet '%s': %d host%s %s still attached to it: %s",
					as.Name, hostsLen, strprocess.Plural(hostsLen), verb, strings.Join(hostList, ", "))
				return fail.NotAvailableError(errorMsg)
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// Leave a chance to abort
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// 1st delete gateway(s)
		gwIDs, innerXErr := instance.deleteGateways(as)
		if innerXErr != nil {
			return innerXErr
		}

		// Unbind Host from current Subnet (not done by relaxedDeleteHost as Host is a gateway to avoid dead-lock as Subnet instance may already be locked)
		if len(gwIDs) > 0 {
			for _, v := range gwIDs {
				if innerXErr = instance.unsafeAbandonHost(props, v); innerXErr != nil {
					return innerXErr
				}
			}
		}

		// 2nd delete VIP if needed
		if as.VIP != nil {
			if innerXErr := svc.DeleteVIP(as.VIP); innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to delete VIP for gateways")
			}
		}

		// 3rd delete security groups associated to Subnet by users (do not include SG created with Subnet, they will be deleted later)
		innerXErr = props.Alter(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			innerXErr := instance.unbindSecurityGroups(ctx, ssgV1)
			return innerXErr
		})
		if innerXErr != nil {
			return innerXErr
		}

		// 4st free CIDR index if the Subnet has been created for a single Host
		if as.SingleHostCIDRIndex > 0 {
			// networkInstance, innerXErr := instance.unsafeInspectNetwork()
			networkInstance, innerXErr := instance.InspectNetwork()
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = FreeCIDRForSingleHost(networkInstance, as.SingleHostCIDRIndex)
			if innerXErr != nil {
				return innerXErr
			}
		}

		// finally delete Subnet
		logrus.Debugf("Deleting Subnet '%s'...", as.Name)
		if innerXErr = instance.deleteSubnetAndConfirm(as.ID); innerXErr != nil {
			return innerXErr
		}

		logrus.Infof("Subnet '%s' successfully deleted.", as.Name)

		// Delete Subnet's own Security Groups
		return instance.deleteSecurityGroups(ctx, [3]string{as.GWSecurityGroupID, as.InternalSecurityGroupID, as.PublicIPSecurityGroupID})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Remove metadata
	return instance.MetadataCore.Delete()
}

// deleteSecurityGroups deletes the Security Groups created for the Subnet
func (instance *Subnet) deleteSecurityGroups(ctx context.Context, sgs [3]string) (xerr fail.Error) {
	var (
		rsg    resources.SecurityGroup
		sgName string
	)
	svc := instance.GetService()
	for _, v := range sgs {
		if v != "" {
			if rsg, xerr = LoadSecurityGroup(svc, v); xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Security Group not found, consider this as a success
					debug.IgnoreError(xerr)
				default:
					return xerr
				}
			} else {
				sgName = rsg.GetName()
				logrus.Debugf("Deleting Security Group '%s'...", sgName)
				if xerr = rsg.Delete(ctx, true); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// Security Group not found, consider this as a success
						debug.IgnoreError(xerr)
					default:
						return xerr
					}
				}
			}
		}
	}
	return nil
}

// Released overloads core.Released() to release the parent Network instance
func (instance *Subnet) Released() {
	if instance == nil || instance.IsNull() {
		return
	}

	// instance.parentNetwork.Released()
	instance.MetadataCore.Released()
}

// InspectNetwork returns the Network instance owning the Subnet
func (instance *Subnet) InspectNetwork() (rn resources.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	var as *abstract.Subnet
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		var ok bool
		as, ok = clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}
	return LoadNetwork(instance.GetService(), as.Network)
}

// deleteGateways deletes all the gateways of the Subnet
// A gateway host that is not found must be considered as a success
func (instance *Subnet) deleteGateways(subnet *abstract.Subnet) (ids []string, xerr fail.Error) {
	svc := instance.GetService()

	ids = []string{}
	if len(subnet.GatewayIDs) > 0 {
		// FIXME: parallelize
		for _, v := range subnet.GatewayIDs {
			hostInstance, xerr := LoadHost(svc, v)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// missing gateway is considered as a successful deletion, continue
					logrus.Tracef("host instance not found, gateway deletion considered as a success")
					debug.IgnoreError(xerr)
				default:
					return ids, xerr
				}
			} else {
				name := hostInstance.GetName()
				logrus.Debugf("Deleting gateway '%s'...", name)

				// delete Host
				ids = append(ids, hostInstance.GetID())
				xerr := hostInstance.(*Host).RelaxedDeleteHost(context.Background())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// missing gateway is considered as a successful deletion, continue
						logrus.Tracef("host instance not found, relaxed gateway deletion considered as a success")
						debug.IgnoreError(xerr)
					default:
						return ids, xerr
					}
				}

				logrus.Debugf("Gateway '%s' successfully deleted.", name)
			}

			// Remove current entry from gateways to delete
			subnet.GatewayIDs = subnet.GatewayIDs[1:]
		}
	}
	return ids, nil
}

// unbindSecurityGroups makes sure the security groups bound to Subnet are unbound
func (instance *Subnet) unbindSecurityGroups(ctx context.Context, sgs *propertiesv1.SubnetSecurityGroups) (xerr fail.Error) {
	svc := instance.GetService()
	for k, v := range sgs.ByName {
		rsg, xerr := LoadSecurityGroup(svc, v)
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
			//goland:noinspection ALL
			defer func(sgInstance resources.SecurityGroup) {
				sgInstance.Released()
			}(rsg)
		}

		if rsg != nil {
			xerr = rsg.UnbindFromSubnet(ctx, instance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// consider a Security Group not found as a successful unbind
					debug.IgnoreError(xerr)
				default:
					return xerr
				}
			}
		}

		delete(sgs.ByID, v)
		delete(sgs.ByName, k)
	}
	return nil
}

// GetDefaultRouteIP returns the IP of the LAN default route
func (instance *Subnet) GetDefaultRouteIP() (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.UnsafeGetDefaultRouteIP()
}

// GetEndpointIP returns the internet (public) IP to reach the Subnet
func (instance *Subnet) GetEndpointIP() (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if instance == nil || instance.IsNull() {
		return ip, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if as.VIP != nil && as.VIP.PublicIP != "" {
			ip = as.VIP.PublicIP
		} else {
			objpgw, innerXErr := LoadHost(instance.GetService(), as.GatewayIDs[0])
			if innerXErr != nil {
				return innerXErr
			}

			ip, innerXErr = objpgw.(*Host).GetPublicIP()
			return innerXErr
		}
		return nil
	})
	return ip, xerr
}

// HasVirtualIP tells if the Subnet uses a VIP a default route
func (instance *Subnet) HasVirtualIP() (bool, fail.Error) {
	if instance == nil || instance.IsNull() {
		return false, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeHasVirtualIP()
}

// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (instance *Subnet) GetVirtualIP() (vip *abstract.VirtualIP, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetVirtualIP()
}

// GetCIDR returns the CIDR of the Subnet
func (instance *Subnet) GetCIDR() (cidr string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return "", fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetCIDR()
}

// GetState returns the current state of the Subnet
func (instance *Subnet) GetState() (state subnetstate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return subnetstate.Unknown, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetState()
}

// ToProtocol converts resources.Network to protocol.Network
func (instance *Subnet) ToProtocol() (_ *protocol.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	// RLock is needed because UnsafeInspectGateway needs such a lock
	instance.lock.Lock()
	defer instance.lock.Unlock()

	var (
		gw  resources.Host
		vip *abstract.VirtualIP
	)

	// Get primary gateway ID
	gw, xerr = instance.UnsafeInspectGateway(true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	primaryGatewayID := gw.GetID()

	// Get secondary gateway id if such a gateway exists
	gwIDs := []string{primaryGatewayID}
	gw, xerr = instance.UnsafeInspectGateway(false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return nil, xerr
		}
	} else {
		gwIDs = append(gwIDs, gw.GetID())
	}

	pn := &protocol.Subnet{
		Id:         instance.GetID(),
		Name:       instance.GetName(),
		Cidr:       func() string { out, _ := instance.unsafeGetCIDR(); return out }(),
		GatewayIds: gwIDs,
		Failover:   func() bool { out, _ := instance.unsafeHasVirtualIP(); return out }(),
		State:      protocol.SubnetState(func() int32 { out, _ := instance.unsafeGetState(); return int32(out) }()),
	}

	vip, xerr = instance.unsafeGetVirtualIP()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return nil, xerr
		}
	}
	if vip != nil {
		pn.VirtualIp = converters.VirtualIPFromAbstractToProtocol(*vip)
	}

	return pn, nil
}

// BindSecurityGroup binds a security group to the Subnet; if enabled is true, apply it immediately
func (instance *Subnet) BindSecurityGroup(ctx context.Context, sg resources.SecurityGroup, enabled resources.SecurityGroupActivation) (xerr fail.Error) {
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

	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if sg == nil {
		return fail.InvalidParameterCannotBeNilError("sg")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"), "(%s)", sg.GetID()).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// First check if the security group is not already registered for the host with the exact same state
			for k, v := range nsgV1.ByID {
				if k == sgID && v.Disabled == bool(!enabled) {
					return fail.DuplicateError("security group '%s' already bound to Subnet")
				}
			}

			// Bind the security group to the Subnet (does the security group side of things)
			if innerXErr := sg.BindToSubnet(ctx, instance, enabled, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
				return innerXErr
			}

			// Updates Subnet metadata
			nsgV1.ByID[sgID].Disabled = bool(!enabled)
			return nil
		})
	})
}

// UnbindSecurityGroup unbinds a security group from the host
func (instance *Subnet) UnbindSecurityGroup(ctx context.Context, sg resources.SecurityGroup) (xerr fail.Error) {
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

	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if sg == nil {
		return fail.InvalidParameterCannotBeNilError("sg")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"), "(%s)", sg.GetID()).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// Check if the security group is listed for the host, inot already registered for the host with the exact same state
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
			if innerXErr := sg.UnbindFromSubnet(ctx, instance); innerXErr != nil {
				return innerXErr
			}

			// updates the metadata
			delete(ssgV1.ByID, sgID)
			delete(ssgV1.ByName, sg.GetName())
			return nil

		})
	})
}

// ListSecurityGroups returns a slice of security groups bound to Subnet
func (instance *Subnet) ListSecurityGroups(ctx context.Context, state securitygroupstate.Enum) (list []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var emptyList []*propertiesv1.SecurityGroupBond
	if instance == nil || instance.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return emptyList, fail.InvalidParameterCannotBeNilError("ctx")
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
		return emptyList, xerr
	}

	if task.Aborted() {
		return emptyList, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"), "(%s)", state.String()).Entering()
	defer tracer.Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return list, instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = FilterBondsByKind(ssgV1.ByID, state)
			return nil
		})
	})
}

// EnableSecurityGroup enables a binded security group to Subnet
func (instance *Subnet) EnableSecurityGroup(ctx context.Context, rsg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if rsg == nil {
		return fail.InvalidParameterCannotBeNilError("rsg")
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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"), "(%s)", rsg.GetID()).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.GetService()
	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			innerXErr := rsg.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				if asg, ok = clonable.(*abstract.SecurityGroup); !ok {
					return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// First check if the security group is not already registered for the host with the exact same state
			var found bool
			for k := range nsgV1.ByID {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if k == asg.ID {
					found = true
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not binded to Subnet '%s'", rsg.GetName(), instance.GetID())
			}

			// Do security group stuff to enable it
			if svc.GetCapabilities().CanDisableSecurityGroup {
				if innerXErr = svc.EnableSecurityGroup(asg); innerXErr != nil {
					return innerXErr
				}
			} else {
				if innerXErr = rsg.BindToSubnet(ctx, instance, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark); innerXErr != nil {
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
func (instance *Subnet) DisableSecurityGroup(ctx context.Context, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sg == nil {
		return fail.InvalidParameterCannotBeNilError("sg")
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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"), "(%s)", sg.GetID()).Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.GetService()
	return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			nsgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			innerXErr := sg.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				if asg, ok = clonable.(*abstract.SecurityGroup); !ok {
					return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				return nil
			})
			if innerXErr != nil {
				return xerr
			}

			// First check if the security group is not already registered for the host with the exact same state
			if _, ok := nsgV1.ByID[asg.ID]; !ok {
				return fail.NotFoundError("security group '%s' is not bound to Subnet '%s'", sg.GetName(), instance.GetID())
			}

			if svc.GetCapabilities().CanDisableSecurityGroup {
				if innerXErr = svc.DisableSecurityGroup(asg); innerXErr != nil {
					return innerXErr
				}
			} else {
				// Do security group stuff to disable it
				if innerXErr = sg.BindToSubnet(ctx, instance, resources.SecurityGroupDisable, resources.KeepCurrentSecurityGroupMark); innerXErr != nil {
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
			nsgV1.ByID[asg.ID].Disabled = true
			return nil
		})
	})
}

// InspectGatewaySecurityGroup returns the instance of SecurityGroup in Subnet related to external access on gateways
func (instance *Subnet) InspectGatewaySecurityGroup() (rsg resources.SecurityGroup, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	rsg = SecurityGroupNullValue()
	if instance == nil || instance.IsNull() {
		return rsg, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		rsg, innerXErr = LoadSecurityGroup(instance.GetService(), as.GWSecurityGroupID)
		return innerXErr
	})
	return rsg, xerr
}

// InspectInternalSecurityGroup returns the instance of SecurityGroup for internal security inside the Subnet
func (instance *Subnet) InspectInternalSecurityGroup() (sg resources.SecurityGroup, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	sg = SecurityGroupNullValue()
	if instance == nil || instance.IsNull() {
		return sg, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		sg, innerXErr = LoadSecurityGroup(instance.GetService(), as.InternalSecurityGroupID)
		return innerXErr
	})
	return sg, xerr
}

// InspectPublicIPSecurityGroup returns the instance of SecurityGroup in Subnet for Hosts with Public IP (which does not apply on gateways)
func (instance *Subnet) InspectPublicIPSecurityGroup() (sg resources.SecurityGroup, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	sg = SecurityGroupNullValue()
	if instance == nil || instance.IsNull() {
		return sg, fail.InvalidInstanceError()
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		sg, innerXErr = LoadSecurityGroup(instance.GetService(), as.PublicIPSecurityGroupID)
		return innerXErr
	})
	return sg, xerr
}

// CreateSubnetWithoutGateway creates a Subnet named like 'singleHostName', without gateway
func (instance *Subnet) CreateSubnetWithoutGateway(ctx context.Context, req abstract.SubnetRequest) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Note: do not use .isNull() here
	if instance == nil {
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

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"),
		"('%s', '%s', %s, <sizing>, '%s', %v)", req.Name, req.CIDR, req.IPVersion.String(), req.ImageRef, req.HA,
	).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.unsafeCreateSubnet(ctx, req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// --- Updates Subnet state in metadata ---
	xerr = instance.unsafeFinalizeSubnetCreation()
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}
