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
	"reflect"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/consts"
	propertiesv1 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v21/lib/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// unsafeInspectGateway returns the gateway related to Subnet
// Note: a write lock of the instance (instance.lock.Lock() ) must have been called before calling this method
func (instance *Subnet) unsafeInspectGateway(ctx context.Context, primary bool) (_ resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	gwIdx := 0
	if !primary {
		gwIdx = 1
	}

	instance.localCache.RLock()
	out := instance.localCache.gateways[gwIdx]
	instance.localCache.RUnlock() // nolint
	if out == nil {
		xerr := instance.updateCachedInformation(ctx)
		if xerr != nil {
			return nil, xerr
		}

		instance.localCache.RLock()
		out = instance.localCache.gateways[gwIdx]
		instance.localCache.RUnlock() // nolint
		if out == nil {
			return nil, fail.NotFoundError("failed to find gateway")
		}
	}

	return out, nil
}

// unsafeGetDefaultRouteIP ...
func (instance *Subnet) unsafeGetDefaultRouteIP(ctx context.Context) (ip string, ferr fail.Error) {
	ip = ""
	xerr := instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if as.VIP != nil && as.VIP.PrivateIP != "" {
			ip = as.VIP.PrivateIP
			return nil
		}
		if len(as.GatewayIDs) > 0 {
			hostInstance, innerErr := LoadHost(ctx, instance.Service(), as.GatewayIDs[0])
			if innerErr != nil {
				return innerErr
			}

			var inErr fail.Error
			ip, inErr = hostInstance.GetPrivateIP(ctx)
			if inErr != nil {
				return inErr
			}
			return nil
		}

		return fail.NotFoundError("failed to find default route IP: no gateway defined")
	})
	return ip, xerr
}

// unsafeGetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (instance *Subnet) unsafeGetVirtualIP() (vip *abstract.VirtualIP, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		vip = as.VIP
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "cannot get Subnet virtual IP")

	}
	if vip == nil {
		return nil, fail.NotFoundError("failed to find Virtual IP binded to gateways for Subnet '%s'", instance.GetName())
	}

	return vip, nil
}

// unsafeGetCIDR returns the CIDR of the network
// Intended to be used when instance is notoriously not nil (because previously checked)
func (instance *Subnet) unsafeGetCIDR() (cidr string, ferr fail.Error) {
	cidr = ""
	xerr := instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
func (instance *Subnet) unsafeGetState() (state subnetstate.Enum, ferr fail.Error) {
	xerr := instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		state = as.State
		return nil
	})
	return state, xerr
}

// unsafeAbandonHost is the non goroutine-safe version of UnbindHost, without parameter validation, that does the real work
// Note: must be used wisely
func (instance *Subnet) unsafeAbandonHost(props *serialize.JSONProperties, hostID string) fail.Error {
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

// unsafeHasVirtualIP tells if the Subnet uses a VIP a default route
func (instance *Subnet) unsafeHasVirtualIP() (bool, fail.Error) {
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

// UnsafeCreateSecurityGroups creates the 3 Security Groups needed by a Subnet
// 'ctx' may contain values "CurrentNetworkAbstractContextKey" and "CurrentNetworkPropertiesContextKey", corresponding respectively
// to Network abstract and Network properties; these values may be used by SecurityGroup.Create() not to try to Alter networkInstance directly (might be inside a code already altering it)
func (instance *Subnet) unsafeCreateSecurityGroups(ctx context.Context, networkInstance resources.Network, keepOnFailure bool, defaultSSHPort int32) (subnetGWSG, subnetInternalSG, subnetPublicIPSG resources.SecurityGroup, ferr fail.Error) {
	var xerr fail.Error
	networkID := networkInstance.GetID()
	networkName := networkInstance.GetName()
	subnetGWSG, xerr = instance.createGWSecurityGroup(ctx, networkID, networkName, keepOnFailure, defaultSSHPort)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	defer instance.undoCreateSecurityGroup(&ferr, keepOnFailure, subnetGWSG)

	subnetPublicIPSG, xerr = instance.createPublicIPSecurityGroup(ctx, networkID, networkName, keepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	defer instance.undoCreateSecurityGroup(&ferr, keepOnFailure, subnetPublicIPSG)

	subnetInternalSG, xerr = instance.createInternalSecurityGroup(ctx, networkID, networkName, keepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	defer instance.undoCreateSecurityGroup(&ferr, keepOnFailure, subnetInternalSG)

	xerr = subnetGWSG.BindToSubnet(ctx, instance, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	defer func() {
		if ferr != nil && !keepOnFailure {
			if derr := subnetGWSG.UnbindFromSubnet(context.Background(), instance); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group for gateways from Subnet", ActionFromError(ferr)))
			}
		}
	}()

	xerr = subnetInternalSG.BindToSubnet(ctx, instance, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsDefault)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}

	return subnetGWSG, subnetInternalSG, subnetPublicIPSG, nil
}

// createGWSecurityGroup creates a Security Group that will be applied to gateways of the Subnet
func (instance *Subnet) createGWSecurityGroup(ctx context.Context, networkID, networkName string, keepOnFailure bool, defaultSSHPort int32) (_ resources.SecurityGroup, ferr fail.Error) {
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetGWSecurityGroupNamePattern, instance.GetName(), networkName)

	var sg resources.SecurityGroup
	sg, xerr = NewSecurityGroup(instance.Service())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetGWSecurityGroupDescriptionPattern, instance.GetName(), networkName)
	xerr = sg.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if ferr != nil && !keepOnFailure {
			if derr := sg.Delete(context.Background(), true); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(ferr), sgName))
			}
		}
	}()

	rules := abstract.SecurityGroupRules{
		{
			Description: "[ingress][ipv4][tcp] Allow SSH",
			Direction:   securitygroupruledirection.Ingress,
			PortFrom:    defaultSSHPort,
			EtherType:   ipversion.IPv4,
			Protocol:    "tcp",
			Sources:     []string{"0.0.0.0/0"},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: "[ingress][ipv6][tcp] Allow SSH",
			Direction:   securitygroupruledirection.Ingress,
			PortFrom:    defaultSSHPort,
			EtherType:   ipversion.IPv6,
			Protocol:    "tcp",
			Sources:     []string{"::/0"},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: "[ingress][ipv4][icmp] Allow everything",
			Direction:   securitygroupruledirection.Ingress,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			Sources:     []string{"0.0.0.0/0"},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: "[ingress][ipv6][icmp] Allow everything",
			Direction:   securitygroupruledirection.Ingress,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			Sources:     []string{"::/0"},
			Targets:     []string{sg.GetID()},
		},
	}
	xerr = sg.AddRules(ctx, rules)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if defaultSSHPort != 22 {
		rules := abstract.SecurityGroupRules{
			{
				Description: "[ingress][ipv4][tcp] Temporary Allow SSH",
				Direction:   securitygroupruledirection.Ingress,
				PortFrom:    22,
				EtherType:   ipversion.IPv4,
				Protocol:    "tcp",
				Sources:     []string{"0.0.0.0/0"},
				Targets:     []string{sg.GetID()},
			},
			{
				Description: "[ingress][ipv6][tcp] Temporary Allow SSH",
				Direction:   securitygroupruledirection.Ingress,
				PortFrom:    22,
				EtherType:   ipversion.IPv6,
				Protocol:    "tcp",
				Sources:     []string{"::/0"},
				Targets:     []string{sg.GetID()},
			},
		}
		xerr = sg.AddRules(ctx, rules)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}

	return sg, nil
}

// createPublicIPSecurityGroup creates a Security Group to be applied to host of the Subnet with public IP that is not a gateway
func (instance *Subnet) createPublicIPSecurityGroup(
	ctx context.Context, networkID, networkName string, keepOnFailure bool,
) (_ resources.SecurityGroup, ferr fail.Error) {
	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetPublicIPSecurityGroupNamePattern, instance.GetName(), networkName)

	var sgInstance resources.SecurityGroup
	var xerr fail.Error

	sgInstance, xerr = NewSecurityGroup(instance.Service())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetPublicIPSecurityGroupDescriptionPattern, instance.GetName(), networkName)
	xerr = sgInstance.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if ferr != nil && !keepOnFailure {
			if derr := sgInstance.Delete(context.Background(), true); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(ferr), sgName))
			}
		}
	}()

	rules := abstract.SecurityGroupRules{
		{
			Description: "[egress][ipv4][all] Allow everything",
			Direction:   securitygroupruledirection.Egress,
			EtherType:   ipversion.IPv4,
			Sources:     []string{sgInstance.GetID()},
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: "[egress][ipv6][all] Allow everything",
			Direction:   securitygroupruledirection.Egress,
			EtherType:   ipversion.IPv6,
			Sources:     []string{sgInstance.GetID()},
			Targets:     []string{"::0/0"},
		},
	}
	xerr = sgInstance.AddRules(ctx, rules)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance, nil
}

// Starting from here, delete the Security Group if exiting with error
func (instance *Subnet) undoCreateSecurityGroup(errorPtr *fail.Error, keepOnFailure bool, sg resources.SecurityGroup) {
	if errorPtr == nil {
		logrus.Errorf("trying to undo an action based on the content of a nil fail.Error; undo cannot be run") // FIXME: return error
		return
	}
	if *errorPtr != nil && !keepOnFailure {
		sgName := sg.GetName()
		if derr := sg.Delete(context.Background(), true); derr != nil {
			_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove Security Group for gateways '%s' of Subnet '%s'", ActionFromError(*errorPtr), sgName, instance.GetName()))
		}
	}
}

// Creates a Security Group to be applied on Hosts in Subnet to allow internal access
func (instance *Subnet) createInternalSecurityGroup(
	ctx context.Context, networkID, networkName string, keepOnFailure bool,
) (_ resources.SecurityGroup, ferr fail.Error) {
	sgName := fmt.Sprintf(subnetInternalSecurityGroupNamePattern, instance.GetName(), networkName)

	cidr, xerr := instance.unsafeGetCIDR()
	if xerr != nil {
		return nil, xerr
	}

	var sg resources.SecurityGroup
	sg, xerr = NewSecurityGroup(instance.Service())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetInternalSecurityGroupDescriptionPattern, instance.GetName(), networkName)
	xerr = sg.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if ferr != nil && !keepOnFailure {
			if derr := sg.Delete(context.Background(), true); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove Security Group '%s'", ActionFromError(ferr), sgName))
			}
		}
	}()

	// adds rules that depends on Security Group ID
	rules := abstract.SecurityGroupRules{
		{
			Description: fmt.Sprintf("[egress][ipv4][all] Allow all from %s", cidr),
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.Egress,
			Sources:     []string{sg.GetID()},
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: fmt.Sprintf("[egress][ipv6][all] Allow all from %s", cidr),
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Egress,
			Sources:     []string{sg.GetID()},
			Targets:     []string{"::0/0"},
		},
		{
			Description: fmt.Sprintf("[ingress][ipv4][all] Allow LAN traffic in %s", cidr),
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.Ingress,
			Sources:     []string{sg.GetID()},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: fmt.Sprintf("[ingress][ipv6][all] Allow LAN traffic in %s", cidr),
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Sources:     []string{sg.GetID()},
			Targets:     []string{sg.GetID()},
		},
	}
	xerr = sg.AddRules(ctx, rules)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return sg, nil
}

func (instance *Subnet) unsafeCreateSubnet(ctx context.Context, req abstract.SubnetRequest) (ferr fail.Error) {
	if req.CIDR == "" {
		return fail.InvalidRequestError("invalid empty string value for 'req.CIDR'")
	}

	networkInstance, abstractNetwork, xerr := instance.validateNetwork(ctx, &req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Check if Subnet already exists and is managed by SafeScale
	xerr = instance.checkUnicity(ctx, req)
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

	svc := instance.Service()
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
		if ferr != nil && abstractSubnet != nil && !req.KeepOnFailure {
			if derr := instance.deleteSubnetThenWaitCompletion(abstractSubnet.ID); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", ActionFromError(ferr)))
			}
		}
	}()

	// Write Subnet object metadata and updates the service cache
	xerr = instance.Carry(ctx, abstractSubnet)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Starting from here, delete Subnet metadata if exiting with error
	defer func() {
		if ferr != nil && !req.KeepOnFailure {
			if derr := instance.MetadataCore.Delete(); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet metadata", ActionFromError(ferr)))
			}
		}
	}()

	xerr = instance.updateCachedInformation(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if req.DefaultSSHPort == 0 {
		req.DefaultSSHPort = 22
	}

	if req.DefaultSSHPort == 0 {
		req.DefaultSSHPort = 22
	}

	subnetGWSG, subnetInternalSG, subnetPublicIPSG, xerr := instance.unsafeCreateSecurityGroups(ctx, networkInstance, req.KeepOnFailure, int32(req.DefaultSSHPort))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if ferr != nil && !req.KeepOnFailure {
			derr := instance.deleteSecurityGroups(context.Background(), [3]string{subnetGWSG.GetID(), subnetInternalSG.GetID(), subnetPublicIPSG.GetID()})
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Groups"))
			}
		}
	}()

	caps, xerr := svc.GetCapabilities()
	if xerr != nil {
		return xerr
	}
	failover := req.HA
	if failover {
		if caps.PrivateVirtualIP {
			logrus.Info("Driver support private Virtual IP, honoring the failover setup for gateways.")
		} else {
			logrus.Warnf("Driver does not support private Virtual IP, cannot set up failover of Subnet default route.")
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
			if ferr != nil && abstractSubnet != nil && abstractSubnet.VIP != nil && !req.KeepOnFailure {
				if derr := svc.DeleteVIP(abstractSubnet.VIP); derr != nil {
					_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete VIP", ActionFromError(ferr)))
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
		if ferr != nil && !req.KeepOnFailure {
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
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to detach Subnet from Network", ActionFromError(ferr)))
			}
		}
	}()

	return nil
}

func (instance *Subnet) unsafeUpdateSubnetStatus(ctx context.Context, target subnetstate.Enum) fail.Error {
	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		as.State = target
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return instance.updateCachedInformation(task.Context())
}

func (instance *Subnet) unsafeFinalizeSubnetCreation(ctx context.Context) fail.Error {
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

	return instance.updateCachedInformation(ctx)
}

func (instance *Subnet) unsafeCreateGateways(ctx context.Context, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements, sgs map[string]struct{}) (ferr fail.Error) {
	svc := instance.Service()
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

			if imageQuery == "" {
				imageQuery = consts.DEFAULTOS
			}
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
						img = aimg
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
		DiskSize:         gwSizing.MinDiskSize,
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
		abErr := tg.AbortWithCause(xerr)
		if abErr != nil {
			logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
		}
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
			abErr := tg.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
			}
		}
	}

	results, groupXErr := tg.WaitGroup()
	groupXErr = debug.InjectPlannedFail(groupXErr)
	if groupXErr != nil {
		return groupXErr
	}
	if results == nil {
		return fail.InconsistentError("task results shouldn't be nil")
	}

	id, xerr := primaryTask.ID()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// handle primary gateway
	{
		var content concurrency.TaskResult
		var ok bool

		if content, ok = results[id]; !ok {
			return fail.InconsistentError("task results does not contain %s", id)
		}
		if content == nil {
			return fail.InconsistentError("task result with %s should not be nil", id)
		}

		result, ok := results[id].(data.Map)
		if !ok {
			return fail.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(results[id]).String())
		}

		{
			primaryGateway, ok = result["host"].(*Host)
			if !ok {
				return fail.InconsistentError("result[host] should be a *Host")
			}
			primaryUserdata, ok = result["userdata"].(*userdata.Content)
			if !ok {
				return fail.InconsistentError("result[userdata] should be a *userdata.Content")
			}
			primaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

			// delete primary gateway if something fails
			{
				// Starting from here, deletes the primary gateway if exiting with error
				defer func() {
					if ferr != nil && !req.KeepOnFailure {
						logrus.Warnf("Cleaning up on failure, deleting gateway '%s'... because of '%s'", primaryGateway.GetName(), ferr.Error())
						derr := primaryGateway.RelaxedDeleteHost(context.Background())
						derr = debug.InjectPlannedFail(derr)
						if derr != nil {
							switch derr.(type) {
							case *fail.ErrTimeout:
								logrus.Warnf("We should have waited more...") // FIXME: Wait until gateway no longer exists
							default:
							}
							_ = ferr.AddConsequence(derr)
						} else {
							logrus.Debugf("Cleaning up on failure, gateway '%s' deleted", primaryGateway.GetName())
						}
						if req.HA {
							if derr := instance.unbindHostFromVIP(as.VIP, primaryGateway); derr != nil {
								_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind VIP from gateway", ActionFromError(ferr)))
							}
						}
					}
				}()

				defer instance.undoBindInternalSecurityGroupToGateway(context.Background(), primaryGateway, req.KeepOnFailure, &ferr)

				// Bind Internal Security Group to gateway
				xerr = instance.bindInternalSecurityGroupToGateway(ctx, primaryGateway)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}
		}
	}

	if req.HA {
		id, xerr := secondaryTask.ID()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		var content concurrency.TaskResult
		var ok bool
		if content, ok = results[id]; !ok {
			return fail.InconsistentError("task results does not contain %s", id)
		}
		if content == nil {
			return fail.InconsistentError("task result with %s should not be nil", id)
		}

		result, ok := results[id].(data.Map)
		if !ok {
			xerr = fail.InconsistentError("'data.Map' expected, '%s' provided", reflect.TypeOf(results[id]).String())
			return xerr
		}

		// else is toxic
		{
			var ok bool
			secondaryGateway, ok = result["host"].(*Host)
			if !ok {
				return fail.InconsistentError("result[host] should be a *Host")
			}
			secondaryUserdata, ok = result["userdata"].(*userdata.Content)
			if !ok {
				return fail.InvalidParameterError("result[userdata] shoulde be a *userdate.Content")
			}
			secondaryUserdata.GatewayHAKeepalivedPassword = keepalivedPassword

			// Starting from here, deletes the secondary gateway if exiting with error
			defer func() {
				if ferr != nil && !req.KeepOnFailure {
					derr := secondaryGateway.RelaxedDeleteHost(context.Background())
					derr = debug.InjectPlannedFail(derr)
					if derr != nil {
						switch derr.(type) {
						case *fail.ErrTimeout:
							logrus.Warnf("We should have waited more") // FIXME: Wait until gateway no longer exists
						default:
						}
						_ = ferr.AddConsequence(derr)
					}
					derr = instance.unbindHostFromVIP(as.VIP, secondaryGateway)
					derr = debug.InjectPlannedFail(derr)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind VIP from gateway", ActionFromError(ferr)))
					}
				}
			}()

			defer instance.undoBindInternalSecurityGroupToGateway(context.Background(), secondaryGateway, req.KeepOnFailure, &ferr)
			// Bind Internal Security Group to gateway

			xerr = instance.bindInternalSecurityGroupToGateway(ctx, secondaryGateway)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	// Update userdata of gateway(s)
	xerr = instance.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) (innerXErr fail.Error) {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

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
		abErr := tg.AbortWithCause(xerr)
		if abErr != nil {
			logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
		}
	}

	if req.HA {
		_, xerr = tg.Start(instance.taskFinalizeGatewayConfiguration, taskFinalizeGatewayConfigurationParameters{
			host:     secondaryGateway,
			userdata: secondaryUserdata,
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			abErr := tg.AbortWithCause(xerr)
			if abErr != nil {
				logrus.Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
			}
		}
	}

	_, xerr = tg.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "error finalizing gateway configuration")
	}

	return nil
}

// unsafeUnbindSecurityGroup unbinds a security group from the host
func (instance *Subnet) unsafeUnbindSecurityGroup(ctx context.Context, sgInstance resources.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.subnet"), "(%s)", sgInstance.GetID()).Entering()
	defer tracer.Exiting()

	// -- Unbind Security Group from Subnet and attached Hosts
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		var subnetHosts *propertiesv1.SubnetHosts
		innerXErr := props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			subnetHosts, ok = clonable.(*propertiesv1.SubnetHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(subnetproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			ssgV1, ok := clonable.(*propertiesv1.SubnetSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SubnetSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sgInstance.GetID()
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
			sgInstanceImpl, ok := sgInstance.(*SecurityGroup)
			if !ok {
				return fail.InconsistentError("failed to cast sgInstance to '*SecurityGroup'")
			}

			innerXErr := sgInstanceImpl.unbindFromSubnetHosts(ctx, taskUnbindFromHostsAttachedToSubnetParams{subnetID: instance.GetID(), subnetName: instance.GetName(), subnetHosts: subnetHosts})
			if innerXErr != nil {
				return innerXErr
			}

			// updates the metadata
			delete(ssgV1.ByID, sgID)
			delete(ssgV1.ByName, sgInstance.GetName())
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// -- Remove Subnet reference in Security Group
	return sgInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
			sgsV1, ok := clonable.(*propertiesv1.SecurityGroupSubnets)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupSubnets' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			delete(sgsV1.ByID, instance.GetID())
			delete(sgsV1.ByName, instance.GetName())
			return nil
		})
	})
}
