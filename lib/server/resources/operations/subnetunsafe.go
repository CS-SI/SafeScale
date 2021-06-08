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
	"reflect"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetstate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/sirupsen/logrus"
)

// UnsafeInspectGateway returns the gateway related to Subnet
// Note: a write lock of the instance (instance.lock.Lock() ) must have been called before calling this method
func (instance *Subnet) UnsafeInspectGateway(primary bool) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	gwIdx := 0
	if !primary {
		gwIdx = 1
	}
	out := instance.gateways[gwIdx]
	if out == nil {
		xerr = instance.updateCachedInformation()
		if xerr != nil {
			return nil, xerr
		}
	}
	out = instance.gateways[gwIdx]
	if out == nil {
		return nil, fail.NotFoundError("failed to find gateway")
	}

	return out, nil
}

// UnsafeGetDefaultRouteIP ...
func (instance *Subnet) UnsafeGetDefaultRouteIP() (ip string, xerr fail.Error) {
	ip = ""
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if as.VIP != nil && as.VIP.PrivateIP != "" {
			ip = as.VIP.PrivateIP
			return nil
		}
		if len(as.GatewayIDs) > 0 {
			rh, innerErr := LoadHost(instance.GetService(), as.GatewayIDs[0])
			if innerErr != nil {
				return innerErr
			}
			defer rh.Released()

			ip, xerr = rh.GetPrivateIP()
			if xerr != nil {
				return xerr
			}
			return nil
		}

		return fail.NotFoundError("failed to find default route IP: no gateway defined")
	})
	return ip, xerr

}

// unsafeGetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (instance *Subnet) unsafeGetVirtualIP() (vip *abstract.VirtualIP, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	xerr = instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (instance *Subnet) unsafeGetCIDR() (cidr string, xerr fail.Error) {
	cidr = ""
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
func (instance *Subnet) unsafeGetState() (state subnetstate.Enum, xerr fail.Error) {
	xerr = instance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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

func (instance *Subnet) UnsafeCreateSecurityGroups(ctx context.Context, networkInstance resources.Network, keepOnFailure bool) (subnetGWSG, subnetInternalSG, subnetPublicIPSG resources.SecurityGroup, xerr fail.Error) {
	subnetGWSG, xerr = instance.createGWSecurityGroup(ctx, networkInstance, keepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	defer instance.undoCreateSecurityGroup(&xerr, keepOnFailure, subnetGWSG)

	subnetPublicIPSG, xerr = instance.createPublicIPSecurityGroup(ctx, networkInstance, keepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	defer instance.undoCreateSecurityGroup(&xerr, keepOnFailure, subnetPublicIPSG)

	subnetInternalSG, xerr = instance.createInternalSecurityGroup(ctx, networkInstance, keepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	defer instance.undoCreateSecurityGroup(&xerr, keepOnFailure, subnetInternalSG)

	xerr = subnetGWSG.BindToSubnet(ctx, instance, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}
	defer func() {
		if xerr != nil && !keepOnFailure {
			if derr := subnetGWSG.UnbindFromSubnet(context.Background(), instance); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group for gateways from Subnet", ActionFromError(xerr)))
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

// createGWSecurityGroup creates a Security Group to be applied to gateways of the Subnet
func (instance *Subnet) createGWSecurityGroup(ctx context.Context, network resources.Network, keepOnFailure bool) (_ resources.SecurityGroup, xerr fail.Error) {
	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetGWSecurityGroupNamePattern, instance.GetName(), network.GetName())

	var sg resources.SecurityGroup
	sg, xerr = NewSecurityGroup(instance.GetService())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetGWSecurityGroupDescriptionPattern, instance.GetName(), network.GetName())
	xerr = sg.Create(ctx, network.GetID(), sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !keepOnFailure {
			if derr := sg.Delete(context.Background(), true); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(xerr), sgName))
			}
		}
	}()

	rules := abstract.SecurityGroupRules{
		{
			Description: "[ingress][ipv4][tcp] Allow SSH",
			Direction:   securitygroupruledirection.Ingress,
			PortFrom:    22,
			EtherType:   ipversion.IPv4,
			Protocol:    "tcp",
			Sources:     []string{"0.0.0.0/0"},
			Targets:     []string{sg.GetID()},
		},
		{
			Description: "[ingress][ipv6][tcp] Allow SSH",
			Direction:   securitygroupruledirection.Ingress,
			PortFrom:    22,
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

	return sg, nil
}

// createPublicIPSecurityGroup creates a Security Group to be applied to host of the Subnet with public IP that is not a gateway
func (instance *Subnet) createPublicIPSecurityGroup(ctx context.Context, network resources.Network, keepOnFailure bool) (_ resources.SecurityGroup, xerr fail.Error) {
	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetPublicIPSecurityGroupNamePattern, instance.GetName(), network.GetName())

	var sg resources.SecurityGroup
	sg, xerr = NewSecurityGroup(instance.GetService())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetPublicIPSecurityGroupDescriptionPattern, instance.GetName(), network.GetName())
	xerr = sg.Create(ctx, network.GetID(), sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !keepOnFailure {
			if derr := sg.Delete(context.Background(), true); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(xerr), sgName))
			}
		}
	}()

	rules := abstract.SecurityGroupRules{
		{
			Description: "[egress][ipv4][all] Allow everything",
			Direction:   securitygroupruledirection.Egress,
			EtherType:   ipversion.IPv4,
			Sources:     []string{sg.GetID()},
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: "[egress][ipv6][all] Allow everything",
			Direction:   securitygroupruledirection.Egress,
			EtherType:   ipversion.IPv6,
			Sources:     []string{sg.GetID()},
			Targets:     []string{"::0/0"},
		},
	}
	xerr = sg.AddRules(ctx, rules)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return sg, nil
}

// Starting from here, delete the Security Group if exiting with error
func (instance *Subnet) undoCreateSecurityGroup(errorPtr *fail.Error, keepOnFailure bool, sg resources.SecurityGroup) {
	if errorPtr == nil {
		logrus.Errorf("trying to undo an action based on the content of a nil fail.Error; undo cannot be run")
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
func (instance *Subnet) createInternalSecurityGroup(ctx context.Context, network resources.Network, keepOnFailure bool) (_ resources.SecurityGroup, xerr fail.Error) {
	sgName := fmt.Sprintf(subnetInternalSecurityGroupNamePattern, instance.GetName(), network.GetName())

	cidr, xerr := instance.unsafeGetCIDR()
	if xerr != nil {
		return nil, xerr
	}

	var sg resources.SecurityGroup
	sg, xerr = NewSecurityGroup(instance.GetService())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetInternalSecurityGroupDescriptionPattern, instance.GetName(), network.GetName())
	xerr = sg.Create(ctx, network.GetID(), sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !keepOnFailure {
			if derr := sg.Delete(context.Background(), true); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove Security Group '%s'", ActionFromError(xerr), sgName))
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
