package resources

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	subnetTransaction     = *subnetTransactionImpl
	subnetTransactionImpl struct {
		metadata.Transaction[*abstract.Subnet, *Subnet]
	}
)

func newSubnetTransaction(ctx context.Context, instance *Subnet) (subnetTransaction, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("instance")
	}

	trx, xerr := metadata.NewTransaction[*abstract.Subnet, *Subnet](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &subnetTransactionImpl{trx}, nil
}

func inspectSubnetMetadata(ctx context.Context, trx subnetTransaction, callback func(*abstract.Subnet, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Subnet](ctx, trx, callback)
}

func inspectSubnetMetadataAbstract(ctx context.Context, trx subnetTransaction, callback func(*abstract.Subnet) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.Subnet](ctx, trx, callback)
}

func inspectSubnetMetadataProperty[P clonable.Clonable](ctx context.Context, trx subnetTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Subnet, P](ctx, trx, property, callback)
}

func inspectSubnetMetadataProperties(ctx context.Context, trx subnetTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Subnet](ctx, trx, callback)
}

func alterSubnetMetadata(ctx context.Context, trx subnetTransaction, callback func(*abstract.Subnet, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.Subnet](ctx, trx, callback)
}

func alterSubnetMetadataAbstract(ctx context.Context, trx subnetTransaction, callback func(*abstract.Subnet) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.Subnet](ctx, trx, callback)
}

func alterSubnetMetadataProperty[P clonable.Clonable](ctx context.Context, trx subnetTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Subnet, P](ctx, trx, property, callback)
}

func alterSubnetMetadataProperties(ctx context.Context, trx subnetTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Subnet](ctx, trx, callback)
}

// IsNull ...
func (subnetTrx *subnetTransactionImpl) IsNull() bool {
	return subnetTrx == nil || subnetTrx.Transaction.IsNull()
}

// GetDefaultRouteIP ...
func (subnetTrx *subnetTransactionImpl) GetDefaultRouteIP(ctx context.Context) (_ string, ferr fail.Error) {
	if valid.IsNull(subnetTrx) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	var ip string
	xerr := inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
		if as.VIP != nil && as.VIP.PrivateIP != "" {
			ip = as.VIP.PrivateIP
			return nil
		}
		if len(as.GatewayIDs) > 0 {
			hostInstance, innerErr := LoadHost(ctx, as.GatewayIDs[0])
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

// GetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (subnetTrx *subnetTransactionImpl) GetVirtualIP(ctx context.Context) (vip *abstract.VirtualIP, ferr fail.Error) {
	if valid.IsNull(subnetTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	subnetName := subnetTrx.GetName()
	xerr := inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
		vip = as.VIP
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "cannot get Subnet virtual IP")
	}
	if vip == nil {
		return nil, fail.NotFoundError("failed to find Virtual IP bound to gateways for Subnet '%s'", subnetName)
	}

	return vip, nil
}

// GetCIDR returns the CIDR of the network
func (subnetTrx *subnetTransactionImpl) GetCIDR(ctx context.Context) (cidr string, ferr fail.Error) {
	if valid.IsNull(subnetTrx) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	cidr = ""
	return cidr, inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
		cidr = as.CIDR
		return nil
	})
}

// GetState returns the state of the network
func (subnetTrx *subnetTransactionImpl) GetState(ctx context.Context) (subnetstate.Enum, fail.Error) {
	state := subnetstate.Unknown
	if valid.IsNull(subnetTrx) {
		return state, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return state, fail.InvalidParameterCannotBeNilError("ctx")
	}

	xerr := inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
		state = as.State
		return nil
	})
	return state, xerr
}

// AbandonHost ...
func (subnetTrx *subnetTransactionImpl) AbandonHost(ctx context.Context, hostID string) fail.Error {
	if valid.IsNull(subnetTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	return alterSubnetMetadataProperty(ctx, subnetTrx, subnetproperty.HostsV1, func(shV1 *propertiesv1.SubnetHosts) fail.Error {
		hostName, found := shV1.ByID[hostID]
		if found {
			delete(shV1.ByName, hostName)
			delete(shV1.ByID, hostID)
		}
		return nil
	})
}

// HasVirtualIP tells if the Subnet uses a VIP as default route
func (subnetTrx *subnetTransactionImpl) HasVirtualIP(ctx context.Context) (bool, fail.Error) {
	if valid.IsNull(subnetTrx) {
		return false, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return false, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var found bool
	xerr := inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
		found = as.VIP != nil
		return nil
	})
	return found, xerr
}

// CreateSecurityGroups creates the 3 Security Groups needed by a Subnet
// 'ctx' may contain value "CurrentNetworkTransactionContextKey" of type networkTransaction, that may be used by SecurityGroup.Create() not to try to Alter Network directly (might be inside a code already altering it)
func (subnetTrx *subnetTransactionImpl) CreateSecurityGroups(inctx context.Context, networkTrx networkTransaction, cidr string, keepOnFailure bool, defaultSSHPort int32) (sa, sb, sc *SecurityGroup, gerr fail.Error) {
	if valid.IsNull(subnetTrx) {
		return nil, nil, nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, nil, nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if networkTrx == nil {
		return nil, nil, nil, fail.InvalidParameterCannotBeNilError("networkTrx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		a, b, c *SecurityGroup
		rErr    fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			var (
				abstractSubnet *abstract.Subnet
				subnetHosts    *propertiesv1.SubnetHosts
			)
			xerr := inspectSubnetMetadata(ctx, subnetTrx, func(as *abstract.Subnet, props *serialize.JSONProperties) fail.Error {
				abstractSubnet = as

				return props.Inspect(subnetproperty.HostsV1, func(p clonable.Clonable) fail.Error {
					var innerErr error
					subnetHosts, innerErr = clonable.Cast[*propertiesv1.SubnetHosts](p)
					return fail.Wrap(innerErr)
				})
			})
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}

			subnetGWSG, subnetGWSGTrx, xerr := subnetTrx.createGWSecurityGroup(ctx, networkTrx, keepOnFailure, defaultSSHPort)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				subnetGWSGTrx.TerminateFromError(ctx, &ferr)

				derr := subnetTrx.undoCreateSecurityGroup(cleanupContextFrom(ctx), &ferr, keepOnFailure, subnetGWSG)
				if derr != nil {
					logrus.WithContext(ctx).Warnf(derr.Error())
				}
			}()

			subnetPublicIPSG, subnetPublicIPSGTrx, xerr := subnetTrx.createPublicIPSecurityGroup(ctx, networkTrx, keepOnFailure)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				subnetPublicIPSGTrx.TerminateFromError(ctx, &ferr)

				derr := subnetTrx.undoCreateSecurityGroup(cleanupContextFrom(ctx), &ferr, keepOnFailure, subnetPublicIPSG)
				if derr != nil {
					logrus.WithContext(ctx).Warnf(derr.Error())
				}
			}()

			subnetInternalSG, subnetInternalSGTrx, xerr := subnetTrx.createInternalSecurityGroup(ctx, networkTrx, cidr, keepOnFailure)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				subnetInternalSGTrx.TerminateFromError(ctx, &ferr)

				derr := subnetTrx.undoCreateSecurityGroup(cleanupContextFrom(ctx), &ferr, keepOnFailure, subnetInternalSG)
				if derr != nil {
					logrus.WithContext(ctx).Warnf(derr.Error())
				}
			}()

			xerr = subnetGWSGTrx.BindToSubnet(ctx, abstractSubnet, subnetHosts, SecurityGroupEnable, KeepCurrentSecurityGroupMark)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					if derr := subnetGWSGTrx.UnbindFromSubnet(cleanupContextFrom(ctx), subnetTrx); derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group for gateways from Subnet", ActionFromError(ferr)))
					}
				}
			}()

			xerr = subnetPublicIPSGTrx.BindToSubnet(ctx, abstractSubnet, subnetHosts, SecurityGroupEnable, KeepCurrentSecurityGroupMark)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					if derr := subnetPublicIPSGTrx.UnbindFromSubnet(cleanupContextFrom(ctx), subnetTrx); derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group for gateways from Subnet", ActionFromError(ferr)))
					}
				}
			}()

			xerr = subnetInternalSGTrx.BindToSubnet(ctx, abstractSubnet, subnetHosts, SecurityGroupEnable, MarkSecurityGroupAsDefault)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}

			ar := result{subnetGWSG, subnetInternalSG, subnetPublicIPSG, nil}
			return ar, ar.rErr
		}()
		chRes <- gres
	}() // nolint

	select {
	case res := <-chRes:
		return res.a, res.b, res.c, res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer
		return nil, nil, nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer
		return nil, nil, nil, fail.Wrap(inctx.Err())
	}
}

// createGWSecurityGroup creates a Security Group that will be applied to gateways of the Subnet
func (subnetTrx *subnetTransactionImpl) createGWSecurityGroup(ctx context.Context, networkTrx networkTransaction, keepOnFailure bool, defaultSSHPort int32) (_ *SecurityGroup, _ securityGroupTransaction, ferr fail.Error) {
	networkName := networkTrx.GetName()
	networkID, err := networkTrx.GetID()
	if err != nil {
		return nil, nil, fail.Wrap(err)
	}

	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetGWSecurityGroupNamePattern, subnetTrx.GetName(), networkName)

	sgInstance, xerr := NewSecurityGroup(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	description := fmt.Sprintf(subnetGWSecurityGroupDescriptionPattern, subnetTrx.GetName(), networkName)
	xerr = sgInstance.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !keepOnFailure {
			derr := sgInstance.Delete(cleanupContextFrom(ctx), true)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Security Group '%s'", ActionFromError(ferr), sgName))
			}
		}
	}()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return nil, nil, xerr
	}
	defer func() {
		if ferr != nil {
			sgTrx.TerminateFromError(ctx, &ferr)
		}
	}()

	sgid, err := sgTrx.GetID()
	if err != nil {
		return nil, nil, fail.Wrap(err)
	}

	xerr = sgTrx.Clear(ctx)
	if xerr != nil {
		return nil, nil, xerr
	}

	rules := abstract.SecurityGroupRules{
		{
			Description: "[ingress][ipv4][tcp] Allow SSH",
			Direction:   securitygroupruledirection.Ingress,
			PortFrom:    defaultSSHPort,
			EtherType:   ipversion.IPv4,
			Protocol:    "tcp",
			Sources:     []string{"0.0.0.0/0"},
			Targets:     []string{sgid},
		},
		{
			Description: "[ingress][ipv6][tcp] Allow SSH",
			Direction:   securitygroupruledirection.Ingress,
			PortFrom:    defaultSSHPort,
			EtherType:   ipversion.IPv6,
			Protocol:    "tcp",
			Sources:     []string{"::/0"},
			Targets:     []string{sgid},
		},
		{
			Description: "[ingress][ipv4][icmp] Allow everything",
			Direction:   securitygroupruledirection.Ingress,
			EtherType:   ipversion.IPv4,
			Protocol:    "icmp",
			Sources:     []string{"0.0.0.0/0"},
			Targets:     []string{sgid},
		},
		{
			Description: "[ingress][ipv6][icmp] Allow everything",
			Direction:   securitygroupruledirection.Ingress,
			EtherType:   ipversion.IPv6,
			Protocol:    "icmp",
			Sources:     []string{"::/0"},
			Targets:     []string{sgid},
		},
	}
	if defaultSSHPort != 22 {
		tempSSHRules := abstract.SecurityGroupRules{
			{
				Description: "[ingress][ipv4][tcp] Temporary Allow SSH",
				Direction:   securitygroupruledirection.Ingress,
				PortFrom:    22,
				EtherType:   ipversion.IPv4,
				Protocol:    "tcp",
				Sources:     []string{"0.0.0.0/0"},
				Targets:     []string{sgid},
			},
			{
				Description: "[ingress][ipv6][tcp] Temporary Allow SSH",
				Direction:   securitygroupruledirection.Ingress,
				PortFrom:    22,
				EtherType:   ipversion.IPv6,
				Protocol:    "tcp",
				Sources:     []string{"::/0"},
				Targets:     []string{sgid},
			},
		}
		rules = append(rules, tempSSHRules...)
	}
	xerr = sgTrx.AddRules(ctx, rules...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	return sgInstance, sgTrx, nil
}

// trxCreatePublicIPSecurityGroup creates a Security Group to be applied to host of the Subnet with public IP that is not a gateway
func (subnetTrx *subnetTransactionImpl) createPublicIPSecurityGroup(ctx context.Context, networkTrx networkTransaction, keepOnFailure bool) (_ *SecurityGroup, _ securityGroupTransaction, ferr fail.Error) {
	networkName := networkTrx.GetName()
	networkID, err := networkTrx.GetID()
	if err != nil {
		return nil, nil, fail.Wrap(err)
	}

	subnetName := subnetTrx.GetName()

	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetPublicIPSecurityGroupNamePattern, subnetName, networkName)
	sgInstance, xerr := NewSecurityGroup(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	description := fmt.Sprintf(subnetPublicIPSecurityGroupDescriptionPattern, subnetName, networkName)
	xerr = sgInstance.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !keepOnFailure {
			derr := sgInstance.Delete(cleanupContextFrom(ctx), true)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Security Group '%s'", ActionFromError(ferr), sgName))
			}
		}
	}()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return nil, nil, xerr
	}
	defer func() {
		if ferr != nil {
			sgTrx.TerminateFromError(ctx, &ferr)
		}
	}()

	sgid, err := sgTrx.GetID()
	if err != nil {
		return nil, nil, fail.Wrap(err)
	}

	rules := abstract.SecurityGroupRules{
		{
			Description: "[egress][ipv4][all] Allow everything",
			Direction:   securitygroupruledirection.Egress,
			EtherType:   ipversion.IPv4,
			Sources:     []string{sgid},
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: "[egress][ipv6][all] Allow everything",
			Direction:   securitygroupruledirection.Egress,
			EtherType:   ipversion.IPv6,
			Sources:     []string{sgid},
			Targets:     []string{"::0/0"},
		},
	}
	xerr = sgTrx.AddRules(ctx, rules...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	return sgInstance, sgTrx, nil
}

// Starting from here, Delete the Security Group if exiting with error
func (subnetTrx *subnetTransactionImpl) undoCreateSecurityGroup(ctx context.Context, errorPtr *fail.Error, keepOnFailure bool, sg *SecurityGroup) fail.Error {
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if errorPtr == nil {
		return fail.NewError("trying to undo an action based on the content of a nil fail.Error; undo cannot be run")
	}

	if *errorPtr != nil && !keepOnFailure {
		sgName := sg.GetName()
		derr := sg.Delete(ctx, true)
		if derr != nil {
			_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove Security Group for gateways '%s' of Subnet '%s'", ActionFromError(*errorPtr), sgName, subnetTrx.GetName()))
		}
	}
	return nil
}

// Creates a Security Group to be applied on Hosts in Subnet to allow internal access
func (subnetTrx *subnetTransactionImpl) createInternalSecurityGroup(ctx context.Context, networkTrx networkTransaction, cidr string, keepOnFailure bool) (_ *SecurityGroup, _ securityGroupTransaction, ferr fail.Error) {
	networkName := networkTrx.GetName()
	networkID, err := networkTrx.GetID()
	if err != nil {
		return nil, nil, fail.Wrap(err)
	}

	subnetName := subnetTrx.GetName()
	sgName := fmt.Sprintf(subnetInternalSecurityGroupNamePattern, subnetName, networkName)
	sgInstance, xerr := NewSecurityGroup(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	description := fmt.Sprintf(subnetInternalSecurityGroupDescriptionPattern, subnetName, networkName)
	xerr = sgInstance.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !keepOnFailure {
			derr := sgInstance.Delete(cleanupContextFrom(ctx), true)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove Security Group '%s'", ActionFromError(ferr), sgName))
			}
		}
	}()

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return nil, nil, xerr
	}
	defer func() {
		if ferr != nil {
			sgTrx.TerminateFromError(ctx, &ferr)
		}
	}()

	sgid, err := sgTrx.GetID()
	if err != nil {
		return nil, nil, fail.Wrap(err)
	}

	// adds rules that depend on Security Group ID
	rules := abstract.SecurityGroupRules{
		{
			Description: fmt.Sprintf("[egress][ipv4][all] Allow all from %s", cidr),
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.Egress,
			Sources:     []string{sgid},
			Targets:     []string{"0.0.0.0/0"},
		},
		{
			Description: fmt.Sprintf("[egress][ipv6][all] Allow all from %s", cidr),
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Egress,
			Sources:     []string{sgid},
			Targets:     []string{"::0/0"},
		},
		{
			Description: fmt.Sprintf("[ingress][ipv4][all] Allow LAN traffic in %s", cidr),
			EtherType:   ipversion.IPv4,
			Direction:   securitygroupruledirection.Ingress,
			Sources:     []string{sgid},
			Targets:     []string{sgid},
		},
		{
			Description: fmt.Sprintf("[ingress][ipv6][all] Allow LAN traffic in %s", cidr),
			EtherType:   ipversion.IPv6,
			Direction:   securitygroupruledirection.Ingress,
			Sources:     []string{sgid},
			Targets:     []string{sgid},
		},
	}
	xerr = sgTrx.AddRules(ctx, rules...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	return sgInstance, sgTrx, nil
}

// BindInternalSecurityGroupToGateway does what its name says
func (subnetTrx *subnetTransactionImpl) BindInternalSecurityGroupToGateway(ctx context.Context, hostTrx hostTransaction) fail.Error {
	if valid.IsNull(subnetTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostTrx == nil {
		return fail.InvalidParameterCannotBeNilError("hostTrx")
	}

	return inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) (innerFErr fail.Error) {
		sg, innerXErr := LoadSecurityGroup(ctx, as.InternalSecurityGroupID)
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to load Subnet '%s' internal Security Group %s", as.Name, as.InternalSecurityGroupID)
		}

		sgTrx, innerXErr := newSecurityGroupTransaction(ctx, sg)
		if innerXErr != nil {
			return innerXErr
		}
		defer sgTrx.TerminateFromError(ctx, &innerFErr)

		innerXErr = sgTrx.BindToHost(ctx, hostTrx, SecurityGroupEnable, MarkSecurityGroupAsSupplemental)
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to apply Subnet '%s' internal Security Group '%s' to Host '%s'", as.Name, sg.GetName(), hostTrx.GetName())
		}

		return nil
	})
}

// undoBindInternalSecurityGroupToGateway does what its name says
func (subnetTrx *subnetTransactionImpl) undoBindInternalSecurityGroupToGateway(ctx context.Context, hostTrx hostTransaction, keepOnFailure bool, errorPtr *fail.Error) (ferr fail.Error) {
	if valid.IsNull(subnetTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostTrx == nil {
		return fail.InvalidParameterCannotBeNilError("hostTrx")
	}

	if errorPtr != nil && *errorPtr != nil && keepOnFailure {
		xerr := inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
			sg, derr := LoadSecurityGroup(ctx, as.InternalSecurityGroupID)
			if derr != nil {
				_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind External Security Group of Subnet '%s' from Host '%s'", as.Name, hostTrx.GetName()))
				return derr
			}

			sgTrx, derr := newSecurityGroupTransaction(ctx, sg)
			if errorPtr != nil {
				_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind External Security Group of Subnet '%s' from Host '%s'", as.Name, hostTrx.GetName()))
				return derr
			}
			defer sgTrx.TerminateFromError(ctx, &ferr)

			derr = sgTrx.UnbindFromHost(ctx, hostTrx)
			if derr != nil {
				_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind External Security Group of Subnet '%s' from Host '%s'", as.Name, hostTrx.GetName()))
				return derr
			}

			return nil
		})
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// deleteSubnetThenWaitCompletion deletes the Subnet identified by 'id' and wait for deletion confirmation
func (subnetTrx *subnetTransactionImpl) deleteSubnetThenWaitCompletion(ctx context.Context) fail.Error {
	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}
	svc := myjob.Service()

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	subnetID, err := subnetTrx.GetID()
	if err != nil {
		return fail.Wrap(xerr)
	}

	// Delete subnet Security Groups
	xerr = inspectSubnetMetadataAbstract(ctx, subnetTrx, func(asg *abstract.Subnet) fail.Error {
		if asg.PublicIPSecurityGroupName != "" {
			sgInstance, innerXErr := LoadSecurityGroup(ctx, asg.PublicIPSecurityGroupName)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError(innerXErr)
				default:
					return innerXErr
				}
			} else {
				innerXErr = sgInstance.Delete(ctx, true)
				if innerXErr != nil {
					return innerXErr
				}
			}
		}

		if asg.InternalSecurityGroupName != "" {
			sgInstance, innerXErr := LoadSecurityGroup(ctx, asg.InternalSecurityGroupName)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError(innerXErr)
				default:
					return innerXErr
				}
			} else {
				innerXErr = sgInstance.Delete(ctx, true)
				if innerXErr != nil {
					return innerXErr
				}
			}
		}

		if asg.GWSecurityGroupName != "" {
			sgInstance, innerXErr := LoadSecurityGroup(ctx, asg.GWSecurityGroupName)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError(innerXErr)
				default:
					return innerXErr
				}
			} else {
				innerXErr = sgInstance.Delete(ctx, true)
				if innerXErr != nil {
					return innerXErr
				}
			}
		}

		return nil
	})
	if xerr != nil {
		return xerr
	}

	// FIXME: OPP List remaining ports and Delete them... If possible otherwise scream

	xerr = svc.DeleteSubnet(ctx, subnetID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If Subnet doesn't exist anymore on the provider infrastructure, do not fail
			debug.IgnoreErrorWithContext(ctx, xerr)
			return nil
		default:
			return xerr
		}
	}
	return retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			_, xerr := svc.InspectSubnet(ctx, subnetID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Subnet not found, good
					debug.IgnoreErrorWithContext(ctx, xerr)
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
}

func (subnetTrx *subnetTransactionImpl) CreateGateway(inctx context.Context, request abstract.HostRequest, sizing abstract.HostSizingRequirements, extra interface{}) (_ data.Map[string, any], _ fail.Error) {
	if valid.IsNil(subnetTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if request.TemplateID == "" {
		return nil, fail.InvalidRequestError("request.TemplateID cannot be empty string")
	}
	if len(request.Subnets) == 0 {
		return nil, fail.InvalidRequestError("request.Networks cannot be an empty '[]*abstract.Network'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	type localresult struct {
		rTr  data.Map[string, any]
		rErr fail.Error
	}
	chRes := make(chan localresult)
	go func() {
		defer close(chRes)

		gres, gerr := func() (_ data.Map[string, any], ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			logrus.WithContext(ctx).Infof("Requesting the creation of gateway '%s' using template ID '%s', template name '%s', with image ID '%s'", request.ResourceName, request.TemplateID, request.TemplateRef, request.ImageID)
			svc := myjob.Service()
			request.PublicIP = true
			request.IsGateway = true

			rgw, xerr := NewHost(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			userData, createXErr := rgw.Create(ctx, request, sizing, extra) // createXErr is tested later

			// Set link to Subnet before testing if Host has been successfully created;
			// in case of failure, we need to have registered the gateway ID in Subnet in case KeepOnFailure is requested, to
			// be able to Delete subnet on later safescale command
			xerr = alterSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				// If Host resources has been created and error occurred after (and KeepOnFailure is requested), rgw.ID() does contain the ID of the Host
				if rgw.IsTaken() {
					id, _ := rgw.GetID()
					if id != "" {
						as.GatewayIDs = append(as.GatewayIDs, id)
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// need to commit right now the changes in Subnet so far
			xerr = subnetTrx.Commit(ctx)
			if xerr != nil {
				return nil, xerr
			}

			// Now test localresult of gateway creation
			if createXErr != nil {
				return nil, createXErr
			}

			// Starting from here, deletes the gateway if exiting with error
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					hid, _ := rgw.GetID()

					if request.CleanOnFailure() {
						ctx := cleanupContextFrom(ctx)
						logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting gateway '%s' Host resource...", request.ResourceName)
						derr := rgw.Delete(ctx)
						if derr != nil {
							msgRoot := "Cleaning up on failure, failed to Delete gateway '%s'"
							switch derr.(type) {
							case *fail.ErrNotFound:
								// missing Host is considered as a successful deletion, continue
								debug.IgnoreErrorWithContext(ctx, derr)
							case *fail.ErrTimeout:
								logrus.WithContext(ctx).Errorf(msgRoot+", timeout: %v", request.ResourceName, derr)
							default:
								logrus.WithContext(ctx).Errorf(msgRoot+": %v", request.ResourceName, derr)
							}
							_ = ferr.AddConsequence(derr)
						} else {
							logrus.WithContext(ctx).Infof("Cleaning up on failure, gateway '%s' deleted", request.ResourceName)
						}
						_ = ferr.AddConsequence(derr)
					} else {
						rgwTrx, derr := newHostTransaction(ctx, rgw)
						if derr == nil {
							defer rgwTrx.TerminateFromError(ctx, &ferr)

							derr = alterHostMetadataAbstract(ctx, rgwTrx, func(as *abstract.HostCore) fail.Error {
								as.LastState = hoststate.Failed
								return nil
							})
							derr = debug.InjectPlannedFail(derr)
							if derr == nil {
								// Need to commit right now to save host state
								derr = rgwTrx.Commit(ctx)
							}
						}
						if derr != nil {
							logrus.WithContext(ctx).Warnf("error marking host '%s' in FAILED state: %v", request.ResourceName, xerr)
							_ = ferr.AddConsequence(derr)
						}
					}

					if hid != "" {
						_ = svc.DeleteHost(cleanupContextFrom(ctx), hid)
					}
				}
			}()

			// Binds gateway to VIP if needed
			xerr = inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				hid, err := rgw.GetID()
				if err != nil {
					return fail.Wrap(err)
				}

				if as != nil && as.VIP != nil {
					xerr = svc.BindHostToVIP(ctx, as.VIP, hid)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return xerr
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			r := data.Map[string, any]{
				"host":     rgw,
				"userdata": userData,
			}
			return r, nil
		}()
		chRes <- localresult{gres, gerr}
	}() // nolint

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer finishes
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer finishes
		return nil, fail.Wrap(inctx.Err())
	}
}

// UnbindSecurityGroups makes sure the security groups bound to Subnet are unbound
func (subnetTrx *subnetTransactionImpl) UnbindSecurityGroups(ctx context.Context, sgs *propertiesv1.SubnetSecurityGroups) (ferr fail.Error) {
	if valid.IsNull(subnetTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgs == nil {
		return fail.InvalidParameterCannotBeNilError("sgs")
	}

	for k := range sgs.ByID {
		sgInstance, xerr := LoadSecurityGroup(ctx, k)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// consider a Security Group not found as a successful unbind
				debug.IgnoreErrorWithContext(ctx, xerr)
			default:
				return xerr
			}
		} else {
			sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
			if xerr != nil {
				return xerr
			}

			xerr = sgTrx.UnbindFromSubnetHosts(ctx, subnetTrx)
			sgTrx.TerminateFromError(ctx, &xerr)
			if xerr != nil {
				return xerr
			}

			// VPL: no need to update SubnetSecurityGroups property, the Subnet is being removed
			// Delete(sgs.ByID, v)
			// Delete(sgs.ByName, k)
		}
	}
	return nil
}
