package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/consts"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupruledirection"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type (
	subnetTransaction = metadata.Transaction[*abstract.Subnet, *Subnet]
)

func newSubnetTransaction(ctx context.Context, instance *Subnet) (subnetTransaction, fail.Error) {
	return metadata.NewTransaction[*abstract.Subnet, *Subnet](ctx, instance)
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

// trxInspectGateway returns the gateway related to Subnet
// Note: you must take a lock (instance.lock.Lock() ) before calling this method
func (instance *Subnet) trxInspectGateway(ctx context.Context, trx subnetTransaction, primary bool) (_ *Host, ferr fail.Error) {
	gwIdx := 0
	if !primary {
		gwIdx = 1
	}

	instance.localCache.RLock()
	out := instance.localCache.gateways[gwIdx]
	instance.localCache.RUnlock() // nolint
	if out == nil {
		xerr := instance.updateCachedInformation(ctx, trx)
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

// unsafeGetDefaultRouteIP ...
func (instance *Subnet) trxGetDefaultRouteIP(ctx context.Context, trx subnetTransaction) (_ string, ferr fail.Error) {
	var ip string
	xerr := inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
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

// trxGetVirtualIP returns an abstract.VirtualIP used by gateway HA
func (instance *Subnet) trxGetVirtualIP(ctx context.Context, trx subnetTransaction) (vip *abstract.VirtualIP, ferr fail.Error) {
	xerr := inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		vip = as.VIP
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "cannot get Subnet virtual IP")
	}
	if vip == nil {
		return nil, fail.NotFoundError("failed to find Virtual IP bound to gateways for Subnet '%s'", instance.GetName())
	}

	return vip, nil
}

// trxGetCIDR returns the CIDR of the network
// Intended to be used when instance is notoriously not nil (because previously checked)
func (instance *Subnet) trxGetCIDR(ctx context.Context, trx subnetTransaction) (cidr string, ferr fail.Error) {
	cidr = ""
	return cidr, inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		cidr = as.CIDR
		return nil
	})
}

// trxGetState returns the state of the network
// Intended to be used when rs is notoriously not null (because previously checked)
func (instance *Subnet) trxGetState(ctx context.Context, trx subnetTransaction) (state subnetstate.Enum, ferr fail.Error) {
	xerr := inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		state = as.State
		return nil
	})
	return state, xerr
}

// trxAbandonHost is the non goroutine-safe version of UnbindHost, without parameter validation, that does the real work
func (instance *Subnet) trxAbandonHost(ctx context.Context, trx subnetTransaction, hostID string) fail.Error {
	return alterSubnetMetadataProperty(ctx, trx, subnetproperty.HostsV1, func(shV1 *propertiesv1.SubnetHosts) fail.Error {
		hostName, found := shV1.ByID[hostID]
		if found {
			delete(shV1.ByName, hostName)
			delete(shV1.ByID, hostID)
		}
		return nil
	})
}

// trxHasVirtualIP tells if the Subnet uses a VIP a default route
func (instance *Subnet) trxHasVirtualIP(ctx context.Context, trx subnetTransaction) (bool, fail.Error) {
	var found bool
	xerr := inspectSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
		found = as.VIP != nil
		return nil
	})
	return found, xerr
}

// trxCreateSecurityGroups creates the 3 Security Groups needed by a Subnet
// 'ctx' may contain value "CurrentNetworkTransactionContextKey" of type networkTransaction, that may be used by SecurityGroup.Create() not to try to Alter Network directly (might be inside a code already altering it)
func (instance *Subnet) trxCreateSecurityGroups(inctx context.Context, subnetTrx subnetTransaction, networkTrx networkTransaction, cidr string, keepOnFailure bool, defaultSSHPort int32) (sa, sb, sc *SecurityGroup, gerr fail.Error) {
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

			subnetGWSG, xerr := instance.trxCreateGWSecurityGroup(ctx, subnetTrx, networkTrx, keepOnFailure, defaultSSHPort)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				derr := instance.undoCreateSecurityGroup(cleanupContextFrom(ctx), &ferr, keepOnFailure, subnetGWSG)
				if derr != nil {
					logrus.WithContext(ctx).Warnf(derr.Error())
				}
			}()

			subnetPublicIPSG, xerr := instance.trxCreatePublicIPSecurityGroup(ctx, subnetTrx, networkTrx, keepOnFailure)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				derr := instance.undoCreateSecurityGroup(cleanupContextFrom(ctx), &ferr, keepOnFailure, subnetPublicIPSG)
				if derr != nil {
					logrus.WithContext(ctx).Warnf(derr.Error())
				}
			}()

			subnetInternalSG, xerr := instance.trxCreateInternalSecurityGroup(ctx, subnetTrx, networkTrx, cidr, keepOnFailure)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				derr := instance.undoCreateSecurityGroup(cleanupContextFrom(ctx), &ferr, keepOnFailure, subnetInternalSG)
				if derr != nil {
					logrus.WithContext(ctx).Warnf(derr.Error())
				}
			}()

			xerr = subnetGWSG.BindToSubnet(ctx, instance, SecurityGroupEnable, KeepCurrentSecurityGroupMark)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					if derr := subnetGWSG.UnbindFromSubnet(cleanupContextFrom(ctx), instance); derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group for gateways from Subnet", ActionFromError(ferr)))
					}
				}
			}()

			xerr = subnetPublicIPSG.BindToSubnet(ctx, instance, SecurityGroupEnable, KeepCurrentSecurityGroupMark)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, nil, xerr}
				return ar, ar.rErr
			}
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					if derr := subnetPublicIPSG.UnbindFromSubnet(cleanupContextFrom(ctx), instance); derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group for gateways from Subnet", ActionFromError(ferr)))
					}
				}
			}()

			xerr = subnetInternalSG.BindToSubnet(ctx, instance, SecurityGroupEnable, MarkSecurityGroupAsDefault)
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
func (instance *Subnet) trxCreateGWSecurityGroup(ctx context.Context, subnetTrx subnetTransaction, networkTrx networkTransaction, keepOnFailure bool, defaultSSHPort int32) (_ *SecurityGroup, ferr fail.Error) {
	networkName := networkTrx.GetName()
	networkID, err := networkTrx.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetGWSecurityGroupNamePattern, subnetTrx.GetName(), networkName)

	sgInstance, xerr := NewSecurityGroup(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetGWSecurityGroupDescriptionPattern, subnetTrx.GetName(), networkName)
	xerr = sgInstance.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	sgid, err := sgInstance.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !keepOnFailure {
			derr := sgInstance.Delete(cleanupContextFrom(ctx), true)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(ferr), sgName))
			}
		}
	}()

	xerr = sgInstance.Clear(ctx)
	if xerr != nil {
		return nil, xerr
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
	xerr = sgInstance.AddRules(ctx, rules...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance, nil
}

// trxCreatePublicIPSecurityGroup creates a Security Group to be applied to host of the Subnet with public IP that is not a gateway
func (instance *Subnet) trxCreatePublicIPSecurityGroup(ctx context.Context, subnetTrx subnetTransaction, networkTrx networkTransaction, keepOnFailure bool) (_ *SecurityGroup, ferr fail.Error) {
	networkName := networkTrx.GetName()
	networkID, err := networkTrx.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	subnetName := subnetTrx.GetName()

	// Creates security group for hosts in Subnet to allow internal access
	sgName := fmt.Sprintf(subnetPublicIPSecurityGroupNamePattern, subnetName, networkName)
	sgInstance, xerr := NewSecurityGroup(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetPublicIPSecurityGroupDescriptionPattern, subnetName, networkName)
	xerr = sgInstance.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	sgid, err := sgInstance.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !keepOnFailure {
			derr := sgInstance.Delete(cleanupContextFrom(ctx), true)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Security Group '%s'", ActionFromError(ferr), sgName))
			}
		}
	}()

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
	xerr = sgInstance.AddRules(ctx, rules...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance, nil
}

// Starting from here, delete the Security Group if exiting with error
func (instance *Subnet) undoCreateSecurityGroup(ctx context.Context, errorPtr *fail.Error, keepOnFailure bool, sg *SecurityGroup) fail.Error {
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
			_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove Security Group for gateways '%s' of Subnet '%s'", ActionFromError(*errorPtr), sgName, instance.GetName()))
		}
	}
	return nil
}

// Creates a Security Group to be applied on Hosts in Subnet to allow internal access
func (instance *Subnet) trxCreateInternalSecurityGroup(ctx context.Context, subnetTrx subnetTransaction, networkTrx networkTransaction, cidr string, keepOnFailure bool) (_ *SecurityGroup, ferr fail.Error) {
	networkName := networkTrx.GetName()
	networkID, err := networkTrx.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	subnetName := subnetTrx.GetName()
	sgName := fmt.Sprintf(subnetInternalSecurityGroupNamePattern, subnetName, networkName)
	sgInstance, xerr := NewSecurityGroup(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	description := fmt.Sprintf(subnetInternalSecurityGroupDescriptionPattern, subnetName, networkName)
	xerr = sgInstance.Create(ctx, networkID, sgName, description, nil)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	sgid, err := sgInstance.GetID()
	if err != nil {
		return nil, fail.Wrap(err)
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
	xerr = sgInstance.AddRules(ctx, rules...)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance, nil
}

// trxUpdateSubnetStatus ...
func (instance *Subnet) trxUpdateSubnetStatus(inctx context.Context, trx subnetTransaction, target subnetstate.Enum) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		xerr := alterSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
			as.State = target
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		xerr = instance.updateCachedInformation(ctx, trx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		chRes <- result{nil}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// trxFinalizeSubnetCreation ...
func (instance *Subnet) trxFinalizeSubnetCreation(inctx context.Context, trx subnetTransaction) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		xerr := alterSubnetMetadataAbstract(ctx, trx, func(as *abstract.Subnet) fail.Error {
			as.State = subnetstate.Ready
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		xerr = instance.updateCachedInformation(ctx, trx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		chRes <- result{nil}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

func (instance *Subnet) trxCreateGateways(inctx context.Context, subnetTrx subnetTransaction, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements, sgs map[string]string, extra interface{}) (_ fail.Error) {
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

			svc := instance.Service()
			if gwSizing == nil {
				gwSizing = &abstract.HostSizingRequirements{MinGPU: -1}
			}

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
				tr, err := instance.trxCreateGateway(ctx, subnetTrx, primaryRequest, *gwSizing, castedExtra)
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
					tr, err := instance.trxCreateGateway(ctx, subnetTrx, secondaryRequest, *gwSizing, castedExtra)
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
				primaryGatewayTrx, xerr := newHostTransaction(ctx, primaryGateway)
				if xerr != nil {
					ar := result{xerr}
					return ar, ar.rErr
				}
				defer primaryGatewayTrx.TerminateFromError(ctx, &ferr)

				// Starting from here, deletes the primary gateway if exiting with error
				defer func() {
					ferr = debug.InjectPlannedFail(ferr)
					if ferr != nil && !req.KeepOnFailure {
						if primaryGateway != nil {
							var derr fail.Error
							defer func() {
								if derr != nil {
									_ = ferr.AddConsequence(derr)
								}
							}()
							logrus.WithContext(cleanupContextFrom(ctx)).Warnf("Cleaning up on failure, deleting gateway '%s'... because of '%s'", primaryGateway.GetName(), ferr.Error())
							derr = primaryGateway.trxRelaxedDeleteHost(cleanupContextFrom(ctx), primaryGatewayTrx)
							derr = debug.InjectPlannedFail(derr)
							if derr != nil {
								debug.IgnoreErrorWithContext(cleanupContextFrom(ctx), derr)
							}
							if req.HA {
								derr = instance.unbindHostFromVIP(cleanupContextFrom(ctx), abstractSubnet.VIP, primaryGateway)
								if derr != nil {
									debug.IgnoreErrorWithContext(cleanupContextFrom(ctx), derr)
								}
							}
							if derr != nil {
								logrus.WithContext(cleanupContextFrom(ctx)).Debugf("Cleaning up on failure, gateway '%s' deleted", primaryGateway.GetName())
							}
						}
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
						derr := instance.trxUndoBindInternalSecurityGroupToGateway(cleanupContextFrom(ctx), subnetTrx, primaryGatewayTrx, req.KeepOnFailure, &ferr)
						if derr != nil {
							logrus.WithContext(ctx).Warnf(derr.Error())
						}
					}()

					// Bind Internal Security Group to gateway
					xerr = instance.trxBindInternalSecurityGroupToGateway(ctx, subnetTrx, primaryGatewayTrx)
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
					secondaryGatewayTrx, xerr := newHostTransaction(ctx, secondaryGateway)
					if xerr != nil {
						ar := result{xerr}
						return ar, ar.rErr
					}
					defer secondaryGatewayTrx.TerminateFromError(ctx, &ferr)

					// Starting from here, deletes the secondary gateway if exiting with error
					defer func() {
						ferr = debug.InjectPlannedFail(ferr)
						if ferr != nil && req.CleanOnFailure() {
							if secondaryGateway != nil {
								var derr fail.Error
								defer func() {
									if derr != nil {
										_ = ferr.AddConsequence(derr)
									}
								}()

								derr = secondaryGateway.trxRelaxedDeleteHost(cleanupContextFrom(ctx), secondaryGatewayTrx)
								derr = debug.InjectPlannedFail(derr)
								if derr == nil {
									derr = instance.unbindHostFromVIP(cleanupContextFrom(ctx), abstractSubnet.VIP, secondaryGateway)
									derr = debug.InjectPlannedFail(derr)
								}
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
						derr := instance.trxUndoBindInternalSecurityGroupToGateway(cleanupContextFrom(ctx), subnetTrx, secondaryGatewayTrx, req.KeepOnFailure, &ferr)
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

					xerr = instance.trxBindInternalSecurityGroupToGateway(ctx, subnetTrx, secondaryGatewayTrx)
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
