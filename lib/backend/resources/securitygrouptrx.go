package resources

import (
	"context"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

type (
	securityGroupTransaction = metadata.Transaction[*abstract.SecurityGroup, *SecurityGroup]
)

func newSecurityGroupTransaction(ctx context.Context, instance *SecurityGroup) (securityGroupTransaction, fail.Error) {
	return metadata.NewTransaction[*abstract.SecurityGroup, *SecurityGroup](ctx, instance)
}

func inspectSecurityGroupMetadata(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup, *serialize.JSONProperties) fail.Error, opts ...options.Option) fail.Error {
	return metadata.Inspect[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

func inspectSecurityGroupMetadataAbstract(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup) fail.Error, opts ...options.Option) fail.Error {
	return metadata.InspectAbstract[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

func inspectSecurityGroupMetadataProperty[P clonable.Clonable](ctx context.Context, trx securityGroupTransaction, property string, callback func(P) fail.Error, opts ...options.Option) fail.Error {
	return metadata.InspectProperty[*abstract.SecurityGroup, P](ctx, trx, property, callback, opts...)
}

func inspectSecurityGroupMetadataProperties(ctx context.Context, trx securityGroupTransaction, callback func(*serialize.JSONProperties) fail.Error, opts ...options.Option) fail.Error {
	return metadata.InspectProperties[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

func reviewSecurityGroupMetadata(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup, *serialize.JSONProperties) fail.Error, opts ...options.Option) fail.Error {
	return metadata.Review[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

func reviewSecurityGroupMetadataAbstract(ctx context.Context, trx securityGroupTransaction, callback func(ahc *abstract.SecurityGroup) fail.Error, opts ...options.Option) fail.Error {
	return metadata.ReviewAbstract[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

func reviewSecurityGroupMetadataProperty[P clonable.Clonable](ctx context.Context, trx securityGroupTransaction, property string, callback func(P) fail.Error, opts ...options.Option) fail.Error {
	return metadata.ReviewProperty[*abstract.SecurityGroup, P](ctx, trx, property, callback, opts...)
}

func reviewSecurityGroupMetadataProperties(ctx context.Context, trx securityGroupTransaction, callback func(*serialize.JSONProperties) fail.Error, opts ...options.Option) fail.Error {
	return metadata.ReviewProperties[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

func alterSecurityGroupMetadata(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup, *serialize.JSONProperties) fail.Error, opts ...options.Option) fail.Error {
	return metadata.Alter[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

func alterSecurityGroupMetadataAbstract(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup) fail.Error, opts ...options.Option) fail.Error {
	return metadata.AlterAbstract[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

func alterSecurityGroupMetadataProperty[P clonable.Clonable](ctx context.Context, trx securityGroupTransaction, property string, callback func(P) fail.Error, opts ...options.Option) fail.Error {
	return metadata.AlterProperty[*abstract.SecurityGroup, P](ctx, trx, property, callback, opts...)
}

func alterSecurityGroupMetadataProperties(ctx context.Context, trx securityGroupTransaction, callback func(*serialize.JSONProperties) fail.Error, opts ...options.Option) fail.Error {
	return metadata.AlterProperties[*abstract.SecurityGroup](ctx, trx, callback, opts...)
}

// trxUnbindFromHosts unbinds security group from all the hosts bound to it and update the host metadata accordingly
func (instance *SecurityGroup) trxUnbindFromHosts(ctx context.Context, sgTrx securityGroupTransaction, in *propertiesv1.SecurityGroupHosts) (ferr fail.Error) {
	if len(in.ByID) > 0 {
		tg := new(errgroup.Group)

		// iterate on hosts bound to the security group and start a go routine to unbind
		for _, v := range in.ByID {
			v := v
			tg.Go(func() error {
				if v.FromSubnet {
					return fail.InvalidRequestError("cannot unbind from host a security group applied from subnet; use disable instead or remove from bound subnet")
				}

				hostInstance, xerr := LoadHost(ctx, v.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						return nil
					default:
						return xerr
					}
				}

				hostTrx, xerr := newHostTransaction(ctx, hostInstance)
				if xerr != nil {
					return xerr
				}
				defer func(trx hostTransaction) { trx.TerminateFromError(ctx, &ferr) }(hostTrx)

				return instance.trxUnbindFromHost(ctx, sgTrx, hostTrx)
			})
		}

		xerr := fail.Wrap(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	// Clear the DefaultFor field if needed
	if in.DefaultFor != "" {
		for k := range in.ByID {
			if k == in.DefaultFor {
				in.DefaultFor = ""
				break
			}
		}
	}

	// Resets the bonds on hosts
	in.ByID = map[string]*propertiesv1.SecurityGroupBond{}
	in.ByName = map[string]string{}
	return nil
}

// trxUnbindFromSubnets unbinds security group from all the subnets bound to it and update the Subnet metadata accordingly
//
//goland:noinspection GoDeferInLoop
func (instance *SecurityGroup) trxUnbindFromSubnets(ctx context.Context, sgTrx securityGroupTransaction, in *propertiesv1.SecurityGroupSubnets) (ferr fail.Error) {
	if len(in.ByID) > 0 {
		tg := new(errgroup.Group)

		// recover from context the Subnet abstract and properties (if it exists)
		var (
			currentSubnetTrx subnetTransaction
			err              error
		)
		value := ctx.Value(currentSubnetTransactionContextKey)
		if value != nil {
			currentSubnetTrx, err = lang.Cast[subnetTransaction](value)
			if err != nil {
				return fail.Wrap(err)
			}
		}

		currentSubnetID, err := currentSubnetTrx.GetID()
		if err != nil {
			return fail.Wrap(err)
		}

		// iterate on all Subnets bound to the Security Group to unbind Security Group from Hosts attached to those subnets (in parallel)
		for _, v := range in.ByName {
			v := v

			var subnetTrx subnetTransaction
			tg.Go(func() error {
				// If current Subnet corresponds to the Subnet found in context, uses the data from the context to prevent deadlock
				if currentSubnetTrx != nil && v == currentSubnetID {
					subnetTrx = currentSubnetTrx
				} else {
					subnetInstance, xerr := LoadSubnet(ctx, "", v)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							// consider a missing subnet as a successful operation and continue the loop
							debug.IgnoreErrorWithContext(ctx, xerr)
							return nil
						default:
							return xerr
						}
					}

					subnetTrx, xerr := newSubnetTransaction(ctx, subnetInstance)
					if xerr != nil {
						return xerr
					}
					defer func(trx subnetTransaction) { trx.TerminateFromError(ctx, &ferr) }(subnetTrx)
				}

				xerr := instance.trxUnbindFromHostsAttachedToSubnet(ctx, sgTrx, subnetTrx)
				xerr = debug.InjectPlannedFail(xerr)
				return xerr
			})
		}

		xerr := fail.Wrap(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		// Remove the bonds on Subnets
		in.ByID = map[string]*propertiesv1.SecurityGroupBond{}
		in.ByName = map[string]string{}
	}

	// Clear the DefaultFor field if needed
	if in.DefaultFor != "" {
		for k := range in.ByID {
			if k == in.DefaultFor {
				in.DefaultFor = ""
				break
			}
		}
	}

	return nil
}

// trxUnbindFromSubnetHosts unbinds the security group from Hosts attached to a Subnet
func (instance *SecurityGroup) trxUnbindFromSubnetHosts(inctx context.Context, sgTrx securityGroupTransaction, subnetTrx subnetTransaction) (_ fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	subnetName := subnetTrx.GetName()
	subnetID, err := subnetTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// Unbind Security Group from Hosts attached to Subnet
			xerr := instance.trxUnbindFromHostsAttachedToSubnet(ctx, sgTrx, subnetTrx)
			if xerr != nil {
				return xerr
			}

			// -- Remove Hosts attached to Subnet referenced in Security Group
			xerr = alterSecurityGroupMetadataProperty(ctx, sgTrx, securitygroupproperty.HostsV1, func(sghV1 *propertiesv1.SecurityGroupHosts) fail.Error {
				// updates security group metadata
				for k, v := range sghV1.ByID {
					delete(sghV1.ByID, k)
					delete(sghV1.ByName, v.Name)
				}
				return nil
			})
			if xerr != nil {
				return xerr
			}

			// -- Remove Subnet referenced in Security Group
			return alterSecurityGroupMetadataProperty(ctx, sgTrx, securitygroupproperty.SubnetsV1, func(sgsV1 *propertiesv1.SecurityGroupSubnets) fail.Error {
				// updates security group metadata
				delete(sgsV1.ByID, subnetID)
				delete(sgsV1.ByName, subnetName)
				return nil
			})
		}()
		chRes <- result{gerr}
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

// trxDelete effectively remove a Security Group
func (instance *SecurityGroup) trxDelete(ctx context.Context, sgTrx securityGroupTransaction, force bool) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	var (
		abstractSG                   *abstract.SecurityGroup
		networkID, removingNetworkID string
	)

	value := ctx.Value(CurrentNetworkTransactionContextKey)
	if value != nil {
		var err error
		networkTrx, err := lang.Cast[networkTransaction](value)
		if err != nil {
			return fail.Wrap(err)
		}

		removingNetworkID, err = networkTrx.GetID()
		if err != nil {
			return fail.Wrap(err)
		}
	}

	xerr := alterSecurityGroupMetadata(ctx, sgTrx, func(asg *abstract.SecurityGroup, props *serialize.JSONProperties) (innerFErr fail.Error) {
		abstractSG = asg
		if networkID == "" {
			networkID = abstractSG.Network
		}

		if !force {
			// check bonds to hosts
			innerXErr := props.Inspect(securitygroupproperty.HostsV1, func(p clonable.Clonable) fail.Error {
				hostsV1, innerErr := clonable.Cast[*propertiesv1.SecurityGroupHosts](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				// Do not remove a SecurityGroup used on hosts
				hostCount := len(hostsV1.ByName)
				if hostCount > 0 {
					keys := make([]string, 0, hostCount)
					for k := range hostsV1.ByName {
						keys = append(keys, k)
					}
					return fail.NotAvailableError("security group '%s' is currently bound to %d host%s: %s", instance.GetName(), hostCount, strprocess.Plural(uint(hostCount)), strings.Join(keys, ","))
				}

				// Do not remove a Security Group marked as default for a host
				if hostsV1.DefaultFor != "" {
					return fail.InvalidRequestError("failed to delete Security Group '%s': is default for host identified by %s", hostsV1.DefaultFor)
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// check bonds to subnets
			innerXErr = props.Inspect(securitygroupproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
				subnetsV1, innerErr := clonable.Cast[*propertiesv1.SecurityGroupSubnets](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				// Do not remove a SecurityGroup used on subnet(s)
				subnetCount := len(subnetsV1.ByID)
				if subnetCount > 0 {
					keys := make([]string, subnetCount)
					for k := range subnetsV1.ByName {
						keys = append(keys, k)
					}
					return fail.NotAvailableError("security group is currently bound to %d subnet%s: %s", subnetCount, strprocess.Plural(uint(subnetCount)), strings.Join(keys, ","))
				}

				// Do not remove a Security Group marked as default for a subnet
				if subnetsV1.DefaultFor != "" {
					return fail.InvalidRequestError("failed to delete SecurityGroup '%s': is default for Subnet identified by '%s'", abstractSG.Name, subnetsV1.DefaultFor)
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}
		}

		// unbind from Subnets (which will unbind from Hosts attached to these Subnets...)
		innerXErr := props.Alter(securitygroupproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
			sgnV1, innerErr := clonable.Cast[*propertiesv1.SecurityGroupSubnets](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return instance.trxUnbindFromSubnets(ctx, sgTrx, sgnV1)
		})
		if innerXErr != nil {
			return innerXErr
		}

		// unbind from the Hosts if there are remaining ones
		innerXErr = props.Alter(securitygroupproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			sghV1, innerErr := clonable.Cast[*propertiesv1.SecurityGroupHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return instance.trxUnbindFromHosts(ctx, sgTrx, sghV1)
		})
		if innerXErr != nil {
			return innerXErr
		}

		// delete SecurityGroup resource
		return deleteProviderSecurityGroup(ctx, instance.Service(), abstractSG)
	})
	if xerr != nil {
		return xerr
	}

	// Need to terminate Security Group transaction to be able to delete metadata (no need to check error as we will delete metadata
	sgTrx.SilentTerminate(ctx)

	// delete Security Group metadata
	xerr = instance.Core.Delete(ctx)
	if xerr != nil {
		return xerr
	}

	// delete Security Groups in Network metadata if the current operation is not to remove this Network (otherwise may deadlock)
	if removingNetworkID != networkID {
		networkInstance, xerr := LoadNetwork(ctx, networkID)
		if xerr != nil {
			return xerr
		}

		networkTrx, xerr := newNetworkTransaction(ctx, networkInstance)
		if xerr != nil {
			return xerr
		}

		xerr = instance.updateNetworkMetadataOnRemoval(ctx, networkTrx)
		networkTrx.TerminateFromError(ctx, &xerr)
		return xerr
	}

	return nil
}

// trxClear is the non goroutine-safe implementation for Clear, that does the real work faster (no locking, less if no parameter validations)
// Note: must be used wisely
func (instance *SecurityGroup) trxClear(inctx context.Context, trx securityGroupTransaction) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		xerr := alterSecurityGroupMetadataAbstract(ctx, trx, func(asg *abstract.SecurityGroup) fail.Error {
			return instance.Service().ClearSecurityGroup(ctx, asg)
		})
		chRes <- result{xerr}
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

// trxAddRules adds rules to a Security Group
func (instance *SecurityGroup) trxAddRules(inctx context.Context, trx securityGroupTransaction, rules ...*abstract.SecurityGroupRule) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		for k, v := range rules {
			xerr := v.Validate()
			if xerr != nil {
				chRes <- result{fail.Wrap(xerr, "failed to validate rule #%d", k)}
				return
			}
		}

		xerr := alterSecurityGroupMetadataAbstract(ctx, trx, func(asg *abstract.SecurityGroup) fail.Error {
			return instance.Service().AddRulesToSecurityGroup(ctx, asg, rules...)
		})
		chRes <- result{xerr}
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

// trxUnbindFromSubnet unbinds the security group from a subnet
func (instance *SecurityGroup) trxUnbindFromSubnet(inctx context.Context, sgTrx securityGroupTransaction, subnetTrx subnetTransaction) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	subnetName := subnetTrx.GetName()
	subnetID, err := subnetTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		// Unbind Security Group from Hosts attached to Subnet
		xerr := instance.trxUnbindFromHostsAttachedToSubnet(ctx, sgTrx, subnetTrx)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		// Update instance metadata
		xerr = alterSecurityGroupMetadataProperty(ctx, sgTrx, securitygroupproperty.SubnetsV1, func(sgsV1 *propertiesv1.SecurityGroupSubnets) fail.Error {
			// updates security group metadata
			delete(sgsV1.ByID, subnetID)
			delete(sgsV1.ByName, subnetName)
			return nil
		})
		chRes <- result{xerr}
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

// trxBindToSubnet binds the security group to a host
// This method is called assuming Subnet resource is locked (so do not used the resource directly to prevent deadlock
func (instance *SecurityGroup) trxBindToSubnet(inctx context.Context, sgTrx securityGroupTransaction, abstractSubnet *abstract.Subnet, subnetHosts *propertiesv1.SubnetHosts, enable SecurityGroupActivation, mark SecurityGroupMark) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if abstractSubnet == nil {
		return fail.InvalidParameterCannotBeNilError("abstractSubnet")
	}
	if subnetHosts == nil {
		return fail.InvalidParameterCannotBeNilError("subnetProps")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		var xerr fail.Error
		switch enable {
		case SecurityGroupEnable:
			xerr = instance.enableOnHostsAttachedToSubnet(ctx, subnetHosts)
		case SecurityGroupDisable:
			xerr = instance.disableOnHostsAttachedToSubnet(ctx, subnetHosts)
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		xerr = alterSecurityGroupMetadata(ctx, sgTrx, func(asg *abstract.SecurityGroup, props *serialize.JSONProperties) fail.Error {
			if mark == MarkSecurityGroupAsDefault {
				if asg.DefaultForHost != "" {
					return fail.InvalidRequestError("security group is already marked as default for subnet %s", asg.DefaultForSubnet)
				}

				asg.DefaultForSubnet = abstractSubnet.ID
			}

			return props.Alter(securitygroupproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
				sgsV1, innerErr := clonable.Cast[*propertiesv1.SecurityGroupSubnets](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				// First check if subnet is present with the state requested; if present with same state, consider situation as a success
				disable := !bool(enable)
				if item, ok := sgsV1.ByID[abstractSubnet.ID]; !ok || item.Disabled == disable {
					item = &propertiesv1.SecurityGroupBond{
						ID:   abstractSubnet.ID,
						Name: abstractSubnet.Name,
					}
					sgsV1.ByID[abstractSubnet.ID] = item
					sgsV1.ByName[abstractSubnet.Name] = abstractSubnet.ID
				}

				// updates security group properties
				sgsV1.ByID[abstractSubnet.ID].Disabled = disable
				return nil
			})
		})
		chRes <- result{xerr}
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

// trxBindToHost binds the security group to a host.
// instance is not locked, it must have been done outside to prevent data races
func (instance *SecurityGroup) trxBindToHost(inctx context.Context, sgTrx securityGroupTransaction, hostTrx hostTransaction, enable SecurityGroupActivation, mark SecurityGroupMark) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		hostName := hostTrx.GetName()
		hostID, err := hostTrx.GetID()
		if err != nil {
			chRes <- result{fail.Wrap(err)}
			return
		}
		logrus.WithContext(ctx).Infof("Binding Security Group '%s' to Host '%s'", instance.GetName(), hostName)

		xerr := alterSecurityGroupMetadata(ctx, sgTrx, func(asg *abstract.SecurityGroup, props *serialize.JSONProperties) fail.Error {
			if mark == MarkSecurityGroupAsDefault {
				if asg.DefaultForHost != "" {
					return fail.InvalidRequestError("security group is already marked as default for host %s", asg.DefaultForHost)
				}

				asg.DefaultForHost = hostID
			}

			return props.Alter(securitygroupproperty.HostsV1, func(p clonable.Clonable) fail.Error {
				sghV1, lvl2err := clonable.Cast[*propertiesv1.SecurityGroupHosts](p)
				if lvl2err != nil {
					return fail.Wrap(lvl2err)
				}

				return alterHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
					switch enable {
					case SecurityGroupEnable:
						// In case the security group is already bound, we must consider a "duplicate" error has a success
						lvl3xerr := instance.Service().BindSecurityGroupToHost(ctx, asg, ahc)
						lvl3xerr = debug.InjectPlannedFail(lvl3xerr)
						if lvl3xerr != nil {
							switch lvl3xerr.(type) {
							case *fail.ErrDuplicate:
								debug.IgnoreErrorWithContext(ctx, lvl3xerr)
								// continue
							default:
								return lvl3xerr
							}
						}
					case SecurityGroupDisable:
						// In case the security group has to be disabled, we must consider a "not found" error has a success
						lvl3xerr := instance.Service().UnbindSecurityGroupFromHost(ctx, asg, ahc)
						lvl3xerr = debug.InjectPlannedFail(lvl3xerr)
						if lvl3xerr != nil {
							switch lvl3xerr.(type) {
							case *fail.ErrNotFound:
								debug.IgnoreErrorWithContext(ctx, lvl3xerr)
								// continue
							default:
								return lvl3xerr
							}
						}
					}

					disable := !bool(enable)
					item, ok := sghV1.ByID[ahc.ID]
					if !ok || item.Disabled == disable {
						item = &propertiesv1.SecurityGroupBond{
							ID:   ahc.ID,
							Name: hostName,
						}
						sghV1.ByID[ahc.ID] = item
						sghV1.ByName[hostName] = ahc.ID
					}

					// update the state
					sghV1.ByID[ahc.ID].Disabled = disable
					return nil
				})
			})
		})
		chRes <- result{xerr}
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
