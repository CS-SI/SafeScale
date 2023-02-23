package resources

import (
	"context"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	securityGroupTransaction = *securityGroupTransactionImpl

	// securityGroupTransaction = metadata.Transaction[*abstract.SecurityGroup, *SecurityGroup]
	securityGroupTransactionImpl struct {
		metadata.Transaction[*abstract.SecurityGroup, *SecurityGroup]
	}
)

func newSecurityGroupTransaction(ctx context.Context, instance *SecurityGroup) (*securityGroupTransactionImpl, fail.Error) {
	trx, xerr := metadata.NewTransaction[*abstract.SecurityGroup, *SecurityGroup](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &securityGroupTransactionImpl{trx}, nil
}

// IsNull ...
func (sgTrx *securityGroupTransactionImpl) IsNull() bool {
	return sgTrx == nil || sgTrx.Transaction.IsNull()
}

// BindToHost binds the security group to a host, using transactions.
// instance is not locked, it must have been done outside to prevent data races
func (sgTrx *securityGroupTransactionImpl) BindToHost(ctx context.Context, hostTrx hostTransaction, enable SecurityGroupActivation, mark SecurityGroupMark) (ferr fail.Error) {
	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostTrx == nil {
		return fail.InvalidParameterCannotBeNilError("hostTrx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	svc, xerr := myjob.Service()
	if xerr != nil {
		return xerr
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	hostName := hostTrx.GetName()
	hostID, err := hostTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	logrus.WithContext(ctx).Infof("Binding Security Group '%s' to Host '%s'", sgTrx.GetName(), hostName)

	return alterSecurityGroupMetadata(ctx, sgTrx, func(asg *abstract.SecurityGroup, props *serialize.JSONProperties) fail.Error {
		if mark == MarkSecurityGroupAsDefault {
			if asg.DefaultForHost != "" {
				return fail.InvalidRequestError("security group is already marked as default for host %s", asg.DefaultForHost)
			}

			asg.DefaultForHost = hostID
		}

		return props.Alter(securitygroupproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			sghV1, lvl2err := lang.Cast[*propertiesv1.SecurityGroupHosts](p)
			if lvl2err != nil {
				return fail.Wrap(lvl2err)
			}

			return alterHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
				switch enable {
				case SecurityGroupEnable:
					// In case the security group is already bound, we must consider a "duplicate" error has a success
					lvl3xerr := svc.BindSecurityGroupToHost(ctx, asg, ahc)
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
					lvl3xerr := svc.UnbindSecurityGroupFromHost(ctx, asg, ahc)
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
}

// UnbindFromHost unbinds a Host from the security group
func (sgTrx *securityGroupTransactionImpl) UnbindFromHost(inctx context.Context, hostTrx hostTransaction) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if hostTrx == nil {
		return fail.InvalidParameterCannotBeNilError("hostTrx")
	}

	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return xerr
	}

	svc, xerr := myjob.Service()
	if xerr != nil {
		return xerr
	}

	sgID, err := sgTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan fail.Error)
	go func() {
		defer close(chRes)

		gerr := func() fail.Error {
			var abstractHost *abstract.HostCore
			xerr := inspectHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
				abstractHost = ahc
				return nil
			})
			if xerr != nil {
				return xerr
			}

			xerr = alterSecurityGroupMetadata(ctx, sgTrx, func(asg *abstract.SecurityGroup, sgProps *serialize.JSONProperties) fail.Error {
				// Unbind Security Group from Host on provider side
				innerXErr := svc.UnbindSecurityGroupFromHost(ctx, asg, abstractHost)
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						// if the security group is not bound to the host, considered as a success and continue
						debug.IgnoreErrorWithContext(ctx, innerXErr)
					default:
						return innerXErr
					}
				}

				// updates security group properties
				return sgProps.Alter(securitygroupproperty.HostsV1, func(p clonable.Clonable) fail.Error {
					sgphV1, innerErr := lang.Cast[*propertiesv1.SecurityGroupHosts](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					delete(sgphV1.ByID, abstractHost.ID)
					delete(sgphV1.ByName, abstractHost.Name)
					return nil
				})
			})
			if xerr != nil {
				return xerr
			}

			return alterHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
				hsgV1, innerErr := lang.Cast[*propertiesv1.HostSecurityGroups](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				delete(hsgV1.ByID, sgID)
				delete(hsgV1.ByName, sgTrx.GetName())
				return nil
			})
		}()
		chRes <- gerr
	}()

	select {
	case res := <-chRes:
		return res
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// UnbindFromHosts unbinds security group from all the hosts bound to it and update the host metadata accordingly
func (sgTrx *securityGroupTransactionImpl) UnbindFromHosts(ctx context.Context, in *propertiesv1.SecurityGroupHosts) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return fail.InvalidParameterCannotBeNilError("in")
	}

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

				return sgTrx.UnbindFromHost(ctx, hostTrx)
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

// UnbindFromSubnets unbinds security group from all the subnets bound to it and update the Subnet metadata accordingly
//
//goland:noinspection GoDeferInLoop
func (sgTrx *securityGroupTransactionImpl) UnbindFromSubnets(ctx context.Context, in *propertiesv1.SecurityGroupSubnets) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return fail.InvalidParameterCannotBeNilError("in")
	}

	if len(in.ByID) > 0 {
		tg := new(errgroup.Group)

		// recover from context the Subnet abstract and properties (if it exists)
		var (
			currentSubnetID  string
			currentSubnetTrx subnetTransaction
		)
		value := ctx.Value(currentSubnetTransactionContextKey)
		if value != nil {
			var err error
			currentSubnetTrx, err = lang.Cast[subnetTransaction](value)
			if err != nil {
				return fail.Wrap(err)
			}

			currentSubnetID, err = currentSubnetTrx.GetID()
			if err != nil {
				return fail.Wrap(err)
			}
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

					subnetTrx, xerr = newSubnetTransaction(ctx, subnetInstance)
					if xerr != nil {
						return xerr
					}
					defer func(trx subnetTransaction) { trx.TerminateFromError(ctx, &ferr) }(subnetTrx)
				}

				xerr := sgTrx.unbindFromHostsAttachedToSubnet(ctx, subnetTrx)
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

// UnbindFromSubnetHosts unbinds the security group from Hosts attached to a Subnet
func (sgTrx *securityGroupTransactionImpl) UnbindFromSubnetHosts(inctx context.Context, subnetTrx subnetTransaction) (_ fail.Error) {
	if valid.IsNil(sgTrx) {
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
			xerr := sgTrx.unbindFromHostsAttachedToSubnet(ctx, subnetTrx)
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

// unbindFromHostsAttachedToSubnet unbinds security group from hosts attached to a Subnet
func (sgTrx *securityGroupTransactionImpl) unbindFromHostsAttachedToSubnet(inctx context.Context, subnetTrx subnetTransaction) fail.Error {
	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan fail.Error)
	go func() {
		defer close(chRes)

		gerr := func() (ferr fail.Error) {
			var subnetHosts map[string]string
			xerr := inspectSubnetMetadataProperty(ctx, subnetTrx, subnetproperty.HostsV1, func(shV1 *propertiesv1.SubnetHosts) fail.Error {
				subnetHosts = shV1.ByID
				return nil
			})
			if xerr != nil {
				return xerr
			}

			if len(subnetHosts) > 0 {
				tg := new(errgroup.Group)

				for k, v := range subnetHosts {
					k, _ := k, v

					tg.Go(func() error {
						hostInstance, xerr := LoadHost(ctx, k)
						if xerr != nil {
							switch xerr.(type) {
							case *fail.ErrNotFound:
								// if Host is not found, consider operation as a success and continue
								debug.IgnoreErrorWithContext(ctx, xerr)
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

						return sgTrx.UnbindFromHost(ctx, hostTrx)
					})

				}

				werr := fail.Wrap(tg.Wait())
				werr = debug.InjectPlannedFail(werr)
				if werr != nil {
					return werr
				}
			}
			return nil
		}()
		chRes <- gerr
	}()

	select {
	case res := <-chRes:
		return res
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// Delete effectively remove a Security Group
func (sgTrx *securityGroupTransactionImpl) Delete(ctx context.Context, force bool) fail.Error {
	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	svc, xerr := myjob.Service()
	if xerr != nil {
		return xerr
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

	xerr = alterSecurityGroupMetadata(ctx, sgTrx, func(asg *abstract.SecurityGroup, props *serialize.JSONProperties) (innerFErr fail.Error) {
		abstractSG = asg
		if networkID == "" {
			networkID = abstractSG.Network
		}

		if !force {
			// check bonds to hosts
			innerXErr := props.Inspect(securitygroupproperty.HostsV1, func(p clonable.Clonable) fail.Error {
				hostsV1, innerErr := lang.Cast[*propertiesv1.SecurityGroupHosts](p)
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
					return fail.NotAvailableError("security group '%s' is currently bound to %d host%s: %s", sgTrx.GetName(), hostCount, strprocess.Plural(uint(hostCount)), strings.Join(keys, ","))
				}

				// Do not remove a Security Group marked as default for a host
				if hostsV1.DefaultFor != "" {
					return fail.InvalidRequestError("failed to Delete Security Group '%s': is default for host identified by %s", hostsV1.DefaultFor)
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// check bonds to subnets
			return props.Inspect(securitygroupproperty.SubnetsV1, func(p clonable.Clonable) fail.Error {
				subnetsV1, innerErr := lang.Cast[*propertiesv1.SecurityGroupSubnets](p)
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
					return fail.InvalidRequestError("failed to Delete SecurityGroup '%s': is default for Subnet identified by '%s'", abstractSG.Name, subnetsV1.DefaultFor)
				}
				return nil
			})
		}

		return nil
	})
	if xerr != nil {
		return xerr
	}

	// unbind from Subnets (which will unbind from Hosts attached to these Subnets...)
	var sgSubnets *propertiesv1.SecurityGroupSubnets
	xerr = inspectSecurityGroupMetadataProperty(ctx, sgTrx, securitygroupproperty.SubnetsV1, func(sgnV1 *propertiesv1.SecurityGroupSubnets) fail.Error {
		sgSubnets = sgnV1
		return nil
	})
	if xerr != nil {
		return xerr
	}

	xerr = sgTrx.UnbindFromSubnets(ctx, sgSubnets)
	if xerr != nil {
		return xerr
	}

	// unbind from the Hosts if there are remaining ones
	var sgHosts *propertiesv1.SecurityGroupHosts
	xerr = alterSecurityGroupMetadataProperty(ctx, sgTrx, securitygroupproperty.HostsV1, func(sghV1 *propertiesv1.SecurityGroupHosts) fail.Error {
		sgHosts = sghV1
		return nil
	})
	if xerr != nil {
		return xerr
	}

	xerr = sgTrx.UnbindFromHosts(ctx, sgHosts)
	if xerr != nil {
		return xerr
	}

	// Delete SecurityGroup resource
	xerr = deleteProviderSecurityGroup(ctx, svc, abstractSG)
	if xerr != nil {
		return xerr
	}

	// Delete Security Groups in Network metadata if the current operation is not to remove this Network (otherwise may deadlock)
	if removingNetworkID != networkID {
		networkInstance, xerr := LoadNetwork(ctx, networkID)
		if xerr != nil {
			return xerr
		}

		networkTrx, xerr := newNetworkTransaction(ctx, networkInstance)
		if xerr != nil {
			return xerr
		}

		xerr = sgTrx.updateNetworkMetadataOnRemoval(ctx, networkTrx)
		networkTrx.TerminateFromError(ctx, &xerr)
		return xerr
	}

	return nil
}

// Clear is the non goroutine-safe implementation for Clear, that does the real work faster (no locking, less if no parameter validations)
// Note: must be used wisely
func (sgTrx *securityGroupTransactionImpl) Clear(ctx context.Context) fail.Error {
	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	svc, xerr := myjob.Service()
	if xerr != nil {
		return xerr
	}

	return alterSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
		return svc.ClearSecurityGroup(ctx, asg)
	})

}

// AddRules adds rules to a Security Group
func (sgTrx *securityGroupTransactionImpl) AddRules(inctx context.Context, rules ...*abstract.SecurityGroupRule) (ferr fail.Error) {
	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	svc, xerr := myjob.Service()
	if xerr != nil {
		return xerr
	}

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

		xerr := alterSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
			return svc.AddRulesToSecurityGroup(ctx, asg, rules...)
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

// UnbindFromSubnet unbinds the security group from a subnet
func (sgTrx *securityGroupTransactionImpl) UnbindFromSubnet(inctx context.Context, subnetTrx subnetTransaction) (ferr fail.Error) {
	if valid.IsNil(sgTrx) {
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
		xerr := sgTrx.unbindFromHostsAttachedToSubnet(ctx, subnetTrx)
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

// BindToSubnet binds the security group to a host
// This method is called assuming Subnet resource is locked (so do not used the resource directly to prevent deadlock
func (sgTrx *securityGroupTransactionImpl) BindToSubnet(inctx context.Context, abstractSubnet *abstract.Subnet, subnetHosts *propertiesv1.SubnetHosts, enable SecurityGroupActivation, mark SecurityGroupMark) (ferr fail.Error) {
	if valid.IsNil(sgTrx) {
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
			xerr = sgTrx.EnableOnHostsAttachedToSubnet(ctx, subnetHosts)
		case SecurityGroupDisable:
			xerr = sgTrx.DisableOnHostsAttachedToSubnet(ctx, subnetHosts)
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
				sgsV1, innerErr := lang.Cast[*propertiesv1.SecurityGroupSubnets](p)
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

// updateNetworkMetadataOnRemoval removes the reference to instance in Network metadata
func (sgTrx *securityGroupTransactionImpl) updateNetworkMetadataOnRemoval(inctx context.Context, networkTrx networkTransaction) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan fail.Error)
	go func() {
		defer close(chRes)

		gerr := func() fail.Error {
			sgid, err := sgTrx.GetID()
			if err != nil {
				return fail.Wrap(err)
			}

			// -- update Security Groups in Network metadata
			return alterNetworkMetadataProperty(ctx, networkTrx, networkproperty.SecurityGroupsV1, func(nsgV1 *propertiesv1.NetworkSecurityGroups) fail.Error {
				delete(nsgV1.ByID, sgid)
				delete(nsgV1.ByName, sgTrx.GetName())
				return nil
			})
		}()
		chRes <- gerr
	}()

	select {
	case res := <-chRes:
		return res
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// EnableOnHostsAttachedToSubnet enables the security group on hosts attached to the network
func (sgTrx *securityGroupTransactionImpl) EnableOnHostsAttachedToSubnet(ctx context.Context, subnetHosts *propertiesv1.SubnetHosts) fail.Error {
	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	if len(subnetHosts.ByID) > 0 {
		tg := new(errgroup.Group)

		for _, v := range subnetHosts.ByID {
			v := v
			tg.Go(func() error {
				return sgTrx.BindAsEnabledOnHost(ctx, v)
			})
		}

		innerXErr := fail.Wrap(tg.Wait())
		innerXErr = debug.InjectPlannedFail(innerXErr)
		return innerXErr
	}

	return nil
}

// DisableOnHostsAttachedToSubnet disables (ie remove) the Security Group from bound Hosts
func (sgTrx *securityGroupTransactionImpl) DisableOnHostsAttachedToSubnet(ctx context.Context, subnetHosts *propertiesv1.SubnetHosts) fail.Error {
	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	if len(subnetHosts.ByID) > 0 {
		tg := new(errgroup.Group)

		for _, v := range subnetHosts.ByID {
			v := v
			tg.Go(func() error {
				return sgTrx.BindAsDisabledOnHost(ctx, v)
			})
		}
		xerr := fail.Wrap(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		return xerr
	}
	return nil
}

// BindAsEnabledOnHost binds the SG if needed (applying rules) and enables it on Host
// params is intended to receive a non-empty string corresponding to host ID
// returns:
// - nil, nil: everything is ok
// - nil, *fail.ErrInvalidParameter: some parameters are invalid
// - nil, *fail.ErrAborted: received abortion signal
// - nil, *fail.ErrNotFound: Host identified by params not found
func (sgTrx *securityGroupTransactionImpl) BindAsEnabledOnHost(inctx context.Context, params concurrency.TaskParameters) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}
	hostID, ok := params.(string)
	if !ok || hostID == "" {
		return fail.InvalidParameterError("params", "must be a non-empty string")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan fail.Error)
	go func() {
		defer close(chRes)

		gerr := func() (finnerXErr fail.Error) {
			hostInstance, innerXErr := LoadHost(ctx, hostID)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// host vanished, considered as a success
					debug.IgnoreErrorWithContext(ctx, innerXErr)
				default:
					return innerXErr
				}
			} else {
				hostTrx, xerr := newHostTransaction(ctx, hostInstance)
				if xerr != nil {
					return xerr
				}
				defer hostTrx.TerminateFromError(ctx, &finnerXErr)

				// Before enabling SG on Host, make sure the SG is bound to Host
				xerr = hostTrx.BindSecurityGroup(ctx, sgTrx, true)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						return hostTrx.EnableSecurityGroup(ctx, sgTrx)
					default:
						return xerr
					}
				}
			}
			return nil
		}()
		chRes <- gerr
	}()

	select {
	case res := <-chRes:
		return res
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// BindAsDisabledOnHost removes rules of security group from host
// params is intended to receive a non-empty string corresponding to host ID
func (sgTrx *securityGroupTransactionImpl) BindAsDisabledOnHost(inctx context.Context, params concurrency.TaskParameters) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(sgTrx) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan fail.Error)
	go func() {
		defer close(chRes)

		gerr := func() (finnerXErr fail.Error) {
			hostID, ok := params.(string)
			if !ok || hostID == "" {
				return fail.InvalidParameterError("params", "must be a non-empty string")
			}

			hostInstance, xerr := LoadHost(ctx, hostID)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// host vanished, considered as a success
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					return xerr
				}
			} else {
				hostTrx, xerr := newHostTransaction(ctx, hostInstance)
				if xerr != nil {
					return xerr
				}
				defer hostTrx.TerminateFromError(ctx, &finnerXErr)

				xerr = hostTrx.BindSecurityGroup(ctx, sgTrx, false)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						return hostTrx.DisableSecurityGroup(ctx, sgTrx)
					default:
						return xerr
					}
				}
			}
			return nil
		}()
		chRes <- gerr
	}()

	select {
	case res := <-chRes:
		return res
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return fail.Wrap(inctx.Err())
	}
}

// ----------------------------------

func inspectSecurityGroupMetadata(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.SecurityGroup](ctx, trx, callback)
}

func inspectSecurityGroupMetadataAbstract(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.SecurityGroup](ctx, trx, callback)
}

func inspectSecurityGroupMetadataProperty[P clonable.Clonable](ctx context.Context, trx securityGroupTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.SecurityGroup, P](ctx, trx, property, callback)
}

func inspectSecurityGroupMetadataProperties(ctx context.Context, trx securityGroupTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.SecurityGroup](ctx, trx, callback)
}

func alterSecurityGroupMetadata(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.SecurityGroup](ctx, trx, callback)
}

func alterSecurityGroupMetadataAbstract(ctx context.Context, trx securityGroupTransaction, callback func(*abstract.SecurityGroup) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.SecurityGroup](ctx, trx, callback)
}

func alterSecurityGroupMetadataProperty[P clonable.Clonable](ctx context.Context, trx securityGroupTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.SecurityGroup, P](ctx, trx, property, callback)
}

func alterSecurityGroupMetadataProperties(ctx context.Context, trx securityGroupTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.AlterProperties[*abstract.SecurityGroup](ctx, trx, callback)
}
