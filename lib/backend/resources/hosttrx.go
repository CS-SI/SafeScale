package resources

import (
	"context"
	"net"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

type (
	hostTransaction = *hostTransactionImpl

	hostTransactionImpl struct {
		metadata.Transaction[*abstract.HostCore, *Host]
	}
)

func newHostTransaction(ctx context.Context, instance *Host) (*hostTransactionImpl, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("instance")
	}

	trx, xerr := metadata.NewTransaction[*abstract.HostCore, *Host](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &hostTransactionImpl{trx}, nil
}

func inspectHostMetadata(ctx context.Context, ht hostTransaction, callback func(*abstract.HostCore, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.HostCore](ctx, ht, callback)
}

func inspectHostMetadataAbstract(ctx context.Context, ht hostTransaction, callback func(ahc *abstract.HostCore) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.HostCore](ctx, ht, callback)
}

func inspectHostMetadataProperty[P clonable.Clonable](ctx context.Context, ht hostTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.HostCore, P](ctx, ht, property, callback)
}

func inspectHostMetadataProperties(ctx context.Context, ht hostTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.HostCore](ctx, ht, callback)
}

func alterHostMetadata(ctx context.Context, ht hostTransaction, callback func(*abstract.HostCore, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Alter[*abstract.HostCore](ctx, ht, callback)
}

func alterHostMetadataAbstract(ctx context.Context, ht hostTransaction, callback func(ahc *abstract.HostCore) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.HostCore](ctx, ht, callback)
}

func alterHostMetadataProperty[P clonable.Clonable](ctx context.Context, ht hostTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.HostCore, P](ctx, ht, property, callback)
}

func alterHostMetadataProperties(ctx context.Context, ht hostTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.AlterProperties[*abstract.HostCore](ctx, ht, callback)
}

// IsNull ...
func (hostTrx *hostTransactionImpl) IsNull() bool {
	return hostTrx == nil || hostTrx.Transaction.IsNull()
}

// DisableSecurityGroup disables a bound security group to Host
func (hostTrx *hostTransactionImpl) DisableSecurityGroup(ctx context.Context, sgTrx securityGroupTransaction) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(hostTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if valid.IsNil(sgTrx) {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	sgName := sgTrx.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "('%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()

	return alterHostMetadata(ctx, hostTrx, func(ahc *abstract.HostCore, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
			hsgV1, innerErr := lang.Cast[*propertiesv1.HostSecurityGroups](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return inspectSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
				// First check if the security group is not already registered for the Host with the exact same state
				var found bool
				for k := range hsgV1.ByID {
					if k == asg.ID {
						found = true
						break
					}
				}
				if !found {
					return fail.NotFoundError("security group '%s' is not bound to Host '%s'", sgName, hostTrx.GetName())
				}

				caps := myjob.Service().Capabilities()
				if caps.CanDisableSecurityGroup {
					innerXErr := myjob.Service().DisableSecurityGroup(ctx, asg)
					innerXErr = debug.InjectPlannedFail(innerXErr)
					if innerXErr != nil {
						return innerXErr
					}
				} else {
					// Bind the security group on provider side; if security group not binded, considered as a success
					innerXErr := myjob.Service().UnbindSecurityGroupFromHost(ctx, asg, ahc)
					innerXErr = debug.InjectPlannedFail(innerXErr)
					if innerXErr != nil {
						switch innerXErr.(type) {
						case *fail.ErrNotFound:
							debug.IgnoreErrorWithContext(ctx, innerXErr)
							// continue
						default:
							return innerXErr
						}
					}
				}

				// found, update properties
				hsgV1.ByID[asg.ID].Disabled = true
				return nil
			})
		})
	})
}

// SetSecurityGroups sets the Security Groups for the host
func (hostTrx *hostTransactionImpl) SetSecurityGroups(ctx context.Context, req abstract.HostRequest, defaultSubnetTrx subnetTransaction) (ferr fail.Error) {
	if valid.IsNull(hostTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if defaultSubnetTrx == nil {
		return fail.InvalidParameterCannotBeNilError("defaultSubnetTrx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	svc := myjob.Service()
	hostName := hostTrx.GetName()

	// In case of use of terraform, the security groups have already been set
	useTerraformer := svc.Capabilities().UseTerraformer

	var defaultAbstractSubnet *abstract.Subnet
	xerr = inspectSubnetMetadataAbstract(ctx, defaultSubnetTrx, func(as *abstract.Subnet) fail.Error {
		defaultAbstractSubnet = as
		return nil
	})
	if xerr != nil {
		return xerr
	}

	var gwsg, pubipsg, lansg *SecurityGroup

	// Apply Security Group for gateways in default Subnet
	if (req.IsGateway || req.Single) && defaultAbstractSubnet.GWSecurityGroupID != "" {
		gwsg, xerr = LoadSecurityGroup(ctx, defaultAbstractSubnet.GWSecurityGroupID)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to query Subnet '%s' Security Group '%s'", defaultAbstractSubnet.Name, defaultAbstractSubnet.GWSecurityGroupID)
		}

		gwsgTrx, xerr := newSecurityGroupTransaction(ctx, gwsg)
		if xerr != nil {
			return xerr
		}
		defer gwsgTrx.TerminateFromError(ctx, &ferr)

		xerr = gwsgTrx.BindToHost(ctx, hostTrx, SecurityGroupEnable, MarkSecurityGroupAsSupplemental)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to apply Subnet's GW Security Group for gateway '%s' on Host '%s'", gwsg.GetName(), req.ResourceName)
		}

		defer func() {
			if ferr != nil && req.CleanOnFailure() {
				derr := gwsgTrx.UnbindFromHost(cleanupContextFrom(ctx), hostTrx)
				if derr != nil {
					_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group '%s' from Host '%s'", ActionFromError(ferr), gwsg.GetName(), hostName))
				}
			}
		}()

		gwid, err := gwsgTrx.GetID()
		if err != nil {
			return fail.Wrap(err)
		}

		xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) (finnerXErr fail.Error) {
			item := &propertiesv1.SecurityGroupBond{
				ID:         gwid,
				Name:       gwsg.GetName(),
				Disabled:   false,
				FromSubnet: true,
			}
			hsgV1.ByID[item.ID] = item
			hsgV1.ByName[item.Name] = item.ID
			return nil
		})
	}

	// Bound Security Group for hosts with public IP in default Subnet
	if (req.IsGateway || req.PublicIP) && defaultAbstractSubnet.PublicIPSecurityGroupID != "" {
		pubipsg, xerr = LoadSecurityGroup(ctx, defaultAbstractSubnet.PublicIPSecurityGroupID)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to query Subnet '%s' Security Group with ID %s", defaultAbstractSubnet.Name, defaultAbstractSubnet.PublicIPSecurityGroupID)
		}

		pubipsgTrx, xerr := newSecurityGroupTransaction(ctx, pubipsg)
		if xerr != nil {
			return xerr
		}
		defer pubipsgTrx.TerminateFromError(ctx, &ferr)

		xerr = pubipsgTrx.BindToHost(ctx, hostTrx, SecurityGroupEnable, MarkSecurityGroupAsSupplemental)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to apply Subnet's Public Security Group for gateway '%s' on Host '%s'", pubipsg.GetName(), req.ResourceName)
		}

		defer func() {
			if ferr != nil && req.CleanOnFailure() {
				derr := pubipsgTrx.UnbindFromHost(cleanupContextFrom(ctx), hostTrx)
				if derr != nil {
					_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group '%s' from Host '%s'", ActionFromError(ferr), pubipsg.GetName(), hostName))
				}
			}
		}()

		pubID, err := pubipsgTrx.GetID()
		if err != nil {
			return fail.Wrap(err)
		}

		xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) fail.Error {
			item := &propertiesv1.SecurityGroupBond{
				ID:         pubID,
				Name:       pubipsg.GetName(),
				Disabled:   false,
				FromSubnet: true,
			}
			hsgV1.ByID[item.ID] = item
			hsgV1.ByName[item.Name] = item.ID
			return nil
		})
		if xerr != nil {
			return xerr
		}
	}

	// Apply internal Security Group of each other subnets
	defer func() {
		if ferr != nil && req.CleanOnFailure() {
			var (
				sg   *SecurityGroup
				derr error
				errs []error
			)
			uncancellableContext := cleanupContextFrom(ctx)
			for _, v := range req.Subnets {
				if v.ID == defaultAbstractSubnet.ID {
					continue
				}

				subnetInstance, deeperXErr := LoadSubnet(uncancellableContext, "", v.ID)
				if deeperXErr != nil {
					_ = ferr.AddConsequence(deeperXErr)
					continue
				}

				subnetTrx, deeperXErr := newSubnetTransaction(ctx, subnetInstance)
				if deeperXErr != nil {
					_ = ferr.AddConsequence(deeperXErr)
					continue
				}
				defer func(trx subnetTransaction) { trx.TerminateFromError(ctx, &ferr) }(subnetTrx)

				sgName := sg.GetName()
				deeperXErr = inspectSubnetMetadataAbstract(uncancellableContext, subnetTrx, func(abstractSubnet *abstract.Subnet) (fdeeperXErr fail.Error) {
					if abstractSubnet.InternalSecurityGroupID != "" {
						sg, derr = LoadSecurityGroup(uncancellableContext, abstractSubnet.InternalSecurityGroupID)
						if derr != nil {
							errs = append(errs, derr)
							return nil
						}

						sgTrx, derr := newSecurityGroupTransaction(uncancellableContext, sg)
						if derr != nil {
							errs = append(errs, derr)
							return nil
						}
						defer sgTrx.TerminateFromError(uncancellableContext, &fdeeperXErr)

						derr = sgTrx.UnbindFromHost(uncancellableContext, hostTrx)
						if derr != nil {
							errs = append(errs, derr)
						}
					}
					return nil
				})
				if deeperXErr != nil {
					_ = ferr.AddConsequence(fail.Wrap(deeperXErr, "cleaning up on failure, failed to unbind Security Group '%s' from Host", sgName))
				}
			}
			if len(errs) > 0 {
				_ = ferr.AddConsequence(fail.Wrap(fail.NewErrorList(errs), "failed to unbind Subnets Security Group from Host '%s'", sg.GetName(), req.ResourceName))
			}
		}
	}()

	// Bind security groups of all remaining Subnets
	for _, v := range req.Subnets {
		// Do not try to bind defaultSubnet on gateway, because this code is running under a lock on defaultSubnet in this case, and this will lead to deadlock
		// (binding of gateway on defaultSubnet is done inside Subnet.Create() call)
		if req.IsGateway && v.ID == defaultAbstractSubnet.ID {
			continue
		}

		otherSubnetInstance, xerr := LoadSubnet(ctx, "", v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		otherSubnetTrx, xerr := newSubnetTransaction(ctx, otherSubnetInstance)
		if xerr != nil {
			return xerr
		}
		defer func(trx subnetTransaction) { trx.TerminateFromError(ctx, &ferr) }(otherSubnetTrx)

		var otherAbstractSubnet *abstract.Subnet
		xerr = inspectSubnetMetadataAbstract(ctx, otherSubnetTrx, func(as *abstract.Subnet) fail.Error {
			otherAbstractSubnet = as
			return nil
		})
		if xerr != nil {
			return xerr
		}

		safe := false

		// Fix for Stein
		{
			st, xerr := svc.ProviderName()
			if xerr != nil {
				return xerr
			}

			if st != "ovh" {
				safe = true
			}
		}

		if cfg, xerr := svc.ConfigurationOptions(); xerr == nil {
			safe = cfg.Safe
		}

		if otherAbstractSubnet.InternalSecurityGroupID != "" {
			lansg, xerr = LoadSecurityGroup(ctx, otherAbstractSubnet.InternalSecurityGroupID)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to load Subnet '%s' internal Security Group %s", otherAbstractSubnet.Name, otherAbstractSubnet.InternalSecurityGroupID)
			}

			if !safe && !useTerraformer {
				xerr = svc.ChangeSecurityGroupSecurity(ctx, false, true, otherAbstractSubnet.Network, "")
				if xerr != nil {
					return fail.Wrap(xerr, "failed to change security group")
				}
			}

			lansgTrx, xerr := newSecurityGroupTransaction(ctx, lansg)
			if xerr != nil {
				return xerr
			}
			defer func(trx securityGroupTransaction) { trx.TerminateFromError(ctx, &ferr) }(lansgTrx)

			xerr = lansgTrx.BindToHost(ctx, hostTrx, SecurityGroupEnable, MarkSecurityGroupAsSupplemental)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to apply Subnet '%s' internal Security Group '%s' to Host '%s'", otherAbstractSubnet.Name, lansg.GetName(), req.ResourceName)
			}

			if !safe && !useTerraformer {
				xerr = svc.ChangeSecurityGroupSecurity(ctx, true, false, otherAbstractSubnet.Network, "")
				if xerr != nil {
					return fail.Wrap(xerr, "failed to change security group")
				}
			}

			langID, err := lansg.GetID()
			if err != nil {
				return fail.Wrap(err)
			}

			xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) fail.Error {
				// register security group in properties
				item := &propertiesv1.SecurityGroupBond{
					ID:         langID,
					Name:       lansg.GetName(),
					Disabled:   false,
					FromSubnet: true,
				}
				hsgV1.ByID[item.ID] = item
				hsgV1.ByName[item.Name] = item.ID
				return nil
			})
			if xerr != nil {
				return xerr
			}
		}
	}

	// Finally bind any supplemental security groups passed by request
	var abstractHostCore *abstract.HostCore
	xerr = inspectHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
		abstractHostCore = ahc
		return nil
	})
	if xerr != nil {
		return xerr
	}

	for k := range req.SecurityGroupByID {
		if k == "" {
			continue
		}

		sgInstance, innerXErr := LoadSecurityGroup(ctx, k)
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to load Security Group with id '%s'", k)
		}

		sgTrx, innerXErr := newSecurityGroupTransaction(ctx, sgInstance)
		if innerXErr != nil {
			return innerXErr
		}
		defer func(trx securityGroupTransaction) { trx.TerminateFromError(ctx, &ferr) }(sgTrx)

		xerr := alterHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) fail.Error {
			innerXErr = alterSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
				logrus.WithContext(ctx).Infof("Binding security group with id %s to host '%s'", asg.Name, hostName)
				return svc.BindSecurityGroupToHost(ctx, asg, abstractHostCore)
			})
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrDuplicate:
					// If Security Group is already bound, consider a success
				default:
					return innerXErr
				}
			}

			// register security group in properties
			item := &propertiesv1.SecurityGroupBond{
				ID:         k,
				Name:       sgTrx.GetName(),
				Disabled:   false,
				FromSubnet: true,
			}
			hsgV1.ByID[item.ID] = item
			hsgV1.ByName[item.Name] = item.ID
			return nil
		})
		if xerr != nil {
			return xerr
		}

		defer func(trx *securityGroupTransactionImpl, sgID string) {
			if ferr != nil {
				derr := inspectSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
					return svc.BindSecurityGroupToHost(ctx, asg, abstractHostCore)
				})
				if derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						// Security Group not bound, consider this as a successful unbind
					default:
						_ = ferr.AddConsequence(derr)
					}
				}
			}
		}(sgTrx, k)
	}

	return nil
}

// UndoSetSecurityGroups ...
func (hostTrx *hostTransactionImpl) UndoSetSecurityGroups(ctx context.Context, errorPtr *fail.Error, keepOnFailure bool) (ferr fail.Error) {
	if valid.IsNull(hostTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if errorPtr == nil {
		return fail.InvalidParameterCannotBeNilError("errorPtr")
	}

	if *errorPtr != nil && !keepOnFailure {
		var hostSGS map[string]string
		xerr := inspectHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) fail.Error {
			hostSGS = hsgV1.ByName
			return nil
		})
		if xerr != nil {
			return xerr
		}

		var errs []error

		// unbind security groups
		for _, v := range hostSGS {
			sg, opXErr := LoadSecurityGroup(ctx, v)
			if opXErr != nil {
				errs = append(errs, opXErr)
				continue
			}

			sgTrx, opXErr := newSecurityGroupTransaction(ctx, sg)
			if opXErr != nil {
				errs = append(errs, opXErr)
				continue
			}
			defer func(trx securityGroupTransaction) { trx.TerminateFromError(ctx, &ferr) }(sgTrx)

			opXErr = sgTrx.UnbindFromHost(ctx, hostTrx)
			if opXErr != nil {
				errs = append(errs, opXErr)
			}
		}
		if len(errs) > 0 {
			return fail.Wrap(fail.NewErrorList(errs), "cleaning up on %s, failed to unbind Security Groups from Host", ActionFromError(*errorPtr))
		}
	}
	return nil
}

// UnbindDefaultSecurityGroupIfNeeded unbinds "default" Security Group from Host if it is bound
func (hostTrx *hostTransactionImpl) UnbindDefaultSecurityGroupIfNeeded(ctx context.Context, networkID string) (ferr fail.Error) {
	if valid.IsNull(hostTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	svc := myjob.Service()
	if svc.Capabilities().UseTerraformer {
		return nil
	}

	sgName, err := svc.GetDefaultSecurityGroupName(ctx)
	if err != nil {
		return fail.Wrap(err)
	}

	if sgName != "" {
		asg, xerr := svc.InspectSecurityGroupByName(ctx, networkID, sgName)
		if xerr != nil {
			return xerr
		}

		xerr = inspectHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
			innerXErr := svc.UnbindSecurityGroupFromHost(ctx, asg, ahc)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// Consider a security group not found as a successful unbind
					debug.IgnoreErrorWithContext(ctx, innerXErr)
				default:
					return fail.Wrap(innerXErr, "failed to unbind Security Group '%s' from Host", sgName)
				}
			}

			return nil
		})
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// UpdateSubnets updates subnets on which host is attached and host property HostNetworkV2
func (hostTrx *hostTransactionImpl) UpdateSubnets(ctx context.Context, req abstract.HostRequest) fail.Error {
	// If Host is a gateway or is single, do not add it as Host attached to the Subnet, it's considered as part of the subnet
	if !req.IsGateway && !req.Single {
		xerr := alterHostMetadataProperty(ctx, hostTrx, hostproperty.NetworkV2, func(hnV2 *propertiesv2.HostNetworking) (ferr fail.Error) {
			hostName := hostTrx.GetName()
			hostID, innerErr := hostTrx.GetID()
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			for _, as := range req.Subnets {
				subnetInstance, innerXErr := LoadSubnet(ctx, "", as.ID)
				if innerXErr != nil {
					return innerXErr
				}

				subnetTrx, innerXErr := newSubnetTransaction(ctx, subnetInstance)
				if innerXErr != nil {
					return innerXErr
				}
				defer func(trx subnetTransaction) { trx.TerminateFromError(ctx, &ferr) }(subnetTrx)

				innerXErr = alterSubnetMetadataProperty(ctx, subnetTrx, subnetproperty.HostsV1, func(subnetHostsV1 *propertiesv1.SubnetHosts) fail.Error {
					subnetHostsV1.ByName[hostName] = hostID
					subnetHostsV1.ByID[hostID] = hostName
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				hnV2.SubnetsByID[as.ID] = as.Name
				hnV2.SubnetsByName[as.Name] = as.ID
			}
			return nil
		})
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// UndoUpdateSubnets removes what UpdateSubnets have done
func (hostTrx *hostTransactionImpl) UndoUpdateSubnets(ctx context.Context, req abstract.HostRequest, errorPtr *fail.Error) {
	_ = func() (ferr fail.Error) {
		defer func() {
			if ferr != nil {
				if *errorPtr == nil {
					*errorPtr = ferr
				} else {
					_ = (*errorPtr).AddConsequence(ferr)
				}
			}
		}()

		if ctx == nil {
			return fail.InvalidParameterCannotBeNilError("ctx")
		}
		if errorPtr == nil {
			return fail.InvalidParameterCannotBeNilError("errorPtr")
		}

		hostName := hostTrx.GetName()
		hostID, err := hostTrx.GetID()
		if err != nil {
			return fail.Wrap(err)
		}

		if errorPtr != nil && *errorPtr != nil && !req.IsGateway && !req.Single && req.CleanOnFailure() {
			xerr := alterHostMetadataProperty(ctx, hostTrx, hostproperty.NetworkV2, func(hnV2 *propertiesv2.HostNetworking) (innerFErr fail.Error) {
				for _, as := range req.Subnets {
					subnetInstance, innerXErr := LoadSubnet(ctx, "", as.ID)
					if innerXErr != nil {
						return innerXErr
					}

					subnetTrx, innerXErr := newSubnetTransaction(ctx, subnetInstance)
					if innerXErr != nil {
						return innerXErr
					}
					defer func(trx subnetTransaction) { trx.TerminateFromError(ctx, &innerFErr) }(subnetTrx)

					innerXErr = alterSubnetMetadataProperty(ctx, subnetTrx, subnetproperty.HostsV1, func(subnetHostsV1 *propertiesv1.SubnetHosts) fail.Error {
						delete(subnetHostsV1.ByID, hostID)
						delete(subnetHostsV1.ByName, hostName)
						return nil
					})
					if innerXErr != nil {
						return innerXErr
					}

					delete(hnV2.SubnetsByID, as.ID)
					delete(hnV2.SubnetsByName, as.ID)
				}
				return nil
			})
			return debug.InjectPlannedFail(xerr)
		}
		return nil
	}()
}

// RelaxedDeleteHost is the method that really deletes a host, being a gateway or not
func (hostTrx *hostTransactionImpl) RelaxedDeleteHost(ctx context.Context, hostSSH sshapi.Connector) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(hostTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	svc := myjob.Service()
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	cache, xerr := svc.Cache(ctx)
	if xerr != nil {
		return xerr
	}

	hostName := hostTrx.GetName()
	hostID, err := hostTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	hostState, xerr := hostTrx.ForceGetState(ctx)
	if xerr != nil {
		return xerr
	}

	defer func() {
		if ferr == nil && cache != nil {
			_ = cache.Delete(ctx, hostID)
			_ = cache.Delete(ctx, hostName)
		}
	}()

	var shares map[string]*propertiesv1.HostShare
	// Do not remove a Host having shared folders that are currently remotely mounted
	xerr = inspectHostMetadataProperties(ctx, hostTrx, func(props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Inspect(hostproperty.SharesV1, func(p clonable.Clonable) fail.Error {
			sharesV1, innerErr := lang.Cast[*propertiesv1.HostShares](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			shares = sharesV1.ByID
			shareCount := len(shares)
			for _, hostShare := range shares {
				count := len(hostShare.ClientsByID)
				if count > 0 {
					// clients found, checks if these clients already exists...
					for _, hostID := range hostShare.ClientsByID {
						_, innerErr := LoadHost(ctx, hostID)
						if innerErr != nil {
							debug.IgnoreErrorWithContext(ctx, innerErr)
							continue
						}

						return fail.NotAvailableError("Host '%s' exports %d share%s and at least one share is mounted", hostName, shareCount, strprocess.Plural(uint(shareCount)))
					}
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Do not Delete a Host with Bucket mounted
		innerXErr = props.Inspect(hostproperty.MountsV1, func(p clonable.Clonable) fail.Error {
			hostMountsV1, innerErr := lang.Cast[*propertiesv1.HostMounts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			nMounted := len(hostMountsV1.BucketMounts)
			if nMounted > 0 {
				return fail.NotAvailableError("Host '%s' has %d Bucket%s mounted", hostName, nMounted, strprocess.Plural(uint(nMounted)))
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Do not Delete a Host with Volumes attached
		return props.Inspect(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			hostVolumesV1, innerErr := lang.Cast[*propertiesv1.HostVolumes](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			nAttached := len(hostVolumesV1.VolumesByID)
			if nAttached > 0 {
				return fail.NotAvailableError("Host '%s' has %d Volume%s attached", hostName, nAttached, strprocess.Plural(uint(nAttached)))
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var (
		single         bool
		singleSubnetID string
		mounts         []*propertiesv1.HostShare
	)
	xerr = inspectHostMetadataProperty(ctx, hostTrx, hostproperty.MountsV1, func(hostMountsV1 *propertiesv1.HostMounts) fail.Error {
		for _, i := range hostMountsV1.RemoteMountsByPath {
			// Retrieve Share data
			shareInstance, loopErr := LoadShare(ctx, i.ShareID)
			if loopErr != nil {
				switch loopErr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError(loopErr)
					continue
				default:
					return loopErr
				}
			}

			// Retrieve data about the server serving the Share
			hostServer, loopErr := shareInstance.GetServer(ctx)
			if loopErr != nil {
				return loopErr
			}

			// Retrieve data about v from its server
			item, loopErr := hostServer.GetShare(ctx, i.ShareID)
			if loopErr != nil {
				return loopErr
			}

			mounts = append(mounts, item)
		}

		return nil
	})
	if xerr != nil {
		return xerr
	}

	// Unmounts tier shares mounted on Host (done outside the previous Host.properties.Reading() section, because
	// Unmount() have to lock for write, and won't succeed while Host.properties.Reading() is running,
	// leading to a deadlock)
	for _, v := range mounts {
		shareInstance, loopErr := LoadShare(ctx, v.ID)
		if loopErr != nil {
			switch loopErr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreErrorWithContext(ctx, loopErr)
				continue
			default:
				return loopErr
			}
		}

		shareTrx, xerr := newShareTransaction(ctx, shareInstance)
		if xerr != nil {
			return xerr
		}
		defer func(trx shareTransaction) { trx.TerminateFromError(ctx, &ferr) }(shareTrx)

		loopErr = shareInstance.trxUnmount(ctx, shareTrx, hostTrx, hostState, hostSSH)
		if loopErr != nil {
			return loopErr
		}
	}

	// if Host exports shares, Delete them
	for _, v := range shares {
		shareInstance, loopErr := LoadShare(ctx, v.Name)
		if loopErr != nil {
			switch loopErr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreErrorWithContext(ctx, loopErr)
				continue
			default:
				return loopErr
			}
		}

		loopErr = shareInstance.Delete(ctx)
		if loopErr != nil {
			return loopErr
		}
	}

	// Walk through property propertiesv1.HostNetworking to remove the reference to the Host in Subnets
	xerr = inspectHostMetadataProperty(ctx, hostTrx, hostproperty.NetworkV2, func(hostNetworkV2 *propertiesv2.HostNetworking) fail.Error {
		single = hostNetworkV2.Single
		if single {
			singleSubnetID = hostNetworkV2.DefaultSubnetID
		}

		if !single {
			var errs []error
			for k := range hostNetworkV2.SubnetsByID {
				if !hostNetworkV2.IsGateway && k != hostNetworkV2.DefaultSubnetID {
					subnetInstance, loopErr := LoadSubnet(ctx, "", k)
					if loopErr != nil {
						logrus.WithContext(ctx).Errorf(loopErr.Error())
						errs = append(errs, loopErr)
						continue
					}

					loopErr = subnetInstance.DetachHost(ctx, hostID)
					if loopErr != nil {
						logrus.WithContext(ctx).Errorf(loopErr.Error())
						errs = append(errs, loopErr)
						continue
					}
				}
			}
			if len(errs) > 0 {
				return fail.Wrap(fail.NewErrorList(errs), "failed to update metadata for Subnets of Host")
			}
		}
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// Unbind Security Groups from Host
	var hostSGS *propertiesv1.HostSecurityGroups
	xerr = inspectHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) (finnerXErr fail.Error) {
		hostSGS = hsgV1
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// Unbind Security Groups from Host
	var errs []error
	for _, v := range hostSGS.ByID {
		sgInstance, xerr := LoadSecurityGroup(ctx, v.ID)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Consider that a Security Group that cannot be loaded or is not bound as a success
				debug.IgnoreErrorWithContext(ctx, xerr)
			default:
				errs = append(errs, xerr)
			}
			continue
		}

		sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
		if xerr != nil {
			errs = append(errs, xerr)
			continue
		}
		defer func(trx securityGroupTransaction) { trx.TerminateFromError(ctx, &ferr) }(sgTrx)

		xerr = sgTrx.UnbindFromHost(ctx, hostTrx)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// Consider that a Security Group that cannot be loaded or is not bound as a success
				debug.IgnoreErrorWithContext(ctx, xerr)
			default:
				errs = append(errs, xerr)
			}
		}
	}
	if len(errs) > 0 {
		return fail.Wrap(fail.NewErrorList(errs), "failed to unbind some Security Groups")
	}

	// Unbind labels from Host
	var hostLabels *propertiesv1.HostLabels
	xerr = inspectHostMetadataProperty(ctx, hostTrx, hostproperty.LabelsV1, func(hlV1 *propertiesv1.HostLabels) fail.Error {
		hostLabels = hlV1
		return nil
	})
	if xerr != nil {
		return xerr
	}

	for k := range hostLabels.ByID {
		labelInstance, innerErr := LoadLabel(ctx, k)
		if innerErr != nil {
			switch innerErr.(type) {
			case *fail.ErrNotFound:
				// Consider that a Security Group that cannot be loaded or is not bound as a success
				debug.IgnoreErrorWithContext(ctx, innerErr)
			default:
				errs = append(errs, innerErr)
			}
			continue
		}

		labelTrx, xerr := newLabelTransaction(ctx, labelInstance)
		if xerr != nil {
			return xerr
		}
		defer func(trx labelTransaction) { trx.TerminateFromError(ctx, &ferr) }(labelTrx)

		innerErr = labelTrx.UnbindFromHost(ctx, hostTrx)
		if innerErr != nil {
			switch innerErr.(type) {
			case *fail.ErrNotFound:
				// Consider that a Security Group that cannot be loaded or is not bound as a success
				debug.IgnoreErrorWithContext(ctx, innerErr)
			default:
				errs = append(errs, innerErr)
			}
		}
	}
	if len(errs) > 0 {
		return fail.Wrap(fail.NewErrorList(errs), "failed to unbind some Security Groups")
	}

	// Delete Host
	var abstractHost *abstract.HostCore
	xerr = inspectHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
		abstractHost = ahc
		return nil
	})
	if xerr != nil {
		return xerr
	}

	waitForDeletion := true
	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			innerErr := svc.DeleteHost(ctx, abstractHost)
			if innerErr != nil {
				switch innerErr.(type) {
				case *fail.ErrNotFound:
					// A Host not found is considered as a successful deletion
					logrus.WithContext(ctx).Tracef("Host not found, deletion considered as a success")
					debug.IgnoreErrorWithContext(ctx, innerErr)
				default:
					return fail.Wrap(innerErr, "cannot Delete Host")
				}
				waitForDeletion = false
			}
			return nil
		},
		timings.SmallDelay(),
		timings.HostCleanupTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}

	// wait for effective Host deletion
	if waitForDeletion {
		xerr = retry.WhileUnsuccessfulWithHardTimeout(
			func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				state, stateErr := svc.GetHostState(ctx, abstractHost.ID)
				if stateErr != nil {
					switch stateErr.(type) {
					case *fail.ErrNotFound:
						// If Host is not found anymore, consider this as a success
						debug.IgnoreErrorWithContext(ctx, stateErr)
						return nil
					default:
						return stateErr
					}
				}
				if state == hoststate.Error {
					return fail.NotAvailableError("Host is in state Error")
				}
				return nil
			},
			timings.NormalDelay(),
			timings.OperationTimeout(),
		)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry:
				xerr = fail.Wrap(fail.Cause(xerr))
				if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
					return xerr
				}
				debug.IgnoreErrorWithContext(ctx, xerr)
			case *fail.ErrNotFound:
				debug.IgnoreErrorWithContext(ctx, xerr)
			default:
				return xerr
			}
		}
	}

	if single {
		// Delete its dedicated Subnet
		singleSubnetInstance, xerr := LoadSubnet(ctx, "", singleSubnetID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		xerr = singleSubnetInstance.Delete(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// reserveCIDRForSingleHost returns the first available CIDR and its index inside the Network 'network'
func reserveCIDRForSingleHost(ctx context.Context, networkTrx networkTransaction) (_ string, _ uint, ferr fail.Error) {
	var index uint
	xerr := alterNetworkMetadataProperty(ctx, networkTrx, networkproperty.SingleHostsV1, func(nshV1 *propertiesv1.NetworkSingleHosts) fail.Error {
		index = nshV1.ReserveSlot()
		return nil
	})
	if xerr != nil {
		return "", 0, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := networkTrx.FreeCIDRForSingleHost(cleanupContextFrom(ctx), index)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free CIDR slot '%d' in Network '%s'", index, networkTrx.GetName()))
			}
		}
	}()

	_, networkNet, err := net.ParseCIDR(abstract.SingleHostNetworkCIDR)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", 0, fail.Wrap(err, "failed to convert CIDR to net.IPNet")
	}

	localresult, xerr := netretry.NthIncludedSubnet(*networkNet, propertiesv1.SingleHostsCIDRMaskAddition, index)
	if xerr != nil {
		return "", 0, xerr
	}
	return localresult.String(), index, nil
}

// ForceGetState returns the current state of the provider Host then alter metadata
func (hostTrx *hostTransactionImpl) ForceGetState(ctx context.Context) (state hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	state = hoststate.Unknown
	if valid.IsNull(hostTrx) {
		return state, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return state, fail.InvalidParameterCannotBeNilError("ctx")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return state, xerr
	}

	xerr = alterHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
		abstractHostFull, innerXErr := myjob.Service().InspectHost(ctx, ahc)
		if innerXErr != nil {
			return innerXErr
		}

		if abstractHostFull != nil {
			state = abstractHostFull.LastState
			if state != ahc.LastState {
				ahc.LastState = state
				return nil
			}

			return fail.AlteredNothingError()
		}

		return fail.InconsistentError("Host shouldn't be nil")
	})
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	return state, nil
}

// BindSecurityGroup binds a security group to the Host; if enabled is true, apply it immediately
func (hostTrx *hostTransactionImpl) BindSecurityGroup(ctx context.Context, sgTrx securityGroupTransaction, enable SecurityGroupActivation) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer fail.OnExitLogError(ctx, &ferr)

	if valid.IsNil(hostTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgTrx == nil {
		return fail.InvalidParameterCannotBeNilError("sgTrx")
	}

	sgName := sgTrx.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(sg='%s', enable=%v)", sgName, enable).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgID, err := sgTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	// If the Security Group is already bound to the Host with the exact same state, considered as a success
	xerr := alterHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) fail.Error {
		item, ok := hsgV1.ByID[sgID]
		if !ok {
			// No entry for bind, create one
			item = &propertiesv1.SecurityGroupBond{
				ID:   sgID,
				Name: sgName,
			}
			hsgV1.ByID[sgID] = item
			hsgV1.ByName[item.Name] = item.ID
		}
		item.Disabled = bool(!enable)
		return nil
	})
	if xerr != nil {
		return xerr
	}

	return sgTrx.BindToHost(ctx, hostTrx, enable, MarkSecurityGroupAsSupplemental)
}

// EnableSecurityGroup enables a bound security group to Host by applying its rules
func (hostTrx *hostTransactionImpl) EnableSecurityGroup(ctx context.Context, sgTrx securityGroupTransaction) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(hostTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNil(sgTrx) {
		return fail.InvalidParameterError("sgTrx", "cannot be null value of 'securityGroupTransaction'")
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return xerr
	}

	hostName := hostTrx.GetName()
	sgName := sgTrx.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(%s)", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()

	return alterHostMetadata(ctx, hostTrx, func(ahc *abstract.HostCore, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
			hsgV1, innerErr := lang.Cast[*propertiesv1.HostSecurityGroups](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return inspectSecurityGroupMetadataAbstract(ctx, sgTrx, func(asg *abstract.SecurityGroup) fail.Error {
				// First check if the security group is not already registered for the Host with the exact same state
				var found bool
				for k := range hsgV1.ByID {
					if k == asg.ID {
						found = true
						break
					}
				}
				if !found {
					return fail.NotFoundError("security group '%s' is not bound to Host '%s'", sgName, hostName)
				}

				caps := myjob.Service().Capabilities()
				if caps.CanDisableSecurityGroup {
					innerXErr := myjob.Service().EnableSecurityGroup(ctx, asg)
					innerXErr = debug.InjectPlannedFail(innerXErr)
					if innerXErr != nil {
						return innerXErr
					}
				} else {
					// Bind the security group on provider side; if already bound (*fail.ErrDuplicate), considered as a success
					innerXErr := myjob.Service().BindSecurityGroupToHost(ctx, asg, ahc)
					innerXErr = debug.InjectPlannedFail(innerXErr)
					if innerXErr != nil {
						switch innerXErr.(type) {
						case *fail.ErrDuplicate:
							debug.IgnoreErrorWithContext(ctx, innerXErr)
						default:
							return innerXErr
						}
					}
				}

				// found and updated, update metadata
				hsgV1.ByID[asg.ID].Disabled = false
				return nil
			})
		})
	})
}

// GetVolumes is the not goroutine-safe version of GetVolumes, without parameter validation, that does the real work
func (hostTrx *hostTransactionImpl) GetVolumes(ctx context.Context) (*propertiesv1.HostVolumes, fail.Error) {
	if valid.IsNull(hostTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var hvV1 *propertiesv1.HostVolumes
	xerr := inspectHostMetadataProperty(ctx, hostTrx, hostproperty.VolumesV1, func(p *propertiesv1.HostVolumes) fail.Error {
		hvV1 = p
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return hvV1, nil
}

// GetMounts returns the information about the mounts of the host
func (hostTrx *hostTransactionImpl) GetMounts(ctx context.Context) (*propertiesv1.HostMounts, fail.Error) {
	if valid.IsNull(hostTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var mounts *propertiesv1.HostMounts
	xerr := inspectHostMetadataProperty(ctx, hostTrx, hostproperty.MountsV1, func(hostMountsV1 *propertiesv1.HostMounts) fail.Error {
		var innerErr error
		mounts, innerErr = clonable.CastedClone[*propertiesv1.HostMounts](hostMountsV1)
		return fail.Wrap(innerErr)
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return mounts, nil
}

// GetDefaultSubnet returns the Networking instance corresponding to host default subnet
func (hostTrx *hostTransactionImpl) GetDefaultSubnet(ctx context.Context) (_ *Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNull(hostTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var subnetInstance *Subnet
	xerr := inspectHostMetadataProperties(ctx, hostTrx, func(props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(hostproperty.NetworkV2) {
			return props.Inspect(hostproperty.NetworkV2, func(p clonable.Clonable) fail.Error {
				networkV2, innerErr := lang.Cast[*propertiesv2.HostNetworking](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				var innerXErr fail.Error
				subnetInstance, innerXErr = LoadSubnet(ctx, "", networkV2.DefaultSubnetID)
				if innerXErr != nil {
					return innerXErr
				}
				return nil
			})
		}
		return props.Inspect(hostproperty.NetworkV2, func(p clonable.Clonable) fail.Error {
			hostNetworkV2, innerErr := lang.Cast[*propertiesv2.HostNetworking](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			var inErr fail.Error
			subnetInstance, inErr = LoadSubnet(ctx, "", hostNetworkV2.DefaultSubnetID)
			if inErr != nil {
				return inErr
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return subnetInstance, nil
}
