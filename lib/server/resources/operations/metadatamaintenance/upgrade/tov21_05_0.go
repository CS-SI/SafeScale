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

package metadataupgrade

import (
	"context"
	"reflect"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/sirupsen/logrus"
)

//goland:noinspection GoSnakeCaseUsage
type toV21_05_0 struct {
	dryRun bool
}

func (tv toV21_05_0) Upgrade(svc iaas.Service, from string, dryRun bool) fail.Error {
	if svc == nil {
		return fail.InvalidParameterCannotBeNilError("svc")
	}

	logrus.Infof("Upgrading metadata from version '%s' to version 'v21.05.0'", from)

	tv.dryRun = dryRun
	xerr := tv.upgradeNetworks(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = tv.upgradeHosts(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = tv.upgradeClusters(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = tv.cleanupDeprecatedMetadata(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = tv.updateSecurityGroupBonds(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

func (tv toV21_05_0) upgradeNetworks(svc iaas.Service) (ferr fail.Error) {
	logrus.Infof("Upgrading metadata of Networks...")

	var (
		abstractOwningNetwork *abstract.Network
		owningInstance        resources.Network
	)

	withDefaultNetwork, err := svc.HasDefaultNetwork()
	if err != nil {
		return err
	}

	var xerr fail.Error
	if withDefaultNetwork {
		// If there is a default Network/VPC, uses it as owning network for all defined networks in metadata to convert to Subnets
		abstractOwningNetwork, xerr = svc.GetDefaultNetwork()
		if xerr != nil {
			return xerr
		}

		owningInstance, xerr = operations.LoadNetwork(context.Background(), svc, abstractOwningNetwork.ID)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				owningInstance, xerr = operations.NewNetwork(svc)
				if xerr != nil {
					return xerr
				}
				xerr = owningInstance.Import(context.Background(), abstractOwningNetwork.ID)
			default:
			}
		}
	} else {
		owningInstance, xerr = operations.NewNetwork(svc)
	}
	if xerr != nil {
		return xerr
	}

	browsingInstance, xerr := operations.NewNetwork(svc)
	if xerr != nil {
		return xerr
	}
	return browsingInstance.Browse(context.Background(), func(abstractCurrentNetwork *abstract.Network) fail.Error {
		if abstractOwningNetwork != nil && (abstractCurrentNetwork.Name == abstractOwningNetwork.Name || abstractCurrentNetwork.ID == abstractOwningNetwork.ID) {
			return nil
		}

		networkInstance, innerXErr := operations.LoadNetwork(context.Background(), svc, abstractCurrentNetwork.Name)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = tv.upgradeNetworkMetadataIfNeeded(owningInstance, networkInstance)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		return innerXErr
	})
}

// upgradeNetworkMetadataIfNeeded upgrades properties to most recent version
func (tv toV21_05_0) upgradeNetworkMetadataIfNeeded(owningInstance, currentInstance resources.Network) fail.Error {
	var (
		networkName, subnetName, subnetID string
		gatewayIDs                        []string
	)

	if owningInstance != nil && !valid.IsNil(owningInstance) {
		networkName = owningInstance.GetName()
	}
	subnetName = currentInstance.GetName()
	svc := currentInstance.Service()

	var somethingMissing bool
	xerr := currentInstance.Alter(func(clonable data.Clonable, currentNetworkProps *serialize.JSONProperties) (ferr fail.Error) {
		abstractNetwork, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		// Make sure the ID of the Network is valid (at least with FlexibleEngine, Network ID corresponds to Subnet ID in previous versions of SafeScale)
		if owningInstance != nil && !valid.IsNil(owningInstance) {
			abstractNetwork.ID = owningInstance.GetID()
		}

		if !currentNetworkProps.Lookup(networkproperty.SubnetsV1) {
			logrus.Tracef("Upgrading metadata of Network '%s'", subnetName)

			// -- creates Subnet in metadata --
			subnetInstance, innerXErr := operations.NewSubnet(svc)
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			abstractSubnet, innerXErr := svc.InspectSubnetByName(networkName, subnetName)
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					somethingMissing = true
					innerXErr = fail.NotFoundError("cannot create Subnet '%s' metadata: Subnet resource does not exist", subnetName)
					logrus.Warning(innerXErr.Error())
					return innerXErr
				default:
					return fail.Wrap(innerXErr, "cannot create Subnet '%s' metadata", subnetName)
				}
			}

			// If Subnet is not "owned" yet, do the necessary to create Network metadata
			if (owningInstance == nil || valid.IsNil(owningInstance)) && abstractSubnet.Network != "" {
				abstractOwningNetwork, innerXErr := svc.InspectNetwork(abstractSubnet.Network)
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						somethingMissing = true
						innerXErr = fail.Wrap(innerXErr, "ignoring migration of Network %s: cannot inspect Network of Subnet '%s'", abstractSubnet.Network, subnetName)
						logrus.Error(innerXErr.Error())
						return innerXErr
					default:
						return fail.Wrap(innerXErr, "cannot inspect Network %s of Subnet '%s'", abstractSubnet.Network, subnetName)
					}
				}

				owningInstance, innerXErr = operations.LoadNetwork(context.Background(), svc, abstractSubnet.Network)
				if innerXErr != nil {
					switch innerXErr.(type) {
					case *fail.ErrNotFound:
						owningInstance, innerXErr = operations.NewNetwork(svc)
						if innerXErr != nil {
							return innerXErr
						}

						innerXErr = owningInstance.Import(context.Background(), abstractSubnet.Network)
						if innerXErr != nil {
							return innerXErr
						}
					default:
						return innerXErr
					}
				}

				networkName = abstractOwningNetwork.Name
			}

			// -- huaweicloud stack driver needs special treatment here ... --
			{ // It only does something for huaweicloud
				stack, xerr := currentInstance.Service().GetStack()
				if xerr != nil {
					return xerr
				}
				xerr = stack.Migrate("networklayers", map[string]interface{}{
					"layer": abstractNetwork,
				})
				if xerr != nil {
					return xerr
				}
			}

			subnetID = abstractSubnet.ID
			abstractSubnet.Name = subnetName
			abstractSubnet.Network = owningInstance.GetID()
			abstractSubnet.IPVersion = ipversion.IPv4
			abstractSubnet.DNSServers = abstractNetwork.DNSServers
			abstractSubnet.Domain = abstractNetwork.Domain
			abstractSubnet.VIP = abstractNetwork.VIP
			abstractSubnet.GatewayIDs = []string{abstractNetwork.GatewayID}
			gatewayIDs = abstractSubnet.GatewayIDs
			abstractSubnet.State = subnetstate.Ready
			if abstractNetwork.SecondaryGatewayID != "" {
				abstractSubnet.GatewayIDs = append(abstractSubnet.GatewayIDs, abstractNetwork.SecondaryGatewayID)
			}

			innerXErr = subnetInstance.Carry(context.Background(), abstractSubnet)
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			// -- create Security groups --
			ctx := context.Background()
			// owningInstance may be identical to currentInstance, so we need to pass the properties of currentInstance through context,
			// to prevent deadlock trying to alter an instance already inside an Alter
			ctx = context.WithValue(ctx, operations.CurrentNetworkPropertiesContextKey, currentNetworkProps) // nolint
			gwSG, internalSG, publicSG, innerXErr := subnetInstance.CreateSecurityGroups(ctx, owningInstance, false, int32(abstractSubnet.DefaultSSHPort))
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			defer func() {
				if ferr != nil {
					sgName := gwSG.GetName()
					derr := gwSG.Delete(context.Background(), true)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Group '%s'", sgName))
					}

					sgName = internalSG.GetName()
					derr = internalSG.Delete(context.Background(), true)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Group '%s'", sgName))
					}

					sgName = publicSG.GetName()
					derr = publicSG.Delete(context.Background(), true)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Security Group '%s'", sgName))
					}
				}
			}()

			// -- register security groups in Subnet --
			innerXErr = subnetInstance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				abstractSubnet, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				abstractSubnet.GWSecurityGroupID = gwSG.GetID()
				abstractSubnet.InternalSecurityGroupID = internalSG.GetID()
				abstractSubnet.PublicIPSecurityGroupID = publicSG.GetID()
				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			// -- transfer Hosts previously attached to Network to Subnet --
			innerXErr = currentNetworkProps.Inspect(networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%sr' provided", reflect.TypeOf(clonable).String())
				}

				return subnetInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Alter(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
						subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
						if !ok {
							return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						for k, v := range networkHostsV1.ByName {
							subnetHostsV1.ByName[k] = v
						}
						for k, v := range networkHostsV1.ByID {
							subnetHostsV1.ByID[k] = v
						}
						return nil
					})
				})
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			// -- transfer Network description to Subnet --
			innerXErr = currentNetworkProps.Inspect(networkproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
				networkDescriptionV1, ok := clonable.(*propertiesv1.NetworkDescription)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.NetworkDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				return subnetInstance.Alter(func(_ data.Clonable, subnetProps *serialize.JSONProperties) fail.Error {
					return subnetProps.Alter(subnetproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
						subnetDescriptionV1, ok := clonable.(*propertiesv1.SubnetDescription)
						if !ok {
							return fail.InconsistentError("'*propertiesv1.SubnetDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						subnetDescriptionV1.Domain = networkDescriptionV1.Domain
						subnetDescriptionV1.Purpose = networkDescriptionV1.Purpose
						subnetDescriptionV1.Created = networkDescriptionV1.Created
						return nil
					})
				})
			})
			if innerXErr != nil {
				return innerXErr
			}

			// --- Clear deprecated properties ---
			innerXErr = currentNetworkProps.Alter(networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				networkHostsV1, ok := clonable.(*propertiesv1.NetworkHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%sr' provided", reflect.TypeOf(clonable).String())
				}

				networkHostsV1.ByName = nil
				networkHostsV1.ByID = nil
				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			// -- fixed owning Network fields if needed --
			if owningInstance != currentInstance {
				innerXErr = owningInstance.Alter(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					owningAbstractNetwork, ok := clonable.(*abstract.Network)
					if !ok {
						return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					owningAbstractNetwork.Tags = abstractNetwork.Tags
					owningAbstractNetwork.DNSServers = abstractNetwork.DNSServers
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}
			}

			// -- finally clear deprecated field of abstractNetwork --
			abstractNetwork.VIP = nil
			abstractNetwork.GatewayID, abstractNetwork.SecondaryGatewayID = "", ""
			abstractNetwork.Domain = ""
			return nil
		}
		logrus.Tracef("metadata of Network '%s' is up to date", currentInstance.GetName())

		// called when nothing has been changed, to prevent useless metadata update
		return fail.AlteredNothingError()
	})
	if xerr != nil && !somethingMissing {
		return xerr
	}

	if !somethingMissing {
		// -- add reference to subnet in owning Network properties --
		if subnetID != "" && subnetName != "" {
			xerr = owningInstance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
					subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%sr' provided", reflect.TypeOf(clonable).String())
					}
					subnetsV1.ByName[subnetName] = subnetID
					subnetsV1.ByID[subnetID] = subnetName
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}

		// -- GCP stack driver needs special treatment... --
		{ // It only does something for gcp
			stack, xerr := currentInstance.Service().GetStack()
			if xerr != nil {
				return xerr
			}
			xerr = stack.Migrate("tags", map[string]interface{}{
				"subnetName":  subnetName,
				"networkName": networkName,
				"subnetID":    subnetID,
			})
			if xerr != nil {
				return xerr
			}
		}

		// -- upgrade gateways (must have been migrated before migrating remaining Hosts, to have proper properties set --
		for _, v := range gatewayIDs {
			hostInstance, innerXErr := operations.LoadHost(context.Background(), svc, v)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = tv.upgradeHostMetadataIfNeeded(hostInstance.(*operations.Host))
			if innerXErr != nil {
				return innerXErr
			}
		}

		// delete currentInstance in metadata if owningInstance is different than currentInstance
		if owningInstance != currentInstance {
			xerr = currentInstance.(*operations.Network).MetadataCore.Delete()
			if xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

func (tv toV21_05_0) upgradeHosts(svc iaas.Service) fail.Error {
	instance, xerr := operations.NewHost(svc)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Upgrading metadata of Hosts...")

	return instance.Browse(context.Background(), func(ahc *abstract.HostCore) fail.Error {
		hostInstance, innerXErr := operations.LoadHost(context.Background(), svc, ahc.Name)
		if innerXErr != nil {
			return innerXErr
		}

		return tv.upgradeHostMetadataIfNeeded(hostInstance.(*operations.Host))
	})
}

// upgradeHostMetadataIfNeeded upgrades Host properties if needed
func (tv toV21_05_0) upgradeHostMetadataIfNeeded(instance *operations.Host) fail.Error {
	xerr := instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		if !props.Lookup(hostproperty.NetworkV2) {
			logrus.Tracef("Upgrading metadata of Host '%s'", instance.GetName())

			abstractHostCore, ok := clonable.(*abstract.HostCore)
			if !ok {
				return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if abstractHostCore.SSHPort == 0 {
				abstractHostCore.SSHPort = 22
			}

			// -- upgrade hostproperty.NetworkV1 to hostproperty.NetworkV2 --
			var hnV1 *propertiesv1.HostNetwork
			innerXErr := props.Inspect(hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
				var ok bool
				hnV1, ok = clonable.(*propertiesv1.HostNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = props.Alter(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hostNetworkingV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				subnetName, ok := hnV1.NetworksByID[hnV1.DefaultNetworkID]
				if !ok {
					return fail.InconsistentError("failed to find the default Network name")
				}

				subnetInstance, innerXErr := operations.LoadSubnet(context.Background(), instance.Service(), "", subnetName)
				if innerXErr != nil {
					return innerXErr
				}

				var previousID string
				subnetID := subnetInstance.GetID()
				_, ok = hnV1.IPv4Addresses[subnetID]
				if ok {
					previousID = subnetID
				}
				if previousID == "" {
					_, ok = hnV1.IPv4Addresses[hnV1.DefaultNetworkID]
					if ok {
						previousID = hnV1.DefaultNetworkID
						if previousID == "" {
							return fail.InconsistentError("failed to find ID corresponding to the previous default Network IP Address")
						}
					}
					return fail.InconsistentError("failed to find ID corresponding to the previous default Network IP Address")
				}

				hostNetworkingV2.DefaultSubnetID = subnetID
				hostNetworkingV2.IPv4Addresses = map[string]string{subnetID: hnV1.IPv4Addresses[previousID]}
				hostNetworkingV2.IPv6Addresses = map[string]string{subnetID: hnV1.IPv6Addresses[previousID]}
				hostNetworkingV2.IsGateway = hnV1.IsGateway
				hostNetworkingV2.SubnetsByID = map[string]string{subnetID: subnetName}
				hostNetworkingV2.SubnetsByName = map[string]string{subnetName: subnetID}
				hostNetworkingV2.PublicIPv4 = hnV1.PublicIPv4
				hostNetworkingV2.PublicIPv6 = hnV1.PublicIPv6
				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			// -- upgrade hostSizingRequirements v1 to v2 --
			var hostSizingV1 *propertiesv1.HostSizing
			innerXErr = props.Inspect(hostproperty.SizingV1, func(clonable data.Clonable) fail.Error {
				var ok bool
				hostSizingV1, ok = clonable.(*propertiesv1.HostSizing)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = props.Alter(hostproperty.SizingV2, func(clonable data.Clonable) fail.Error {
				hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hostSizingV2.Template = hostSizingV1.Template
				hostSizingV2.RequestedSize = &propertiesv2.HostSizingRequirements{
					MinCores:    hostSizingV1.RequestedSize.Cores,
					MaxCores:    hostSizingV1.RequestedSize.Cores*2 - 1,
					MinRAMSize:  hostSizingV1.RequestedSize.RAMSize,
					MaxRAMSize:  hostSizingV1.RequestedSize.RAMSize*2 - 1.0,
					MinDiskSize: hostSizingV1.RequestedSize.DiskSize,
					MinGPU:      hostSizingV1.RequestedSize.GPUNumber,
					MinCPUFreq:  hostSizingV1.RequestedSize.CPUFreq,
				}
				hostSizingV2.AllocatedSize = &propertiesv2.HostEffectiveSizing{
					Cores:     hostSizingV1.AllocatedSize.Cores,
					RAMSize:   hostSizingV1.AllocatedSize.RAMSize,
					DiskSize:  hostSizingV1.AllocatedSize.DiskSize,
					GPUNumber: hostSizingV1.AllocatedSize.GPUNumber,
					GPUType:   hostSizingV1.AllocatedSize.GPUType,
					CPUFreq:   hostSizingV1.AllocatedSize.CPUFreq,
				}
				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			// Make sure tenant in description property is set correctly
			innerXErr = props.Alter(hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
				hostDescV1, ok := clonable.(*propertiesv1.HostDescription)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				var iErr fail.Error
				hostDescV1.Tenant, iErr = instance.Service().GetName()
				if iErr != nil {
					return iErr
				}
				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			return nil
		}

		logrus.Tracef("Host '%s' is up to date", instance.GetName())
		return fail.AlteredNothingError()
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- Make sure host is referenced in Subnet --
	var subnetInstance resources.Subnet
	xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkingV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expectede, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var inErr fail.Error
			subnetInstance, inErr = operations.LoadSubnet(context.Background(), instance.Service(), "", hostNetworkingV2.DefaultSubnetID)
			return inErr
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- make sure SGs are applied to Host
	isGateway, xerr := instance.IsGateway()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if !isGateway {
		xerr = subnetInstance.AttachHost(context.Background(), instance)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	} else {
		// Subnet.AttachHost() does not work for gateways, we have to do the job manually
		xerr = subnetInstance.Review(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			subnetAbstract, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if subnetAbstract.InternalSecurityGroupID != "" {
				sgInstance, innerXErr := operations.LoadSecurityGroup(context.Background(), instance.Service(), subnetAbstract.InternalSecurityGroupID)
				if innerXErr != nil {
					return innerXErr
				}

				innerXErr = sgInstance.BindToHost(context.Background(), instance, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark)
				if innerXErr != nil {
					return innerXErr
				}
			}

			if subnetAbstract.GWSecurityGroupID != "" {
				sgInstance, innerXErr := operations.LoadSecurityGroup(context.Background(), instance.Service(), subnetAbstract.GWSecurityGroupID)
				if innerXErr != nil {
					return innerXErr
				}

				return sgInstance.BindToHost(context.Background(), instance, resources.SecurityGroupEnable, resources.KeepCurrentSecurityGroupMark)
			}
			return nil
		})
		if xerr != nil {
			return xerr
		}
	}

	// -- GCP stack driver needs special treatment --
	{ // it only does something for gcp
		stack, xerr := instance.Service().GetStack()
		if xerr != nil {
			return xerr
		}
		xerr = stack.Migrate("removetag", map[string]interface{}{
			"instance":       instance,
			"subnetInstance": subnetInstance,
		})
		if xerr != nil {
			return xerr
		}
	}

	// We need to update cache information of Host before remotely execute a command, so reload metadata to trigger cache update
	xerr = instance.Reload(context.Background())
	if xerr != nil {
		return xerr
	}

	return nil
}

func (tv toV21_05_0) upgradeClusters(svc iaas.Service) fail.Error {
	browseInstance, xerr := operations.NewCluster(context.Background(), svc)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Upgrading metadata of Clusters...")
	return browseInstance.Browse(context.Background(), func(aci *abstract.ClusterIdentity) fail.Error {
		clusterInstance, xerr := operations.LoadCluster(context.Background(), svc, aci.Name)
		if xerr != nil {
			return xerr
		}

		xerr = tv.upgradeClusterMetadataIfNeeded(clusterInstance.(*operations.Cluster))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return nil
	})
}

func (tv toV21_05_0) upgradeClusterMetadataIfNeeded(instance *operations.Cluster) (ferr fail.Error) {
	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidParameterCannotBeNilError("instance")
	}

	logrus.Tracef("Upgrading metadata of Cluster '%s'...", instance.GetName())

	xerr := tv.upgradeClusterNodesPropertyIfNeeded(instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	missingSomething, xerr := tv.upgradeClusterNetworkPropertyIfNeeded(instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if missingSomething {
		logrus.Warningf("Ignoring metadata upgrade of Cluster '%s' due to missing referenced resources", instance.GetName())
	} else {
		xerr = tv.upgradeClusterDefaultsPropertyIfNeeded(instance)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		if flavor, flErr := instance.GetFlavor(); flErr == nil && flavor == clusterflavor.K8S {
			var (
				featName string
				feat     resources.Feature
				requires map[string]struct{}
			)

			altErr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
					featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.Features' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					if len(featuresV1.Installed) == 0 {
						featuresV1.Installed = make(map[string]*propertiesv1.ClusterInstalledFeature)
					}
					featName = "kubernetes"
					var inErr fail.Error
					feat, inErr = operations.NewFeature(context.Background(), instance.Service(), featName)
					if inErr != nil {
						return inErr
					}

					requires, inErr = feat.Dependencies()
					if inErr != nil {
						return inErr
					}

					featuresV1.Installed[featName] = &propertiesv1.ClusterInstalledFeature{
						Name:     featName,
						FileName: feat.GetFilename(),
						Requires: requires,
					}
					return nil
				})
			})
			if altErr != nil {
				return altErr
			}

			// Now add reference to kubernetes in cluster hosts properties
			masters, inErr := instance.ListMasterIDs(context.Background())
			if inErr != nil {
				switch inErr.(type) {
				case *fail.ErrNotAvailable:
					break
				default:
					return inErr
				}
			} else {
				inErr = tv.addFeatureInProperties(feat, instance.Service(), masters)
				if inErr != nil {
					return inErr
				}
			}

			nodes, inErr := instance.ListNodeIDs(context.Background())
			if inErr != nil {
				switch inErr.(type) {
				case *fail.ErrNotAvailable:
					break
				default:
					return inErr
				}
			} else {
				inErr = tv.addFeatureInProperties(feat, instance.Service(), nodes)
				if inErr != nil {
					return inErr
				}
			}

			netconf, inErr := instance.GetNetworkConfig()
			if inErr != nil {
				return inErr
			}

			gws := data.IndexedListOfStrings{}
			if netconf.GatewayID != "" {
				gws[0] = netconf.GatewayID
			}
			if netconf.SecondaryGatewayID != "" {
				gws[1] = netconf.SecondaryGatewayID
			}
			if len(gws) > 0 {
				inErr = tv.addFeatureInProperties(feat, instance.Service(), gws)
				if inErr != nil {
					return inErr
				}
			}
		}

		// Fixed Cluster status if it's stuck to Starting (bug from v20.06?)
		return instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
				stateV1, ok := clonable.(*propertiesv1.ClusterState)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				if stateV1.State == clusterstate.Starting {
					stateV1.State = clusterstate.Nominal
					return nil
				}

				return fail.AlteredNothingError()
			})
		})
	}
	return nil
}

func (tv toV21_05_0) addFeatureInProperties(feat resources.Feature, svc iaas.Service, hosts data.IndexedListOfStrings) fail.Error {
	requires, xerr := feat.Dependencies()
	if xerr != nil {
		return xerr
	}
	featName := feat.GetName()

	requirementDependencies := make(map[string]map[string]struct{})
	for name := range requires {
		f, xerr := operations.NewFeature(context.Background(), svc, name)
		if xerr != nil {
			logrus.Error(xerr.Error())
			continue
		}

		req, xerr := f.Dependencies()
		if xerr != nil {
			logrus.Error(xerr.Error())
			continue
		}

		requirementDependencies[name] = req
	}

	for _, id := range hosts {
		host, xerr := operations.LoadHost(context.Background(), svc, id)
		if xerr != nil {
			return xerr
		}

		xerr = host.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
				featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				if len(featuresV1.Installed) == 0 {
					featuresV1.Installed = make(map[string]*propertiesv1.HostInstalledFeature)
				}

				// register feature and direct requirements in installed features for Host
				featuresV1.Installed[featName] = &propertiesv1.HostInstalledFeature{
					HostContext: false,
					Requires:    requires,
				}
				for name, req := range requirementDependencies {
					featuresV1.Installed[name] = &propertiesv1.HostInstalledFeature{
						HostContext: false,
						Requires:    req,
					}
				}
				return nil
			})
		})
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// upgradeClusterNodesPropertyIfNeeded upgrades current Nodes property to last Nodes property (currently NodesV2)
func (tv toV21_05_0) upgradeClusterNodesPropertyIfNeeded(instance *operations.Cluster) fail.Error {
	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(clusterproperty.NodesV3) {
			return nil
		}

		if props.Lookup(clusterproperty.NodesV2) {
			var (
				nodesV2 *propertiesv2.ClusterNodes
				ok      bool
			)
			innerXErr := props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
				nodesV2, ok = clonable.(*propertiesv2.ClusterNodes)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			if len(nodesV2.Masters) > 0 {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					for _, i := range nodesV2.Masters {
						nodesV3.GlobalLastIndex++

						node := &propertiesv3.ClusterNode{
							ID:          i.ID,
							NumericalID: nodesV3.GlobalLastIndex,
							Name:        i.Name,
							PrivateIP:   i.PrivateIP,
							PublicIP:    i.PublicIP,
						}
						nodesV3.Masters = append(nodesV3.Masters, nodesV3.GlobalLastIndex)
						nodesV3.ByNumericalID[nodesV3.GlobalLastIndex] = node
					}
					for _, i := range nodesV2.PrivateNodes {
						nodesV3.GlobalLastIndex++

						node := &propertiesv3.ClusterNode{
							ID:          i.ID,
							NumericalID: nodesV3.GlobalLastIndex,
							Name:        i.Name,
							PrivateIP:   i.PrivateIP,
							PublicIP:    i.PublicIP,
						}
						nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, nodesV3.GlobalLastIndex)
						nodesV3.ByNumericalID[nodesV3.GlobalLastIndex] = node
					}
					nodesV3.MasterLastIndex = nodesV2.MasterLastIndex
					nodesV3.PrivateLastIndex = nodesV2.PrivateLastIndex
					return nil
				})
			}
		}

		if props.Lookup(clusterproperty.NodesV1) {
			var (
				nodesV1 *propertiesv1.ClusterNodes
				ok      bool
			)

			innerXErr := props.Inspect(clusterproperty.NodesV1, func(clonable data.Clonable) fail.Error {
				nodesV1, ok = clonable.(*propertiesv1.ClusterNodes)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				for _, i := range nodesV1.Masters {
					nodesV3.GlobalLastIndex++

					node := &propertiesv3.ClusterNode{
						ID:          i.ID,
						NumericalID: nodesV3.GlobalLastIndex,
						Name:        i.Name,
						PrivateIP:   i.PrivateIP,
						PublicIP:    i.PublicIP,
					}
					nodesV3.Masters = append(nodesV3.Masters, node.NumericalID)
					nodesV3.MasterByID[node.ID] = node.NumericalID
					nodesV3.MasterByName[node.Name] = node.NumericalID
					nodesV3.ByNumericalID[node.NumericalID] = node
				}
				for _, i := range nodesV1.PrivateNodes {
					nodesV3.GlobalLastIndex++

					node := &propertiesv3.ClusterNode{
						ID:          i.ID,
						NumericalID: nodesV3.GlobalLastIndex,
						Name:        i.Name,
						PrivateIP:   i.PrivateIP,
						PublicIP:    i.PublicIP,
					}
					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
					nodesV3.PrivateNodeByID[node.ID] = node.NumericalID
					nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
					nodesV3.ByNumericalID[node.NumericalID] = node
				}
				nodesV3.MasterLastIndex = nodesV1.MasterLastIndex
				nodesV3.PrivateLastIndex = nodesV1.PrivateLastIndex
				return nil
			})
		}

		// Returning explicitly this error tells Alter not to try to commit changes, there are none
		return fail.AlteredNothingError()
	})
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}

// upgradeClusterNetworkPropertyIfNeeded creates a clusterproperty.NetworkV3 property if previous versions are found
func (tv toV21_05_0) upgradeClusterNetworkPropertyIfNeeded(instance *operations.Cluster) (bool, fail.Error) {
	identity, xerr := instance.GetIdentity()
	if xerr != nil {
		return true, xerr
	}

	clusterName := identity.GetName()
	subnetName := "net-" + clusterName

	var missingSomething bool
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(clusterproperty.NetworkV3) {
			return fail.AlteredNothingError()
		}

		var (
			config *propertiesv3.ClusterNetwork
			update bool
		)

		var inErr fail.Error
		if props.Lookup(clusterproperty.NetworkV2) {
			// Having a clusterproperty.NetworkV2, need to update instance with clusterproperty.NetworkV3
			inErr = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				networkInstance, subnetInstance, clusterCreatedNetwork, nErr := inspectNetworkAndSubnet(instance, subnetName)
				nErr = debug.InjectPlannedFail(nErr)
				if nErr != nil {
					switch nErr.(type) {
					case *fail.ErrNotFound:
						nErr = fail.Wrap(nErr, "missing metadata of Network or Subnet referenced by Cluster %s", clusterName)
						logrus.Warning(nErr.Error())
						missingSomething = true
					default:
					}
					return nErr
				}

				config = &propertiesv3.ClusterNetwork{
					NetworkID:          networkInstance.GetID(),
					CreatedNetwork:     clusterCreatedNetwork,
					SubnetID:           subnetInstance.GetID(),
					CIDR:               networkV2.CIDR,
					GatewayID:          networkV2.GatewayID,
					GatewayIP:          networkV2.GatewayIP,
					SecondaryGatewayID: networkV2.SecondaryGatewayID,
					SecondaryGatewayIP: networkV2.SecondaryGatewayIP,
					PrimaryPublicIP:    networkV2.PrimaryPublicIP,
					SecondaryPublicIP:  networkV2.SecondaryPublicIP,
					DefaultRouteIP:     networkV2.DefaultRouteIP,
					EndpointIP:         networkV2.EndpointIP,
					Domain:             networkV2.Domain,
				}
				update = true
				return nil
			})
		} else {
			// Having a clusterproperty.NetworkV1, need to update instance with clusterproperty.NetworkV3
			inErr = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
				networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
				if !ok {
					return fail.InconsistentError()
				}

				networkInstance, subnetInstance, clusterCreatedNetwork, nErr := inspectNetworkAndSubnet(instance, subnetName)
				nErr = debug.InjectPlannedFail(nErr)
				if nErr != nil {
					return nErr
				}

				config = &propertiesv3.ClusterNetwork{
					NetworkID:      networkInstance.GetID(),
					CreatedNetwork: clusterCreatedNetwork,
					SubnetID:       subnetInstance.GetID(),
					CIDR:           networkV1.CIDR,
					GatewayID:      networkV1.GatewayID,
					GatewayIP:      networkV1.GatewayIP,
					DefaultRouteIP: networkV1.GatewayIP,
					EndpointIP:     networkV1.PublicIP,
				}
				update = true
				return nil
			})
		}
		inErr = debug.InjectPlannedFail(inErr)
		if inErr != nil && !missingSomething {
			return inErr
		}

		if !missingSomething && update {
			return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
				networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				_, _ = networkV3.Replace(config)
				return nil
			})
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			return missingSomething, nil
		default:
			return missingSomething, xerr
		}
	}
	return missingSomething, nil
}

func inspectNetworkAndSubnet(instance *operations.Cluster, networkName string) (resources.Network, resources.Subnet, bool, fail.Error) {
	subnetInstance, xerr := operations.LoadSubnet(context.Background(), instance.Service(), "", networkName)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, false, xerr
	}

	networkInstance, xerr := subnetInstance.InspectNetwork(context.Background())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, false, xerr
	}

	// determine if the Network of the Subnet has been created by cluster creation
	clusterCreatedNetwork := true
	withDefaultNetwork, err := instance.Service().HasDefaultNetwork()
	if err != nil {
		return nil, nil, false, err
	}
	if withDefaultNetwork {
		defaultNetwork, xerr := instance.Service().GetDefaultNetwork()
		if xerr != nil {
			return nil, nil, false, xerr
		}

		if defaultNetwork.GetName() != instance.GetName() {
			clusterCreatedNetwork = false
		}
	}
	return networkInstance, subnetInstance, clusterCreatedNetwork, nil
}

// upgradeClusterDefaultsPropertyIfNeeded ...
func (tv toV21_05_0) upgradeClusterDefaultsPropertyIfNeeded(instance *operations.Cluster) fail.Error {
	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(clusterproperty.DefaultsV2) {
			return fail.AlteredNothingError()
		}

		// If property.DefaultsV2 is not found but there is a property.DefaultsV1, converts it to DefaultsV2
		return props.Inspect(clusterproperty.DefaultsV1, func(clonable data.Clonable) fail.Error {
			defaultsV1, ok := clonable.(*propertiesv1.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
				defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				_, err := defaultsV2.Replace(converters.ClusterDefaultsPropertyV1ToV2(defaultsV1))
				if err != nil {
					return fail.Wrap(err)
				}
				return nil
			})
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			return nil
		default:
			debug.IgnoreError(xerr)
		}
	}
	return xerr
}

func (tv toV21_05_0) cleanupDeprecatedMetadata(svc iaas.Service) fail.Error {
	xerr := tv.cleanupDeprecatedNetworkMetadata(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = tv.cleanupDeprecatedHostMetadata(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = tv.cleanupDeprecatedClusterMetadata(svc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

func (tv toV21_05_0) cleanupDeprecatedNetworkMetadata(svc iaas.Service) fail.Error {
	browseInstance, xerr := operations.NewNetwork(svc)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Cleaning up deprecated metadata of Networks...")
	return browseInstance.Browse(context.Background(), func(an *abstract.Network) fail.Error {
		networkInstance, innerXErr := operations.LoadNetwork(context.Background(), svc, an.ID)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		return networkInstance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			abstractNetwork, ok := clonable.(*abstract.Network)
			if !ok {
				return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			abstractNetwork.GatewayID = ""
			abstractNetwork.SecondaryGatewayID = ""
			abstractNetwork.Domain = ""
			abstractNetwork.VIP = nil
			abstractNetwork.Subnetworks = nil
			return nil
		})
	})
}

func (tv toV21_05_0) cleanupDeprecatedHostMetadata(svc iaas.Service) fail.Error {
	instance, xerr := operations.NewHost(svc)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Cleaning up deprecated metadata of Hosts...")
	return instance.Browse(context.Background(), func(ahc *abstract.HostCore) fail.Error {
		hostInstance, innerXErr := operations.LoadHost(context.Background(), svc, ahc.ID)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		return hostInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			if props.Lookup(hostproperty.NetworkV1) {
				innerXErr = props.Alter(hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
					hostNetworkingV1, ok := clonable.(*propertiesv1.HostNetwork)
					if !ok {
						return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					_, _ = hostNetworkingV1.Replace(&propertiesv1.HostNetwork{})
					return nil
				})
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}
			}

			if props.Lookup(hostproperty.SizingV1) {
				innerXErr = props.Alter(hostproperty.SizingV1, func(clonable data.Clonable) fail.Error {
					hostSizingV1, ok := clonable.(*propertiesv1.HostSizing)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					_, _ = hostSizingV1.Replace(&propertiesv1.HostSizing{})
					return nil
				})
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}
			}

			return nil
		})
	})
}

func (tv toV21_05_0) cleanupDeprecatedClusterMetadata(svc iaas.Service) fail.Error {
	instance, xerr := operations.NewCluster(context.Background(), svc)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Cleaning up deprecated metadata of Clusters...")
	return instance.Browse(context.Background(), func(aci *abstract.ClusterIdentity) fail.Error {
		clusterInstance, innerXErr := operations.LoadCluster(context.Background(), svc, aci.Name)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		return clusterInstance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			if props.Lookup(clusterproperty.NodesV2) {
				innerXErr := props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
					nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					_, _ = nodesV2.Replace(&propertiesv2.ClusterNodes{})
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}
			}

			if props.Lookup(clusterproperty.NodesV1) {
				innerXErr := props.Alter(clusterproperty.NodesV1, func(clonable data.Clonable) fail.Error {
					nodesV1, ok := clonable.(*propertiesv1.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					_, _ = nodesV1.Replace(&propertiesv1.ClusterNodes{})
					return nil
				})
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}
			}

			if props.Lookup(clusterproperty.NetworkV3) {
				if props.Lookup(clusterproperty.NetworkV1) {
					innerXErr := props.Alter(clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
						networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
						if !ok {
							return fail.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						_, _ = networkV1.Replace(&propertiesv1.ClusterNetwork{})
						return nil
					})
					innerXErr = debug.InjectPlannedFail(innerXErr)
					if innerXErr != nil {
						return innerXErr
					}
				}
				if props.Lookup(clusterproperty.NetworkV2) {
					innerXErr := props.Alter(clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
						networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
						if !ok {
							return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						_, _ = networkV2.Replace(&propertiesv2.ClusterNetwork{})
						return nil
					})
					innerXErr = debug.InjectPlannedFail(innerXErr)
					if innerXErr != nil {
						return innerXErr
					}
				}
			}

			if props.Lookup(clusterproperty.DefaultsV1) {
				return props.Inspect(clusterproperty.DefaultsV1, func(clonable data.Clonable) fail.Error {
					defaultsV1, ok := clonable.(*propertiesv1.ClusterDefaults)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					_, _ = defaultsV1.Replace(&propertiesv1.ClusterDefaults{})
					return nil
				})
			}

			return nil
		})
	})
}

// updateSecurityGroupBonds updates the Security Groups for each Host
func (tv toV21_05_0) updateSecurityGroupBonds(svc iaas.Service) fail.Error {
	subnetBrowserInstance, xerr := operations.NewSubnet(svc)
	if xerr != nil {
		return xerr
	}

	return subnetBrowserInstance.Browse(context.Background(), func(subnetAbstract *abstract.Subnet) fail.Error {
		subnetInstance, innerXErr := operations.LoadSubnet(context.Background(), svc, "", subnetAbstract.ID)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		var (
			subnetHosts    map[string]string
			abstractSubnet *abstract.Subnet
		)
		innerXErr = subnetInstance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			var ok bool
			abstractSubnet, ok = clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			return props.Inspect(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				subnetHosts = subnetHostsV1.ByID
				return nil
			})
		})
		if innerXErr != nil {
			return innerXErr
		}

		sgGW, innerXErr := operations.LoadSecurityGroup(context.Background(), svc, subnetAbstract.GWSecurityGroupID)
		if innerXErr != nil {
			return innerXErr
		}

		_, innerXErr = operations.LoadSecurityGroup(context.Background(), svc, subnetAbstract.PublicIPSecurityGroupID)
		if innerXErr != nil {
			return innerXErr
		}

		sgLAN, innerXErr := operations.LoadSecurityGroup(context.Background(), svc, subnetAbstract.InternalSecurityGroupID)
		if innerXErr != nil {
			return innerXErr
		}

		// Bind gateways to appropriate Security Groups...
		for _, v := range abstractSubnet.GatewayIDs {
			hostInstance, innerXErr := operations.LoadHost(context.Background(), svc, v)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = hostInstance.BindSecurityGroup(context.Background(), sgLAN, true)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = hostInstance.BindSecurityGroup(context.Background(), sgGW, true)
			if innerXErr != nil {
				return innerXErr
			}
		}

		// Bind Hosts in Subnet (except gateways) to appropriate Security Group...
		for k := range subnetHosts {
			hostInstance, innerXErr := operations.LoadHost(context.Background(), svc, k)
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = hostInstance.BindSecurityGroup(context.Background(), sgLAN, true)
			if innerXErr != nil {
				return innerXErr
			}
		}
		return nil
	})
}
