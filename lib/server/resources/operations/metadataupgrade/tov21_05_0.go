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

package metadataupgrade

import (
	"context"
	"reflect"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/sirupsen/logrus"
)

type toV21_05_0 struct{
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

	return nil
}

func (tv toV21_05_0) upgradeNetworks(svc iaas.Service) (xerr fail.Error) {
	logrus.Infof("Upgrading metadata of Networks...")

	var (
		abstractOwningNetwork *abstract.Network
		owningInstance        resources.Network
	)
	if svc.HasDefaultNetwork() {
		// If there is a default Network/VPC, uses it as owning network for all defined networks in metadata to convert to Subnets
		abstractOwningNetwork, xerr = svc.GetDefaultNetwork()
		if xerr != nil {
			return xerr
		}

		owningInstance, xerr = operations.LoadNetwork(svc, abstractOwningNetwork.ID)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				owningInstance, xerr = operations.NewNetwork(svc)
				if xerr == nil {
					xerr = owningInstance.Import(context.Background(), abstractOwningNetwork.ID)
				}
				default:
			}
		}
	} else {
		owningInstance, xerr = operations.NewNetwork(svc)
	}
	if xerr != nil {
		return xerr
	}

	return owningInstance.Browse(context.Background(), func(abstractCurrentNetwork *abstract.Network) fail.Error {
		if abstractOwningNetwork != nil && (abstractCurrentNetwork.Name == abstractOwningNetwork.Name || abstractCurrentNetwork.ID == abstractOwningNetwork.ID) {
			return nil
		}

		networkInstance, innerXErr := operations.LoadNetwork(svc, abstractCurrentNetwork.Name)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = tv.upgradeNetworkMetadataIfNeeded(owningInstance, networkInstance)
		networkInstance.Released()
		innerXErr = debug.InjectPlannedFail(innerXErr)
		return innerXErr
	})
}

// upgradeNetworkMetadatasIfNeeded upgrades properties to most recent version
func (tv toV21_05_0) upgradeNetworkMetadataIfNeeded(owningInstance, currentInstance resources.Network) fail.Error {
	var (
		networkName, subnetName string
	)
	if owningInstance == nil || owningInstance.IsNull() {
		owningInstance = currentInstance
	}
	networkName = owningInstance.GetName()
	subnetName = currentInstance.GetName()

	xerr := currentInstance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		abstractNetwork, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if !props.Lookup(networkproperty.SubnetsV1) {
			logrus.Tracef("Upgrading metadata of Network '%s'", networkName)

			svc := currentInstance.GetService()

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
					return fail.NotFoundError("cannot create Subnet '%s' metadata: Subnet resource does not exist", subnetName)
				default:
					return fail.Wrap(innerXErr, "cannot create Subnet '%s' metadata", subnetName)
				}
			}

			abstractSubnet.Network = owningInstance.GetID()
			abstractSubnet.IPVersion = ipversion.IPv4
			abstractSubnet.DNSServers = abstractNetwork.DNSServers
			abstractSubnet.Domain = abstractNetwork.Domain
			abstractSubnet.VIP = abstractNetwork.VIP
			abstractSubnet.GatewayIDs = []string{abstractNetwork.GatewayID}
			abstractSubnet.State = subnetstate.Ready
			if abstractNetwork.SecondaryGatewayID != "" {
				abstractSubnet.GatewayIDs = append(abstractSubnet.GatewayIDs, abstractNetwork.SecondaryGatewayID)
			}

			innerXErr = subnetInstance.(*operations.Subnet).Carry(abstractSubnet)
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			defer subnetInstance.Released()

			// -- create Security groups --
			gwSG, internalSG, publicSG, innerXErr := subnetInstance.(*operations.Subnet).UnsafeCreateSecurityGroups(context.Background(), owningInstance, false)
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			defer func() {
				if innerXErr != nil {
					sgName := gwSG.GetName()
					derr := gwSG.Delete(context.Background(), true)
					if derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr,"cleaning up on failure, failed to delete Security Group '%s'", sgName))
					}

					sgName = internalSG.GetName()
					derr = internalSG.Delete(context.Background(), true)
					if derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr,"cleaning up on failure, failed to delete Security Group '%s'", sgName))
					}

					sgName = publicSG.GetName()
					derr = publicSG.Delete(context.Background(), true)
					if derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr,"cleaning up on failure, failed to delete Security Group '%s'", sgName))
					}
				} else {
					gwSG.Released()
					internalSG.Released()
					publicSG.Released()
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
				sgName := gwSG.GetName()
				derr := gwSG.Delete(context.Background(), true)
				if derr != nil {
					_ = innerXErr.AddConsequence(fail.Wrap(derr,"cleaning up on failure, failed to delete Security Group '%s'", sgName))
				}

				sgName = internalSG.GetName()
				derr = internalSG.Delete(context.Background(), true)
				if derr != nil {
					_ = innerXErr.AddConsequence(fail.Wrap(derr,"cleaning up on failure, failed to delete Security Group '%s'", sgName))
				}

				sgName = publicSG.GetName()
				derr = publicSG.Delete(context.Background(), true)
				if derr != nil {
					_ = innerXErr.AddConsequence(fail.Wrap(derr,"cleaning up on failure, failed to delete Security Group '%s'", sgName))
				}

				return innerXErr
			}

			// -- add reference to subnet in network properties --
			innerXErr = props.Alter(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
				subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%sr' provided", reflect.TypeOf(clonable).String())
				}
				subnetsV1.ByName[abstractSubnet.Name] = abstractSubnet.ID
				subnetsV1.ByID[abstractSubnet.ID] = abstractSubnet.Name
				return nil
			})
			innerXErr = debug.InjectPlannedFail(innerXErr)
			if innerXErr != nil {
				return innerXErr
			}

			// -- transfer Hosts attached to Network to Subnet --
			innerXErr = props.Alter(networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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

			// --- Clear deprecated properties ---
			innerXErr = props.Alter(networkproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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

			// -- finally clear deprecated field of abstractNetwork --
			abstractNetwork.VIP = nil
			abstractNetwork.GatewayID, abstractNetwork.SecondaryGatewayID = "", ""
			abstractNetwork.Domain = ""
			return nil
		} else {
			logrus.Tracef("metadata of Network '%s' is up to date", currentInstance.GetName())
		}

		// called when nothing has been changed, to prevent useless metadata update
		return fail.AlteredNothingError()
	})
	if xerr != nil {
		return xerr
	}

	// delete network in metadata of owningInstance is different than currentInstance
	if owningInstance != currentInstance {
		xerr = currentInstance.(*operations.Network).MetadataCore.Delete()
		if xerr != nil {
			return xerr
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
		hostInstance, innerXErr := operations.LoadHost(svc, ahc.Name)
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

			// upgrade hostproperty.NetworkV1 to hostproperty.NetworkV2
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

				subnetInstance, innerXErr := operations.LoadSubnet(instance.GetService(), "", hnV1.DefaultNetworkID)
				if innerXErr != nil {
					return innerXErr
				}

				defer subnetInstance.Released()
				// subnetInstance, innerXErr := operations.LoadSubnet(instance.GetService(), hnV1.DefaultNetworkID, subnetInstance.GetName())
				// if innerXErr != nil {
				// 	return innerXErr
				// }
				//
				// defer subnetInstance.Released()

				hostNetworkingV2.DefaultSubnetID = subnetInstance.GetID()
				hostNetworkingV2.IPv4Addresses = map[string]string{subnetInstance.GetID(): hnV1.IPv4Addresses[subnetInstance.GetID()]}
				hostNetworkingV2.IPv6Addresses = map[string]string{subnetInstance.GetID(): hnV1.IPv6Addresses[subnetInstance.GetID()]}
				hostNetworkingV2.IsGateway = hnV1.IsGateway
				hostNetworkingV2.SubnetsByID = map[string]string{subnetInstance.GetID(): subnetInstance.GetName()}
				hostNetworkingV2.SubnetsByName = map[string]string{subnetInstance.GetName(): subnetInstance.GetID()}
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

				hostDescV1.Tenant = instance.GetService().GetName()
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

	// Make sure host is referenced in Subnet
	isGateway, xerr := instance.IsGateway()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if !isGateway {
		var subnetInstance resources.Subnet
		xerr = instance.Review(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) (innerXErr fail.Error) {
				hostNetworkingV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expectede, '%s' provided", reflect.TypeOf(clonable).String())
				}

				subnetInstance, innerXErr = operations.LoadSubnet(instance.GetService(), "", hostNetworkingV2.DefaultSubnetID)
				return innerXErr
			})
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		xerr = subnetInstance.AdoptHost(context.Background(), instance)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

func (tv toV21_05_0) upgradeClusters(svc iaas.Service) fail.Error {
	instance, xerr := operations.NewCluster(svc)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Upgrading metadata of Clusters...")
	return instance.Browse(context.Background(), func(aci *abstract.ClusterIdentity) fail.Error {
		clusterInstance, xerr := operations.LoadCluster(svc, aci.Name)
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

func (tv toV21_05_0) upgradeClusterMetadataIfNeeded(instance *operations.Cluster) fail.Error {
	if instance == nil || instance.IsNull() {
		return fail.InvalidParameterCannotBeNilError("instance")
	}

	logrus.Tracef("Upgrading metadata of Cluster '%s'...", instance.GetName())

	xerr := tv.upgradeClusterNodesPropertyIfNeeded(instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = tv.upgradeClusterNetworkPropertyIfNeeded(instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = tv.upgradeClusterDefaultsPropertyIfNeeded(instance)
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}

// upgradeClusterNodesPropertyIfNeeded upgrades current Nodes property to last Nodes property (currently NodesV2)
func (tv toV21_05_0) upgradeClusterNodesPropertyIfNeeded(instance *operations.Cluster) fail.Error {
	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(clusterproperty.NodesV3) {
			logrus.Tracef("metadata of Cluster '%s' is up to date", instance.GetName())
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
func (tv toV21_05_0) upgradeClusterNetworkPropertyIfNeeded(instance *operations.Cluster) fail.Error {
	xerr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(clusterproperty.NetworkV3) {
			return fail.AlteredNothingError()
		}

		var (
			config *propertiesv3.ClusterNetwork
			update bool
		)

		if props.Lookup(clusterproperty.NetworkV2) {
			// Having a clusterproperty.NetworkV2, need to update instance with clusterproperty.NetworkV3
			innerXErr = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				networkInstance, innerXErr := operations.LoadNetwork(instance.GetService(), networkV2.NetworkID)
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}

				defer networkInstance.Released()
				subnetInstance, innerXErr := operations.LoadSubnet(instance.GetService(), networkInstance.GetName(), networkInstance.GetName())
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}

				defer subnetInstance.Released()

				// In v2, NetworkID actually contains the subnet ID; we do not need ID of the Network owning the Subnet in
				// the property, meaning that Network would have to be deleted also on Cluster deletion because Network
				// AND Subnet were created forcibly at Cluster creation.
				config = &propertiesv3.ClusterNetwork{
					NetworkID:          networkV2.NetworkID,
					CreatedNetwork:     true,
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
			innerXErr = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
				networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
				if !ok {
					return fail.InconsistentError()
				}

				networkInstance, innerXErr := operations.LoadNetwork(instance.GetService(), networkV1.NetworkID)
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}

				defer networkInstance.Released()
				subnetInstance, innerXErr := operations.LoadSubnet(instance.GetService(), networkInstance.GetName(), networkInstance.GetName())
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}

				defer subnetInstance.Released()

				config = &propertiesv3.ClusterNetwork{
					NetworkID:      networkV1.NetworkID,
					CreatedNetwork: true,
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
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		if update {
			return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
				networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				_ = networkV3.Replace(config)
				return nil
			})
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) { //nolint
		case *fail.ErrAlteredNothing:
			xerr = nil
		}
	}
	return xerr
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

				defaultsV2.Replace(converters.ClusterDefaultsPropertyV1ToV2(defaultsV1))
				return nil
			})
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			xerr = nil
		default:
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
	instance, xerr := operations.NewNetwork(svc)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Cleaning up deprecated metadata of Networks...")
	return instance.Browse(context.Background(), func(an *abstract.Network) fail.Error {
		networkInstance, innerXErr := operations.LoadNetwork(svc, an.ID)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		defer networkInstance.Released()

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
		hostInstance, innerXErr := operations.LoadHost(svc, ahc.ID)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		defer hostInstance.Released()
		return hostInstance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			if props.Lookup(hostproperty.NetworkV1) {
				innerXErr = props.Alter(hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
					hostNetworkingV1, ok := clonable.(*propertiesv1.HostNetwork)
					if !ok {
						return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					_ = hostNetworkingV1.Replace(&propertiesv1.HostNetwork{})
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

					_ = hostSizingV1.Replace(&propertiesv1.HostSizing{})
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
	instance, xerr := operations.NewCluster(svc)
	if xerr != nil {
		return xerr
	}

	logrus.Infof("Cleaning up deprecated metadata of Clusters...")
	return instance.Browse(context.Background(), func(aci *abstract.ClusterIdentity) fail.Error {
		clusterInstance, innerXErr := operations.LoadCluster(svc, aci.Name)
		innerXErr = debug.InjectPlannedFail(innerXErr)
		if innerXErr != nil {
			return innerXErr
		}

		defer clusterInstance.Released()
		return clusterInstance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			if props.Lookup(clusterproperty.NodesV2) {
				innerXErr := props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
					nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					_ = nodesV2.Replace(&propertiesv2.ClusterNodes{})
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

					_ = nodesV1.Replace(&propertiesv1.ClusterNodes{})
					return nil
				})
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}
			}

			if props.Lookup(clusterproperty.NetworkV1) {
				innerXErr := props.Alter(clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
					networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					_ = networkV1.Replace(&propertiesv1.ClusterNetwork{})
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
					_ = networkV2.Replace(&propertiesv2.ClusterNetwork{})
					return nil
				})
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}
			}

			if props.Lookup(clusterproperty.DefaultsV1) {
				return props.Inspect(clusterproperty.DefaultsV1, func(clonable data.Clonable) fail.Error {
					defaultsV1, ok := clonable.(*propertiesv1.ClusterDefaults)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					_ = defaultsV1.Replace(&propertiesv1.ClusterDefaults{})
					return nil
				})
			}

			return nil
		})
	})
}
