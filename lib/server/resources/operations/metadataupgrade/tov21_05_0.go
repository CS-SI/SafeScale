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

type toV21_05_0 struct{}

func (tv toV21_05_0) Upgrade(svc iaas.Service, from string) fail.Error {
	if svc == nil {
		return fail.InvalidParameterCannotBeNilError("svc")
	}

	logrus.Infof("Upgrading metadata from version '%s' to version 'v21.05.0'", from)

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

	return fail.NotImplementedError()
}

func (tv toV21_05_0) upgradeNetworks(svc iaas.Service) fail.Error {
	instance, xerr := operations.NewNetwork(svc)
	if xerr != nil {
		return xerr
	}

	return instance.Browse(context.Background(), func(an *abstract.Network) fail.Error {
		networkInstance, innerXErr := operations.LoadNetwork(svc, an.ID)
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = tv.upgradeNetworkMetadataIfNeeded(networkInstance)
		networkInstance.Released()
		return innerXErr
	})
}

// upgradeNetworkMetadatasIfNeeded upgrades properties to most recent version
func (tv toV21_05_0) upgradeNetworkMetadataIfNeeded(instance resources.Network) fail.Error {
	xerr := instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		abstractNetwork, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		if !props.Lookup(networkproperty.SubnetsV1) {
			logrus.Tracef("Upgrading metadata of Network '%s'", instance.GetName())

			svc := instance.GetService()

			// -- creates Subnet in metadata --
			subnetInstance, xerr := operations.NewSubnet(svc)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
			defer subnetInstance.Released()

			abstractSubnet, xerr := svc.InspectSubnetByName(instance.GetName(), instance.GetName())
			if xerr != nil {
				return xerr
			}

			abstractSubnet.Network = abstractNetwork.ID
			abstractSubnet.IPVersion = ipversion.IPv4
			abstractSubnet.DNSServers = abstractNetwork.DNSServers
			abstractSubnet.Domain = abstractNetwork.Domain
			abstractSubnet.VIP = abstractNetwork.VIP
			abstractSubnet.GatewayIDs = append(abstractSubnet.GatewayIDs, abstractNetwork.GatewayID)
			if abstractNetwork.SecondaryGatewayID != "" {
				abstractSubnet.GatewayIDs = append(abstractSubnet.GatewayIDs, abstractNetwork.SecondaryGatewayID)
			}
			abstractSubnet.State = subnetstate.Ready
			xerr = subnetInstance.(*operations.Subnet).Carry(abstractSubnet)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			// -- add reference to subnet in network properties --
			xerr = props.Alter(networkproperty.SubnetsV1, func(clonable data.Clonable) fail.Error {
				subnetsV1, ok := clonable.(*propertiesv1.NetworkSubnets)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.NetworkSubnets' expected, '%sr' provided", reflect.TypeOf(clonable).String())
				}
				subnetsV1.ByName[abstractSubnet.Name] = abstractSubnet.ID
				subnetsV1.ByID[abstractSubnet.ID] = abstractSubnet.Name
				return nil
			})

			// -- finally clear deprecated field of abstractNetwork --
			abstractNetwork.VIP = nil
			abstractNetwork.GatewayID, abstractNetwork.SecondaryGatewayID = "", ""
			abstractNetwork.Domain = ""
			return nil
		} else {
			logrus.Tracef("metadata of Network '%s' is up to date", instance.GetName())
		}

		// called when nothing has been changed, to prevent useless metadata update
		return fail.AlteredNothingError()
	})
	return xerr
}

func (tv toV21_05_0) upgradeHosts(svc iaas.Service) fail.Error {
	instance, xerr := operations.NewHost(svc)
	if xerr != nil {
		return xerr
	}

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
	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		if !props.Lookup(hostproperty.NetworkV2) {
			logrus.Tracef("Upgrading metadata of Host '%s'", instance.GetName())

			// upgrade hostproperty.NetworkV1 to hostproperty.NetworkV2
			var hnV1 *propertiesv1.HostNetwork
			innerXErr := props.Alter(hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
				var ok bool
				hnV1, ok = clonable.(*propertiesv1.HostNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = props.Alter(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hnV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hnV2.DefaultSubnetID = hnV1.DefaultNetworkID
				hnV2.IPv4Addresses = hnV1.IPv4Addresses
				hnV2.IPv6Addresses = hnV1.IPv6Addresses
				hnV2.IsGateway = hnV1.IsGateway
				hnV2.PublicIPv4 = hnV1.PublicIPv4
				hnV2.PublicIPv6 = hnV1.PublicIPv6
				hnV2.SubnetsByID = hnV1.NetworksByID
				hnV2.SubnetsByName = hnV1.NetworksByName
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// FIXME: clean old property or leave it ? will differ from v2 through time if Subnets are added for example
		} else {
			logrus.Tracef("Host '%s' is up to date", instance.GetName())
		}

		return fail.AlteredNothingError()
	})
}

func (tv toV21_05_0) upgradeClusters(svc iaas.Service) fail.Error {
	instance, xerr := operations.NewCluster(svc)
	if xerr != nil {
		return xerr
	}
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

	logrus.Tracef("Upgrading metadata of Cluster '%s'", instance.GetName())

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

		logrus.Tracef("Upgrading metadata of Cluster '%s'", instance.GetName())

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
			if innerXErr != nil {
				return innerXErr
			}

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

				// In v2, NetworkID actually contains the subnet ID; we do not need ID of the Network owning the Subnet in
				// the property, meaning that Network would have to be deleted also on Cluster deletion because Network
				// AND Subnet were created forcibly at Cluster creation.
				config = &propertiesv3.ClusterNetwork{
					NetworkID:          "",
					SubnetID:           networkV2.NetworkID,
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

				config = &propertiesv3.ClusterNetwork{
					SubnetID:       networkV1.NetworkID,
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
		if innerXErr != nil {
			return innerXErr
		}

		if update {
			return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
				networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				networkV3.Replace(config)
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
