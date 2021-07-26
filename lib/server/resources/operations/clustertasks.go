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
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/lib/utils/net"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/sirupsen/logrus"
)

// taskCreateCluster is the TaskAction that creates a Cluster
func (instance *Cluster) taskCreateCluster(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	req := params.(abstract.ClusterRequest)
	ctx := task.Context()

	// Check if Cluster exists in metadata; if yes, error
	existing, xerr := LoadCluster(instance.GetService(), req.Name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// good, continue
		default:
			return nil, xerr
		}
	} else {
		existing.Released()
		return nil, fail.DuplicateError("a Cluster named '%s' already exist", req.Name)
	}

	// Create first metadata of Cluster after initialization
	xerr = instance.firstLight(req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	cleanFailure := false
	// Starting from here, delete metadata if exiting with error
	// but if the next cleaning steps fail, we must keep the metadata to try again, so we have the cleanFailure flag to detect that issue
	defer func() {
		if xerr != nil && !req.KeepOnFailure && !cleanFailure {
			logrus.Debugf("Cleaning up on %s, deleting metadata of Cluster '%s'...", ActionFromError(xerr), req.Name)
			if derr := instance.MetadataCore.Delete(); derr != nil {
				logrus.Errorf("cleaning up on %s, failed to delete metadata of Cluster '%s'", ActionFromError(xerr), req.Name)
				_ = xerr.AddConsequence(derr)
			} else {
				logrus.Debugf("Cleaning up on %s, successfully deleted metadata of Cluster '%s'", ActionFromError(xerr), req.Name)
			}
		}
	}()

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Obtain number of nodes to create
	_, privateNodeCount, _, xerr := instance.determineRequiredNodes()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if req.InitialNodeCount == 0 {
		req.InitialNodeCount = privateNodeCount
	}
	if req.InitialNodeCount > 0 && req.InitialNodeCount < privateNodeCount {
		logrus.Warnf("[Cluster %s] cannot create less than required minimum of workers by the Flavor (%d requested, minimum being %d for flavor '%s')", req.Name, req.InitialNodeCount, privateNodeCount, req.Flavor.String())
		req.InitialNodeCount = privateNodeCount
	}

	// Define the sizing requirements for Cluster hosts
	if req.GatewaysDef.Image == "" {
		req.GatewaysDef.Image = req.OS
	}
	if req.MastersDef.Image == "" {
		req.MastersDef.Image = req.OS
	}
	if req.NodesDef.Image == "" {
		req.NodesDef.Image = req.OS
	}
	gatewaysDef, mastersDef, nodesDef, xerr := instance.determineSizingRequirements(req)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Create the Network and Subnet
	networkInstance, subnetInstance, xerr := instance.createNetworkingResources(task, req, gatewaysDef)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			logrus.Debugf("Cleaning up on failure, deleting Subnet '%s'...", subnetInstance.GetName())
			if derr := subnetInstance.Delete(context.Background()); derr != nil {
				switch derr.(type) {
				case *fail.ErrNotFound:
					// missing Subnet is considered as a successful deletion, continue
					debug.IgnoreError(derr)
				default:
					cleanFailure = true
					logrus.Errorf("Cleaning up on %s, failed to delete Subnet '%s'", ActionFromError(xerr), subnetInstance.GetName())
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", ActionFromError(xerr)))
				}
			} else {
				logrus.Debugf("Cleaning up on %s, successfully deleted Subnet '%s'", ActionFromError(xerr), subnetInstance.GetName())
				if req.NetworkID == "" {
					logrus.Debugf("Cleaning up on %s, deleting Network '%s'...", ActionFromError(xerr), networkInstance.GetName())
					if derr := networkInstance.Delete(context.Background()); derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Network is considered as a successful deletion, continue
							debug.IgnoreError(derr)
						default:
							cleanFailure = true
							logrus.Errorf("cleaning up on %s, failed to delete Network '%s'", ActionFromError(xerr), networkInstance.GetName())
							_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Network", ActionFromError(xerr)))
						}
					} else {
						logrus.Debugf("Cleaning up on %s, successfully deleted Network '%s'", ActionFromError(xerr), networkInstance.GetName())
					}
				}
			}
		}
	}()

	// Creates and configures hosts
	xerr = instance.createHostResources(task, subnetInstance, *mastersDef, *nodesDef, req.InitialNodeCount, req.KeepOnFailure)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Starting from here, exiting with error deletes hosts if req.keepOnFailure is false
	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			// Disable abort signal during the cleanup
			defer task.DisarmAbortSignal()()

			logrus.Debugf("Cleaning up on failure, deleting Hosts...")
			var list map[uint]*propertiesv3.ClusterNode
			derr := instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					list = nodesV3.ByNumericalID
					return nil
				})
			})
			if derr != nil {
				cleanFailure = true
				_ = xerr.AddConsequence(derr)
				return
			}

			if len(list) > 0 {
				tg, tgerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/onfailure"))
				if tgerr != nil {
					cleanFailure = true
					_ = xerr.AddConsequence(tgerr)
					return
				}

				for _, v := range list {
					if v.ID != "" {
						_, tgerr = tg.Start(instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{node: v}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/delete", v.Name)))
						if tgerr != nil {
							cleanFailure = true
							_ = xerr.AddConsequence(tgerr)
						}
					}
				}

				if _, _, tgerr = tg.WaitGroupFor(temporal.GetLongOperationTimeout()); tgerr != nil {
					cleanFailure = true
					_ = xerr.AddConsequence(tgerr)
				}
			}
		}
	}()

	// configure Cluster as a whole
	xerr = instance.configureCluster(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Sets nominal state of the new Cluster in metadata
	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		// update metadata about disabled default features
		innerXErr := props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			featuresV1.Disabled = req.DisabledDefaultFeatures
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Nominal
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	return nil, xerr
}

// firstLight contains the code leading to Cluster first metadata written
func (instance *Cluster) firstLight(req abstract.ClusterRequest) fail.Error {
	if req.Name = strings.TrimSpace(req.Name); req.Name == "" {
		return fail.InvalidParameterError("req.Name", "cannot be empty string")
	}

	// Initializes instance
	ci := abstract.NewClusterIdentity()
	ci.Name = req.Name
	ci.Flavor = req.Flavor
	ci.Complexity = req.Complexity

	xerr := instance.carry(ci)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		aci, ok := clonable.(*abstract.ClusterIdentity)
		if !ok {
			return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		innerXErr := props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// VPL: For now, always disable addition of feature proxycache
			featuresV1.Disabled["proxycache"] = struct{}{}
			// ENDVPL
			for k := range req.DisabledDefaultFeatures {
				featuresV1.Disabled[k] = struct{}{}
			}
			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to disable feature 'proxycache'")
		}

		// Sets initial state of the new Cluster and create metadata
		innerXErr = props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Creating
			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to set initial state of Cluster")
		}

		// sets default sizing from req
		innerXErr = props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.Defaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.GatewaysDef)
			defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.MastersDef)
			defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.NodesDef)
			defaultsV2.Image = req.NodesDef.Image
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// FUTURE: sets the Cluster composition (when we will be able to manage Cluster spread on several tenants...)
		innerXErr = props.Alter(clusterproperty.CompositeV1, func(clonable data.Clonable) fail.Error {
			compositeV1, ok := clonable.(*propertiesv1.ClusterComposite)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterComposite' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			compositeV1.Tenants = []string{req.Tenant}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Create a KeyPair for the user cladm
		kpName := "cluster_" + req.Name + "_cladm_key"
		kp, innerXErr := abstract.NewKeyPair(kpName)
		if innerXErr != nil {
			return innerXErr
		}
		aci.Keypair = kp

		// Generate needed password for account cladm
		cladmPassword, innerErr := utils.GeneratePassword(16)
		if innerErr != nil {
			return fail.ConvertError(innerErr)
		}
		aci.AdminPassword = cladmPassword

		// Links maker based on Flavor
		return instance.bootstrap(aci.Flavor)
	})
	xerr = debug.InjectPlannedFail(xerr)
	return xerr
}

// determineSizingRequirements calculates the sizings needed for the hosts of the Cluster
func (instance *Cluster) determineSizingRequirements(req abstract.ClusterRequest) (
	_ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, xerr fail.Error,
) {

	var (
		gatewaysDefault *abstract.HostSizingRequirements
		mastersDefault  *abstract.HostSizingRequirements
		nodesDefault    *abstract.HostSizingRequirements
		imageQuery, imageID      string
	)

	// if task.Aborted() {
	// 	return nil, nil, nil, fail.AbortedError(nil, "aborted")
	// }

	// Determine default image

	imageQuery = req.NodesDef.Image
	if imageQuery == "" {
		if cfg, xerr := instance.GetService().GetConfigurationOptions(); xerr == nil {
			if anon, ok := cfg.Get("DefaultImage"); ok {
				imageQuery = anon.(string)
			}
		}
	}
	if imageQuery == "" && instance.makers.DefaultImage != nil {
		imageQuery = instance.makers.DefaultImage(instance)
	}
	if imageQuery == "" {
		imageQuery = "Ubuntu 20.04"
	}
	svc := instance.GetService()
	_, imageID, xerr = determineImageID(svc, imageQuery)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}

	// Determine getGateway sizing
	if instance.makers.DefaultGatewaySizing != nil {
		gatewaysDefault = complementSizingRequirements(nil, instance.makers.DefaultGatewaySizing(instance))
	} else {
		gatewaysDefault = &abstract.HostSizingRequirements{
			MinCores:    2,
			MaxCores:    4,
			MinRAMSize:  7.0,
			MaxRAMSize:  16.0,
			MinDiskSize: 50,
			MinGPU:      -1,
		}
	}

	emptySizing := abstract.HostSizingRequirements{
		MinGPU: -1,
	}

	gatewaysDef := complementSizingRequirements(&req.GatewaysDef, *gatewaysDefault)
	gatewaysDef.Image = imageID

	if !req.GatewaysDef.Equals(emptySizing) {
		if lower, err := req.GatewaysDef.LowerThan(gatewaysDefault); err == nil && lower {
			if !req.Force {
				return nil, nil, nil, fail.NewError("requested gateway sizing less than recommended")
			}
		}
	}

	tmpl, xerr := svc.FindTemplateBySizing(*gatewaysDef)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}

	gatewaysDef.Template = tmpl.ID

	// Determine master sizing
	if instance.makers.DefaultMasterSizing != nil {
		mastersDefault = complementSizingRequirements(nil, instance.makers.DefaultMasterSizing(instance))
	} else {
		mastersDefault = &abstract.HostSizingRequirements{
			MinCores:    4,
			MaxCores:    8,
			MinRAMSize:  15.0,
			MaxRAMSize:  32.0,
			MinDiskSize: 100,
			MinGPU:      -1,
		}
	}
	mastersDef := complementSizingRequirements(&req.MastersDef, *mastersDefault)
	mastersDef.Image = imageID

	if !req.MastersDef.Equals(emptySizing) {
		if lower, err := req.MastersDef.LowerThan(mastersDefault); err == nil && lower {
			if !req.Force {
				return nil, nil, nil, fail.NewError("requested master sizing less than recommended")
			}
		}
	}

	if mastersDef.Equals(*gatewaysDef) {
		mastersDef.Template = gatewaysDef.Template
	} else {
		tmpl, xerr = svc.FindTemplateBySizing(*mastersDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, nil, xerr
		}
		mastersDef.Template = tmpl.ID
	}

	// Determine node sizing
	if instance.makers.DefaultNodeSizing != nil {
		nodesDefault = complementSizingRequirements(nil, instance.makers.DefaultNodeSizing(instance))
	} else {
		nodesDefault = &abstract.HostSizingRequirements{
			MinCores:    4,
			MaxCores:    8,
			MinRAMSize:  15.0,
			MaxRAMSize:  32.0,
			MinDiskSize: 100,
			MinGPU:      -1,
		}
	}
	nodesDef := complementSizingRequirements(&req.NodesDef, *nodesDefault)
	nodesDef.Image = imageID

	if !req.NodesDef.Equals(emptySizing) {
		if lower, err := req.NodesDef.LowerThan(nodesDefault); err == nil && lower {
			if !req.Force {
				return nil, nil, nil, fail.NewError("requested node sizing less than recommended")
			}
		}
	}

	if nodesDef.Equals(*gatewaysDef) { //nolint
		nodesDef.Template = gatewaysDef.Template
	} else if nodesDef.Equals(*mastersDef) {
		nodesDef.Template = mastersDef.Template
	} else {
		tmpl, xerr = svc.FindTemplateBySizing(*nodesDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, nil, xerr
		}
		nodesDef.Template = tmpl.ID
	}

	// Updates property
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*gatewaysDef)
			defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*mastersDef)
			defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*nodesDef)
			defaultsV2.Image = imageQuery
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, nil, xerr
	}

	return gatewaysDef, mastersDef, nodesDef, nil
}

// createNetworkingResources creates the network and subnet for the Cluster
func (instance *Cluster) createNetworkingResources(task concurrency.Task, req abstract.ClusterRequest, gatewaysDef *abstract.HostSizingRequirements) (_ resources.Network, _ resources.Subnet, xerr fail.Error) {
	if task.Aborted() {
		return nil, nil, fail.AbortedError(nil, "aborted")
	}

	ctx := context.WithValue(task.Context(), concurrency.KeyForTaskInContext, task)

	// Determine if getGateway Failover must be set
	caps := instance.GetService().GetCapabilities()
	gwFailoverDisabled := req.Complexity == clustercomplexity.Small || !caps.PrivateVirtualIP
	for k := range req.DisabledDefaultFeatures {
		if k == "gateway-failover" {
			gwFailoverDisabled = true
			break
		}
	}

	req.Name = strings.ToLower(strings.TrimSpace(req.Name))

	// Creates Network
	var rn resources.Network
	if req.NetworkID != "" {
		rn, xerr = LoadNetwork(instance.GetService(), req.NetworkID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, fail.Wrap(xerr, "failed to use network %s to contain Cluster Subnet", req.NetworkID)
		}
	} else {
		logrus.Debugf("[Cluster %s] creating Network '%s'", req.Name, req.Name)
		networkReq := abstract.NetworkRequest{
			Name:          req.Name,
			CIDR:          req.CIDR,
			KeepOnFailure: req.KeepOnFailure,
		}

		rn, xerr = NewNetwork(instance.GetService())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, fail.Wrap(xerr, "failed to instanciate new Network")
		}

		xerr = rn.Create(ctx, networkReq)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, nil, fail.Wrap(xerr, "failed to create Network '%s'", req.Name)
		}

		defer func() {
			if xerr != nil && !req.KeepOnFailure {
				// Using context.Background() here disables abort
				if derr := rn.Delete(context.Background()); derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						// missing Network is considered as a successful deletion, continue
						debug.IgnoreError(derr)
					default:
						_ = xerr.AddConsequence(derr)
					}
				}
			}
		}()
	}
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			networkV3.NetworkID = rn.GetID()
			networkV3.CreatedNetwork = req.NetworkID == "" // empty NetworkID means that the Network would have to be deleted when the Cluster will be
			networkV3.CIDR = req.CIDR
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	if task.Aborted() {
		return nil, nil, fail.AbortedError(nil, "aborted")
	}

	// Creates Subnet
	logrus.Debugf("[Cluster %s] creating Subnet '%s'", req.Name, req.Name)
	subnetReq := abstract.SubnetRequest{
		Name:          req.Name,
		NetworkID:     rn.GetID(),
		CIDR:          req.CIDR,
		HA:            !gwFailoverDisabled,
		ImageRef:      gatewaysDef.Image,
		KeepOnFailure: false, // We consider subnet and its gateways as a whole; if any error occurs during the creation of the whole, do keep nothing
	}

	subnetInstance, xerr := NewSubnet(instance.GetService())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	xerr = subnetInstance.Create(ctx, subnetReq, "", gatewaysDef)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrInvalidRequest:
			// Some cloud providers do not allow to create a Subnet with the same CIDR than the Network; try with a sub-CIDR once
			logrus.Warnf("Cloud Provider does not allow to use the same CIDR than the Network one, trying a subset of CIDR...")
			_, ipNet, err := net.ParseCIDR(subnetReq.CIDR)
			err = debug.InjectPlannedError(err)
			if err != nil {
				_ = xerr.AddConsequence(fail.Wrap(err, "failed to compute subset of CIDR '%s'", req.CIDR))
				return nil, nil, xerr
			}

			if subIPNet, subXErr := netutils.FirstIncludedSubnet(*ipNet, 1); subXErr == nil {
				subnetReq.CIDR = subIPNet.String()
			} else {
				_ = xerr.AddConsequence(fail.Wrap(subXErr, "failed to compute subset of CIDR '%s'", req.CIDR))
				return nil, nil, xerr
			}
			if subXErr := subnetInstance.Create(ctx, subnetReq, "", gatewaysDef); subXErr != nil {
				return nil, nil, fail.Wrap(subXErr, "failed to create Subnet '%s' (with CIDR %s) in Network '%s' (with CIDR %s)", subnetReq.Name, subnetReq.CIDR, rn.GetName(), req.CIDR)
			}
			logrus.Infof("CIDR '%s' used successfully for Subnet, there will be less available private IP Addresses than expected.", subnetReq.CIDR)
			xerr = nil
		default:
			return nil, nil, fail.Wrap(xerr, "failed to create Subnet '%s' in Network '%s'", req.Name, rn.GetName())
		}
	}

	defer func() {
		if xerr != nil && !req.KeepOnFailure {
			if derr := subnetInstance.Delete(context.Background()); derr != nil {
				switch derr.(type) {
				case *fail.ErrNotFound:
					// missing Subnet is considered as a successful deletion, continue
					debug.IgnoreError(derr)
				default:
					_ = xerr.AddConsequence(derr)
				}
			}
		}
	}()

	if task.Aborted() {
		return nil, nil, fail.AbortedError(nil, "aborted")
	}

	// Updates again Cluster metadata, propertiesv3.ClusterNetwork, with subnet infos
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			primaryGateway, innerXErr := subnetInstance.InspectGateway(true)
			if innerXErr != nil {
				return innerXErr
			}

			var secondaryGateway resources.Host
			if !gwFailoverDisabled {
				secondaryGateway, innerXErr = subnetInstance.InspectGateway(false)
				if innerXErr != nil {
					return innerXErr
				}
			}
			networkV3.SubnetID = subnetInstance.GetID()
			networkV3.GatewayID = primaryGateway.GetID()
			if networkV3.GatewayIP, innerXErr = primaryGateway.GetPrivateIP(); innerXErr != nil {
				return innerXErr
			}
			if networkV3.DefaultRouteIP, innerXErr = subnetInstance.GetDefaultRouteIP(); innerXErr != nil {
				return innerXErr
			}
			if networkV3.EndpointIP, innerXErr = subnetInstance.GetEndpointIP(); innerXErr != nil {
				return innerXErr
			}
			if networkV3.PrimaryPublicIP, innerXErr = primaryGateway.GetPublicIP(); innerXErr != nil {
				return innerXErr
			}
			if !gwFailoverDisabled {
				networkV3.SecondaryGatewayID = secondaryGateway.GetID()
				if networkV3.SecondaryGatewayIP, innerXErr = secondaryGateway.GetPrivateIP(); innerXErr != nil {
					return innerXErr
				}
				if networkV3.SecondaryPublicIP, innerXErr = secondaryGateway.GetPublicIP(); innerXErr != nil {
					return innerXErr
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, nil, xerr
	}

	logrus.Debugf("[Cluster %s] Subnet '%s' in Network '%s' creation successful.", req.Name, rn.GetName(), req.Name)
	return rn, subnetInstance, nil
}

// createHostResources creates and configures hosts for the Cluster
func (instance *Cluster) createHostResources(
	task concurrency.Task,
	subnet resources.Subnet,
	mastersDef abstract.HostSizingRequirements,
	nodesDef abstract.HostSizingRequirements,
	initialNodeCount uint,
	keepOnFailure bool,
) (xerr fail.Error) {
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	ctx := task.Context()
	startedTasks := []concurrency.Task{}

	defer func() {
		if xerr != nil {
			// Disable abort signal during the cleanup
			defer task.DisarmAbortSignal()()

			taskID := func(t concurrency.Task) string {
				tid, cleanErr := t.ID()
				if cleanErr != nil {
					_ = xerr.AddConsequence(cleanErr)
					tid = "<unknown>"
				}
				return tid
			}

			// On error, instructs Tasks/TaskGroups to abort, to stop as soon as possible
			for _, v := range startedTasks {
				if !v.Aborted() {
					cleanErr := v.Abort()
					if cleanErr != nil {
						cleanErr = fail.Wrap(cleanErr, "cleaning up on failure, failed to abort Task/TaskGroup %s spawn by createHostResources()", reflect.TypeOf(v).String(), taskID(v))
						logrus.Error(cleanErr.Error())
						_ = xerr.AddConsequence(cleanErr)
					}
				}
			}

			// we have to wait for completion of aborted Tasks/TaskGroups, not get out before
			for _, v := range startedTasks {
				_, _, werr := v.WaitFor(temporal.GetLongOperationTimeout())
				if werr != nil {
					werr = fail.Wrap(werr, "cleaning up on failure, failed to wait for %s %s", reflect.TypeOf(v).String(), taskID(v))
					_ = xerr.AddConsequence(werr)
				}
			}
		}
	}()

	var (
		primaryGateway, secondaryGateway  resources.Host
		gatewayInstallStatus              fail.Error
		gatewayConfigurationStatus        fail.Error
		mastersStatus, privateNodesStatus fail.Error
	)

	primaryGateway, xerr = subnet.InspectGateway(true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	haveSecondaryGateway := true
	secondaryGateway, xerr = subnet.InspectGateway(false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// It's a valid state not to have a secondary gateway, so continue
			haveSecondaryGateway = false
		default:
			return xerr
		}
	}

	_, xerr = primaryGateway.WaitSSHReady(ctx, temporal.GetExecutionTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "wait for remote ssh service to be ready")
	}

	if haveSecondaryGateway {
		_, xerr = secondaryGateway.WaitSSHReady(ctx, temporal.GetExecutionTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, "failed to wait for remote ssh service to become ready")
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	masterCount, _, _, xerr := instance.determineRequiredNodes()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	gwInstallTasks, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/gateway"))
	if xerr != nil {
		return xerr
	}

	// Step 1: starts gateway installation plus masters creation plus nodes creation
	_, xerr = gwInstallTasks.Start(instance.taskInstallGateway, taskInstallGatewayParameters{primaryGateway}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/%s/install", primaryGateway.GetName())))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	startedTasks = append(startedTasks, gwInstallTasks)

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	if haveSecondaryGateway {
		_, xerr = gwInstallTasks.Start(instance.taskInstallGateway, taskInstallGatewayParameters{secondaryGateway}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/%s/install", secondaryGateway.GetName())))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Starting from here, delete masters if exiting with error and req.keepOnFailure is not true
	defer func() {
		if xerr != nil && !keepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			list, merr := instance.UnsafeListMasters()
			if merr != nil {
				_ = xerr.AddConsequence(merr)
				return
			}

			if len(list) > 0 {
				tg, tgerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/onfailure"))
				if tgerr != nil {
					_ = xerr.AddConsequence(tgerr)
					return
				}

				for _, v := range list {
					if v.ID != "" {
						_, derr := tg.Start(instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{node: v}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/delete", v.Name)))
						if derr != nil {
							_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete master '%s'", v.Name))
						}
					}
				}
				if _, _, derr := tg.WaitGroupFor(temporal.GetLongOperationTimeout()); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to wait for master deletions"))
				}
			}
		}
	}()

	mastersCreateTasks, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/masters"))
	if xerr != nil {
		return xerr
	}

	_, xerr = mastersCreateTasks.Start(instance.taskCreateMasters, taskCreateMastersParameters{
		count:         masterCount,
		mastersDef:    mastersDef,
		keepOnFailure: keepOnFailure,
	}, concurrency.InheritParentIDOption)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	startedTasks = append(startedTasks, mastersCreateTasks)

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Starting from here, if exiting with error, delete nodes
	defer func() {
		if xerr != nil && !keepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			list, merr := instance.unsafeListNodes()
			if merr != nil {
				_ = xerr.AddConsequence(merr)
				return
			}

			if len(list) > 0 {
				tg, tgerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/onfailure"))
				if tgerr != nil {
					_ = xerr.AddConsequence(fail.Wrap(tgerr, "cleaning up on failure, failed to create TaskGroup"))
					return
				}

				for _, v := range list {
					if v.ID != "" {
						_, derr := tg.Start(instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{node: v}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/delete", v.Name)))
						if derr != nil {
							_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete node '%s'", v.Name))
						}
					}
				}
				if _, _, derr := tg.WaitGroupFor(temporal.GetLongOperationTimeout()); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to wait for node deletions"))
				}
			}
		}
	}()

	privateNodesCreateTasks, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/nodes"))
	if xerr != nil {
		return xerr
	}

	_, xerr = privateNodesCreateTasks.Start(instance.taskCreateNodes, taskCreateNodesParameters{
		count:         initialNodeCount,
		public:        false,
		nodesDef:      nodesDef,
		keepOnFailure: keepOnFailure,
	}, concurrency.InheritParentIDOption)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	startedTasks = append(startedTasks, privateNodesCreateTasks)

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Step 2: awaits gateway installation end and masters installation end
	if _, gatewayInstallStatus = gwInstallTasks.WaitGroup(); gatewayInstallStatus != nil {
		return gatewayInstallStatus
	}

	if _, mastersStatus = mastersCreateTasks.WaitGroup(); mastersStatus != nil {
		return mastersStatus
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Step 3: start gateway configuration (needs MasterIPs so masters must be installed first)
	// Configure gateway(s) and waits for the result

	gwCfgTasks, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/configuregateways"))
	if xerr != nil {
		return xerr
	}

	_, xerr = gwCfgTasks.Start(instance.taskConfigureGateway, taskConfigureGatewayParameters{Host: primaryGateway}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/configure", primaryGateway.GetName())))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	startedTasks = append(startedTasks, gwCfgTasks)

	if haveSecondaryGateway {
		_, xerr = gwCfgTasks.Start(instance.taskConfigureGateway, taskConfigureGatewayParameters{Host: secondaryGateway}, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	_, gatewayConfigurationStatus = gwCfgTasks.WaitGroup()
	if gatewayConfigurationStatus != nil {
		return gatewayConfigurationStatus
	}

	// Step 4: configure masters (if masters created successfully and gateways configured successfully)
	mastersCfgTask, xerr := concurrency.NewTaskWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/masters"))
	if xerr != nil {
		return xerr
	}

	_, mastersStatus = mastersCfgTask.Run(instance.taskConfigureMasters, nil, concurrency.InheritParentIDOption, concurrency.AmendID("/configure"))
	if mastersStatus != nil {
		return mastersStatus
	}

	// Step 5: awaits nodes creation
	_, privateNodesStatus = privateNodesCreateTasks.Wait()
	if privateNodesStatus != nil {
		return privateNodesStatus
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Step 6: Starts nodes configuration, if all masters and nodes have been created and gateway has been configured with success
	privateNodesCfgTask, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption, concurrency.AmendID("/nodes"))
	if xerr != nil {
		return xerr
	}

	_, privateNodesStatus = privateNodesCfgTask.Run(instance.taskConfigureNodes, nil, concurrency.InheritParentIDOption, concurrency.AmendID("/configure"))
	if privateNodesStatus != nil {
		return privateNodesStatus
	}

	return nil
}

// complementSizingRequirements complements req with default values if needed
func complementSizingRequirements(req *abstract.HostSizingRequirements, def abstract.HostSizingRequirements) *abstract.HostSizingRequirements {
	var finalDef abstract.HostSizingRequirements
	if req == nil {
		finalDef = def
	} else {
		finalDef = *req

		if def.MinCores > 0 && finalDef.MinCores == 0 {
			finalDef.MinCores = def.MinCores
		}
		if def.MaxCores > 0 && finalDef.MaxCores == 0 {
			finalDef.MaxCores = def.MaxCores
		}
		if def.MinRAMSize > 0.0 && finalDef.MinRAMSize == 0.0 {
			finalDef.MinRAMSize = def.MinRAMSize
		}
		if def.MaxRAMSize > 0.0 && finalDef.MaxRAMSize == 0.0 {
			finalDef.MaxRAMSize = def.MaxRAMSize
		}
		if def.MinDiskSize > 0 && finalDef.MinDiskSize == 0 {
			finalDef.MinDiskSize = def.MinDiskSize
		}
		if finalDef.MinGPU <= 0 && def.MinGPU > 0 {
			finalDef.MinGPU = def.MinGPU
		}
		if finalDef.MinCPUFreq == 0 && def.MinCPUFreq > 0 {
			finalDef.MinCPUFreq = def.MinCPUFreq
		}
		if finalDef.MinCores <= 0 {
			finalDef.MinCores = 2
		}
		if finalDef.MaxCores <= 0 {
			finalDef.MaxCores = 4
		}
		if finalDef.MinRAMSize <= 0.0 {
			finalDef.MinRAMSize = 7.0
		}
		if finalDef.MaxRAMSize <= 0.0 {
			finalDef.MaxRAMSize = 16.0
		}
		if finalDef.MinDiskSize <= 0 {
			finalDef.MinDiskSize = 50
		}
	}

	return &finalDef
}

// taskStartHost is the code called in a Task to start a Host
func (instance *Cluster) taskStartHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	id, ok := params.(string)
	if !ok || id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("params")
	}

	xerr = instance.GetService().StartHost(id)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) { //nolint
		case *fail.ErrDuplicate: // A host already started is considered as a successful run
			logrus.Tracef("host duplicated, start considered as a success")
			debug.IgnoreError(xerr)
			return nil, nil
		}
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return nil, nil
}

func (instance *Cluster) taskStopHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	id, ok := params.(string)
	if !ok || id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("params")
	}

	xerr = instance.GetService().StopHost(id, false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) { //nolint
		case *fail.ErrDuplicate: // A host already stopped is considered as a successful run
			logrus.Tracef("host duplicated, stopping considered as a success")
			debug.IgnoreError(xerr)
			return nil, nil
		}
	}
	return nil, xerr
}

type taskInstallGatewayParameters struct {
	Host resources.Host
}

// taskInstallGateway installs necessary components on one gateway
func (instance *Cluster) taskInstallGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	p, ok := params.(taskInstallGatewayParameters)
	if !ok {
		return result, fail.InvalidParameterError("params", "must be a 'taskInstallGatewayParameters'")
	}
	if p.Host == nil {
		return result, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	hostLabel := p.Host.GetName()

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), params).WithStopwatch().Entering()
	defer tracer.Exiting()

	logrus.Debugf("[%s] starting installation...", hostLabel)

	_, xerr = p.Host.WaitSSHReady(task.Context(), temporal.GetHostTimeout())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Installs docker and docker-compose on gateway
	xerr = instance.installDocker(task.Context(), p.Host, hostLabel)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// // Installs proxycache server on gateway (if not disabled)
	// xerr = instance.installProxyCacheServer(task.Context(), p.Host, hostLabel)
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return nil, xerr
	// }

	// Installs requirements as defined by Cluster Flavor (if it exists)
	xerr = instance.installNodeRequirements(task.Context(), clusternodetype.Gateway, p.Host, hostLabel)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] preparation successful", hostLabel)
	return nil, nil
}

type taskConfigureGatewayParameters struct {
	Host resources.Host
}

// taskConfigureGateway prepares one gateway
func (instance *Cluster) taskConfigureGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// validate and convert parameters
	p, ok := params.(taskConfigureGatewayParameters)
	if !ok {
		return result, fail.InvalidParameterError("params", "must be a 'taskConfigureGatewayParameters'")
	}
	if p.Host == nil {
		return result, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	hostLabel := p.Host.GetName()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	logrus.Debugf("[%s] starting configuration...", hostLabel)

	if instance.makers.ConfigureGateway != nil {
		xerr = instance.makers.ConfigureGateway(instance)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}

	logrus.Debugf("[%s] configuration successful in [%s].", p.Host.GetName(), tracer.Stopwatch().String())
	return nil, nil
}

type taskCreateMastersParameters struct {
	count         uint
	mastersDef    abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateMasters creates masters
func (instance *Cluster) taskCreateMasters(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(tg, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Convert and validate parameters
	p, ok := params.(taskCreateMastersParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreteMastersParameters'")
	}
	if p.count < 1 {
		return nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
	}

	clusterName := instance.GetName()

	if p.count == 0 {
		logrus.Debugf("[Cluster %s] no masters to create.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[Cluster %s] creating %d master%s...", clusterName, p.count, strprocess.Plural(p.count))

	timeout := temporal.GetContextTimeout() + time.Duration(p.count)*time.Minute
	taskParams := taskCreateMasterParameters{
		masterDef:     p.mastersDef,
		timeout:       timeout,
		keepOnFailure: p.keepOnFailure,
	}
	for i := uint(1); i <= p.count; i++ {
		taskParams.index = i
		_, xerr := tg.Start(instance.taskCreateMaster, taskParams, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%d/create", i)))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}
	tr, xerr := tg.WaitGroup()
	if xerr != nil {
		return nil, fail.NewError("[Cluster %s] failed to create master(s): %s", clusterName, xerr.Error())
	}

	logrus.Debugf("[Cluster %s] masters creation successful.", clusterName)
	return tr, nil
}

type taskCreateMasterParameters struct {
	index         uint
	masterDef     abstract.HostSizingRequirements
	timeout       time.Duration
	keepOnFailure bool
}

// taskCreateMaster creates one master
func (instance *Cluster) taskCreateMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	// Convert and validate parameters
	p, ok := params.(taskCreateMasterParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreateMasterParameters'")
	}

	if p.index < 1 {
		return nil, fail.InvalidParameterError("params.index", "must be an integer greater than 0")
	}

	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, xerr = instance.buildHostname("master", clusternodetype.Master)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).Entering()
	defer tracer.Exiting()

	hostLabel := fmt.Sprintf("master #%d", p.index)
	logrus.Debugf("[%s] starting master Host creation...", hostLabel)

	// First creates master in metadata, to keep track of its tried creation, in case of failure
	var nodeIdx uint
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nodesV3.GlobalLastIndex++
			nodeIdx = nodesV3.GlobalLastIndex

			node := &propertiesv3.ClusterNode{
				NumericalID: nodeIdx,
				Name:        hostReq.ResourceName,
			}
			nodesV3.ByNumericalID[nodeIdx] = node
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	// Starting from here, if exiting with error, remove entry from master nodes of the metadata
	defer func() {
		if xerr != nil && !p.keepOnFailure {
			derr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					delete(nodesV3.ByNumericalID, nodeIdx)
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove master from Cluster metadata", ActionFromError(xerr)))
			}
		}
	}()

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	netCfg, xerr := instance.GetNetworkConfig()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	subnet, xerr := LoadSubnet(instance.GetService(), "", netCfg.SubnetID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// -- Create the Host --
	xerr = subnet.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		hostReq.Subnets = []*abstract.Subnet{as}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	hostReq.PublicIP = false
	hostReq.KeepOnFailure = p.keepOnFailure
	if p.masterDef.Image != "" {
		hostReq.ImageID = p.masterDef.Image
	}
	if p.masterDef.Template != "" {
		hostReq.TemplateID = p.masterDef.Template
	}

	hostInstance, xerr := NewHost(instance.GetService())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = hostInstance.Create(task.Context(), hostReq, p.masterDef)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !p.keepOnFailure {
			if derr := hostInstance.Delete(context.Background()); derr != nil {
				switch derr.(type) {
				case *fail.ErrNotFound:
					// missing Host is considered as a successful deletion, continue
					debug.IgnoreError(derr)
				default:
					_ = xerr.AddConsequence(derr)
				}
			}
		}
	}()

	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			node := nodesV3.ByNumericalID[nodeIdx]
			node.ID = hostInstance.GetID()

			// Recover public IP of the master if it exists
			node.PublicIP, innerXErr = hostInstance.GetPublicIP()
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// No public IP, this can happen; continue
				default:
					return innerXErr
				}
			}

			// Recover the private IP of the master that MUST exist
			node.PrivateIP, innerXErr = hostInstance.GetPrivateIP()
			if innerXErr != nil {
				return innerXErr
			}

			// Updates property
			nodesV3.Masters = append(nodesV3.Masters, nodeIdx)
			nodesV3.MasterByName[node.Name] = node.NumericalID
			nodesV3.MasterByID[node.ID] = node.NumericalID

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	hostLabel = fmt.Sprintf("master #%d (%s)", p.index, hostInstance.GetName())

	// xerr = instance.installProxyCacheClient(task.Context(), hostInstance, hostLabel)
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return nil, xerr
	// }

	xerr = instance.installNodeRequirements(task.Context(), clusternodetype.Master, hostInstance, hostLabel)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] Host creation successful.", hostLabel)
	return hostInstance, nil
}

// taskConfigureMasters configure masters
func (instance *Cluster) taskConfigureMasters(task concurrency.Task, _ concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()

	logrus.Debugf("[Cluster %s] Configuring masters...", instance.GetName())
	started := time.Now()

	// var subtasks []concurrency.Task
	masters, xerr := instance.UnsafeListMasters()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	if len(masters) == 0 {
		return nil, nil
	}

	tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	var (
		loadErrors []error
		 taskErrors []error
	)
	for i, master := range masters {
		if master.ID == "" {
			continue
		}

		host, xerr := LoadHost(instance.GetService(), master.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.Warnf("failed to get metadata of Host: %s", xerr.Error())
			loadErrors = append(loadErrors, xerr)
			continue
		}

		//goland:noinspection ALL
		defer func(hostInstance resources.Host) {
			hostInstance.Released()
		}(host)

		_, xerr = tg.Start(instance.taskConfigureMaster, taskConfigureMasterParameters{
			Index: i + 1,
			Host:  host,
		}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/configure", host.GetName())))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			taskErrors = append(taskErrors, xerr)
		}
	}

	if len(loadErrors) != 0 {
		logrus.Warnf("there were error reading master's metadata")
		return nil, fail.NewErrorList(loadErrors)
	}

	if len(taskErrors) != 0 {
		return nil, fail.NewErrorList(taskErrors)
	}

	tr, xerr := tg.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[Cluster %s] Masters configuration successful in [%s].", instance.GetName(), temporal.FormatDuration(time.Since(started)))
	return tr, nil
}

type taskConfigureMasterParameters struct {
	Index uint
	Host  resources.Host
}

// taskConfigureMaster configures one master
func (instance *Cluster) taskConfigureMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	// Convert and validate params
	p, ok := params.(taskConfigureMasterParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskConfigureMasterParameters'")
	}

	if p.Index < 1 {
		return nil, fail.InvalidParameterError("params.indexindex", "cannot be an integer less than 1")
	}
	if p.Host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	started := time.Now()

	hostLabel := fmt.Sprintf("master #%d (%s)", p.Index, p.Host.GetName())
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// install docker feature (including docker-compose)
	xerr = instance.installDocker(task.Context(), p.Host, hostLabel)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Configure master for flavour
	if instance.makers.ConfigureMaster != nil {
		xerr = instance.makers.ConfigureMaster(instance, p.Index, p.Host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to configure master '%s'", p.Host.GetName())
		}

		logrus.Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
		return nil, nil
	}

	// Not finding a callback isn't an error, so return nil in this case
	return nil, nil
}

type taskCreateNodesParameters struct {
	count         uint
	public        bool
	nodesDef      abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateNodes creates nodes
func (instance *Cluster) taskCreateNodes(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("tg")
	}

	// Convert then validate params
	p, ok := params.(taskCreateNodesParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreateNodesParameters'")
	}
	if p.count < 1 {
		return nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d, %v)", p.count, p.public).WithStopwatch().Entering()
	defer tracer.Exiting()

	clusterName := instance.GetName()

	if p.count == 0 {
		logrus.Debugf("[Cluster %s] no nodes to create.", clusterName)
		return nil, nil
	}
	logrus.Debugf("[Cluster %s] creating %d node%s...", clusterName, p.count, strprocess.Plural(p.count))

	tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
	if xerr != nil {
		return nil, xerr
	}

	timeout := temporal.GetContextTimeout() + time.Duration(p.count)*time.Minute
	for i := uint(1); i <= p.count; i++ {
		_, xerr := tg.Start(instance.taskCreateNode, taskCreateNodeParameters{
			index:         i,
			nodeDef:       p.nodesDef,
			timeout:       timeout,
			keepOnFailure: p.keepOnFailure,
		}, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}

	tr, err := tg.WaitGroup()
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[Cluster %s] %d node%s creation successful.", clusterName, p.count, strprocess.Plural(p.count))
	return tr, nil
}

type taskCreateNodeParameters struct {
	index         uint
	nodeDef       abstract.HostSizingRequirements
	timeout       time.Duration // Not used currently
	keepOnFailure bool
}

// taskCreateNode creates a node in the Cluster
func (instance *Cluster) taskCreateNode(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	// Convert then validate parameters
	p, ok := params.(taskCreateNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}

	if p.index < 1 {
		return nil, fail.InvalidParameterError("params.indexindex", "cannot be an integer less than 1")
	}

	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, xerr = instance.buildHostname("node", clusternodetype.Node)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d)", p.index).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostLabel := fmt.Sprintf("node #%d", p.index)
	logrus.Debugf(tracer.TraceMessage("[%s] starting Host creation...", hostLabel))

	// First creates node in metadata, to keep track of its tried creation, in case of failure
	var nodeIdx uint
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nodesV3.GlobalLastIndex++
			nodeIdx = nodesV3.GlobalLastIndex
			node := &propertiesv3.ClusterNode{
				NumericalID: nodeIdx,
				Name:        hostReq.ResourceName,
			}
			nodesV3.ByNumericalID[nodeIdx] = node
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	// Starting from here, if exiting with error, remove entry from nodes in the metadata
	defer func() {
		if xerr != nil && !p.keepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			derr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					delete(nodesV3.ByNumericalID, nodeIdx)
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove node from Cluster metadata", ActionFromError(xerr)))
			}
		}
	}()

	netCfg, xerr := instance.GetNetworkConfig()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	subnet, xerr := LoadSubnet(instance.GetService(), "", netCfg.SubnetID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Create the hostInstance
	xerr = subnet.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		hostReq.Subnets = []*abstract.Subnet{as}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	hostReq.PublicIP = false
	hostReq.KeepOnFailure = p.keepOnFailure

	if p.nodeDef.Image != "" {
		hostReq.ImageID = p.nodeDef.Image
	}
	if p.nodeDef.Template != "" {
		hostReq.TemplateID = p.nodeDef.Template
	}

	hostInstance, xerr := NewHost(instance.GetService())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	_, xerr = hostInstance.Create(task.Context(), hostReq, p.nodeDef)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !p.keepOnFailure {
			if derr := hostInstance.Delete(context.Background()); derr != nil {
				switch derr.(type) {
				case *fail.ErrNotFound:
					// missing Host is considered as a successful deletion, continue
					debug.IgnoreError(derr)
				default:
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Host '%s'", ActionFromError(xerr), hostInstance.GetName()))
				}
			}
		}
	}()

	var node *propertiesv3.ClusterNode
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			node = nodesV3.ByNumericalID[nodeIdx]
			node.ID = hostInstance.GetID()
			node.PublicIP, innerXErr = hostInstance.GetPublicIP()
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// No public IP, this can happen; continue
				default:
					return innerXErr
				}
			}

			if node.PrivateIP, innerXErr = hostInstance.GetPrivateIP(); innerXErr != nil {
				return innerXErr
			}

			nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
			nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
			nodesV3.PrivateNodeByID[node.ID] = node.NumericalID

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	hostLabel = fmt.Sprintf("node #%d (%s)", p.index, hostInstance.GetName())

	// xerr = instance.installProxyCacheClient(task.Context(), hostInstance, hostLabel)
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return nil, xerr
	// }

	xerr = instance.installNodeRequirements(task.Context(), clusternodetype.Node, hostInstance, hostLabel)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] Host creation successful.", hostLabel)
	return node, nil
}

// taskConfigureNodes configures nodes
func (instance *Cluster) taskConfigureNodes(task concurrency.Task, _ concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	clusterName := instance.GetName()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()

	list, err := instance.unsafeListNodes()
	err = debug.InjectPlannedFail(err)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		logrus.Debugf("[Cluster %s] no nodes to configure.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[Cluster %s] configuring nodes...", clusterName)

	tg, xerr := concurrency.NewTaskGroupWithParent(task, concurrency.InheritParentIDOption)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	for i, node := range list {
		if node.ID == "" {
			continue
		}

		_, xerr = tg.Start(instance.taskConfigureNode, taskConfigureNodeParameters{
			Index: i + 1,
			Node:  node,
		}, concurrency.InheritParentIDOption, concurrency.AmendID(fmt.Sprintf("/host/%s/configure", node.Name)))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
	}

	_, xerr = tg.WaitGroup()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[Cluster %s] nodes configuration successful.", clusterName)
	return nil, nil
}

type taskConfigureNodeParameters struct {
	Index uint
	Node  *propertiesv3.ClusterNode
}

// taskConfigureNode configure one node
func (instance *Cluster) taskConfigureNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	// Convert and validate params
	p, ok := params.(taskConfigureNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskConfigureNodeParameters'")
	}
	if p.Index < 1 {
		return nil, fail.InvalidParameterError("params.indexindex", "cannot be an integer less than 1")
	}
	if p.Node == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Node")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d, %s)", p.Index, p.Node.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostLabel := fmt.Sprintf("node #%d (%s)", p.Index, p.Node.Name)
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	hostInstance, xerr := LoadHost(instance.GetService(), p.Node.ID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, fail.Wrap(xerr, "failed to get metadata of node '%s'", p.Node.Name)
	}

	//goland:noinspection ALL
	defer func(item resources.Host) {
		item.Released()
	}(hostInstance)

	// Docker and docker-compose installation is mandatory on all nodes
	xerr = instance.installDocker(task.Context(), hostInstance, hostLabel)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Now configures node specifically for Cluster flavor
	if instance.makers.ConfigureNode == nil {
		return nil, nil
	}
	xerr = instance.makers.ConfigureNode(instance, p.Index, hostInstance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Error(xerr.Error())
		return nil, xerr
	}

	logrus.Debugf("[%s] configuration successful.", hostLabel)
	return nil, nil
}

type taskDeleteNodeOnFailureParameters struct {
	node *propertiesv3.ClusterNode
}

// taskDeleteNodeOnFailure deletes a node when a failure occured
func (instance *Cluster) taskDeleteNodeOnFailure(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	// Convert and validate params
	casted, ok := params.(taskDeleteNodeOnFailureParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeOnFailureParameters'")
	}

	node := casted.node

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// prefix := "Cleaning up on failure, "
	// hostName := node.Name
	// logrus.Debugf(prefix + fmt.Sprintf("deleting Host '%s'", hostName))

	hostInstance, xerr := LoadHost(instance.GetService(), node.ID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Tracef("Node %s not found, deletion considered successful", node.Name)
			return nil, nil
		default:
			return nil, xerr
		}
	}

	return nil, deleteHostOnFailure(hostInstance)
	// xerr = hostInstance.Delete(context.Background())
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	switch xerr.(type) {
	// 	case *fail.ErrNotFound:
	// 		logrus.Tracef("Node %s not found, deletion considered successful", hostName)
	// 		return nil, nil
	// 	default:
	// 		return nil, xerr
	// 	}
	// }
	//
	// logrus.Debugf(prefix + fmt.Sprintf("successfully deleted Host '%s'", hostName))
	// return nil, nil
}

type taskDeleteNodeParameters struct {
	node   *propertiesv3.ClusterNode
	master *Host
}

// taskDeleteNode deletes one node
func (instance *Cluster) taskDeleteNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	// Convert and validate paramsx
	p, ok := params.(taskDeleteNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeParameters'")
	}
	if p.node == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.node")
	}
	if p.node.NumericalID == 0 {
		return nil, fail.InvalidParameterError("params.node.NumericalID", "cannot be 0")
	}
	if p.node.ID == "" && p.node.Name == "" {
		return nil, fail.InvalidParameterError("params.node.ID|params.node.Name", "ID or Name must be set")
	}

	nodeName := p.node.Name
	if nodeName == "" {
		nodeName = p.node.ID
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	defer func() {
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to delete Node '%s'", p.node.Name)
		}
	}()

	logrus.Debugf("Deleting Node '%s'", nodeName)
	xerr = instance.deleteNode(task.Context(), p.node, p.master)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Debugf("Node %s not found, deletion considered successful", nodeName)
			return nil, nil
		default:
			return nil, xerr
		}
	}

	logrus.Debugf("Successfully deleted Node '%s'", nodeName)
	return nil, nil
}

// taskDeleteMaster deletes one master
func (instance *Cluster) taskDeleteMaster(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	// Convert and validate params
	p, ok := params.(taskDeleteNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeParameters'")
	}
	if p.node == nil {
		return nil, fail.InvalidParameterError("params.node", "cannot be nil")
	}
	if p.node.ID == "" && p.node.Name == "" {
		return nil, fail.InvalidParameterError("params.node.ID|params.node.Name", "ID or Name must be set")
	}

	nodeName := p.node.Name
	if nodeName == "" {
		nodeName = p.node.ID
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	host, xerr := LoadHost(instance.GetService(), nodeName, HostLightOption)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Tracef("Master %s not found, deletion considered successful", p.node.Name)
			return nil, nil
		default:
			return nil, xerr
		}
	}

	logrus.Debugf("Deleting Master '%s'", p.node.Name)
	xerr = instance.deleteMaster(task.Context(), host)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Debugf("Master %s not found, deletion considered successful", p.node.Name)
			return nil, nil
		default:
			return nil, xerr
		}
	}

	logrus.Debugf("Successfully deleted Master '%s'", p.node.Name)
	return nil, nil
}

type taskDeleteHostOnFailureParameters struct {
	host resources.Host
}

// taskDeleteHostOnFailure deletes a host
func (instance *Cluster) taskDeleteHostOnFailure(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance == nil || instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	// Convert and validate params
	casted, ok := params.(taskDeleteHostOnFailureParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskDeleteHostOnFailureParameters'")
	}
	hostInstance := casted.host

	return nil, deleteHostOnFailure(hostInstance)
}

// deleteHostOnFailure deletes a Host with appropriate logs
func deleteHostOnFailure(instance resources.Host) fail.Error {
	prefix := "Cleaning up on failure, "
	hostName := instance.GetName()
	logrus.Debugf(prefix + fmt.Sprintf("deleting Host '%s'", hostName))

	xerr := instance.Delete(context.Background())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.Tracef("Host %s not found, deletion considered successful", hostName)
			return nil
		default:
			return xerr
		}
	}

	logrus.Debugf(prefix + fmt.Sprintf("successfully deleted Host '%s'", hostName))
	return nil
}
