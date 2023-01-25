/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package resources

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/consts"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// taskCreateCluster is the TaskAction that creates a Cluster
func (instance *Cluster) taskCreateCluster(inctx context.Context, clusterTrx clusterTransaction, params interface{}) (_ interface{}, _ fail.Error) {
	req, ok := params.(abstract.ClusterRequest)
	if !ok {
		return nil, fail.InvalidParameterError("params", "should be an abstract.ClusterRequest")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, gerr := func() (_ interface{}, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// Check if Cluster exists in metadata; if yes, error
			_, xerr := LoadCluster(ctx, req.Name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					return nil, xerr
				}
			} else {
				ar := result{nil, fail.DuplicateError("a Cluster named '%s' already exist", req.Name)}
				return nil, ar.rErr
			}

			// Create first metadata of Cluster after initialization
			xerr = instance.firstLight(ctx, clusterTrx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			cleanFailure := false
			// Starting from here, delete metadata if exiting with error
			// but if the next cleaning steps fail, we must keep the metadata to try again, so we have the cleanFailure flag to detect that issue
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() && !cleanFailure {
					logrus.WithContext(ctx).Debugf("Cleaning up on %s, deleting metadata of Cluster '%s'...", ActionFromError(ferr), req.Name)
					if derr := instance.Core.Delete(jobapi.NewContextPropagatingJob(inctx)); derr != nil {
						logrus.WithContext(context.Background()).Errorf(
							"cleaning up on %s, failed to delete metadata of Cluster '%s'", ActionFromError(ferr), req.Name,
						)
						_ = ferr.AddConsequence(derr)
					} else {
						logrus.WithContext(ctx).Debugf(
							"Cleaning up on %s, successfully deleted metadata of Cluster '%s'", ActionFromError(ferr), req.Name,
						)
					}
				}
			}()

			// Obtain number of nodes to create
			_, privateNodeCount, _, xerr := instance.trxDetermineRequiredNodes(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			if req.InitialNodeCount == 0 {
				req.InitialNodeCount = privateNodeCount
			}
			if req.InitialNodeCount > 0 && req.InitialNodeCount < privateNodeCount {
				logrus.WithContext(ctx).Warnf("[Cluster %s] cannot create less than required minimum of workers by the Flavor (%d requested, minimum being %d for flavor '%s')", req.Name, req.InitialNodeCount, privateNodeCount, req.Flavor.String())
				req.InitialNodeCount = privateNodeCount
			}

			// Define the sizing dependencies for Cluster hosts
			if req.GatewaysDef.Image == "" {
				req.GatewaysDef.Image = req.OS
			}
			if req.MastersDef.Image == "" {
				req.MastersDef.Image = req.OS
			}
			if req.NodesDef.Image == "" {
				req.NodesDef.Image = req.OS
			}

			gatewaysDef, mastersDef, nodesDef, xerr := instance.trxDetermineSizingRequirements(ctx, clusterTrx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			var (
				networkInstance *Network
				subnetInstance  *Subnet
			)
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() && subnetInstance != nil && networkInstance != nil {
					logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Subnet '%s'...", subnetInstance.GetName())
					if derr := subnetInstance.Delete(jobapi.NewContextPropagatingJob(inctx)); derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Subnet is considered as a successful deletion, continue
							debug.IgnoreErrorWithContext(ctx, derr)
						default:
							cleanFailure = true
							logrus.WithContext(context.Background()).Errorf("Cleaning up on %s, failed to delete Subnet '%s'", ActionFromError(ferr), subnetInstance.GetName())
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", ActionFromError(ferr)))
						}
					} else {
						logrus.WithContext(ctx).Debugf("Cleaning up on %s, successfully deleted Subnet '%s'", ActionFromError(ferr), subnetInstance.GetName())
						if req.NetworkID == "" {
							logrus.WithContext(ctx).Debugf("Cleaning up on %s, deleting Network '%s'...", ActionFromError(ferr), networkInstance.GetName())
							if derr := networkInstance.Delete(jobapi.NewContextPropagatingJob(inctx)); derr != nil {
								switch derr.(type) {
								case *fail.ErrNotFound:
									// missing Network is considered as a successful deletion, continue
									debug.IgnoreErrorWithContext(ctx, derr)
								default:
									cleanFailure = true
									logrus.WithContext(context.Background()).Errorf("cleaning up on %s, failed to delete Network '%s'", ActionFromError(ferr), networkInstance.GetName())
									_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Network", ActionFromError(ferr)))
								}
							} else {
								logrus.WithContext(ctx).Debugf("Cleaning up on %s, successfully deleted Network '%s'", ActionFromError(ferr), networkInstance.GetName())
							}
						}
					}
				}
			}()

			// Create the Network and Subnet
			networkInstance, subnetInstance, xerr = instance.createNetworkingResources(ctx, clusterTrx, req, gatewaysDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// FIXME: At some point clusterIdentity has to change...

			// Starting from here, exiting with error deletes hosts if req.keepOnFailure is false
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() {
					logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Hosts...")
					var list []machineID

					var nodemap map[uint]*propertiesv3.ClusterNode
					derr := inspectClusterMetadataProperty(cleanupContextFrom(ctx), clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
						nodemap = nodesV3.ByNumericalID
						return nil
					})
					if derr != nil {
						cleanFailure = true
						_ = ferr.AddConsequence(derr)
						return
					}

					for _, v := range nodemap {
						list = append(list, machineID{ID: v.ID, Name: v.Name})
					}

					if len(list) > 0 {
						clean := new(errgroup.Group)
						for _, v := range list {
							captured := v
							if captured.ID != "" {
								clean.Go(func() error {
									p := taskDeleteNodeOnFailureParameters{
										ID:            captured.ID,
										Name:          captured.Name,
										KeepOnFailure: req.KeepOnFailure,
										Timeout:       2 * time.Minute,
									}
									_, err := instance.taskDeleteNodeOnFailure(cleanupContextFrom(ctx), p)
									return err
								})
							}
						}
						clErr := fail.Wrap(clean.Wait())
						if clErr != nil {
							cleanFailure = true
							return
						}
					} else {
						logrus.WithContext(ctx).Warningf("relying on metadata here was a mistake...")
					}
				}
			}()

			// Creates and configures hosts
			xerr = instance.createHostResources(ctx, clusterTrx, subnetInstance, *mastersDef, *nodesDef, req.InitialNodeCount, ExtractFeatureParameters(req.FeatureParameters), req.KeepOnFailure)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// configure Cluster as a whole
			xerr = instance.configureCluster(ctx, clusterTrx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// Sets nominal state of the new Cluster in metadata
			xerr = alterClusterMetadataProperties(ctx, clusterTrx, func(props *serialize.JSONProperties) fail.Error {
				// update metadata about disabled default features
				innerXErr := props.Alter(clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
					featuresV1, err := clonable.Cast[*propertiesv1.ClusterFeatures](p)
					if err != nil {
						return fail.Wrap(err)
					}

					featuresV1.Disabled = req.DisabledDefaultFeatures
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				return props.Alter(clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
					stateV1, err := clonable.Cast[*propertiesv1.ClusterState](p)
					if err != nil {
						return fail.Wrap(err)
					}

					stateV1.State = clusterstate.Nominal
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return nil, xerr
			}

			return nil, nil
		}() // nolint
		chRes <- result{gres, gerr}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait cleanup
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// firstLight contains the code leading to Cluster first metadata written
func (instance *Cluster) firstLight(inctx context.Context, clusterTrx clusterTransaction, req abstract.ClusterRequest) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			if req.Name = strings.TrimSpace(req.Name); req.Name == "" {
				xerr := fail.InvalidParameterError("req.Name", "cannot be empty string")
				return xerr
			}

			// Initializes instance
			ci, xerr := abstract.NewCluster(abstract.WithName(req.Name))
			if xerr != nil {
				return xerr
			}

			ci.Flavor = req.Flavor
			ci.Complexity = req.Complexity
			ci.Tags["CreationDate"] = time.Now().Format(time.RFC3339)

			xerr = instance.carry(ctx, ci)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = alterClusterMetadata(ctx, clusterTrx, func(aci *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
				innerXErr := props.Alter(clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
					featuresV1, err := clonable.Cast[*propertiesv1.ClusterFeatures](p)
					if err != nil {
						return fail.Wrap(err)
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
				innerXErr = props.Alter(clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
					stateV1, err := clonable.Cast[*propertiesv1.ClusterState](p)
					if err != nil {
						return fail.Wrap(err)
					}

					stateV1.State = clusterstate.Creating
					return nil
				})
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to set initial state of Cluster")
				}

				// sets default sizing from req
				innerXErr = props.Alter(clusterproperty.DefaultsV3, func(p clonable.Clonable) fail.Error {
					defaultsV3, err := clonable.Cast[*propertiesv3.ClusterDefaults](p)
					if err != nil {
						return fail.Wrap(err)
					}

					defaultsV3.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.GatewaysDef)
					defaultsV3.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.MastersDef)
					defaultsV3.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(req.NodesDef)
					defaultsV3.Image = req.NodesDef.Image
					defaultsV3.ImageID = req.NodesDef.Image
					defaultsV3.GatewayTemplateID = req.GatewaysDef.Template
					defaultsV3.NodeTemplateID = req.NodesDef.Template
					defaultsV3.MasterTemplateID = req.MastersDef.Template
					defaultsV3.FeatureParameters = req.FeatureParameters
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				// FUTURE: sets the Cluster composition (when we will be able to manage Cluster spread on several tenants...)
				innerXErr = props.Alter(clusterproperty.CompositeV1, func(p clonable.Clonable) fail.Error {
					compositeV1, err := clonable.Cast[*propertiesv1.ClusterComposite](p)
					if err != nil {
						return fail.Wrap(err)
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
					return fail.Wrap(innerErr)
				}
				aci.AdminPassword = cladmPassword

				// Links maker based on Flavor
				return instance.bootstrap(aci.Flavor)
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			}
			return xerr
		}()
		chRes <- result{gerr}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return fail.Wrap(inctx.Err())
	}
}

// trxDetermineSizingRequirements calculates the sizings needed for the hosts of the Cluster
func (instance *Cluster) trxDetermineSizingRequirements(inctx context.Context, clusterTrx clusterTransaction, req abstract.ClusterRequest) (
	_ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, xerr fail.Error,
) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		aa   *abstract.HostSizingRequirements
		ab   *abstract.HostSizingRequirements
		ac   *abstract.HostSizingRequirements
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var (
				gatewaysDefault     *abstract.HostSizingRequirements
				mastersDefault      *abstract.HostSizingRequirements
				nodesDefault        *abstract.HostSizingRequirements
				imageQuery, imageID string
			)

			// Determine default image
			imageQuery = req.NodesDef.Image
			if imageQuery == "" {
				cfg, xerr := instance.Service().ConfigurationOptions()
				if xerr != nil {
					xerr := fail.Wrap(xerr, "failed to get configuration options")
					return result{nil, nil, nil, xerr}, xerr
				}
				imageQuery = cfg.DefaultImage
			}
			makers := instance.localCache.makers
			if imageQuery == "" && makers.DefaultImage != nil {
				imageQuery = makers.DefaultImage(instance)
			}
			if imageQuery == "" {
				imageQuery = consts.DEFAULTOS
			}
			svc := instance.Service()
			_, imageID, xerr = determineImageID(ctx, svc, imageQuery)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}

			// Determine getGateway sizing
			if makers.DefaultGatewaySizing != nil {
				gatewaysDefault = complementSizingRequirements(nil, makers.DefaultGatewaySizing(instance))
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
						xerr := fail.NewError("requested gateway sizing less than recommended")
						return result{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr := svc.FindTemplateBySizing(ctx, *gatewaysDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}

			gatewaysDef.Template = tmpl.ID

			// Determine master sizing
			if makers.DefaultMasterSizing != nil {
				mastersDefault = complementSizingRequirements(nil, makers.DefaultMasterSizing(instance))
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
						xerr := fail.NewError("requested master sizing less than recommended")
						return result{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr = svc.FindTemplateBySizing(ctx, *mastersDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}

			mastersDef.Template = tmpl.ID

			// Determine node sizing
			if makers.DefaultNodeSizing != nil {
				nodesDefault = complementSizingRequirements(nil, makers.DefaultNodeSizing(instance))
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
						xerr := fail.NewError("requested node sizing less than recommended")
						return result{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr = svc.FindTemplateBySizing(ctx, *nodesDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}
			nodesDef.Template = tmpl.ID

			// Updates property
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.DefaultsV2, func(defaultsV2 *propertiesv2.ClusterDefaults) fail.Error { //nolint
				defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*gatewaysDef)
				defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*mastersDef)
				defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*nodesDef)
				defaultsV2.Image = imageQuery
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{nil, nil, nil, xerr}, xerr
			}

			return result{gatewaysDef, mastersDef, nodesDef, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.aa, res.ab, res.ac, res.rErr
	case <-ctx.Done():
		return nil, nil, nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, nil, nil, fail.Wrap(inctx.Err())
	}
}

// createNetworkingResources creates the network and subnet for the Cluster
func (instance *Cluster) createNetworkingResources(
	inctx context.Context, clusterTrx clusterTransaction, req abstract.ClusterRequest, gatewaysDef *abstract.HostSizingRequirements,
) (_ *Network, _ *Subnet, ferr fail.Error) {

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rn   *Network
		rsn  *Subnet
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			req.Name = strings.ToLower(strings.TrimSpace(req.Name))

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/create/network/%s", oldKey, req.Name)) // nolint
			}

			// Determine if getGateway Failover must be set
			svc := instance.Service()
			caps := svc.Capabilities()
			gwFailoverDisabled := req.Complexity == clustercomplexity.Small || !caps.PrivateVirtualIP
			for k := range req.DisabledDefaultFeatures {
				if k == "gateway-failover" {
					gwFailoverDisabled = true
					break
				}
			}

			// Creates Network
			var (
				networkInstance *Network
				xerr            fail.Error
			)
			if req.NetworkID != "" {
				networkInstance, xerr = LoadNetwork(ctx, req.NetworkID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, nil, fail.Wrap(xerr, "failed to use network %s to contain Cluster Subnet", req.NetworkID)}
					return ar, ar.rErr
				}
			} else {
				logrus.WithContext(ctx).Debugf("[Cluster %s] creating Network '%s'", req.Name, req.Name)
				networkReq := abstract.NetworkRequest{
					Name:          req.Name,
					CIDR:          req.CIDR,
					KeepOnFailure: req.KeepOnFailure,
				}

				defer func() {
					ferr = debug.InjectPlannedFail(ferr)
					if ferr != nil && req.CleanOnFailure() {
						// FIXME: introduce jobapi.NewNewContextPropagatingJob() in cleanupContextFrom()
						if derr := networkInstance.Delete(cleanupContextFrom(ctx) /*jobapi.NewContextPropagatingJob(inctx)*/); derr != nil {
							switch derr.(type) {
							case *fail.ErrNotFound:
								// missing Network is considered as a successful deletion, continue
								debug.IgnoreErrorWithContext(ctx, derr)
							default:
								_ = ferr.AddConsequence(derr)
							}
						}
					}
				}()

				networkInstance, xerr = NewNetwork(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, nil, fail.Wrap(xerr, "failed to instantiate new Network")}
					return ar, ar.rErr
				}

				xerr = networkInstance.Create(ctx, networkReq)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, nil, fail.Wrap(xerr, "failed to create Network '%s'", req.Name)}
					return ar, ar.rErr
				}
			}
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NetworkV3, func(networkV3 *propertiesv3.ClusterNetwork) fail.Error {
				var innerErr error
				networkV3.NetworkID, innerErr = networkInstance.GetID()
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				networkV3.CreatedNetwork = req.NetworkID == "" // empty NetworkID means that the Network would have to be deleted when the Cluster will be
				networkV3.CIDR = req.CIDR
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, nil, xerr}
				return ar, xerr
			}

			nid, err := networkInstance.GetID()
			if err != nil {
				xerr := fail.Wrap(err)
				ar := result{nil, nil, xerr}
				return ar, xerr
			}

			// Creates Subnet
			logrus.WithContext(ctx).Debugf("[Cluster %s] creating Subnet '%s'", req.Name, req.Name)
			subnetReq := abstract.SubnetRequest{
				Name:           req.Name,
				NetworkID:      nid,
				CIDR:           req.CIDR,
				HA:             !gwFailoverDisabled,
				ImageRef:       gatewaysDef.Image,
				DefaultSSHPort: uint32(req.DefaultSshPort),
				KeepOnFailure:  false, // We consider subnet and its gateways as a whole; if any error occurs during the creation of the whole, do keep nothing
			}

			subnetInstance, xerr := NewSubnet(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() && subnetInstance != nil {
					// FIXME
					if derr := subnetInstance.Delete(cleanupContextFrom(ctx) /*jobapi.NewContextPropagatingJob(inctx)*/); derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Subnet is considered as a successful deletion, continue
							debug.IgnoreErrorWithContext(ctx, derr)
						default:
							_ = ferr.AddConsequence(derr)
						}
					}
				}
			}()

			cluID, _ := instance.GetID()
			xerr = subnetInstance.Create(ctx, subnetReq, "", gatewaysDef, map[string]string{
				"type":      "gateway",
				"clusterID": cluID,
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrInvalidRequest:
					// Some cloud providers do not allow to create a Subnet with the same CIDR than the Network; try with a sub-CIDR once
					logrus.WithContext(ctx).Warnf("Cloud Provider does not allow to use the same CIDR than the Network one, trying a subset of CIDR...")
					_, ipNet, err := net.ParseCIDR(subnetReq.CIDR)
					err = debug.InjectPlannedError(err)
					if err != nil {
						_ = xerr.AddConsequence(fail.Wrap(err, "failed to compute subset of CIDR '%s'", req.CIDR))
						return result{nil, nil, xerr}, xerr
					}

					subIPNet, subXErr := netutils.FirstIncludedSubnet(*ipNet, 1)
					if subXErr != nil {
						_ = xerr.AddConsequence(fail.Wrap(subXErr, "failed to compute subset of CIDR '%s'", req.CIDR))
						return result{nil, nil, xerr}, xerr
					}
					subnetReq.CIDR = subIPNet.String()

					newSubnetInstance, xerr := NewSubnet(ctx) // subnetInstance.Create CANNOT be reused
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						ar := result{nil, nil, xerr}
						return ar, xerr
					}
					subnetInstance = newSubnetInstance // replace the external reference

					cluID, _ := instance.GetID()
					subXErr = subnetInstance.Create(ctx, subnetReq, "", gatewaysDef, map[string]string{
						"type":      "gateway",
						"clusterID": cluID,
					})
					if subXErr != nil {
						ar := result{nil, nil, fail.Wrap(
							subXErr, "failed to create Subnet '%s' (with CIDR %s) in Network '%s' (with CIDR %s)",
							subnetReq.Name, subnetReq.CIDR, req.NetworkID, req.CIDR,
						)}
						return ar, ar.rErr
					}
					logrus.WithContext(ctx).Infof("CIDR '%s' used successfully for Subnet, there will be less available private IP Addresses than expected.", subnetReq.CIDR)
				default:
					ar := result{nil, nil, fail.Wrap(
						xerr, "failed to create Subnet '%s' in Network '%s'", req.Name, req.NetworkID,
					)}
					return ar, ar.rErr
				}
			}

			// Updates again Cluster metadata, propertiesv3.ClusterNetwork, with subnet infos
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NetworkV3, func(networkV3 *propertiesv3.ClusterNetwork) fail.Error {
				primaryGateway, innerXErr := subnetInstance.InspectGateway(ctx, true)
				if innerXErr != nil {
					return innerXErr
				}

				var secondaryGateway *Host
				if !gwFailoverDisabled {
					secondaryGateway, innerXErr = subnetInstance.InspectGateway(ctx, false)
					if innerXErr != nil {
						return innerXErr
					}
				}
				var innerErr error
				networkV3.SubnetID, innerErr = subnetInstance.GetID()
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}
				networkV3.GatewayID, innerErr = primaryGateway.GetID()
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}
				if networkV3.GatewayIP, innerXErr = primaryGateway.GetPrivateIP(ctx); innerXErr != nil {
					return innerXErr
				}
				if networkV3.DefaultRouteIP, innerXErr = subnetInstance.GetDefaultRouteIP(ctx); innerXErr != nil {
					return innerXErr
				}
				if networkV3.EndpointIP, innerXErr = subnetInstance.GetEndpointIP(ctx); innerXErr != nil {
					return innerXErr
				}
				if networkV3.PrimaryPublicIP, innerXErr = primaryGateway.GetPublicIP(ctx); innerXErr != nil {
					return innerXErr
				}
				if !gwFailoverDisabled {
					networkV3.SecondaryGatewayID, innerErr = secondaryGateway.GetID()
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}
					if networkV3.SecondaryGatewayIP, innerXErr = secondaryGateway.GetPrivateIP(ctx); innerXErr != nil {
						return innerXErr
					}
					if networkV3.SecondaryPublicIP, innerXErr = secondaryGateway.GetPublicIP(ctx); innerXErr != nil {
						return innerXErr
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{nil, nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] Subnet '%s' in Network '%s' creation successful.", req.Name, networkInstance.GetName(), req.Name)
			chRes <- result{networkInstance, subnetInstance, nil}
			return result{networkInstance, subnetInstance, nil}, nil
		}() // nolint
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rn, res.rsn, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes // wait for cleanup
		return nil, nil, fail.Wrap(inctx.Err())
	}

}

// createHostResources creates and configures hosts for the Cluster
func (instance *Cluster) createHostResources(
	inctx context.Context,
	clusterTrx clusterTransaction,
	subnet *Subnet,
	mastersDef abstract.HostSizingRequirements,
	nodesDef abstract.HostSizingRequirements,
	initialNodeCount uint,
	parameters data.Map[string, any],
	keepOnFailure bool,
) (_ fail.Error) {
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

			primaryGateway, xerr := subnet.InspectGateway(ctx, true)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			haveSecondaryGateway := true
			secondaryGateway, xerr := subnet.InspectGateway(ctx, false)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreErrorWithContext(ctx, xerr)
					// It's a valid state not to have a secondary gateway, so continue
					haveSecondaryGateway = false
				default:
					return result{xerr}, xerr
				}
			}

			// if this happens, then no, we don't have a secondary gateway, and we have also another problem...
			if haveSecondaryGateway {
				pgi, err := primaryGateway.GetID()
				if err != nil {
					xerr := fail.Wrap(err)
					return result{xerr}, xerr
				}

				sgi, err := secondaryGateway.GetID()
				if err != nil {
					xerr := fail.Wrap(err)
					return result{xerr}, xerr
				}

				if pgi == sgi {
					ar := result{fail.InconsistentError("primary and secondary gateways have the same id %s", pgi)}
					return ar, ar.rErr
				}
			}

			eg := new(errgroup.Group)
			eg.Go(func() error {
				_, xerr := instance.taskInstallGateway(ctx, clusterTrx, taskInstallGatewayParameters{host: primaryGateway, variables: parameters})
				return xerr
			})
			if haveSecondaryGateway {
				eg.Go(func() error {
					_, xerr := instance.taskInstallGateway(ctx, clusterTrx, taskInstallGatewayParameters{host: secondaryGateway, variables: parameters})
					return xerr
				})
			}

			xerr = fail.Wrap(eg.Wait())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			masterCount, _, _, xerr := instance.trxDetermineRequiredNodes(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			// Starting from here, delete masters if exiting with error and req.keepOnFailure is not true
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					// FIXME:
					masters, merr := trxListMasters(cleanupContextFrom(ctx), clusterTrx)
					if merr != nil {
						_ = ferr.AddConsequence(merr)
						return
					}

					var list []machineID
					for _, mach := range masters {
						list = append(list, machineID{ID: mach.ID, Name: mach.Name})
					}

					// FIXME:
					hosts, merr := instance.Service().ListHosts(cleanupContextFrom(ctx) /*jobapi.NewContextPropagatingJob(inctx)*/, false)
					if merr != nil {
						_ = ferr.AddConsequence(merr)
						return
					}

					clusterName := instance.GetName()
					for _, invol := range hosts {
						theName := invol.GetName()
						theID, _ := invol.GetID()
						if strings.Contains(theName, "master") {
							if strings.Contains(theName, clusterName) {
								list = append(list, machineID{ID: theID, Name: invol.GetName()})
							}
						}
					}

					if len(list) > 0 {
						clean := new(errgroup.Group)
						for _, v := range list {
							captured := v
							if captured.ID != "" {
								clean.Go(func() error {
									// FIXME:
									_, err := instance.taskDeleteNodeOnFailure(cleanupContextFrom(ctx) /*jobapi.NewContextPropagatingJob(inctx)*/, taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name, KeepOnFailure: keepOnFailure, Timeout: 2 * time.Minute})
									return err
								})
							}
						}
						clErr := fail.Wrap(clean.Wait())
						if clErr != nil {
							_ = ferr.AddConsequence(clErr)
						}
						return
					}
				}
			}()

			// Step 3: start gateway configuration (needs MasterIPs so masters must be installed first)
			// Configure gateway(s) and waits for the localresult

			// Step 4: configure masters (if masters created successfully and gateways configured successfully)

			// Step 5: awaits nodes creation

			// Step 6: Starts nodes configuration, if all masters and nodes have been created and gateway has been configured with success

			waitForMasters := make(chan struct{})
			waitForBoth := make(chan struct{})
			egMas := new(errgroup.Group)
			egMas.Go(func() error {
				defer func() {
					close(waitForMasters)
				}()
				_, xerr := instance.taskCreateMasters(ctx, clusterTrx, taskCreateMastersParameters{
					count:         masterCount,
					mastersDef:    mastersDef,
					keepOnFailure: keepOnFailure,
				})
				if xerr != nil {
					return xerr
				}
				return nil
			})
			egMas.Go(func() error {
				<-waitForMasters
				defer func() {
					if !haveSecondaryGateway {
						close(waitForBoth)
					}
				}()
				_, xerr := instance.taskConfigureGateway(ctx, taskConfigureGatewayParameters{primaryGateway})
				if xerr != nil {
					return xerr
				}
				return nil
			})
			if haveSecondaryGateway {
				egMas.Go(func() error {
					<-waitForMasters
					defer func() {
						close(waitForBoth)
					}()
					_, xerr := instance.taskConfigureGateway(ctx, taskConfigureGatewayParameters{secondaryGateway})
					if xerr != nil {
						return xerr
					}
					return nil
				})
			}
			egMas.Go(func() error {
				<-waitForMasters
				<-waitForBoth
				_, xerr := instance.taskConfigureMasters(ctx, clusterTrx, taskConfigureMastersParameters{parameters})
				return xerr
			})

			xerr = fail.Wrap(egMas.Wait())
			if xerr != nil {
				return result{xerr}, xerr
			}

			// Starting from here, if exiting with error, delete nodes
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					var derr fail.Error
					defer func() {
						if derr != nil {
							_ = ferr.AddConsequence(derr)
						}
					}()

					nlist, derr := instance.trxListNodes(cleanupContextFrom(ctx), clusterTrx)
					if derr != nil {
						return
					}

					var list []machineID
					for _, mach := range nlist {
						list = append(list, machineID{ID: mach.ID, Name: mach.Name})
					}

					hosts, derr := instance.Service().ListHosts(cleanupContextFrom(ctx), false)
					if derr != nil {
						return
					}

					clusterName := instance.GetName()
					for _, invol := range hosts {
						theName := invol.GetName()
						theID, _ := invol.GetID()
						if strings.Contains(theName, "node") && len(clusterName) > 0 && strings.Contains(theName, clusterName) {
							list = append(list, machineID{ID: theID, Name: invol.GetName()})
						}
					}

					if len(list) > 0 {
						clean := new(errgroup.Group)
						for _, v := range list {
							captured := v
							if captured.ID != "" {
								clean.Go(func() error {
									// FIXME:
									_, err := instance.taskDeleteNodeOnFailure(cleanupContextFrom(ctx), taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name, KeepOnFailure: keepOnFailure, Timeout: 2 * time.Minute})
									return err
								})
							}
						}
						derr = fail.Wrap(clean.Wait())
					}
				}
			}()

			egNod := new(errgroup.Group)
			egNod.Go(func() error {
				_, xerr := instance.taskCreateNodes(ctx, clusterTrx, taskCreateNodesParameters{
					count:         initialNodeCount,
					public:        false,
					nodesDef:      nodesDef,
					keepOnFailure: keepOnFailure,
				})
				if xerr != nil {
					return xerr
				}

				_, xerr = instance.trxConfigureNodes(ctx, clusterTrx, parameters)
				if xerr != nil {
					return xerr
				}

				return nil
			})
			xerr = fail.Wrap(egNod.Wait())
			if xerr != nil {
				return result{xerr}, xerr
			}

			return result{nil}, nil
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes // wait for cleanup
		return fail.Wrap(inctx.Err())
	}
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
func (instance *Cluster) taskStartHost(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	id, ok := params.(string)
	if !ok || id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("params")
	}

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/start/host/%s", oldKey, id)) // nolint
	}

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()
			timings, xerr := svc.Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			xerr = svc.StartHost(ctx, id)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) { // nolint
				case *fail.ErrDuplicate: // A host already started is considered as a successful run
					logrus.WithContext(ctx).Tracef("host duplicated, start considered as a success")
					debug.IgnoreErrorWithContext(ctx, xerr)
					return result{nil, nil}, nil
				}
			}
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// -- refresh state of host --
			hostInstance, xerr := LoadHost(ctx, id)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			_, xerr = hostInstance.WaitSSHReady(ctx, timings.HostOperationTimeout())
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			_, xerr = hostInstance.ForceGetState(ctx)
			return result{nil, xerr}, xerr
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}

}

func (instance *Cluster) taskStopHost(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	id, ok := params.(string)
	if !ok || id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("params")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()
			xerr := svc.StopHost(ctx, id, false)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) { // nolint
				case *fail.ErrDuplicate: // A host already stopped is considered as a successful run
					logrus.WithContext(ctx).Tracef("host duplicated, stopping considered as a success")
					debug.IgnoreErrorWithContext(ctx, xerr)
					return result{nil, nil}, nil
				default:
					return result{nil, xerr}, xerr
				}
			}

			// -- refresh state of host --
			hostInstance, xerr := LoadHost(ctx, id)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			_, xerr = hostInstance.ForceGetState(ctx)
			return result{nil, xerr}, xerr
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskInstallGatewayParameters struct {
	host      *Host
	variables data.Map[string, any]
}

// taskInstallGateway installs necessary components on one gateway
func (instance *Cluster) taskInstallGateway(inctx context.Context, clusterTrx clusterTransaction, params taskInstallGatewayParameters) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	if params.host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	// variables, _ := data.FromMap(p.variables)
	variables := params.variables
	hostLabel := params.host.GetName()

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	// FIXME: recycle concurrency.AmendID()
	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/install/gateway/%s", oldKey, hostLabel)) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), params).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("starting installation.")

			_, xerr = params.host.WaitSSHReady(ctx, timings.HostOperationTimeout())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Installs docker and docker-compose on gateway
			xerr = instance.trxInstallDocker(ctx, clusterTrx, params.host, hostLabel, variables)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Installs dependencies as defined by Cluster Flavor (if it exists)
			xerr = instance.trxInstallNodeRequirements(ctx, clusterTrx, clusternodetype.Gateway, params.host, hostLabel)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[%s] preparation successful", hostLabel)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskConfigureGatewayParameters struct {
	Host *Host
}

// taskConfigureGateway prepares one gateway
func (instance *Cluster) taskConfigureGateway(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// validate and convert parameters
	p, ok := params.(taskConfigureGatewayParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskConfigureGatewayParameters'")
	}
	if p.Host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	hostLabel := p.Host.GetName()

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/configure/gateway/%s", oldKey, hostLabel)) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			logrus.WithContext(ctx).Debugf("starting configuration")

			makers := instance.localCache.makers
			if makers.ConfigureGateway != nil {
				xerr := makers.ConfigureGateway(instance)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}
			}

			logrus.WithContext(ctx).Debugf("[%s] configuration successful in [%s].", hostLabel, tracer.Stopwatch().String())
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}

}

type taskCreateMastersParameters struct {
	count         uint
	mastersDef    abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateMasters creates masters
func (instance *Cluster) taskCreateMasters(inctx context.Context, clusterTrx clusterTransaction, params any) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	p, err := lang.Cast[taskCreateMastersParameters](params)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	if p.count < 1 {
		xerr := fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
		return nil, xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	if p.count == 0 {
		logrus.WithContext(ctx).Debugf("[Cluster %s] no masters to create.", instance.GetName())
		return nil, nil
	}

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()
			timings, xerr := svc.Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("Creating %d master%s...", p.count, strprocess.Plural(p.count))

			timeout := time.Duration(p.count) * timings.HostCreationTimeout() // FIXME: OPP This became the timeout for the whole cluster creation....

			winSize := 8
			cfg, xerr := svc.ConfigurationOptions()
			if xerr == nil {
				winSize = cfg.ConcurrentMachineCreationLimit
			}

			var listMasters []StdResult
			masterChan := make(chan StdResult, p.count)

			err := runWindow(ctx, clusterTrx, p.count, uint(math.Min(float64(p.count), float64(winSize))), timeout, masterChan, instance.trxCreateMaster, taskCreateMasterParameters{
				masterDef:     p.mastersDef,
				timeout:       timings.HostCreationTimeout(),
				keepOnFailure: p.keepOnFailure,
			})
			if err != nil {
				close(masterChan)
				return result{nil, fail.Wrap(err)}, fail.Wrap(err)
			}

			close(masterChan)
			for v := range masterChan {
				if v.Err != nil {
					continue
				}
				if v.ToBeDeleted {
					if aho, ok := v.Content.(*Host); ok {
						xerr = aho.Delete(cleanupContextFrom(ctx))
						debug.IgnoreErrorWithContext(ctx, xerr)
						continue
					}
				}
				listMasters = append(listMasters, v)
			}

			logrus.WithContext(ctx).Debugf("Masters creation successful: %v", listMasters)
			return result{listMasters, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskCreateMasterParameters struct {
	masterDef     abstract.HostSizingRequirements
	timeout       time.Duration
	keepOnFailure bool
}

// trxCreateMaster creates one master
func (instance *Cluster) trxCreateMaster(inctx context.Context, clusterTrx clusterTransaction, params any) (_ interface{}, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	p, err := lang.Cast[taskCreateMasterParameters](params)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	hostReq := abstract.HostRequest{}
	var xerr fail.Error
	hostReq.ResourceName, xerr = instance.trxBuildHostname(ctx, clusterTrx, "master", clusternodetype.Master)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/create/master/%s", oldKey, hostReq.ResourceName)) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			sleepTime := <-instance.randomDelayCh
			time.Sleep(time.Duration(sleepTime) * time.Millisecond)

			// First creates master in metadata, to keep track of its tried creation, in case of failure
			var nodeIdx uint
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				nodesV3.GlobalLastIndex++
				nodeIdx = nodesV3.GlobalLastIndex
				node := &propertiesv3.ClusterNode{
					NumericalID: nodeIdx,
					Name:        hostReq.ResourceName,
				}
				nodesV3.ByNumericalID[nodeIdx] = node
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", fmt.Sprintf("master #%d", nodeIdx))}
				return ar, ar.rErr
			}

			hostLabel := fmt.Sprintf("master %s", hostReq.ResourceName)
			logrus.WithContext(ctx).Debugf("[%s] starting master Host creation...", hostLabel)

			// VPL: transaction rollback will do the job
			// // Starting from here, if exiting with error, remove entry from master nodes of the metadata
			// defer func() {
			// 	ferr = debug.InjectPlannedFail(ferr)
			// 	if ferr != nil && !p.keepOnFailure {
			// 		derr := alterClusterMetadataProperty(cleanupContextFrom(ctx), clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
			// 			delete(nodesV3.ByNumericalID, nodeIdx)
			// 			return nil
			// 		})
			// 		if derr != nil {
			// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove master from Cluster metadata", ActionFromError(ferr)))
			// 		}
			// 	}
			// }()

			netCfg, xerr := instance.GetNetworkConfig(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			subnet, xerr := LoadSubnet(ctx, "", netCfg.SubnetID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			subnetTrx, xerr := newSubnetTransaction(ctx, subnet)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}
			defer subnetTrx.TerminateBasedOnError(ctx, &ferr)

			// -- Create the Host --
			xerr = inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				hostReq.Subnets = []*abstract.Subnet{as}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{nil, xerr}, xerr
			}

			hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			hostReq.PublicIP = false
			hostReq.KeepOnFailure = p.keepOnFailure
			if p.masterDef.Image != "" {
				hostReq.ImageID = p.masterDef.Image
			}
			if p.masterDef.Template != "" {
				hostReq.TemplateID = p.masterDef.Template
			}

			hostInstance, xerr := NewHost(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure && hostInstance != nil {
					derr := hostInstance.Delete(cleanupContextFrom(ctx))
					if derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Host is considered as a successful deletion, continue
							debug.IgnoreErrorWithContext(ctx, derr)
						default:
							_ = ferr.AddConsequence(derr)
						}
					}
				}
			}()

			cluID, _ := instance.GetID()
			_, xerr = hostInstance.Create(ctx, hostReq, p.masterDef, map[string]string{
				"type":      "master",
				"clusterID": cluID,
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) (innerXErr fail.Error) {
				node := nodesV3.ByNumericalID[nodeIdx]
				var err error
				node.ID, err = hostInstance.GetID()
				if err != nil {
					return fail.Wrap(err)
				}

				// Recover public IP of the master if it exists
				var inErr fail.Error
				node.PublicIP, inErr = hostInstance.GetPublicIP(ctx)
				if inErr != nil {
					switch inErr.(type) {
					case *fail.ErrNotFound:
						// No public IP, this can happen; continue
					default:
						return inErr
					}
				}

				// Recover the private IP of the master that MUST exist
				node.PrivateIP, inErr = hostInstance.GetPrivateIP(ctx)
				if inErr != nil {
					return inErr
				}

				// Updates property
				nodesV3.Masters = append(nodesV3.Masters, nodeIdx)
				nodesV3.MasterByName[node.Name] = node.NumericalID
				nodesV3.MasterByID[node.ID] = node.NumericalID
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
				return ar, ar.rErr
			}

			hostLabel = fmt.Sprintf("master (%s)", hostReq.ResourceName)
			xerr = instance.trxInstallNodeRequirements(ctx, clusterTrx, clusternodetype.Master, hostInstance, hostLabel)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[%s] Master creation successful.", hostLabel)
			return result{hostInstance, nil}, nil
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for clean
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

func withTimeout(xerr fail.Error) bool {
	if _, ok := xerr.(*fail.ErrTimeout); ok {
		return true
	}

	result := false
	if elist, ok := xerr.(*fail.ErrorList); ok {
		for _, each := range elist.ToErrorSlice() {
			if ato, isTout := each.(*fail.ErrTimeout); isTout {
				logrus.WithContext(context.Background()).Warnf("Found a tg timeout: %v", ato)
				result = true
			}
		}
	}

	return result
}

type taskConfigureMastersParameters struct {
	variables data.Map[string, any]
}

// taskConfigureMasters configure masters
func (instance *Cluster) taskConfigureMasters(inctx context.Context, clusterTrx clusterTransaction, params any) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	p, err := lang.Cast[taskConfigureMastersParameters](params)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	variables := p.variables

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			clusterName := instance.GetName()
			logrus.WithContext(ctx).Debugf("[Cluster %s] Configuring masters...", clusterName)

			masters, xerr := trxListMasters(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}
			if len(masters) == 0 {
				ar := result{nil, fail.NewError("[Cluster %s] master list cannot be empty.", clusterName)}
				return ar, ar.rErr
			}

			for _, master := range masters {
				if master.ID == "" {
					ar := result{nil, fail.InvalidParameterError("masters", "cannot contain items with empty ID")}
					return ar, ar.rErr
				}
			}

			tgm := new(errgroup.Group)
			for _, master := range masters {
				capturedMaster := master
				tgm.Go(func() error {
					host, xerr := LoadHost(ctx, capturedMaster.ID)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return nil
						default:
							return xerr
						}
					}

					_, xerr = instance.taskConfigureMaster(ctx, clusterTrx, taskConfigureMasterParameters{
						Host:      host,
						variables: variables,
					})
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return nil
						default:
							return xerr
						}
					}
					return nil
				})
			}

			xerr = fail.Wrap(tgm.Wait())
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] masters configuration successful", clusterName)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskConfigureMasterParameters struct {
	Host      *Host
	variables data.Map[string, any]
}

// taskConfigureMaster configures one master
func (instance *Cluster) taskConfigureMaster(inctx context.Context, clusterTrx clusterTransaction, params any) (_ any, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// Convert and validate params
	p, ok := params.(taskConfigureMasterParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskConfigureMasterParameters'")
	}
	if p.Host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}
	variables := p.variables

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/configure/master/%s", oldKey, p.Host.GetName())) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			started := time.Now()

			logrus.WithContext(ctx).Debugf("starting configuration...")

			does, xerr := p.Host.Exists(ctx)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			if !does {
				return result{nil, nil}, nil
			}

			// install docker feature (including docker-compose)
			hostLabel := fmt.Sprintf("master (%s)", p.Host.GetName())
			xerr = instance.trxInstallDocker(ctx, clusterTrx, p.Host, hostLabel, variables)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Configure master for flavor
			makers := instance.localCache.makers
			if makers.ConfigureMaster != nil {
				xerr = makers.ConfigureMaster(instance, p.Host)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, fail.Wrap(xerr, "failed to configure master '%s'", p.Host.GetName())}
					return ar, ar.rErr
				}

				logrus.WithContext(ctx).Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
				return result{nil, nil}, nil
			}

			// Not finding a callback isn't an error, so return nil in this case
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskCreateNodesParameters struct {
	count         uint
	public        bool
	nodesDef      abstract.HostSizingRequirements
	keepOnFailure bool
}

func drainChannel(dch chan struct{}) {
	for {
		end := false
		select {
		case <-dch:
		default:
			end = true
		}
		if end {
			break
		}
	}
	close(dch)
}

func runWindow(
	inctx context.Context,
	clusterTrx clusterTransaction,
	count uint,
	windowSize uint,
	timeout time.Duration,
	uat chan StdResult,
	runner func(context.Context, clusterTransaction, interface{}) (interface{}, fail.Error), data interface{},
) error {

	if windowSize > count {
		return errors.Errorf("window size cannot be greater than task size: %d, %d", count, windowSize)
	}

	if windowSize == count {
		if count >= 4 {
			windowSize -= 2
		}
	}

	window := make(chan struct{}, windowSize) // Sliding window of windowSize
	target := make(chan struct{}, count)
	done := make(chan struct{})

	treeCtx, cancel := context.WithCancel(inctx)
	defer cancel()

	finished := false
	for { // only 4 simultaneous creations
		select {
		case <-done:
			finished = true
		case <-treeCtx.Done():
			finished = true
		case window <- struct{}{}:
		}
		if finished {
			cancel()
			break
		}

		go func() {
			defer func() {
				<-window
			}()

			res, err := runner(treeCtx, clusterTrx, data)
			if err != nil {
				// log the error
				logrus.WithContext(treeCtx).Errorf("window runner failed with: %s", err)
				return
			}

			select {
			case <-done:
				uat <- StdResult{
					Content:     res,
					Err:         err,
					ToBeDeleted: true,
				}
				return
			case <-treeCtx.Done():
				uat <- StdResult{
					Content:     res,
					Err:         err,
					ToBeDeleted: true,
				}
				return
			default:
				uat <- StdResult{
					Content:     res,
					Err:         err,
					ToBeDeleted: false,
				}
			}

			select {
			case <-done:
				return
			case <-treeCtx.Done():
				return
			case target <- struct{}{}:
				if len(target) == int(count) {
					close(done)
					return
				}
				return
			default: // if it blocks because it's full, end of story
				close(done)
				return
			}
		}()
	}

	defer drainChannel(window)
	defer drainChannel(target)

	select {
	case <-done:
		return nil
	case <-inctx.Done():
		return errors.Errorf("Task was cancelled by parent: %s", inctx.Err())
	case <-treeCtx.Done():
		if len(uat) == int(count) {
			return nil
		}
		return errors.Errorf("Task was canceled when target is %d\n", len(target))
	}
}

type StdResult struct {
	Content     interface{}
	Err         error
	ToBeDeleted bool
}

// taskCreateNodes creates nodes
func (instance *Cluster) taskCreateNodes(inctx context.Context, clusterTrx clusterTransaction, params any) (_ any, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// Convert then validate params
	p, ok := params.(taskCreateNodesParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreateNodesParameters'")
	}
	if p.count < 1 {
		return nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d, %v)", p.count, p.public).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("Creating %d node%s...", p.count, strprocess.Plural(p.count))

			timeout := time.Duration(p.count) * timings.HostCreationTimeout()

			winSize := 8
			svc := instance.Service()
			if cfg, xerr := svc.ConfigurationOptions(); xerr == nil {
				winSize = cfg.ConcurrentMachineCreationLimit
			}

			var listNodes []StdResult
			nodesChan := make(chan StdResult, p.count)

			err := runWindow(ctx, clusterTrx, p.count, uint(math.Min(float64(p.count), float64(winSize))), timeout, nodesChan, instance.taskCreateNode, taskCreateNodeParameters{
				nodeDef:       p.nodesDef,
				timeout:       timings.HostOperationTimeout(),
				keepOnFailure: p.keepOnFailure,
			})
			if err != nil {
				return result{nil, fail.Wrap(err)}, fail.Wrap(err)
			}

			close(nodesChan)
			for v := range nodesChan {
				if v.Err != nil {
					continue
				}
				if v.ToBeDeleted {
					_, xerr = instance.trxDeleteNodeWithCtx(ctx, clusterTrx, v.Content.(*propertiesv3.ClusterNode), nil)
					debug.IgnoreErrorWithContext(ctx, xerr)
					continue
				}
				listNodes = append(listNodes, v)
			}

			logrus.WithContext(ctx).Debugf("%d node%s creation successful.", p.count, strprocess.Plural(p.count))
			return result{listNodes, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskCreateNodeParameters struct {
	index         uint
	nodeDef       abstract.HostSizingRequirements
	timeout       time.Duration // Not used currently
	keepOnFailure bool
}

func cleanupContextFrom(inctx context.Context) context.Context {
	newCtx := jobapi.NewContextPropagatingJob(inctx)

	// FIXME: Make "ID" a constant, with an explicit value...
	oldKey := inctx.Value("ID")
	if oldKey != nil {
		newCtx = context.WithValue(newCtx, "ID", oldKey) // nolint

		// cleanup functions can look for "cleanup" to decide if a ctx is a cleanup context
		newCtx = context.WithValue(newCtx, "cleanup", true) // nolint
	}

	return newCtx
}

// taskCreateNode creates a node in the Cluster
func (instance *Cluster) taskCreateNode(inctx context.Context, clusterTrx clusterTransaction, params interface{}) (_ interface{}, _ fail.Error) {
	var xerr fail.Error
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// Convert then validate parameters
	p, ok := params.(taskCreateNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreateNodeParameters'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, xerr = instance.trxBuildHostname(ctx, clusterTrx, "node", clusternodetype.Node)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/create/node/%s", oldKey, hostReq.ResourceName)) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d)", p.index).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			sleepTime := <-instance.randomDelayCh
			time.Sleep(time.Duration(sleepTime) * time.Millisecond)

			// -- First creates node in metadata, to keep track of its tried creation, in case of failure --
			var nodeIdx uint
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				nodesV3.GlobalLastIndex++
				nodeIdx = nodesV3.GlobalLastIndex
				node := &propertiesv3.ClusterNode{
					NumericalID: nodeIdx,
					Name:        hostReq.ResourceName,
				}
				nodesV3.ByNumericalID[nodeIdx] = node
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", fmt.Sprintf("node %s", hostReq.ResourceName))}
				return ar, ar.rErr
			}

			hostLabel := fmt.Sprintf("node %s", hostReq.ResourceName)

			// Starting from here, if exiting with error, remove entry from node of the metadata
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure {
					derr := alterClusterMetadataProperty(cleanupContextFrom(ctx), clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
						delete(nodesV3.ByNumericalID, nodeIdx)
						return nil
					})
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove node from Cluster metadata", ActionFromError(ferr)))
					}
				}
			}()

			netCfg, xerr := instance.GetNetworkConfig(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			subnet, xerr := LoadSubnet(ctx, "", netCfg.SubnetID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			subnetTrx, xerr := newSubnetTransaction(ctx, subnet)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}
			defer subnetTrx.TerminateBasedOnError(ctx, &ferr)

			// -- Create the Host instance corresponding to the new node --
			xerr = inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				hostReq.Subnets = []*abstract.Subnet{as}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{nil, xerr}, xerr
			}

			hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			hostReq.PublicIP = false
			hostReq.KeepOnFailure = p.keepOnFailure

			if p.nodeDef.Image != "" {
				hostReq.ImageID = p.nodeDef.Image
			}
			if p.nodeDef.Template != "" {
				hostReq.TemplateID = p.nodeDef.Template
			}

			hostInstance, xerr := NewHost(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure && hostInstance != nil {
					derr := hostInstance.Delete(cleanupContextFrom(ctx))
					if derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Host is considered as a successful deletion, continue
							debug.IgnoreErrorWithContext(ctx, derr)
						default:
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Host '%s'", ActionFromError(ferr), hostInstance.GetName()))
						}
					}
				}
			}()

			// here is the actual creation of the machine
			cluID, _ := instance.GetID()
			_, xerr = hostInstance.Create(ctx, hostReq, p.nodeDef, map[string]string{
				"type":      "node",
				"clusterID": cluID,
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf(tracer.TraceMessage("[%s] Host updating cluster metadata...", hostLabel))

			// -- update cluster metadata --
			var node *propertiesv3.ClusterNode
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) (innerXErr fail.Error) {
				node = nodesV3.ByNumericalID[nodeIdx]
				var innerErr error
				node.ID, innerErr = hostInstance.GetID()
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				var inErr fail.Error
				node.PublicIP, inErr = hostInstance.GetPublicIP(ctx)
				if inErr != nil {
					switch inErr.(type) {
					case *fail.ErrNotFound:
						// No public IP, this can happen; continue
					default:
						return inErr
					}
				}

				if node.PrivateIP, inErr = hostInstance.GetPrivateIP(ctx); inErr != nil {
					return inErr
				}

				nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
				nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
				nodesV3.PrivateNodeByID[node.ID] = node.NumericalID

				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
				return ar, ar.rErr
			}

			// VPL: transaction rollback will do the job
			// // Starting from here, rollback on cluster metadata in case of failure
			// defer func() {
			// 	ferr = debug.InjectPlannedFail(ferr)
			// 	if ferr != nil && !p.keepOnFailure {
			// 		derr := alterClusterMetadataProperty(cleanupContextFrom(ctx), clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) (innerXErr fail.Error) {
			// 			if found, indexInSlice := containsClusterNode(nodesV3.PrivateNodes, nodeIdx); found {
			// 				length := len(nodesV3.PrivateNodes)
			// 				if indexInSlice < length-1 {
			// 					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes[:indexInSlice], nodesV3.PrivateNodes[indexInSlice+1:]...)
			// 				} else {
			// 					nodesV3.PrivateNodes = nodesV3.PrivateNodes[:indexInSlice]
			// 				}
			// 			}
			//
			// 			hid, err := hostInstance.GetID()
			// 			if err != nil {
			// 				return fail.Wrap(err)
			// 			}
			//
			// 			delete(nodesV3.PrivateNodeByName, hostInstance.GetName())
			// 			delete(nodesV3.PrivateNodeByID, hid)
			// 			return nil
			// 		})
			// 		if derr != nil {
			// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove node '%s' from metadata of cluster '%s'", hostInstance.GetName(), instance.GetName()))
			// 		}
			// 	}
			// }()

			logrus.WithContext(ctx).Debugf(tracer.TraceMessage("[%s] Host installing node requirements...", hostLabel))

			xerr = instance.trxInstallNodeRequirements(ctx, clusterTrx, clusternodetype.Node, hostInstance, hostLabel)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[%s] Node creation successful.", hostLabel)
			return result{node, nil}, nil
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// trxConfigureNodes configures nodes
func (instance *Cluster) trxConfigureNodes(inctx context.Context, clusterTrx clusterTransaction, variables data.Map[string, any]) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			list, err := instance.trxListNodes(ctx, clusterTrx)
			err = debug.InjectPlannedFail(err)
			if err != nil {
				return result{nil, err}, err
			}
			if len(list) == 0 {
				ar := result{nil, fail.NewError("[Cluster %s] node list cannot be empty.", instance.GetName())}
				return ar, ar.rErr
			}

			clusterName := instance.GetName()
			logrus.WithContext(ctx).Debugf("[Cluster %s] configuring nodes...", instance.GetName())

			for _, node := range list {
				if node.ID == "" {
					ar := result{nil, fail.InvalidParameterError("list", "cannot contain items with empty ID")}
					return ar, ar.rErr
				}
			}

			type cfgRes struct {
				who  string
				what interface{}
			}

			resCh := make(chan cfgRes, len(list))
			eg := new(errgroup.Group)
			for _, node := range list {
				capturedNode := node
				eg.Go(func() error {
					tr, xerr := instance.taskConfigureNode(ctx, clusterTrx, capturedNode, variables)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return nil
						default:
							return xerr
						}
					}

					resCh <- cfgRes{
						who:  capturedNode.ID,
						what: tr,
					}

					return nil
				})
			}
			xerr := fail.Wrap(eg.Wait())
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			tgMap := make(map[string]interface{})
			close(resCh)
			for v := range resCh {
				tgMap[v.who] = v.what
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] nodes configuration successful: %v", clusterName, tgMap)
			return result{tgMap, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// taskConfigureNode configure one node
func (instance *Cluster) taskConfigureNode(inctx context.Context, clusterTrx clusterTransaction, node *propertiesv3.ClusterNode, variables data.Map[string, any]) (_ any, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if node == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Node")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%s)", node.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			hostLabel := fmt.Sprintf("node (%s)", node.Name)
			logrus.WithContext(ctx).Debugf("[%s] starting configuration...", hostLabel)

			hostInstance, xerr := LoadHost(ctx, node.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					ar := result{nil, fail.Wrap(xerr, "failed to get metadata of node '%s'", node.Name)}
					return ar, ar.rErr
				}
			}

			does, xerr := hostInstance.Exists(ctx)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			if !does {
				return result{nil, nil}, nil
			}

			// Docker and docker-compose installation is mandatory on all nodes
			xerr = instance.trxInstallDocker(ctx, clusterTrx, hostInstance, hostLabel, variables)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Now configures node specifically for Cluster flavor
			makers := instance.localCache.makers
			if makers.ConfigureNode == nil {
				return result{nil, nil}, nil
			}

			xerr = makers.ConfigureNode(instance, hostInstance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				logrus.WithContext(ctx).Error(xerr.Error())
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[%s] configuration successful.", hostLabel)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type machineID struct {
	ID   string
	Name string
}

type taskDeleteNodeOnFailureParameters struct {
	ID            string
	Name          string
	KeepOnFailure bool
	Timeout       time.Duration
}

// taskDeleteNodeOnFailure deletes a node when a failure occurred
func (instance *Cluster) taskDeleteNodeOnFailure(inctx context.Context, params taskDeleteNodeOnFailureParameters) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// Convert and validate params
	if params.ID == "" {
		return nil, fail.InvalidParameterError("ID", "must NOT be empty")
	}
	if params.KeepOnFailure {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			hostInstance, xerr := LoadHost(ctx, params.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					_ = instance.Service().DeleteHost(ctx, params.ID)
					return result{nil, nil}, nil
				default:
					return result{nil, xerr}, xerr
				}
			}

			xerr = hostInstance.Delete(ctx)
			_ = instance.Service().DeleteHost(ctx, params.ID)
			if xerr != nil {
				return result{}, xerr
			}

			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-time.After(params.Timeout):
		cancel()
		<-chRes
		return nil, fail.TimeoutError(fmt.Errorf("timeout trying to delete node on failure"), params.Timeout)
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

func (instance *Cluster) trxDeleteNodeWithCtx(inctx context.Context, clusterTrx clusterTransaction, node *propertiesv3.ClusterNode, master *Host) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if node == nil {
		return nil, fail.InvalidParameterCannotBeNilError("node")
	}
	if node.NumericalID == 0 {
		return nil, fail.InvalidParameterError("node.NumericalID", "cannot be 0")
	}
	if node.ID == "" && node.Name == "" {
		return nil, fail.InvalidParameterError("node.ID|node.Name", "ID or Name must be set")
	}
	if node.Name == "" {
		node.Name = node.ID
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/delete/node/%s", oldKey, node.Name)) // nolint
	}

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// FIXME: This is another mitigation....
			trueNodeID := node.ID

			logrus.WithContext(ctx).Debugf("Deleting Node...")
			xerr := instance.trxDeleteNode(ctx, clusterTrx, node, master)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					return result{nil, xerr}, xerr
				}
			}

			// kill zombies (instances without metadata)
			_ = instance.Service().DeleteHost(ctx, trueNodeID)

			logrus.WithContext(ctx).Debugf("Successfully deleted Node '%s'", node.Name)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// trxDeleteMaster deletes one master
func (instance *Cluster) trxDeleteMaster(inctx context.Context, clusterTrx clusterTransaction, node *propertiesv3.ClusterNode) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if node == nil {
		return nil, fail.InvalidParameterCannotBeNilError("node")
	}
	if node.ID == "" && node.Name == "" {
		return nil, fail.InvalidParameterError("node.ID|node.Name", "ID or Name must be set")
	}
	nodeRef := node.Name
	if nodeRef == "" {
		nodeRef = node.ID
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/delete/master/%s", oldKey, nodeRef)) // nolint
	}

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			logrus.WithContext(ctx).Debugf("Deleting Master %s", nodeRef)
			trueMasterID := node.ID
			xerr := instance.deleteMaster(ctx, clusterTrx, trueMasterID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					return result{nil, xerr}, xerr
				}
			}

			// kill zombies (instances without metadata)
			svc := instance.Service()
			_ = svc.DeleteHost(ctx, trueMasterID)

			logrus.WithContext(ctx).Debugf("Successfully deleted Master '%s'", node.Name)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskUpdateClusterInventoryMasterParameters struct {
	ctx           context.Context
	master        *Host
	inventoryData string
}

// taskUpdateClusterInventoryMaster task to update a Host (master) ansible inventory
func (instance *Cluster) taskUpdateClusterInventoryMaster(inctx context.Context, params any) (_ any, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// Convert and validate params
	casted, ok := params.(taskUpdateClusterInventoryMasterParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskUpdateClusterInventoryMasterParameters'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			xerr := instance.updateClusterInventoryMaster(ctx, casted)
			return result{nil, xerr}, xerr
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// updateClusterInventoryMaster updates a Host (master) ansible inventory
func (instance *Cluster) updateClusterInventoryMaster(inctx context.Context, param taskUpdateClusterInventoryMasterParameters) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		master := param.master
		inventoryData := param.inventoryData
		does, xerr := master.Exists(ctx)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}
		if !does {
			chRes <- result{nil}
			return
		}

		rfcItem := Item{
			Remote:       fmt.Sprintf("%s/%s", utils.TempFolder, "ansible-inventory.py"),
			RemoteOwner:  "cladm:cladm",
			RemoteRights: "ou+rx-w,g+rwx",
		}

		target := fmt.Sprintf("%s/ansible/inventory/", utils.EtcFolder)
		commands := []string{
			fmt.Sprintf("[ -f %s_inventory.py ] && sudo rm -f %s_inventory.py || exit 0", target, target),
			fmt.Sprintf("sudo mkdir -p %s && sudo mv %s %s_inventory.py", target, rfcItem.Remote, target),
			fmt.Sprintf("sudo chown cladm:root %s_inventory.py", target),
			fmt.Sprintf("ansible-inventory -i %s_inventory.py --list", target),
			fmt.Sprintf("[ -f %sinventory.py ] && sudo rm -f %sinventory.py  || exit 0", target, target),
			fmt.Sprintf("sudo mv %s_inventory.py %sinventory.py", target, target),
		}
		prerr := fmt.Sprintf("[Cluster %s, master %s] Ansible inventory update: ", instance.GetName(), master.GetName())
		errmsg := []string{
			fmt.Sprintf("%sfail to clean up temporaries", prerr),
			fmt.Sprintf("%sfail to move uploaded inventory", prerr),
			fmt.Sprintf("%sfail to update rights of uploaded inventory", prerr),
			fmt.Sprintf("%sfail to test/run uploaded inventory", prerr),
			fmt.Sprintf("%sfail to remove previous inventory", prerr),
			fmt.Sprintf("%sfail to move uploaded inventory to final destination", prerr),
		}

		// Remove possible junks
		cmd := fmt.Sprintf("[ -f %s ] && sudo rm -f %s || exit 0", rfcItem.Remote, rfcItem.Remote)
		connTimeout := timings.ConnectionTimeout()
		delay := timings.NormalDelay()
		retcode, stdout, stderr, xerr := master.Run(ctx, cmd, outputs.COLLECT, connTimeout, delay)
		if xerr != nil {
			chRes <- result{fail.Wrap(xerr, "%sfail to clean previous temporaries", prerr)}
			return
		}
		if retcode != 0 {
			xerr := fail.NewError("%sfail to clean previous temporaries", prerr)
			xerr.Annotate("cmd", cmd)
			xerr.Annotate("stdout", stdout)
			xerr.Annotate("stderr", stderr)
			xerr.Annotate("retcode", retcode)
			chRes <- result{xerr}
			return
		}

		// Upload new inventory
		xerr = rfcItem.UploadString(ctx, inventoryData, master)
		if xerr != nil {
			chRes <- result{fail.Wrap(xerr, "%supload fail", prerr)}
			return
		}

		// Run update commands
		for a, acmd := range commands {
			i, cmd := a, acmd
			retcode, stdout, stderr, xerr = master.Run(ctx, cmd, outputs.COLLECT, connTimeout, delay)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{fail.Wrap(xerr, errmsg[i])}
				return
			}
			if retcode != 0 {
				xerr := fail.NewError(errmsg[i])
				xerr.Annotate("cmd", cmd)
				xerr.Annotate("stdout", stdout)
				xerr.Annotate("stderr", stderr)
				xerr.Annotate("retcode", retcode)
				chRes <- result{xerr}
				return
			}
		}

		chRes <- result{nil}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return fail.Wrap(inctx.Err())
	}
}
