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

package operations

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/sony/gobreaker"
	"math"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	mapset "github.com/deckarep/golang-set"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/consts"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// taskCreateCluster is the TaskAction that creates a Cluster
func (instance *Cluster) taskCreateCluster(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	req, ok := params.(abstract.ClusterRequest)
	if !ok {
		return nil, fail.InvalidParameterError("params", "should be an abstract.ClusterRequest")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	defer func() {
		// drop the cache when we are done creating the cluster
		if ka, err := instance.Service().GetCache(context.Background()); err == nil {
			if ka != nil {
				_ = ka.Clear(context.Background())
			}
		}
	}()

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
			_, xerr := LoadCluster(ctx, instance.Service(), req.Name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreError2(ctx, xerr)
				default:
					return nil, xerr
				}
			} else {
				ar := result{nil, fail.DuplicateError("a Cluster named '%s' already exist", req.Name)}
				return nil, ar.rErr
			}

			// this is the real constructor of the cluster, the one that populates the cluster with meaningful data
			// FIXME: OPP Having this function here is a severe problem, this function should be IN LoadCluster
			// Create first metadata of Cluster after initialization
			xerr = instance.firstLight(ctx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			cleanFailure := false
			// Starting from here, delete metadata if exiting with error
			// but if the next cleaning steps fail, we must keep the metadata to try again, so we have the cleanFailure flag to detect that issue
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !req.KeepOnFailure && !cleanFailure {
					logrus.WithContext(ctx).Debugf("Cleaning up on %s, deleting metadata of Cluster '%s'...", ActionFromError(ferr), req.Name)
					if instance.MetadataCore != nil {
						theID, _ := instance.GetID()

						if derr := instance.MetadataCore.Delete(cleanupContextFrom(ctx)); derr != nil {
							logrus.WithContext(cleanupContextFrom(ctx)).Errorf(
								"cleaning up on %s, failed to delete metadata of Cluster '%s'", ActionFromError(ferr), req.Name,
							)
							_ = ferr.AddConsequence(derr)
						} else {
							logrus.WithContext(ctx).Debugf(
								"Cleaning up on %s, successfully deleted metadata of Cluster '%s'", ActionFromError(ferr), req.Name,
							)
						}

						if ka, err := instance.Service().GetCache(ctx); err == nil {
							if ka != nil {
								if theID != "" {
									_ = ka.Delete(ctx, fmt.Sprintf("%T/%s", instance, theID))
								}
							}
						}
					}
				}
			}()

			// Obtain number of nodes to create
			privateMasterCount, privateNodeCount, _, xerr := instance.determineRequiredNodes(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			if req.InitialNodeCount == 0 {
				req.InitialNodeCount = privateNodeCount
			}
			if req.InitialNodeCount > 0 && req.InitialNodeCount < privateNodeCount {
				logrus.WithContext(ctx).Warnf("[Cluster %s] creating less than required minimum of workers by the Flavor (%d requested, minimum being %d for flavor '%s')", req.Name, req.InitialNodeCount, privateNodeCount, req.Flavor.String())
				// req.InitialNodeCount = privateNodeCount
			}

			if req.InitialMasterCount == 0 {
				req.InitialMasterCount = privateMasterCount
			}
			if req.InitialMasterCount > 0 && req.InitialMasterCount < privateMasterCount {
				logrus.WithContext(ctx).Warnf("[Cluster %s] creating less than required minimum of Masters by the Flavor (%d requested, minimum being %d for flavor '%s')", req.Name, req.InitialMasterCount, privateMasterCount, req.Flavor.String())
				// req.InitialMasterCount = privateMasterCount
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

			// logrus.WithContext(ctx).Warningf("This is the request: %s", litter.Sdump(req))

			gatewaysDef, mastersDef, nodesDef, xerr := instance.determineSizingRequirements(ctx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// logrus.WithContext(ctx).Warningf("This is treated master request: %s", litter.Sdump(mastersDef))
			// logrus.WithContext(ctx).Warningf("This is treated node request: %s", litter.Sdump(nodesDef))

			if req.Flavor == clusterflavor.K8S {
				lowerOS := strings.ToLower(req.GatewaysDef.Image)
				if strings.Contains(lowerOS, "centos 7") {
					return nil, fail.NewError("Sorry, K8s with CentOS 7 not supported")
				}

				lowerOS = strings.ToLower(req.MastersDef.Image)
				if strings.Contains(lowerOS, "centos 7") {
					return nil, fail.NewError("Sorry, K8s with CentOS 7 not supported")
				}

				lowerOS = strings.ToLower(req.NodesDef.Image)
				if strings.Contains(lowerOS, "centos 7") {
					return nil, fail.NewError("Sorry, K8s with CentOS 7 not supported")
				}
			}

			var networkInstance resources.Network
			var subnetInstance resources.Subnet
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !req.KeepOnFailure {
					if subnetInstance != nil && networkInstance != nil {
						logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Subnet '%s'...", req.Name)
						if derr := subnetInstance.Delete(cleanupContextFrom(ctx)); derr != nil {
							switch derr.(type) {
							case *fail.ErrNotFound:
								// missing Subnet is considered as a successful deletion, continue
								debug.IgnoreError2(ctx, derr)
							default:
								cleanFailure = true
								logrus.WithContext(cleanupContextFrom(ctx)).Errorf("Cleaning up on %s, failed to delete Subnet '%s'", ActionFromError(ferr),
									req.Name)
								_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", ActionFromError(ferr)))
							}
						} else {
							logrus.WithContext(ctx).Debugf("Cleaning up on %s, successfully deleted Subnet '%s'", ActionFromError(ferr),
								req.Name)
							if req.NetworkID == "" {
								logrus.WithContext(ctx).Debugf("Cleaning up on %s, deleting Network '%s'...", ActionFromError(ferr), req.NetworkID)
								if derr := networkInstance.Delete(cleanupContextFrom(ctx)); derr != nil {
									switch derr.(type) {
									case *fail.ErrNotFound:
										// missing Network is considered as a successful deletion, continue
										debug.IgnoreError2(ctx, derr)
									default:
										cleanFailure = true
										logrus.WithContext(cleanupContextFrom(ctx)).Errorf("cleaning up on %s, failed to delete Network '%s'", ActionFromError(ferr),
											req.NetworkID)
										_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Network", ActionFromError(ferr)))
									}
								} else {
									logrus.WithContext(ctx).Debugf("Cleaning up on %s, successfully deleted Network '%s'", ActionFromError(ferr),
										req.NetworkID)
								}
							}
						}
					}
				}
			}()

			// Create the Network and Subnet
			networkInstance, subnetInstance, xerr = instance.createNetworkingResources(ctx, req, gatewaysDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			gws, xerr := instance.trueListGateways(ctx)
			if xerr != nil {
				return nil, xerr
			}

			mas := mapset.NewSet()
			for _, agw := range gws {
				mas.Add(agw.Core.ID)
			}

			instance.gateways = []string{}
			mi := mas.Iter()
			for v := range mi {
				instance.gateways = append(instance.gateways, v.(string))
			}

			// Starting from here, exiting with error deletes hosts if req.keepOnFailure is false
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !req.KeepOnFailure {
					logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Hosts...")

					var toDelete []*abstract.HostFull
					masters, derr := instance.trueListMasters(cleanupContextFrom(ctx))
					if derr != nil {
						_ = ferr.AddConsequence(derr)
					} else {
						toDelete = append(toDelete, masters...)
					}
					nodes, derr := instance.trueListNodes(cleanupContextFrom(ctx))
					if derr != nil {
						_ = ferr.AddConsequence(derr)
					} else {
						toDelete = append(toDelete, nodes...)
					}

					if len(toDelete) > 0 {
						clean := new(errgroup.Group)
						for _, v := range toDelete {
							captured := v
							if captured.Core.ID != "" {
								clean.Go(func() error {
									_, err := instance.taskDeleteNodeOnFailure(cleanupContextFrom(ctx), taskDeleteNodeOnFailureParameters{ID: captured.Core.ID, Name: captured.Core.Name, KeepOnFailure: req.KeepOnFailure, Timeout: 2 * time.Minute, clusterName: req.Name})
									return err
								})
							}
						}
						clErr := fail.ConvertError(clean.Wait())
						if clErr != nil {
							cleanFailure = true
							return
						}
					}
				}
			}()

			efe, serr := ExtractFeatureParameters(req.FeatureParameters)
			if serr != nil {
				return nil, fail.ConvertError(serr)
			}

			// Creates and configures hosts
			xerr = instance.createHostResources(ctx, subnetInstance, *mastersDef, *nodesDef, req, efe, req.KeepOnFailure)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// configure Cluster as a whole
			xerr = instance.configureCluster(ctx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// Sets nominal state of the new Cluster in metadata
			xerr = instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}

}

// firstLight contains the code leading to Cluster first metadata written
func (instance *Cluster) firstLight(inctx context.Context, req abstract.ClusterRequest) fail.Error {
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

			// FIXME: OPP This is the true cluster constructor
			// Initializes instance
			ci := abstract.NewClusterIdentity()
			ci.Name = req.Name
			ci.Flavor = req.Flavor
			ci.Complexity = req.Complexity
			ci.Tags["CreationDate"] = time.Now().Format(time.RFC3339)

			*instance.cluID = *ci

			xerr := instance.carry(ctx, ci)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				aci, ok := clonable.(*abstract.ClusterIdentity)
				if !ok {
					return fail.InconsistentError(
						"'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}

				innerXErr := props.Alter(
					clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
						featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv1.ClusterFeatures' expected, '%s' provided",
								reflect.TypeOf(clonable).String(),
							)
						}

						for k := range req.DisabledDefaultFeatures {
							featuresV1.Disabled[k] = struct{}{}
						}
						return nil
					},
				)
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to disable features")
				}

				// Sets initial state of the new Cluster and create metadata
				innerXErr = props.Alter(
					clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
						stateV1, ok := clonable.(*propertiesv1.ClusterState)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String(),
							)
						}
						stateV1.State = clusterstate.Creating
						return nil
					},
				)
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to set initial state of Cluster")
				}

				// sets default sizing from req
				innerXErr = props.Alter(clusterproperty.DefaultsV3, func(clonable data.Clonable) fail.Error {
					defaultsV3, ok := clonable.(*propertiesv3.ClusterDefaults)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv3.Defaults' expected, '%s' provided", reflect.TypeOf(clonable).String(),
						)
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
				innerXErr = props.Alter(clusterproperty.CompositeV1, func(clonable data.Clonable) fail.Error {
					compositeV1, ok := clonable.(*propertiesv1.ClusterComposite)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv1.ClusterComposite' expected, '%s' provided",
							reflect.TypeOf(clonable).String(),
						)
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

				*instance.cluID = *aci

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
		<-chRes
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return fail.ConvertError(inctx.Err())
	}
}

// determineSizingRequirements calculates the sizings needed for the hosts of the Cluster
func (instance *Cluster) determineSizingRequirements(inctx context.Context, req abstract.ClusterRequest) (
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
				cfg, xerr := instance.Service().GetConfigurationOptions(ctx)
				if xerr != nil {
					xerr := fail.Wrap(xerr, "failed to get configuration options")
					return result{nil, nil, nil, xerr}, xerr
				}
				if anon, ok := cfg.Get("DefaultImage"); ok {
					imageQuery, ok = anon.(string)
					if !ok {
						xerr := fail.InconsistentError("failed to convert anon to 'string'")
						return result{nil, nil, nil, xerr}, xerr
					}
				}
			}
			makers, xerr := instance.getMaker(ctx)
			if xerr != nil {
				return result{nil, nil, nil, xerr}, xerr
			}

			if imageQuery == "" && makers.DefaultImage != nil {
				imageQuery = makers.DefaultImage(ctx, instance)
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
				gatewaysDefault = complementSizingRequirements(nil, makers.DefaultGatewaySizing(ctx, instance))
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
				mastersDefault = complementSizingRequirements(nil, makers.DefaultMasterSizing(ctx, instance))
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
				nodesDefault = complementSizingRequirements(nil, makers.DefaultNodeSizing(ctx, instance))
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
			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		<-chRes
		return nil, nil, nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, nil, nil, fail.ConvertError(inctx.Err())
	}

}

// createNetworkingResources creates the network and subnet for the Cluster
func (instance *Cluster) createNetworkingResources(inctx context.Context, req abstract.ClusterRequest, gatewaysDef *abstract.HostSizingRequirements) (_ resources.Network, _ resources.Subnet, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rn   resources.Network
		rsn  resources.Subnet
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
			caps, xerr := svc.GetCapabilities(ctx)
			if xerr != nil {
				return result{nil, nil, xerr}, xerr
			}
			gwFailoverDisabled := req.Complexity == clustercomplexity.Small || !caps.PrivateVirtualIP
			for k := range req.DisabledDefaultFeatures {
				if k == "gateway-failover" {
					gwFailoverDisabled = true
					break
				}
			}

			// Creates Network
			var networkInstance resources.Network
			if req.NetworkID != "" {
				networkInstance, xerr = LoadNetwork(ctx, svc, req.NetworkID)
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
					if ferr != nil && !req.KeepOnFailure {
						if networkInstance != nil {
							if derr := networkInstance.Delete(cleanupContextFrom(ctx)); derr != nil {
								switch derr.(type) {
								case *fail.ErrNotFound:
									// missing Network is considered as a successful deletion, continue
									debug.IgnoreError2(ctx, derr)
								default:
									_ = ferr.AddConsequence(derr)
								}
							}
						}
					}
				}()

				networkInstance, xerr = NewNetwork(svc)
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
			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(
					clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
						networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String(),
							)
						}

						var err error
						networkV3.NetworkID, err = networkInstance.GetID()
						if err != nil {
							return fail.ConvertError(err)
						}

						networkV3.CreatedNetwork = req.NetworkID == "" // empty NetworkID means that the Network would have to be deleted when the Cluster will be
						networkV3.CIDR = req.CIDR
						return nil
					},
				)
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, nil, xerr}
				return ar, xerr
			}

			nid, err := networkInstance.GetID()
			if err != nil {
				xerr := fail.ConvertError(err)
				ar := result{nil, nil, xerr}
				return ar, xerr
			}

			cid, _ := instance.GetID()

			// Creates Subnet
			logrus.WithContext(ctx).Debugf("[Cluster %s] creating Subnet '%s'", req.Name, req.Name)
			subnetReq := abstract.SubnetRequest{
				Name:           req.Name,
				NetworkID:      nid,
				CIDR:           req.CIDR,
				HA:             !gwFailoverDisabled,
				ImageRef:       gatewaysDef.Image,
				DefaultSSHPort: uint32(req.DefaultSshPort),
				ClusterID:      cid,
				KeepOnFailure:  false, // We consider subnet and its gateways as a whole; if any error occurs during the creation of the whole, do keep nothing
			}

			subnetInstance, xerr := NewSubnet(svc)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, nil, xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !req.KeepOnFailure {
					if subnetInstance != nil {
						if derr := subnetInstance.Delete(cleanupContextFrom(ctx)); derr != nil {
							switch derr.(type) {
							case *fail.ErrNotFound:
								// missing Subnet is considered as a successful deletion, continue
								debug.IgnoreError2(ctx, derr)
							default:
								_ = ferr.AddConsequence(derr)
							}
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
					// Some cloud providers do not allow to create a Subnet with the same CIDR as the Network; try with a sub-CIDR once
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

					newSubnetInstance, xerr := NewSubnet(svc) // subnetInstance.Create CANNOT be reused
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						ar := result{nil, nil, xerr}
						return ar, xerr
					}
					subnetInstance = newSubnetInstance // replace the external reference

					cluID, _ := instance.GetID()
					if subXErr := subnetInstance.Create(ctx, subnetReq, "", gatewaysDef, map[string]string{
						"type":      "gateway",
						"clusterID": cluID,
					}); subXErr != nil {
						ar := result{nil, nil, fail.Wrap(
							subXErr, "failed to create Subnet '%s' (with CIDR %s) in Network '%s' (with CIDR %s)",
							subnetReq.Name, subnetReq.CIDR, req.NetworkID, req.CIDR,
						)}
						return ar, ar.rErr
					}
					logrus.WithContext(ctx).Infof(
						"CIDR '%s' used successfully for Subnet, there will be less available private IP Addresses than expected.",
						subnetReq.CIDR,
					)
				default:
					ar := result{nil, nil, fail.Wrap(
						xerr, "failed to create Subnet '%s' in Network '%s'", req.Name, req.NetworkID,
					)}
					return ar, ar.rErr
				}
			}

			// Updates again Cluster metadata, propertiesv3.ClusterNetwork, with subnet infos
			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
					networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					primaryGateway, innerXErr := subnetInstance.InspectGateway(ctx, true)
					if innerXErr != nil {
						return innerXErr
					}

					var secondaryGateway resources.Host
					if !gwFailoverDisabled {
						secondaryGateway, innerXErr = subnetInstance.InspectGateway(ctx, false)
						if innerXErr != nil {
							return innerXErr
						}
					}
					var err error
					networkV3.SubnetID, err = subnetInstance.GetID()
					if err != nil {
						return fail.ConvertError(err)
					}
					networkV3.GatewayID, err = primaryGateway.GetID()
					if err != nil {
						return fail.ConvertError(err)
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
						networkV3.SecondaryGatewayID, err = secondaryGateway.GetID()
						if err != nil {
							return fail.ConvertError(err)
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
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{nil, nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] Subnet '%s' in Network '%s' creation successful.", req.Name, req.NetworkID, req.Name)
			return result{networkInstance, subnetInstance, nil}, nil
		}() // nolint
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rn, res.rsn, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for cleanup
		return nil, nil, fail.ConvertError(inctx.Err())
	}

}

// createHostResources creates and configures hosts for the Cluster
func (instance *Cluster) createHostResources(
	inctx context.Context,
	subnet resources.Subnet,
	mastersDef abstract.HostSizingRequirements,
	nodesDef abstract.HostSizingRequirements,
	cluReq abstract.ClusterRequest,
	parameters data.Map,
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
					debug.IgnoreError2(ctx, xerr)
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
					xerr := fail.ConvertError(err)
					return result{xerr}, xerr
				}

				sgi, err := secondaryGateway.GetID()
				if err != nil {
					xerr := fail.ConvertError(err)
					return result{xerr}, xerr
				}

				if pgi == sgi {
					ar := result{fail.InconsistentError("primary and secondary gateways have the same id %s", pgi)}
					return ar, ar.rErr
				}
			}

			eg := new(errgroup.Group)
			eg.Go(func() error {
				_, xerr := instance.taskInstallGateway(ctx, taskInstallGatewayParameters{host: primaryGateway, variables: parameters, clusterName: cluReq.Name, request: cluReq})
				return xerr
			})
			if haveSecondaryGateway {
				eg.Go(func() error {
					_, xerr := instance.taskInstallGateway(ctx, taskInstallGatewayParameters{host: secondaryGateway, variables: parameters, clusterName: cluReq.Name, request: cluReq})
					return xerr
				})
			}

			xerr = fail.ConvertError(eg.Wait())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			masterCount, _, _, xerr := instance.determineRequiredNodes(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			// FIXME: that's a bad practice -> overwriting initial request (what could be go wrong?)
			if cluReq.InitialMasterCount == 0 {
				cluReq.InitialMasterCount = masterCount
			}
			if cluReq.InitialMasterCount > 0 && cluReq.InitialMasterCount < masterCount {
				logrus.WithContext(ctx).Warnf("[Cluster %s] creating less than required minimum of Masters by the Flavor (%d requested, minimum being %d for flavor '%s')", cluReq.Name, cluReq.InitialMasterCount, masterCount, cluReq.Flavor.String())
				// cluReq.InitialMasterCount = masterCount
			}

			// Starting from here, delete masters if exiting with error and req.keepOnFailure is not true
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					masters, merr := instance.trueListMasters(cleanupContextFrom(ctx))
					if merr != nil {
						_ = ferr.AddConsequence(merr)
						return
					}

					var list []machineID
					for _, mach := range masters {
						list = append(list, machineID{ID: mach.Core.ID, Name: mach.Core.Name})
					}

					hosts, merr := instance.Service().ListHosts(cleanupContextFrom(ctx), false)
					if merr != nil {
						_ = ferr.AddConsequence(merr)
						return
					}

					for _, invol := range hosts {
						theName := invol.GetName()
						theID, _ := invol.GetID()
						iname := cluReq.Name
						if strings.Contains(theName, "master") {
							if len(iname) > 0 {
								if strings.Contains(theName, iname) {
									list = append(list, machineID{ID: theID, Name: invol.GetName()})
								}
							}
						}
					}

					if len(list) > 0 {
						clean := new(errgroup.Group)
						for _, v := range list {
							captured := v
							if captured.ID != "" {
								clean.Go(func() error {
									_, err := instance.taskDeleteNodeOnFailure(cleanupContextFrom(ctx), taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name, KeepOnFailure: keepOnFailure, Timeout: 2 * time.Minute, clusterName: cluReq.Name})
									return err
								})
							}
						}
						clErr := fail.ConvertError(clean.Wait())
						if clErr != nil {
							_ = ferr.AddConsequence(clErr)
						}
						return
					}
				}
			}()

			egMas := new(errgroup.Group)
			egMas.Go(func() error {
				masters, xerr := instance.taskCreateMasters(ctx, taskCreateMastersParameters{
					count:         cluReq.InitialMasterCount,
					mastersDef:    mastersDef,
					keepOnFailure: keepOnFailure,
					clusterName:   cluReq.Name,
					request:       cluReq,
				})
				if xerr != nil {
					return xerr
				}

				_, xerr = instance.taskConfigureMasters(ctx, taskConfigureMastersParameters{
					clusterName: cluReq.Name,
					variables:   parameters,
					masters:     masters.([]*Host),
					request:     cluReq,
				})
				return xerr
			})
			xerr = fail.ConvertError(egMas.Wait())
			if xerr != nil {
				return result{xerr}, xerr
			}

			// Starting from here, if exiting with error, delete nodes
			// FIXME: OPP, another mistake
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					var derr fail.Error
					defer func() {
						if derr != nil {
							_ = ferr.AddConsequence(derr)
						}
					}()

					nlist, derr := instance.trueListNodes(cleanupContextFrom(ctx))
					if derr != nil {
						return
					}

					var list []machineID
					for _, mach := range nlist {
						list = append(list, machineID{ID: mach.Core.ID, Name: mach.Core.Name})
					}

					if len(list) > 0 {
						clean := new(errgroup.Group)
						for _, v := range list {
							captured := v
							if captured.ID != "" {
								clean.Go(func() error {
									_, err := instance.taskDeleteNodeOnFailure(cleanupContextFrom(ctx), taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name, KeepOnFailure: keepOnFailure, Timeout: 2 * time.Minute, clusterName: cluReq.Name})
									return err
								})
							}
						}
						derr = fail.ConvertError(clean.Wait())
					}
				}
			}()

			egNod := new(errgroup.Group)
			egNod.Go(func() error {
				nops, xerr := instance.taskCreateNodes(ctx, taskCreateNodesParameters{
					count:         cluReq.InitialNodeCount,
					public:        false,
					nodesDef:      nodesDef,
					keepOnFailure: keepOnFailure,
					clusterName:   cluReq.Name,
					request:       cluReq,
				})
				if xerr != nil {
					return xerr
				}

				nodes, _ := nops.([]*propertiesv3.ClusterNode) // nolint
				_, xerr = instance.taskConfigureNodes(ctx, taskConfigureNodesParameters{
					variables:   parameters,
					clusterName: cluReq.Name,
					nodes:       nodes,
					request:     cluReq,
				})
				if xerr != nil {
					return xerr
				}

				return nil
			})
			xerr = fail.ConvertError(egNod.Wait())
			if xerr != nil {
				return result{xerr}, xerr
			}

			if _, ok := cluReq.DisabledDefaultFeatures["docker"]; !ok {
				xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
						featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
						if !ok {
							return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}

						featuresV1.Installed["docker"] = &propertiesv1.ClusterInstalledFeature{
							Name: "docker",
						}
						return nil
					})
				})
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					xerr = fail.Wrap(xerr, callstack.WhereIsThis())
					return result{xerr}, xerr
				}
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
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for cleanup
		return fail.ConvertError(inctx.Err())
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

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			id, ok := params.(string)
			if !ok || id == "" {
				xerr := fail.InvalidParameterCannotBeEmptyStringError("params")
				return result{nil, xerr}, xerr
			}

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/start/host/%s", oldKey, id)) // nolint
			}

			svc := instance.Service()

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			xerr = svc.StartHost(ctx, id)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) { // nolint
				case *fail.ErrDuplicate: // A host already started is considered as a successful run
					logrus.WithContext(ctx).Tracef("host duplicated, start considered as a success")
					debug.IgnoreError2(ctx, xerr)
					return result{nil, nil}, nil
				}
			}
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// -- refresh state of host --
			hostInstance, xerr := LoadHost(ctx, svc, id)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			_, xerr = hostInstance.WaitSSHReady(ctx, timings.HostOperationTimeout())
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}

}

func (instance *Cluster) taskStopHost(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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

			id, ok := params.(string)
			if !ok || id == "" {
				xerr := fail.InvalidParameterCannotBeEmptyStringError("params")
				return result{nil, xerr}, xerr
			}

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/stop/host/%s", oldKey, id)) // nolint
			}

			svc := instance.Service()
			xerr := svc.StopHost(ctx, id, false)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) { // nolint
				case *fail.ErrDuplicate: // A host already stopped is considered as a successful run
					logrus.WithContext(ctx).Tracef("host duplicated, stopping considered as a success")
					debug.IgnoreError2(ctx, xerr)
					return result{nil, nil}, nil
				default:
					return result{nil, xerr}, xerr
				}
			}

			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskInstallGatewayParameters struct {
	host        resources.Host
	variables   data.Map
	clusterName string
	request     abstract.ClusterRequest
}

// taskInstallGateway installs necessary components on one gateway
func (instance *Cluster) taskInstallGateway(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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
			p, ok := params.(taskInstallGatewayParameters)
			if !ok {
				xerr := fail.InvalidParameterError("params", "must be a 'taskInstallGatewayParameters'")
				return result{nil, xerr}, xerr
			}
			if p.host == nil {
				xerr := fail.InvalidParameterCannotBeNilError("params.Host")
				return result{nil, xerr}, xerr
			}

			hostLabel := p.host.GetName()

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/install/gateway/%s", oldKey, hostLabel)) // nolint
			}

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("starting installation.")

			_, xerr = p.host.WaitSSHReady(ctx, timings.HostOperationTimeout())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Installs dependencies as defined by Cluster Flavor (if it exists)
			xerr = instance.installNodeRequirements(ctx, clusternodetype.Gateway, p.host, hostLabel, p.request)
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
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskCreateMastersParameters struct {
	count         uint
	mastersDef    abstract.HostSizingRequirements
	keepOnFailure bool
	clusterName   string
	request       abstract.ClusterRequest
}

// taskCreateMasters creates masters
func (instance *Cluster) taskCreateMasters(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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

			// Convert and validate parameters
			p, ok := params.(taskCreateMastersParameters)
			if !ok {
				xerr := fail.InvalidParameterError("params", "must be a 'taskCreteMastersParameters'")
				return result{nil, xerr}, xerr
			}
			if p.count < 1 {
				xerr := fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
				return result{nil, xerr}, xerr
			}

			if p.count == 0 {
				logrus.WithContext(ctx).Debugf("No masters to create.")
				return result{nil, nil}, nil
			}

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("Creating %d master%s...", p.count, strprocess.Plural(p.count))

			tcount := uint(math.Max(4, float64(p.count)))
			timeout := time.Duration(tcount) * timings.HostCreationTimeout() // FIXME: OPP This became the timeout for the whole cluster creation....

			winSize := 8
			st, xerr := instance.Service().GetProviderName()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}
			if st != "ovh" {
				winSize = int((8 * p.count) / 10)
				if winSize < 8 {
					winSize = 8
				}
			}
			svc := instance.Service()
			if cfg, xerr := svc.GetConfigurationOptions(ctx); xerr == nil {
				if aval, ok := cfg.Get("ConcurrentMachineCreationLimit"); ok {
					if val, ok := aval.(int); ok {
						winSize = val
					}
				}
			}

			var theMasters []*Host
			masterChan := make(chan StdResult, 4*p.count)

			ctx, tc := context.WithTimeout(ctx, timeout)
			defer tc()

			err := runWindow(ctx, p.count, uint(math.Min(float64(p.count), float64(winSize))), masterChan, instance.taskCreateMaster, taskCreateMasterParameters{
				masterDef:     p.mastersDef,
				timeout:       timings.HostCreationTimeout(),
				keepOnFailure: p.keepOnFailure,
				clusterName:   p.clusterName,
				request:       p.request,
			})
			if err != nil {
				close(masterChan)
				return result{nil, fail.ConvertError(err)}, fail.ConvertError(err)
			}

			close(masterChan)
			for v := range masterChan {
				if v.Err != nil {
					continue
				}
				if v.ToBeDeleted {
					if aho, ok := v.Content.(*Host); ok {
						hid, _ := aho.GetID()
						xerr = aho.Delete(cleanupContextFrom(ctx))
						debug.IgnoreError2(ctx, xerr)

						xerr = svc.DeleteHost(cleanupContextFrom(ctx), hid)
						debug.IgnoreError2(ctx, xerr)
						continue
					}
				}
				theMasters = append(theMasters, v.Content.(*Host))
				if theID, err := v.Content.(*Host).GetID(); err == nil {
					instance.masters = append(instance.masters, theID)
				}
			}

			logrus.WithContext(ctx).Debugf("Masters creation successful: %v", theMasters)
			return result{theMasters, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskCreateMasterParameters struct {
	masterDef     abstract.HostSizingRequirements
	timeout       time.Duration
	keepOnFailure bool
	clusterName   string
	request       abstract.ClusterRequest
}

// taskCreateMaster creates one master
func (instance *Cluster) taskCreateMaster(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *Host
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// Convert and validate parameters
			p, ok := params.(taskCreateMasterParameters)
			if !ok {
				ar := result{nil, fail.InvalidParameterError("params", "must be a 'taskCreateMasterParameters'")}
				return ar, ar.rErr
			}

			sleepTime := <-instance.randomDelayCh
			time.Sleep(time.Duration(sleepTime) * time.Millisecond)

			hostReq := abstract.HostRequest{}
			hostReq.ResourceName, xerr = instance.buildHostname(ctx, "master", clusternodetype.Master)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/create/master/%s", oldKey, hostReq.ResourceName)) // nolint
			}

			// First creates master in metadata, to keep track of its tried creation, in case of failure
			var nodeIdx uint
			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(
					clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
						nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
							)
						}

						nodesV3.GlobalLastIndex++
						nodeIdx = nodesV3.GlobalLastIndex

						node := &propertiesv3.ClusterNode{
							NumericalID: nodeIdx,
							Name:        hostReq.ResourceName,
						}
						nodesV3.ByNumericalID[nodeIdx] = node
						return nil
					},
				)
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", fmt.Sprintf("master #%d", nodeIdx))}
				return ar, ar.rErr
			}

			hostLabel := fmt.Sprintf("master %s", hostReq.ResourceName)
			logrus.WithContext(ctx).Debugf("[%s] starting master Host creation...", hostLabel)

			// Starting from here, if exiting with error, remove entry from master nodes of the metadata
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure {
					derr := instance.Alter(cleanupContextFrom(ctx), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
						return props.Alter(
							clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
								nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
								if !ok {
									return fail.InconsistentError(
										"'*propertiesv3.ClusterNodes' expected, '%s' provided",
										reflect.TypeOf(clonable).String(),
									)
								}

								delete(nodesV3.ByNumericalID, nodeIdx)
								return nil
							},
						)
					})
					if derr != nil {
						_ = ferr.AddConsequence(
							fail.Wrap(
								derr, "cleaning up on %s, failed to remove master from Cluster metadata", ActionFromError(ferr),
							),
						)
					}
				}
			}()

			netCfg, xerr := instance.GetNetworkConfig(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			svc := instance.Service()
			subnet, xerr := LoadSubnet(ctx, svc, "", netCfg.SubnetID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// -- Create the Host --
			xerr = subnet.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				as, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError(
						"'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}

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

			hostInstance, xerr := NewHost(svc)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure {
					if hostInstance != nil {
						hid, _ := hostInstance.GetID()

						if derr := hostInstance.Delete(cleanupContextFrom(ctx)); derr != nil {
							switch derr.(type) {
							case *fail.ErrNotFound:
								// missing Host is considered as a successful deletion, continue
								debug.IgnoreError2(ctx, derr)
							default:
								_ = ferr.AddConsequence(derr)
							}
						}

						if hid != "" {
							_ = svc.DeleteHost(cleanupContextFrom(ctx), hid)
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

			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(
					clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
						nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
							)
						}

						node := nodesV3.ByNumericalID[nodeIdx]
						var err error
						node.ID, err = hostInstance.GetID()
						if err != nil {
							return fail.ConvertError(err)
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
						nodesV3.MasterByID[node.ID] = node.NumericalID

						return nil
					},
				)
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
				return ar, ar.rErr
			}

			hostLabel = fmt.Sprintf("master (%s)", hostReq.ResourceName)

			xerr = instance.installNodeRequirements(ctx, clusternodetype.Master, hostInstance, hostLabel, p.request)
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
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
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
	clusterName string
	variables   data.Map
	masters     []*Host
	request     abstract.ClusterRequest
}

// taskConfigureMasters configure masters
func (instance *Cluster) taskConfigureMasters(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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

			p, ok := params.(taskConfigureMastersParameters)
			if !ok {
				xerr := fail.InconsistentError("failed to cast 'params' to 'taskConfiguraMastersParameters'")
				return result{nil, xerr}, xerr
			}
			variables, _ := data.FromMap(p.variables)

			iname := p.clusterName
			logrus.WithContext(ctx).Debugf("[Cluster %s] Configuring masters...", iname)

			masters := p.masters

			tgm := new(errgroup.Group)
			for _, master := range masters {
				capturedMaster := master
				tgm.Go(func() error {
					id, err := capturedMaster.GetID()
					if err != nil {
						return err
					}

					host, xerr := LoadHost(ctx, instance.Service(), id)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return nil
						default:
							return xerr
						}
					}

					_, xerr = instance.taskConfigureMaster(ctx, taskConfigureMasterParameters{
						Host:        host,
						variables:   variables,
						clusterName: p.clusterName,
						request:     p.request,
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

			xerr := fail.ConvertError(tgm.Wait())
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] masters configuration successful", iname)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskConfigureMasterParameters struct {
	Host        resources.Host
	variables   data.Map
	clusterName string
	request     abstract.ClusterRequest
}

// taskConfigureMaster configures one master
func (instance *Cluster) taskConfigureMaster(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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

			// Convert and validate params
			p, ok := params.(taskConfigureMasterParameters)
			if !ok {
				ar := result{nil, fail.InvalidParameterError("params", "must be a 'taskConfigureMasterParameters'")}
				return ar, ar.rErr
			}

			if p.Host == nil {
				ar := result{nil, fail.InvalidParameterCannotBeNilError("params.Host")}
				return ar, ar.rErr
			}

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/configure/master/%s", oldKey, p.Host.GetName())) // nolint
			}
			logrus.WithContext(ctx).Debugf("starting configuration...")

			does, xerr := p.Host.Exists(ctx)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			if !does {
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
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskCreateNodesParameters struct {
	clusterName   string
	count         uint
	public        bool
	nodesDef      abstract.HostSizingRequirements
	keepOnFailure bool
	request       abstract.ClusterRequest
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

func runWindow(inctx context.Context, count uint, windowSize uint, uat chan StdResult, runner func(context.Context, interface{}) (interface{}, fail.Error), data interface{}) error {
	if windowSize > count {
		return errors.Errorf("window size cannot be greater than task size: %d, %d", count, windowSize)
	}

	if uint32(cap(uat)) < uint32(2*count+windowSize) { // Account for a 50% success ratio creating machines
		return errors.Errorf("channel must hold count + windowSize")
	}

	if windowSize == count {
		if count >= 4 {
			windowSize -= 2
		}
	}

	var st gobreaker.Settings
	st.Name = "window"
	st.MaxRequests = uint32(count + windowSize)
	st.ReadyToTrip = func(counts gobreaker.Counts) bool {
		failureRatio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 6 && failureRatio >= 0.8
	}

	cb := gobreaker.NewCircuitBreaker(st)

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
				if r := recover(); r != nil {
					logrus.WithContext(treeCtx).Errorf("Unexpected panic: %v", r)
				}
			}()

			if sta := cb.State(); sta == gobreaker.StateOpen {
				logrus.WithContext(treeCtx).Error("Too many consecutive failures")
				cancel()
				return
			}

			defer func() {
				<-window
			}()

			res, err := cb.Execute(func() (interface{}, error) {
				ares, aerr := runner(treeCtx, data)
				if aerr != nil {
					if strings.Contains(aerr.Error(), "context canceled") {
						return ares, aerr
					}
					logrus.WithContext(treeCtx).Errorf("window runner failed with: %s", aerr)
					return ares, aerr
				}
				return ares, nil
			})

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
				if err != nil { // only when err != nil our target should decrease
					return
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
		if sta := cb.State(); sta == gobreaker.StateOpen {
			return errors.Errorf("Too many errors")
		}
		return nil
	case <-inctx.Done():
		return errors.Errorf("Task was cancelled by parent: %s", inctx.Err())
	case <-treeCtx.Done():
		if sta := cb.State(); sta == gobreaker.StateOpen {
			return errors.Errorf("Too many errors")
		}
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
func (instance *Cluster) taskCreateNodes(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  []*propertiesv3.ClusterNode
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			// Convert then validate params
			p, ok := params.(taskCreateNodesParameters)
			if !ok {
				ar := result{nil, fail.InvalidParameterError("params", "must be a 'taskCreateNodesParameters'")}
				return ar, ar.rErr
			}
			if p.count < 1 {
				ar := result{nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")}
				return ar, ar.rErr
			}

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("Creating %d node%s...", p.count, strprocess.Plural(p.count))

			tcount := uint(math.Max(4, float64(p.count)))
			timeout := time.Duration(tcount) * timings.HostCreationTimeout()

			// another tweak for Stein
			winSize := 8
			st, xerr := instance.Service().GetProviderName()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}
			if st != "ovh" {
				winSize = int((8 * p.count) / 10)
				if winSize < 8 {
					winSize = 8
				}
			}

			svc := instance.Service()
			if cfg, xerr := svc.GetConfigurationOptions(ctx); xerr == nil {
				if aval, ok := cfg.Get("ConcurrentMachineCreationLimit"); ok {
					if val, ok := aval.(int); ok {
						winSize = val
					}
				}
			}

			nodesChan := make(chan StdResult, 4*p.count)
			ctx, tc := context.WithTimeout(ctx, timeout)
			defer tc()

			err := runWindow(ctx, p.count, uint(math.Min(float64(p.count), float64(winSize))), nodesChan, instance.taskCreateNode, taskCreateNodeParameters{
				nodeDef:       p.nodesDef,
				timeout:       timings.HostOperationTimeout(),
				keepOnFailure: p.keepOnFailure,
				clusterName:   p.clusterName,
				request:       p.request,
			})
			if err != nil {
				return result{nil, fail.ConvertError(err)}, fail.ConvertError(err)
			}

			close(nodesChan)
			var lino []*propertiesv3.ClusterNode
			for v := range nodesChan {
				if v.Err != nil {
					continue
				}
				if v.ToBeDeleted {
					crucial, ok := v.Content.(*propertiesv3.ClusterNode)
					if !ok {
						continue
					}
					_, xerr = instance.taskDeleteNodeWithCtx(cleanupContextFrom(ctx), taskDeleteNodeParameters{node: v.Content.(*propertiesv3.ClusterNode), clusterName: p.clusterName})
					debug.IgnoreError2(ctx, xerr)

					xerr = svc.DeleteHost(cleanupContextFrom(ctx), crucial.ID)
					debug.IgnoreError2(ctx, xerr)
					continue
				}
				lino = append(lino, v.Content.(*propertiesv3.ClusterNode))
			}

			logrus.WithContext(ctx).Debugf("%d node%s creation successful.", p.count, strprocess.Plural(p.count))
			return result{lino, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskCreateNodeParameters struct {
	clusterName   string
	nodeDef       abstract.HostSizingRequirements
	timeout       time.Duration // Not used currently
	keepOnFailure bool
	request       abstract.ClusterRequest
}

func cleanupContextFrom(inctx context.Context) context.Context {
	if oldKey := inctx.Value("ID"); oldKey != nil {
		ctx := context.WithValue(context.Background(), "ID", oldKey) // nolint
		// cleanup functions can look for "cleanup" to decide if a ctx is a cleanup context
		ctx = context.WithValue(ctx, "cleanup", true) // nolint
		return ctx
	}
	return context.Background()
}

// taskCreateNode creates a node in the Cluster
func (instance *Cluster) taskCreateNode(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  *propertiesv3.ClusterNode
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// Convert then validate parameters
			p, ok := params.(taskCreateNodeParameters)
			if !ok {
				ar := result{nil, fail.InvalidParameterError("params", "must be a data.Map")}
				return ar, ar.rErr
			}

			sleepTime := <-instance.randomDelayCh
			time.Sleep(time.Duration(sleepTime) * time.Millisecond)

			hostReq := abstract.HostRequest{}
			hostReq.ResourceName, xerr = instance.buildHostname(ctx, "node", clusternodetype.Node)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/create/node/%s", oldKey, hostReq.ResourceName)) // nolint
			}

			// -- First creates node in metadata, to keep track of its tried creation, in case of failure --
			var nodeIdx uint
			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(
					clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
						nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
							)
						}

						nodesV3.GlobalLastIndex++
						nodeIdx = nodesV3.GlobalLastIndex
						node := &propertiesv3.ClusterNode{
							NumericalID: nodeIdx,
							Name:        hostReq.ResourceName,
						}
						nodesV3.ByNumericalID[nodeIdx] = node
						return nil
					},
				)
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
					derr := instance.Alter(cleanupContextFrom(ctx), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

			svc := instance.Service()
			subnet, xerr := LoadSubnet(ctx, svc, "", netCfg.SubnetID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			// -- Create the Host instance corresponding to the new node --
			xerr = subnet.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				as, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

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

			// finally, creating a host metadata...
			hostInstance, xerr := NewHost(svc)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure {
					if hostInstance != nil {
						hid, _ := hostInstance.GetID()

						if derr := hostInstance.Delete(cleanupContextFrom(ctx)); derr != nil {
							switch derr.(type) {
							case *fail.ErrNotFound:
								// missing Host is considered as a successful deletion, continue
								debug.IgnoreError2(ctx, derr)
							default:
								hostName := hostReq.ResourceName
								_ = ferr.AddConsequence(
									fail.Wrap(
										derr, "cleaning up on %s, failed to delete Host '%s'", ActionFromError(ferr),
										hostName,
									),
								)
							}
						}

						if hid != "" {
							_ = svc.DeleteHost(cleanupContextFrom(ctx), hid)
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

			logrus.WithContext(ctx).Debugf("[%s] Host updating cluster metadata...", hostLabel)

			// -- update cluster metadata --
			var node *propertiesv3.ClusterNode
			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(
					clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
						nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
							)
						}

						node = nodesV3.ByNumericalID[nodeIdx]
						var err error
						node.ID, err = hostInstance.GetID()
						if err != nil {
							return fail.ConvertError(err)
						}

						var inErr fail.Error
						node.PublicIP, inErr = hostInstance.GetPublicIP(ctx)
						if inErr != nil {
							switch inErr.(type) {
							case *fail.ErrNotFound:
								// No public IP, this can happen; continue
								debug.IgnoreError2(ctx, inErr)
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
					},
				)
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
				return ar, ar.rErr
			}

			// Starting from here, rollback on cluster metadata in case of failure
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure {
					derr := instance.Alter(cleanupContextFrom(ctx), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
						return props.Alter(
							clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
								nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
								if !ok {
									return fail.InconsistentError(
										"'*propertiesv3.ClusterNodes' expected, '%s' provided",
										reflect.TypeOf(clonable).String(),
									)
								}

								if found, indexInSlice := containsClusterNode(nodesV3.PrivateNodes, nodeIdx); found {
									length := len(nodesV3.PrivateNodes)
									if indexInSlice < length-1 {
										nodesV3.PrivateNodes = append(
											nodesV3.PrivateNodes[:indexInSlice], nodesV3.PrivateNodes[indexInSlice+1:]...,
										)
									} else {
										nodesV3.PrivateNodes = nodesV3.PrivateNodes[:indexInSlice]
									}
								}

								hid, err := hostInstance.GetID()
								if err != nil {
									return fail.ConvertError(err)
								}

								delete(nodesV3.PrivateNodeByName, hostInstance.GetName())
								delete(nodesV3.PrivateNodeByID, hid)

								return nil
							},
						)
					})
					if derr != nil {
						iname := hostLabel
						_ = ferr.AddConsequence(
							fail.Wrap(
								derr, "cleaning up on failure, failed to remove node '%s' from metadata of cluster '%s'",
								iname, p.clusterName,
							),
						)
					}
				}
			}()

			logrus.WithContext(ctx).Debugf("[%s] Host installing node requirements...", hostLabel)

			xerr = instance.installNodeRequirements(ctx, clusternodetype.Node, hostInstance, hostLabel, p.request)
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
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskConfigureNodesParameters struct {
	variables   data.Map
	clusterName string
	nodes       []*propertiesv3.ClusterNode
	request     abstract.ClusterRequest
}

// taskConfigureNodes configures nodes
func (instance *Cluster) taskConfigureNodes(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	p, ok := params.(taskConfigureNodesParameters)
	if !ok {
		return nil, fail.InconsistentError("failed to cast 'params' to 'taskConfigureNodesParameters'")
	}
	variables, _ := data.FromMap(p.variables)
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
			clusterName := p.clusterName

			logrus.WithContext(ctx).Debugf("[Cluster %s] configuring nodes...", clusterName)

			for _, node := range p.nodes {
				if node.ID == "" {
					ar := result{nil, fail.InvalidParameterError("list", "cannot contain items with empty ID")}
					return ar, ar.rErr
				}
			}

			type cfgRes struct {
				who  string
				what interface{}
			}

			resCh := make(chan cfgRes, len(p.nodes))
			eg := new(errgroup.Group)
			for _, node := range p.nodes {
				capturedNode := node
				eg.Go(func() error {
					tr, xerr := instance.taskConfigureNode(ctx, taskConfigureNodeParameters{
						node:        capturedNode,
						variables:   variables,
						clusterName: p.clusterName,
						request:     p.request,
					})
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
			xerr := fail.ConvertError(eg.Wait())
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
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskConfigureNodeParameters struct {
	node        *propertiesv3.ClusterNode
	variables   data.Map
	clusterName string
	request     abstract.ClusterRequest
}

// taskConfigureNode configure one node
func (instance *Cluster) taskConfigureNode(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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
			// Convert and validate params
			p, ok := params.(taskConfigureNodeParameters)
			if !ok {
				ar := result{nil, fail.InvalidParameterError("params", "must be a 'taskConfigureNodeParameters'")}
				return ar, ar.rErr
			}
			if p.node == nil {
				ar := result{nil, fail.InvalidParameterCannotBeNilError("params.Node")}
				return ar, ar.rErr
			}

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/configure/node/%s", oldKey, p.node.Name)) // nolint
			}

			hostLabel := fmt.Sprintf("node (%s)", p.node.Name)
			logrus.WithContext(ctx).Debugf("[%s] starting configuration...", hostLabel)

			hostInstance, xerr := LoadHost(ctx, instance.Service(), p.node.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					ar := result{nil, fail.Wrap(xerr, "failed to get metadata of node '%s'", p.node.Name)}
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

			// Now configures node specifically for Cluster flavor
			makers, xerr := instance.getMaker(ctx)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			if makers.ConfigureNode == nil {
				return result{nil, nil}, nil
			}

			xerr = makers.ConfigureNode(ctx, instance, hostInstance)
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
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
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
	clusterName   string
}

// taskDeleteNodeOnFailure deletes a node when a failure occurred
func (instance *Cluster) taskDeleteNodeOnFailure(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	casted, ok := params.(taskDeleteNodeOnFailureParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeOnFailureParameters'")
	}

	if casted.ID == "" {
		return nil, fail.InvalidParameterError("ID", "must NOT be empty")
	}

	if casted.KeepOnFailure {
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

			node := casted

			// kill zombies (instances without metadata)
			svc := instance.Service()

			host, xerr := LoadHost(ctx, svc, node.ID)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					_ = svc.DeleteHost(ctx, node.ID)
					return result{nil, nil}, nil
				default:
					return result{nil, xerr}, xerr
				}
			}

			xerr = host.Delete(ctx)
			if xerr != nil {
				_ = svc.DeleteHost(ctx, node.ID)
				return result{}, xerr
			}

			_ = svc.DeleteHost(ctx, node.ID)

			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-time.After(casted.Timeout):
		<-chRes
		return nil, fail.TimeoutError(fmt.Errorf("timeout trying to delete node on failure"), casted.Timeout)
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskDeleteNodeParameters struct {
	node        *propertiesv3.ClusterNode
	master      *Host
	clusterName string
}

func (instance *Cluster) taskDeleteNodeWithCtx(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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
			// Convert and validate params
			p, ok := params.(taskDeleteNodeParameters)
			if !ok {
				ar := result{nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeParameters'")}
				return ar, ar.rErr
			}
			if p.node == nil {
				ar := result{nil, fail.InvalidParameterCannotBeNilError("params.node")}
				return ar, ar.rErr
			}
			if p.node.NumericalID == 0 {
				ar := result{nil, fail.InvalidParameterError("params.node.NumericalID", "cannot be 0")}
				return ar, ar.rErr
			}
			if p.node.ID == "" && p.node.Name == "" {
				ar := result{nil, fail.InvalidParameterError("params.node.ID|params.node.Name", "ID or Name must be set")}
				return ar, ar.rErr
			}

			nodeName := p.node.Name
			if nodeName == "" {
				nodeName = p.node.ID
			}

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/delete/node/%s", oldKey, nodeName)) // nolint
			}

			// FIXME: This is another mitigation....
			trueNodeID := p.node.ID

			logrus.WithContext(ctx).Debugf("Deleting Node...")
			xerr := instance.deleteNode(ctx, p.node, p.master)
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
			_ = svc.DeleteHost(ctx, trueNodeID)

			logrus.WithContext(ctx).Debugf("Successfully deleted Node '%s'", nodeName)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
}

// taskDeleteMaster deletes one master
func (instance *Cluster) taskDeleteMaster(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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
			// Convert and validate params
			p, ok := params.(taskDeleteNodeParameters)
			if !ok {
				ar := result{nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeParameters'")}
				return ar, ar.rErr
			}
			if p.node == nil {
				ar := result{nil, fail.InvalidParameterError("params.node", "cannot be nil")}
				return ar, ar.rErr
			}
			if p.node.ID == "" && p.node.Name == "" {
				ar := result{nil, fail.InvalidParameterError("params.node.ID|params.node.Name", "ID or Name must be set")}
				return ar, ar.rErr
			}

			nodeRef := p.node.Name
			if nodeRef == "" {
				nodeRef = p.node.ID
			}

			if oldKey := ctx.Value("ID"); oldKey != nil {
				ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/delete/master/%s", oldKey, nodeRef)) // nolint
			}

			trueMasterID := p.node.ID

			logrus.WithContext(ctx).Debugf("Deleting Master '%s'", p.node.Name)
			xerr := instance.deleteMaster(ctx, trueMasterID)
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

			logrus.WithContext(ctx).Debugf("Successfully deleted Master '%s'", p.node.Name)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskRegenerateClusterInventoryParameters struct {
	ctx           context.Context
	master        resources.Host
	inventoryData string
	clusterName   string
}

// taskRegenerateClusterInventory task to update a Host (master) ansible inventory
func (instance *Cluster) taskRegenerateClusterInventory(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
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
			// Convert and validate params
			casted, ok := params.(taskRegenerateClusterInventoryParameters)
			if !ok {
				ar := result{nil, fail.InvalidParameterError("params", "must be a 'taskRegenerateClusterInventoryParameters'")}
				return ar, ar.rErr
			}

			xerr := instance.updateClusterInventoryMaster(ctx, casted)
			return result{nil, xerr}, xerr
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return nil, fail.ConvertError(inctx.Err())
	}
}

// updateClusterInventoryMaster updates a Host (master) ansible inventory
func (instance *Cluster) updateClusterInventoryMaster(inctx context.Context, param taskRegenerateClusterInventoryParameters) (ferr fail.Error) {
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
		iname := param.clusterName

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
		prerr := fmt.Sprintf("[Cluster %s, master %s] Ansible inventory update: ", iname, master.GetName())
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
		<-chRes // wait for cleanup
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return fail.ConvertError(inctx.Err())
	}
}
