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

package operations

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/consts"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
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
func (instance *Cluster) taskCreateCluster(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	req, ok := params.(abstract.ClusterRequest)
	if !ok {
		return nil, fail.InvalidParameterError("params", "should be an abstract.ClusterRequest")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() (ferr fail.Error) {
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		// Check if Cluster exists in metadata; if yes, error
		_, xerr := LoadCluster(ctx, instance.Service(), req.Name)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
			default:
				chRes <- result{nil, xerr}
				return xerr
			}
		} else {
			ar := result{nil, fail.DuplicateError("a Cluster named '%s' already exist", req.Name)}
			chRes <- ar
			return ar.rErr
		}

		// Create first metadata of Cluster after initialization
		xerr = instance.firstLight(ctx, req)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		cleanFailure := false
		// Starting from here, delete metadata if exiting with error
		// but if the next cleaning steps fail, we must keep the metadata to try again, so we have the cleanFailure flag to detect that issue
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !req.KeepOnFailure && !cleanFailure {
				logrus.WithContext(ctx).Debugf("Cleaning up on %s, deleting metadata of Cluster '%s'...", ActionFromError(ferr), req.Name)
				if derr := instance.MetadataCore.Delete(context.Background()); derr != nil {
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
		_, privateNodeCount, _, xerr := instance.determineRequiredNodes(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
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

		// logrus.WithContext(ctx).Warnf("This is the cluster creation request before determination: %s", spew.Sdump(req))

		gatewaysDef, mastersDef, nodesDef, xerr := instance.determineSizingRequirements(ctx, req)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		var networkInstance resources.Network
		var subnetInstance resources.Subnet
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !req.KeepOnFailure { // FIXME: subnetInstance nil
				if subnetInstance != nil && networkInstance != nil {
					logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Subnet '%s'...", subnetInstance.GetName())
					if derr := subnetInstance.Delete(context.Background()); derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Subnet is considered as a successful deletion, continue
							debug.IgnoreError(derr)
						default:
							cleanFailure = true
							logrus.WithContext(context.Background()).Errorf("Cleaning up on %s, failed to delete Subnet '%s'", ActionFromError(ferr),
								subnetInstance.GetName())
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Subnet", ActionFromError(ferr)))
						}
					} else {
						logrus.WithContext(ctx).Debugf("Cleaning up on %s, successfully deleted Subnet '%s'", ActionFromError(ferr),
							subnetInstance.GetName())
						if req.NetworkID == "" {
							logrus.WithContext(ctx).Debugf("Cleaning up on %s, deleting Network '%s'...", ActionFromError(ferr), networkInstance.GetName())
							if derr := networkInstance.Delete(context.Background()); derr != nil {
								switch derr.(type) {
								case *fail.ErrNotFound:
									// missing Network is considered as a successful deletion, continue
									debug.IgnoreError(derr)
								default:
									cleanFailure = true
									logrus.WithContext(context.Background()).Errorf("cleaning up on %s, failed to delete Network '%s'", ActionFromError(ferr),
										networkInstance.GetName())
									_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Network", ActionFromError(ferr)))
								}
							} else {
								logrus.WithContext(ctx).Debugf("Cleaning up on %s, successfully deleted Network '%s'", ActionFromError(ferr),
									networkInstance.GetName())
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
			chRes <- result{nil, xerr}
			return xerr
		}

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		// FIXME: At some point clusterIdentity has to change...

		// Starting from here, exiting with error deletes hosts if req.keepOnFailure is false
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !req.KeepOnFailure {
				logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Hosts...")
				var list []machineID

				var nodemap map[uint]*propertiesv3.ClusterNode
				derr := instance.Inspect(context.Background(), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
						nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
						if !ok {
							return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}

						nodemap = nodesV3.ByNumericalID
						return nil
					})
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
					tg, tgerr := concurrency.NewTaskGroupWithContext(
						context.Background(), concurrency.InheritParentIDOption, concurrency.AmendID("/onfailure"),
					)
					if tgerr != nil {
						cleanFailure = true
						_ = ferr.AddConsequence(tgerr)
						return
					}

					for _, v := range list {
						captured := v
						if captured.ID != "" {
							_, tgerr = tg.Start(
								instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name},
								concurrency.InheritParentIDOption,
								concurrency.AmendID(fmt.Sprintf("/host/%s/delete", captured.Name)),
							)
							if tgerr != nil {
								_ = ferr.AddConsequence(tgerr)
								abErr := tg.AbortWithCause(tgerr)
								if abErr != nil {
									logrus.WithContext(ctx).Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
								}
								cleanFailure = true
								break
							}
						}
					}

					_, _, tgerr = tg.WaitGroupFor(timings.HostLongOperationTimeout())
					tgerr = debug.InjectPlannedFail(tgerr)
					if tgerr != nil {
						cleanFailure = true
						_ = ferr.AddConsequence(tgerr)
					}
				} else {
					logrus.Warningf("relying on metadata here was a mistake...")
				}
			}
		}()

		// Creates and configures hosts
		xerr = instance.createHostResources(ctx, subnetInstance, *mastersDef, *nodesDef, req.InitialNodeCount, ExtractFeatureParameters(req.FeatureParameters), req.KeepOnFailure)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		// configure Cluster as a whole
		xerr = instance.configureCluster(ctx, req)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
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
			chRes <- result{nil, xerr}
			return xerr
		}

		chRes <- result{nil, nil}
		return nil
	}() // nolint
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait cleanup
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
		if req.Name = strings.TrimSpace(req.Name); req.Name == "" {
			chRes <- result{fail.InvalidParameterError("req.Name", "cannot be empty string")}
			return
		}

		// Initializes instance
		ci := abstract.NewClusterIdentity()
		ci.Name = req.Name
		ci.Flavor = req.Flavor
		ci.Complexity = req.Complexity
		ci.Tags["CreationDate"] = time.Now().Format(time.RFC3339)

		xerr := instance.carry(ctx, ci)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
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
					// VPL: For now, always disable addition of feature proxycache
					featuresV1.Disabled["proxycache"] = struct{}{}
					// ENDVPL
					for k := range req.DisabledDefaultFeatures {
						featuresV1.Disabled[k] = struct{}{}
					}
					return nil
				},
			)
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to disable feature 'proxycache'")
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

			// Links maker based on Flavor
			return instance.bootstrap(aci.Flavor)
		})
		xerr = debug.InjectPlannedFail(xerr)
		chRes <- result{xerr}

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
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
				chRes <- result{nil, nil, nil, fail.Wrap(xerr, "failed to get configuration options")}
				return
			}
			if anon, ok := cfg.Get("DefaultImage"); ok {
				imageQuery, ok = anon.(string)
				if !ok {
					chRes <- result{nil, nil, nil, fail.InconsistentError("failed to convert anon to 'string'")}
					return
				}
			}
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
			chRes <- result{nil, nil, nil, xerr}
			return
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
					chRes <- result{nil, nil, nil, fail.NewError("requested gateway sizing less than recommended")}
					return
				}
			}
		}

		tmpl, xerr := svc.FindTemplateBySizing(ctx, *gatewaysDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, nil, nil, xerr}
			return
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
					chRes <- result{nil, nil, nil, fail.NewError("requested master sizing less than recommended")}
					return
				}
			}
		}

		tmpl, xerr = svc.FindTemplateBySizing(ctx, *mastersDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, nil, nil, xerr}
			return
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
					chRes <- result{nil, nil, nil, fail.NewError("requested node sizing less than recommended")}
					return
				}
			}
		}

		tmpl, xerr = svc.FindTemplateBySizing(ctx, *nodesDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, nil, nil, xerr}
			return
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
			chRes <- result{nil, nil, nil, xerr}
			return
		}

		chRes <- result{gatewaysDef, mastersDef, nodesDef, nil}

	}()
	select {
	case res := <-chRes:
		return res.aa, res.ab, res.ac, res.rErr
	case <-ctx.Done():
		return nil, nil, nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
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
	go func() (ferr fail.Error) {
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		// Determine if getGateway Failover must be set
		svc := instance.Service()
		caps, xerr := svc.GetCapabilities(ctx)
		if xerr != nil {
			chRes <- result{nil, nil, xerr}
			return xerr
		}
		gwFailoverDisabled := req.Complexity == clustercomplexity.Small || !caps.PrivateVirtualIP
		for k := range req.DisabledDefaultFeatures {
			if k == "gateway-failover" {
				gwFailoverDisabled = true
				break
			}
		}

		req.Name = strings.ToLower(strings.TrimSpace(req.Name))

		// Creates Network
		var networkInstance resources.Network
		if req.NetworkID != "" {
			networkInstance, xerr = LoadNetwork(ctx, svc, req.NetworkID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, fail.Wrap(xerr, "failed to use network %s to contain Cluster Subnet", req.NetworkID)}
				chRes <- ar
				return ar.rErr
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
					if derr := networkInstance.Delete(context.Background()); derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Network is considered as a successful deletion, continue
							debug.IgnoreError(derr)
						default:
							_ = ferr.AddConsequence(derr)
						}
					}
				}
			}()

			networkInstance, xerr = NewNetwork(svc)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, fail.Wrap(xerr, "failed to instantiate new Network")}
				chRes <- ar
				return ar.rErr
			}

			xerr = networkInstance.Create(ctx, networkReq)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, nil, fail.Wrap(xerr, "failed to create Network '%s'", req.Name)}
				chRes <- ar
				return ar.rErr
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
			chRes <- result{nil, nil, xerr}
			return xerr
		}

		nid, err := networkInstance.GetID()
		if err != nil {
			xerr := fail.ConvertError(err)
			chRes <- result{nil, nil, xerr}
			return xerr
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

		subnetInstance, xerr := NewSubnet(svc)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, nil, xerr}
			return xerr
		}

		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !req.KeepOnFailure {
				if derr := subnetInstance.Delete(context.Background()); derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						// missing Subnet is considered as a successful deletion, continue
						debug.IgnoreError(derr)
					default:
						_ = ferr.AddConsequence(derr)
					}
				}
			}
		}()

		xerr = subnetInstance.Create(ctx, subnetReq, "", gatewaysDef)
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
					chRes <- result{nil, nil, xerr}
					return xerr
				}

				subIPNet, subXErr := netutils.FirstIncludedSubnet(*ipNet, 1)
				if subXErr != nil {
					_ = xerr.AddConsequence(fail.Wrap(subXErr, "failed to compute subset of CIDR '%s'", req.CIDR))
					chRes <- result{nil, nil, xerr}
					return xerr
				}
				subnetReq.CIDR = subIPNet.String()

				newSubnetInstance, xerr := NewSubnet(svc) // subnetInstance.Create CANNOT be reused
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, nil, xerr}
					chRes <- ar
					return xerr
				}
				subnetInstance = newSubnetInstance // replace the external reference

				if subXErr := subnetInstance.Create(ctx, subnetReq, "", gatewaysDef); subXErr != nil {
					ar := result{nil, nil, fail.Wrap(
						subXErr, "failed to create Subnet '%s' (with CIDR %s) in Network '%s' (with CIDR %s)",
						subnetReq.Name, subnetReq.CIDR, networkInstance.GetName(), req.CIDR,
					)}
					chRes <- ar
					return ar.rErr
				}
				logrus.WithContext(ctx).Infof(
					"CIDR '%s' used successfully for Subnet, there will be less available private IP Addresses than expected.",
					subnetReq.CIDR,
				)
			default:
				ar := result{nil, nil, fail.Wrap(
					xerr, "failed to create Subnet '%s' in Network '%s'", req.Name, networkInstance.GetName(),
				)}
				chRes <- ar
				return ar.rErr
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
			chRes <- result{nil, nil, xerr}
			return xerr
		}

		logrus.WithContext(ctx).Debugf("[Cluster %s] Subnet '%s' in Network '%s' creation successful.", req.Name, networkInstance.GetName(), req.Name)
		chRes <- result{networkInstance, subnetInstance, nil}
		return nil
	}() // nolint
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
	initialNodeCount uint,
	parameters data.Map,
	keepOnFailure bool,
) (_ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() (ferr fail.Error) {
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		var startedTasks []concurrency.Task

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				taskID := func(t concurrency.Task) string {
					tid, cleanErr := t.ID()
					if cleanErr != nil {
						_ = ferr.AddConsequence(cleanErr)
						tid = "<unknown>"
					}
					return tid
				}

				// On error, instructs Tasks/TaskGroups to abort, to stop as soon as possible
				for _, v := range startedTasks {
					if !v.Aborted() {
						cleanErr := v.AbortWithCause(ferr)
						if cleanErr != nil {
							cleanErr = fail.Wrap(
								cleanErr,
								"cleaning up on failure, failed to abort Task/TaskGroup %s spawn by createHostResources()",
								reflect.TypeOf(v).String(), taskID(v),
							)
							logrus.WithContext(ctx).Error(cleanErr.Error())
							_ = ferr.AddConsequence(cleanErr)
						}
					}
				}

				// we have to wait for completion of aborted Tasks/TaskGroups, not get out before
				timeout := timings.HostLongOperationTimeout()
				for _, v := range startedTasks {
					_, _, werr := v.WaitFor(timeout)
					if werr != nil {
						werr = fail.Wrap(
							werr, "cleaning up on failure, failed to wait for %s %s", reflect.TypeOf(v).String(), taskID(v),
						)
						_ = ferr.AddConsequence(werr)
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

		primaryGateway, xerr = subnet.InspectGateway(ctx, true)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		haveSecondaryGateway := true
		secondaryGateway, xerr = subnet.InspectGateway(ctx, false)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				debug.IgnoreError(xerr)
				// It's a valid state not to have a secondary gateway, so continue
				haveSecondaryGateway = false
			default:
				chRes <- result{xerr}
				return xerr
			}
		}

		// if this happens, then no, we don't have a secondary gateway, and we have also another problem...
		if haveSecondaryGateway {
			pgi, err := primaryGateway.GetID()
			if err != nil {
				xerr := fail.ConvertError(err)
				chRes <- result{xerr}
				return xerr
			}

			sgi, err := secondaryGateway.GetID()
			if err != nil {
				xerr := fail.ConvertError(err)
				chRes <- result{xerr}
				return xerr
			}

			if pgi == sgi {
				ar := result{fail.InconsistentError("primary and secondary gateways have the same id %s", pgi)}
				chRes <- ar
				return ar.rErr
			}
		}

		_, xerr = primaryGateway.WaitSSHReady(ctx, timings.ExecutionTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			ar := result{fail.Wrap(xerr, "wait for remote ssh service to be ready")}
			chRes <- ar
			return ar.rErr
		}

		if haveSecondaryGateway {
			_, xerr = secondaryGateway.WaitSSHReady(ctx, timings.ExecutionTimeout())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{fail.Wrap(xerr, "failed to wait for remote ssh service to become ready")}
				chRes <- ar
				return ar.rErr
			}
		}

		masterCount, _, _, xerr := instance.determineRequiredNodes(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		gwInstallTasks, xerr := concurrency.NewTaskGroupWithContext(
			ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/gateway"),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		// Step 1: starts gateway installation plus masters creation plus nodes creation
		_, xerr = gwInstallTasks.Start(
			instance.taskInstallGateway, taskInstallGatewayParameters{host: primaryGateway, variables: parameters}, concurrency.InheritParentIDOption,
			concurrency.AmendID(fmt.Sprintf("/%s/install", primaryGateway.GetName())),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		startedTasks = append(startedTasks, gwInstallTasks)

		if haveSecondaryGateway {
			_, xerr = gwInstallTasks.Start(
				instance.taskInstallGateway, taskInstallGatewayParameters{host: secondaryGateway, variables: parameters},
				concurrency.InheritParentIDOption,
				concurrency.AmendID(fmt.Sprintf("/%s/install", secondaryGateway.GetName())),
			)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil { // no need to abort and wait, the previous defer takes care of that
				chRes <- result{xerr}
				return xerr
			}
		}

		// Starting from here, delete masters if exiting with error and req.keepOnFailure is not true
		defer func() { // FIXME: OPP This needs review
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !keepOnFailure {
				masters, merr := instance.unsafeListMasters(context.Background())
				if merr != nil {
					_ = ferr.AddConsequence(merr)
					return
				}

				var list []machineID
				for _, mach := range masters {
					list = append(list, machineID{ID: mach.ID, Name: mach.Name})
				}

				hosts, merr := instance.Service().ListHosts(context.Background(), false)
				if merr != nil {
					_ = ferr.AddConsequence(merr)
					return
				}

				for _, invol := range hosts {
					theName := invol.GetName()
					theId, _ := invol.GetID()
					if strings.Contains(theName, "master") {
						if strings.Contains(theName, instance.GetName()) {
							list = append(list, machineID{ID: theId, Name: invol.GetName()})
						}
					}
				}

				if len(list) > 0 {
					tg, tgerr := concurrency.NewTaskGroupWithContext(
						context.Background(), concurrency.InheritParentIDOption, concurrency.AmendID("/onfailure"),
					)
					if tgerr != nil {
						_ = ferr.AddConsequence(tgerr)
						return
					}

					for _, v := range list {
						captured := v
						if captured.ID != "" {
							_, derr := tg.Start(
								instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name},
								concurrency.InheritParentIDOption,
								concurrency.AmendID(fmt.Sprintf("/host/%s/delete", captured.Name)),
							)
							if derr != nil {
								_ = ferr.AddConsequence(
									fail.Wrap(
										derr, "cleaning up on failure, failed to delete master '%s'", captured.Name,
									),
								)
								abErr := tg.AbortWithCause(derr)
								if abErr != nil {
									logrus.WithContext(ctx).Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
								}
								break
							}
						}
					}
					_, _, derr := tg.WaitGroupFor(timings.HostLongOperationTimeout())
					derr = debug.InjectPlannedFail(derr)
					if derr != nil {
						_ = ferr.AddConsequence(
							fail.Wrap(
								derr, "cleaning up on failure, failed to wait for master deletions",
							),
						)
					}
				}
			}
		}()

		mastersCreateTasks, xerr := concurrency.NewTaskGroupWithContext(
			ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/masters"),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		_, xerr = mastersCreateTasks.Start(
			instance.taskCreateMasters, taskCreateMastersParameters{
				count:         masterCount,
				mastersDef:    mastersDef,
				keepOnFailure: keepOnFailure,
			}, concurrency.InheritParentIDOption,
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil { // no need to abort and wait, the previous defer takes care of that
			chRes <- result{xerr}
			return xerr
		}

		startedTasks = append(startedTasks, mastersCreateTasks)

		// Starting from here, if exiting with error, delete nodes
		defer func() { // FIXME: OPP, This needs review
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !keepOnFailure {
				nlist, merr := instance.unsafeListNodes(context.Background())
				if merr != nil {
					_ = ferr.AddConsequence(merr)
					return
				}

				var list []machineID
				for _, mach := range nlist {
					list = append(list, machineID{ID: mach.ID, Name: mach.Name})
				}

				hosts, merr := instance.Service().ListHosts(context.Background(), false)
				if merr != nil {
					_ = ferr.AddConsequence(merr)
					return
				}

				for _, invol := range hosts {
					theName := invol.GetName()
					theId, _ := invol.GetID()
					if strings.Contains(theName, "node") {
						if strings.Contains(theName, instance.GetName()) {
							list = append(list, machineID{ID: theId, Name: invol.GetName()})
						}
					}
				}

				if len(list) > 0 {
					tg, tgerr := concurrency.NewTaskGroupWithContext(
						context.Background(), concurrency.InheritParentIDOption, concurrency.AmendID("/onfailure"),
					)
					if tgerr != nil {
						_ = ferr.AddConsequence(fail.Wrap(tgerr, "cleaning up on failure, failed to create TaskGroup"))
						return
					}

					for _, v := range list {
						captured := v
						if captured.ID != "" {
							_, derr := tg.Start(
								instance.taskDeleteNodeOnFailure, taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name},
								concurrency.InheritParentIDOption,
								concurrency.AmendID(fmt.Sprintf("/host/%s/delete", captured.Name)),
							)
							if derr != nil {
								_ = ferr.AddConsequence(
									fail.Wrap(
										derr, "cleaning up on failure, failed to delete node '%s'", captured.Name,
									),
								)
								abErr := tg.AbortWithCause(derr)
								if abErr != nil {
									logrus.WithContext(ctx).Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
								}
								break
							}
						}
					}
					_, _, derr := tg.WaitGroupFor(timings.HostLongOperationTimeout())
					derr = debug.InjectPlannedFail(derr)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to wait for node deletions"))
					}
				}
			}
		}()

		privateNodesCreateTasks, xerr := concurrency.NewTaskGroupWithContext(ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/nodes"))
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		_, xerr = privateNodesCreateTasks.Start(
			instance.taskCreateNodes, taskCreateNodesParameters{
				count:         initialNodeCount,
				public:        false,
				nodesDef:      nodesDef,
				keepOnFailure: keepOnFailure,
			}, concurrency.InheritParentIDOption,
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil { // no need to abort and wait, the previous defer takes care of that
			chRes <- result{xerr}
			return xerr
		}

		startedTasks = append(startedTasks, privateNodesCreateTasks)

		// Step 2: awaits gateway installation end and masters installation end
		var gatewayInstallResult concurrency.TaskGroupResult
		if gatewayInstallResult, gatewayInstallStatus = gwInstallTasks.WaitGroup(); gatewayInstallStatus != nil {
			// no need to abort and wait, the previous defer takes care of that
			chRes <- result{gatewayInstallStatus}
			return gatewayInstallStatus
		}
		logrus.WithContext(ctx).Debugf("gateway install returned: %v", gatewayInstallResult)

		var masterCreationResult concurrency.TaskGroupResult
		if masterCreationResult, mastersStatus = mastersCreateTasks.WaitGroup(); mastersStatus != nil {
			// no need to abort and wait, the previous defer takes care of that
			chRes <- result{mastersStatus}
			return mastersStatus
		}
		logrus.WithContext(ctx).Debugf("master creation returned: %v", masterCreationResult)

		// Step 3: start gateway configuration (needs MasterIPs so masters must be installed first)
		// Configure gateway(s) and waits for the result

		gwCfgTasks, xerr := concurrency.NewTaskGroupWithContext(
			ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/configuregateways"),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			// no need to abort and wait, the previous defer takes care of that
			chRes <- result{xerr}
			return xerr
		}

		_, xerr = gwCfgTasks.Start(
			instance.taskConfigureGateway, taskConfigureGatewayParameters{Host: primaryGateway},
			concurrency.InheritParentIDOption,
			concurrency.AmendID(fmt.Sprintf("/host/%s/configure", primaryGateway.GetName())),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			// no need to abort and wait, the previous defer takes care of that
			chRes <- result{xerr}
			return xerr
		}

		startedTasks = append(startedTasks, gwCfgTasks)

		if haveSecondaryGateway {
			_, xerr = gwCfgTasks.Start(
				instance.taskConfigureGateway, taskConfigureGatewayParameters{Host: secondaryGateway},
				concurrency.InheritParentIDOption,
			)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				// no need to abort and wait, the previous defer takes care of that
				chRes <- result{xerr}
				return xerr
			}
		}

		var gatewayCfgResult concurrency.TaskGroupResult
		gatewayCfgResult, gatewayConfigurationStatus = gwCfgTasks.WaitGroup()
		if gatewayConfigurationStatus != nil {
			chRes <- result{gatewayConfigurationStatus}
			return gatewayConfigurationStatus
		}
		logrus.WithContext(ctx).Debugf("gateway cfg returned: %v", gatewayCfgResult)

		// Step 4: configure masters (if masters created successfully and gateways configured successfully)
		mastersCfgTask, xerr := concurrency.NewTaskWithContext(
			ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/masters"),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		_, mastersStatus = instance.taskConfigureMasters(mastersCfgTask, taskConfigureMastersParameters{parameters})
		if mastersStatus != nil {
			chRes <- result{mastersStatus}
			return mastersStatus
		}
		logrus.WithContext(ctx).Debugf("masters finished configuration")

		// Step 5: awaits nodes creation
		var privateNodesResult concurrency.TaskGroupResult
		privateNodesResult, privateNodesStatus = privateNodesCreateTasks.WaitGroup()
		if privateNodesStatus != nil {
			chRes <- result{privateNodesStatus}
			return privateNodesStatus
		}
		logrus.WithContext(ctx).Debugf("private node creation returned: %v", privateNodesResult)

		// Step 6: Starts nodes configuration, if all masters and nodes have been created and gateway has been configured with success
		privateNodesCfgTask, xerr := concurrency.NewTaskGroupWithContext(
			ctx, concurrency.InheritParentIDOption, concurrency.AmendID("/nodes"),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return xerr
		}

		_, privateNodesStatus = instance.taskConfigureNodes(privateNodesCfgTask, taskConfigureNodesParameters{variables: parameters})
		if privateNodesStatus != nil {
			chRes <- result{privateNodesStatus}
			return privateNodesStatus
		}

		chRes <- result{nil}
		return nil
	}() // nolint
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
func (instance *Cluster) taskStartHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		id, ok := params.(string)
		if !ok || id == "" {
			chRes <- result{nil, fail.InvalidParameterCannotBeEmptyStringError("params")}
			return
		}

		svc := instance.Service()

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		xerr = svc.StartHost(ctx, id)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) { // nolint
			case *fail.ErrDuplicate: // A host already started is considered as a successful run
				logrus.WithContext(ctx).Tracef("host duplicated, start considered as a success")
				debug.IgnoreError(xerr)
				chRes <- result{nil, nil}
				return
			}
		}
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		// -- refresh state of host --
		hostInstance, xerr := LoadHost(ctx, svc, id)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		_, xerr = hostInstance.WaitSSHReady(ctx, timings.HostOperationTimeout())
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		_, xerr = hostInstance.ForceGetState(ctx)
		chRes <- result{nil, xerr}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

func (instance *Cluster) taskStopHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		id, ok := params.(string)
		if !ok || id == "" {
			chRes <- result{nil, fail.InvalidParameterCannotBeEmptyStringError("params")}
			return
		}

		svc := instance.Service()
		xerr = svc.StopHost(ctx, id, false)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) { // nolint
			case *fail.ErrDuplicate: // A host already stopped is considered as a successful run
				logrus.WithContext(ctx).Tracef("host duplicated, stopping considered as a success")
				debug.IgnoreError(xerr)
				chRes <- result{nil, nil}
				return
			default:
				chRes <- result{nil, xerr}
				return
			}
		}

		// -- refresh state of host --
		hostInstance, xerr := LoadHost(ctx, svc, id)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		_, xerr = hostInstance.ForceGetState(ctx)
		chRes <- result{nil, xerr}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskInstallGatewayParameters struct {
	host      resources.Host
	variables data.Map
}

// taskInstallGateway installs necessary components on one gateway
func (instance *Cluster) taskInstallGateway(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		p, ok := params.(taskInstallGatewayParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskInstallGatewayParameters'")}
			return
		}
		if p.host == nil {
			chRes <- result{nil, fail.InvalidParameterCannotBeNilError("params.Host")}
			return
		}

		variables, _ := data.FromMap(p.variables)
		hostLabel := p.host.GetName()

		tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), params).WithStopwatch().Entering()
		defer tracer.Exiting()

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[%s] starting installation...", hostLabel)

		_, xerr = p.host.WaitSSHReady(ctx, timings.HostOperationTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		// Installs docker and docker-compose on gateway
		xerr = instance.installDocker(ctx, p.host, hostLabel, variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		// Installs dependencies as defined by Cluster Flavor (if it exists)
		xerr = instance.installNodeRequirements(ctx, clusternodetype.Gateway, p.host, hostLabel)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[%s] preparation successful", hostLabel)
		chRes <- result{nil, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskConfigureGatewayParameters struct {
	Host resources.Host
}

// taskConfigureGateway prepares one gateway
func (instance *Cluster) taskConfigureGateway(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		// validate and convert parameters
		p, ok := params.(taskConfigureGatewayParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskConfigureGatewayParameters'")}
			return
		}
		if p.Host == nil {
			chRes <- result{nil, fail.InvalidParameterCannotBeNilError("params.Host")}
			return
		}

		hostLabel := p.Host.GetName()

		tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
		defer tracer.Exiting()

		logrus.WithContext(ctx).Debugf("[%s] starting configuration...", hostLabel)

		makers := instance.localCache.makers
		if makers.ConfigureGateway != nil {
			xerr = makers.ConfigureGateway(instance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, xerr}
				return
			}
		}

		logrus.WithContext(ctx).Debugf("[%s] configuration successful in [%s].", p.Host.GetName(), tracer.Stopwatch().String())
		chRes <- result{nil, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskCreateMastersParameters struct {
	count         uint
	mastersDef    abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateMasters creates masters
func (instance *Cluster) taskCreateMasters(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inCtx := task.Context()
	ctx, cancel := context.WithCancel(inCtx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		tg, xerr := concurrency.NewTaskGroupWithContext(ctx, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		tracer := debug.NewTracer(tg, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
		defer tracer.Exiting()

		// Convert and validate parameters
		p, ok := params.(taskCreateMastersParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskCreteMastersParameters'")}
			return
		}
		if p.count < 1 {
			chRes <- result{nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")}
			return
		}

		clusterName := instance.GetName()

		if p.count == 0 {
			logrus.WithContext(ctx).Debugf("[Cluster %s] no masters to create.", clusterName)
			chRes <- result{nil, nil}
			return
		}

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[Cluster %s] creating %d master%s...", clusterName, p.count, strprocess.Plural(p.count))

		timeout := 3 * timings.HostCreationTimeout()
		var collectedErs []error

		for i := uint(1); i <= p.count; i++ {
			captured := i
			taskParams := taskCreateMasterParameters{
				masterDef:     p.mastersDef,
				timeout:       timeout,
				index:         captured,
				keepOnFailure: p.keepOnFailure,
			}
			_, ierr := tg.StartWithTimeout(
				instance.taskCreateMaster, taskParams, timeout, concurrency.InheritParentIDOption,
				concurrency.AmendID(fmt.Sprintf("/host/%d/create", captured)),
			)
			ierr = debug.InjectPlannedFail(ierr)
			if ierr != nil {
				collectedErs = append(collectedErs, ierr)
				abErr := tg.AbortWithCause(ierr)
				if abErr != nil {
					logrus.WithContext(ctx).Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
		}

		var tr concurrency.TaskGroupResult
		tr, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if withTimeout(xerr) {
				logrus.WithContext(ctx).Warnf("Timeouts creating masters !!")
			}
			rerr := fail.NewError("[Cluster %s] failed to create master(s): %s", clusterName, xerr)
			if len(collectedErs) != 0 {
				_ = rerr.AddConsequence(fail.NewErrorList(collectedErs))
			}
			chRes <- result{nil, rerr}
			return
		}

		if len(collectedErs) != 0 {
			chRes <- result{nil, fail.NewError(
				"[Cluster %s] failed to create master(s): %s", clusterName, fail.NewErrorList(collectedErs),
			)}
			return
		}

		logrus.WithContext(ctx).Debugf("[Cluster %s] masters creation successful: %v", clusterName, tr)
		chRes <- result{tr, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inCtx.Done():
		return nil, fail.ConvertError(inCtx.Err())
	}
}

type taskCreateMasterParameters struct {
	index         uint
	masterDef     abstract.HostSizingRequirements
	timeout       time.Duration
	keepOnFailure bool
}

// taskCreateMaster creates one master
func (instance *Cluster) taskCreateMaster(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() (ferr fail.Error) {
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		// Convert and validate parameters
		p, ok := params.(taskCreateMasterParameters)
		if !ok {
			ar := result{nil, fail.InvalidParameterError("params", "must be a 'taskCreateMasterParameters'")}
			chRes <- ar
			return ar.rErr
		}

		if p.index < 1 {
			ar := result{nil, fail.InvalidParameterError("params.index", "must be an integer greater than 0")}
			chRes <- ar
			return ar.rErr
		}

		sleepTime := <-instance.randomDelayCh
		time.Sleep(time.Duration(sleepTime) * time.Millisecond)

		hostReq := abstract.HostRequest{}
		hostReq.ResourceName, xerr = instance.buildHostname(ctx, "master", clusternodetype.Master)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).Entering()
		defer tracer.Exiting()

		hostLabel := fmt.Sprintf("master #%d", p.index)
		logrus.WithContext(ctx).Debugf("[%s] starting master Host creation...", hostLabel)

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
			ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
			chRes <- ar
			return ar.rErr
		}

		// Starting from here, if exiting with error, remove entry from master nodes of the metadata
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !p.keepOnFailure {
				derr := instance.Alter(context.Background(), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
			chRes <- result{nil, xerr}
			return xerr
		}

		svc := instance.Service()
		subnet, xerr := LoadSubnet(ctx, svc, "", netCfg.SubnetID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
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
			chRes <- result{nil, xerr}
			return xerr
		}

		hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
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
			chRes <- result{nil, xerr}
			return xerr
		}

		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !p.keepOnFailure {
				if derr := hostInstance.Delete(context.Background()); derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						// missing Host is considered as a successful deletion, continue
						debug.IgnoreError(derr)
					default:
						_ = ferr.AddConsequence(derr)
					}
				}
			}
		}()

		_, xerr = hostInstance.Create(ctx, hostReq, p.masterDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
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
					nodesV3.MasterByName[node.Name] = node.NumericalID
					nodesV3.MasterByID[node.ID] = node.NumericalID

					return nil
				},
			)
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
			chRes <- ar
			return ar.rErr
		}

		hostLabel = fmt.Sprintf("master #%d (%s)", p.index, hostInstance.GetName())

		xerr = instance.installNodeRequirements(ctx, clusternodetype.Master, hostInstance, hostLabel)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		logrus.WithContext(ctx).Debugf("[%s] Master creation successful.", hostLabel)
		chRes <- result{hostInstance, nil}
		return nil
	}() // nolint
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for clean
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for clean
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
	variables data.Map
}

// taskConfigureMasters configure masters
func (instance *Cluster) taskConfigureMasters(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	started := time.Now()
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			logrus.WithContext(ctx).Debugf(
				"[Cluster %s] Masters configuration FAILED with [%s] in [%s].", instance.GetName(), spew.Sdump(ferr),
				temporal.FormatDuration(time.Since(started)),
			)
		} else {
			logrus.WithContext(ctx).Debugf(
				"[Cluster %s] Masters configuration successful in [%s].", instance.GetName(),
				temporal.FormatDuration(time.Since(started)),
			)
		}
	}()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		p, ok := params.(taskConfigureMastersParameters)
		if !ok {
			chRes <- result{nil, fail.InconsistentError("failed to cast 'params' to 'taskConfiguraMastersParameters'")}
			return
		}
		variables, _ := data.FromMap(p.variables)
		tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
		defer tracer.Exiting()

		logrus.WithContext(ctx).Debugf("[Cluster %s] Configuring masters...", instance.GetName())

		masters, xerr := instance.unsafeListMasters(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}
		if len(masters) == 0 {
			ar := result{nil, fail.NewError("[Cluster %s] master list cannot be empty.", instance.GetName())}
			chRes <- result{nil, ar.rErr}
			return
		}

		tg, xerr := concurrency.NewTaskGroupWithContext(ctx, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		var (
			loadErrors []error
			taskErrors []error
		)

		for _, master := range masters {
			if master.ID == "" {
				chRes <- result{nil, fail.InvalidParameterError("masters", "cannot contain items with empty ID")}
				return
			}
		}

		for i, master := range masters {
			captured := i
			capturedMaster := master
			host, xerr := LoadHost(ctx, instance.Service(), capturedMaster.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				loadErrors = append(loadErrors, xerr)
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.WithContext(ctx).Errorf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}

			_, xerr = tg.Start(
				instance.taskConfigureMaster, taskConfigureMasterParameters{
					Index:     captured + 1,
					Host:      host,
					variables: variables,
				}, concurrency.InheritParentIDOption,
				concurrency.AmendID(fmt.Sprintf("/host/%s/configure", host.GetName())),
			)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				// a return here (unless is the first for iteration) will likely leave unchecked started tasks
				taskErrors = append(taskErrors, xerr)
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.WithContext(ctx).Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
		}

		var tr concurrency.TaskGroupResult
		tr, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if withTimeout(xerr) {
				logrus.WithContext(ctx).Warnf("Timeouts configuring masters !!")
			}
			rerr := fail.NewError("[Cluster %s] failed to configure master(s): %s", instance.GetName(), xerr)
			if len(loadErrors) != 0 {
				_ = rerr.AddConsequence(fail.NewErrorList(loadErrors))
			}
			if len(taskErrors) != 0 {
				_ = rerr.AddConsequence(fail.NewErrorList(taskErrors))
			}
			chRes <- result{nil, rerr}
			return
		}

		if len(loadErrors) != 0 || len(taskErrors) != 0 {
			var allErrors []error
			allErrors = append(allErrors, loadErrors...)
			allErrors = append(allErrors, taskErrors...)
			chRes <- result{nil, fail.NewError(allErrors)}
			return
		}

		logrus.WithContext(ctx).Debugf("[Cluster %s] masters configuration successful: %v", instance.GetName(), tr)
		chRes <- result{tr, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskConfigureMasterParameters struct {
	Index     uint
	Host      resources.Host
	variables data.Map
}

// taskConfigureMaster configures one master
func (instance *Cluster) taskConfigureMaster(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		// Convert and validate params
		p, ok := params.(taskConfigureMasterParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskConfigureMasterParameters'")}
			return
		}

		if p.Index < 1 {
			chRes <- result{nil, fail.InvalidParameterError("params.indexindex", "cannot be an integer less than 1")}
			return
		}
		if p.Host == nil {
			chRes <- result{nil, fail.InvalidParameterCannotBeNilError("params.Host")}
			return
		}

		variables, _ := data.FromMap(p.variables)

		started := time.Now()

		hostLabel := fmt.Sprintf("master #%d (%s)", p.Index, p.Host.GetName())
		logrus.WithContext(ctx).Debugf("[%s] starting configuration...", hostLabel)

		// install docker feature (including docker-compose)
		xerr = instance.installDocker(ctx, p.Host, hostLabel, variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		// Configure master for flavor
		makers := instance.localCache.makers
		if makers.ConfigureMaster != nil {
			xerr = makers.ConfigureMaster(instance, p.Index, p.Host)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{nil, fail.Wrap(xerr, "failed to configure master '%s'", p.Host.GetName())}
				return
			}

			logrus.WithContext(ctx).Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
			chRes <- result{nil, nil}
			return
		}

		// Not finding a callback isn't an error, so return nil in this case
		chRes <- result{nil, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskCreateNodesParameters struct {
	count         uint
	public        bool
	nodesDef      abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateNodes creates nodes
func (instance *Cluster) taskCreateNodes(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("tg")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		// Convert then validate params
		p, ok := params.(taskCreateNodesParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskCreateNodesParameters'")}
			return
		}
		if p.count < 1 {
			chRes <- result{nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")}
			return
		}

		tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d, %v)", p.count, p.public).WithStopwatch().Entering()
		defer tracer.Exiting()

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		clusterName := instance.GetName()

		if p.count == 0 {
			logrus.WithContext(ctx).Debugf("[Cluster %s] no nodes to create.", clusterName)
			chRes <- result{nil, nil}
			return
		}
		logrus.WithContext(ctx).Debugf("[Cluster %s] creating %d node%s...", clusterName, p.count, strprocess.Plural(p.count))

		tg, xerr := concurrency.NewTaskGroupWithContext(ctx, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		timeout := 3 * timings.HostCreationTimeout()
		for i := uint(1); i <= p.count; i++ {
			captured := i
			_, xerr := tg.StartWithTimeout(
				instance.taskCreateNode, taskCreateNodeParameters{
					index:         captured,
					nodeDef:       p.nodesDef,
					timeout:       timeout,
					keepOnFailure: p.keepOnFailure,
				}, timeout, concurrency.InheritParentIDOption,
			)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.WithContext(ctx).Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
		}

		tr, xerr := tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if withTimeout(xerr) {
				logrus.WithContext(ctx).Warnf("Timeouts creating nodes !!")
			}
			rerr := fail.NewError("[Cluster %s] failed to create nodes(s): %s", instance.GetName(), xerr)
			chRes <- result{nil, rerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[Cluster %s] %d node%s creation successful.", clusterName, p.count, strprocess.Plural(p.count))
		chRes <- result{tr, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskCreateNodeParameters struct {
	index         uint
	nodeDef       abstract.HostSizingRequirements
	timeout       time.Duration // Not used currently
	keepOnFailure bool
}

// taskCreateNode creates a node in the Cluster
func (instance *Cluster) taskCreateNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() (ferr fail.Error) {
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		// Convert then validate parameters
		p, ok := params.(taskCreateNodeParameters)
		if !ok {
			ar := result{nil, fail.InvalidParameterError("params", "must be a data.Map")}
			chRes <- ar
			return ar.rErr
		}

		if p.index < 1 {
			ar := result{nil, fail.InvalidParameterError("params.index", "cannot be an integer less than 1")}
			chRes <- ar
			return ar.rErr
		}

		sleepTime := <-instance.randomDelayCh
		time.Sleep(time.Duration(sleepTime) * time.Millisecond)

		hostReq := abstract.HostRequest{}
		hostReq.ResourceName, xerr = instance.buildHostname(ctx, "node", clusternodetype.Node)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d)", p.index).WithStopwatch().Entering()
		defer tracer.Exiting()

		hostLabel := fmt.Sprintf("node #%d", p.index)
		logrus.WithContext(ctx).Debugf(tracer.TraceMessage("[%s] starting Host creation...", hostLabel))

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
			ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
			chRes <- ar
			return ar.rErr
		}

		// Starting from here, if exiting with error, remove entry from node of the metadata
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !p.keepOnFailure {
				derr := instance.Alter(context.Background(), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
			chRes <- ar
			return ar.rErr
		}

		svc := instance.Service()
		subnet, xerr := LoadSubnet(ctx, svc, "", netCfg.SubnetID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			ar := result{nil, xerr}
			chRes <- ar
			return ar.rErr
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
			chRes <- result{nil, xerr}
			return xerr
		}

		hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		hostReq.PublicIP = false
		hostReq.KeepOnFailure = p.keepOnFailure

		if p.nodeDef.Image != "" {
			hostReq.ImageID = p.nodeDef.Image
		}
		if p.nodeDef.Template != "" {
			hostReq.TemplateID = p.nodeDef.Template
		}

		hostInstance, xerr := NewHost(svc)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !p.keepOnFailure {
				if derr := hostInstance.Delete(context.Background()); derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						// missing Host is considered as a successful deletion, continue
						debug.IgnoreError(derr)
					default:
						_ = ferr.AddConsequence(
							fail.Wrap(
								derr, "cleaning up on %s, failed to delete Host '%s'", ActionFromError(ferr),
								hostInstance.GetName(),
							),
						)
					}
				}
			}
		}()

		// here is the actual creation of the machine
		_, xerr = hostInstance.Create(ctx, hostReq, p.nodeDef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		logrus.WithContext(ctx).Debugf(tracer.TraceMessage("[%s] Host updating cluster metadata...", hostLabel))

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
			ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
			chRes <- ar
			return ar.rErr
		}

		// Starting from here, rollback on cluster metadata in case of failure
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil && !p.keepOnFailure {
				derr := instance.Alter(context.Background(), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
					_ = ferr.AddConsequence(
						fail.Wrap(
							derr, "cleaning up on failure, failed to remove node '%s' from metadata of cluster '%s'",
							hostInstance.GetName(), instance.GetName(),
						),
					)
				}
			}
		}()

		logrus.WithContext(ctx).Debugf(tracer.TraceMessage("[%s] Host installing node requirements...", hostLabel))

		xerr = instance.installNodeRequirements(ctx, clusternodetype.Node, hostInstance, hostLabel)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return xerr
		}

		logrus.WithContext(ctx).Debugf("[%s] Node creation successful.", hostLabel)
		chRes <- result{node, nil}
		return nil
	}() // nolint
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(inctx.Err())
	}

}

type taskConfigureNodesParameters struct {
	variables data.Map
}

// taskConfigureNodes configures nodes
func (instance *Cluster) taskConfigureNodes(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	p, ok := params.(taskConfigureNodesParameters)
	if !ok {
		return nil, fail.InconsistentError("failed to cast 'params' to 'taskConfigureNodesParameters'")
	}
	variables, _ := data.FromMap(p.variables)
	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	started := time.Now()
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			logrus.WithContext(ctx).Debugf(
				"[Cluster %s] Nodes configuration FAILED with [%s] in [%s].", instance.GetName(), spew.Sdump(ferr),
				temporal.FormatDuration(time.Since(started)),
			)
		} else {
			logrus.WithContext(ctx).Debugf(
				"[Cluster %s] Nodes configuration successful in [%s].", instance.GetName(),
				temporal.FormatDuration(time.Since(started)),
			)
		}
	}()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		clusterName := instance.GetName()

		tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
		defer tracer.Exiting()

		list, err := instance.unsafeListNodes(ctx)
		err = debug.InjectPlannedFail(err)
		if err != nil {
			chRes <- result{nil, err}
			return
		}
		if len(list) == 0 {
			chRes <- result{nil, fail.NewError("[Cluster %s] node list cannot be empty.", instance.GetName())}
			return
		}

		logrus.WithContext(ctx).Debugf("[Cluster %s] configuring nodes...", clusterName)

		var (
			startErrs []error
		)

		tg, xerr := concurrency.NewTaskGroupWithContext(ctx, concurrency.InheritParentIDOption)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		for _, node := range list {
			if node.ID == "" {
				chRes <- result{nil, fail.InvalidParameterError("list", "cannot contain items with empty ID")}
				return
			}
		}

		for i, node := range list {
			captured := i
			capturedNode := node
			_, xerr = tg.Start(
				instance.taskConfigureNode, taskConfigureNodeParameters{
					index:     captured + 1,
					node:      capturedNode,
					variables: variables,
				}, concurrency.InheritParentIDOption,
				concurrency.AmendID(fmt.Sprintf("/host/%s/configure", capturedNode.Name)),
			)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				// a return here (unless is the first for iteration) will likely leave unchecked started tasks, which is bad
				startErrs = append(startErrs, xerr)
				abErr := tg.AbortWithCause(xerr)
				if abErr != nil {
					logrus.WithContext(ctx).Warnf("there was an error trying to abort TaskGroup: %s", spew.Sdump(abErr))
				}
				break
			}
		}

		var tgr concurrency.TaskGroupResult
		tgr, xerr = tg.WaitGroup()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if withTimeout(xerr) {
				logrus.WithContext(ctx).Warnf("Timeouts configuring nodes !!")
			}
			rerr := fail.NewError("[Cluster %s] failed to configure nodes(s): %s", instance.GetName(), xerr)
			if len(startErrs) > 0 {
				_ = rerr.AddConsequence(fail.NewErrorList(startErrs)) // not actually a consequence, but a temporary patch until the logic of this function is fixed
			}
			chRes <- result{nil, rerr}
			return
		}

		if len(startErrs) != 0 {
			var allErrors []error
			allErrors = append(allErrors, startErrs...)
			chRes <- result{nil, fail.NewError("[Cluster %s] failed to configure nodes(s): %s", instance.GetName(), fail.NewErrorList(allErrors))}
			return
		}

		logrus.WithContext(ctx).Debugf("[Cluster %s] nodes configuration successful: %v", clusterName, tgr)
		chRes <- result{tgr, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskConfigureNodeParameters struct {
	index     uint
	node      *propertiesv3.ClusterNode
	variables data.Map
}

// taskConfigureNode configure one node
func (instance *Cluster) taskConfigureNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		// Convert and validate params
		p, ok := params.(taskConfigureNodeParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskConfigureNodeParameters'")}
			return
		}
		if p.index < 1 {
			chRes <- result{nil, fail.InvalidParameterError("params.indexindex", "cannot be an integer less than 1")}
			return
		}
		if p.node == nil {
			chRes <- result{nil, fail.InvalidParameterCannotBeNilError("params.Node")}
			return
		}
		variables, _ := data.FromMap(p.variables)

		tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d, %s)", p.index, p.node.Name).WithStopwatch().Entering()
		defer tracer.Exiting()

		hostLabel := fmt.Sprintf("node #%d (%s)", p.index, p.node.Name)
		logrus.WithContext(ctx).Debugf("[%s] starting configuration...", hostLabel)

		hostInstance, xerr := LoadHost(ctx, instance.Service(), p.node.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, fail.Wrap(xerr, "failed to get metadata of node '%s'", p.node.Name)}
			return
		}

		// Docker and docker-compose installation is mandatory on all nodes
		xerr = instance.installDocker(ctx, hostInstance, hostLabel, variables)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{nil, xerr}
			return
		}

		// Now configures node specifically for Cluster flavor
		makers := instance.localCache.makers
		if makers.ConfigureNode == nil {
			chRes <- result{nil, nil}
			return
		}

		xerr = makers.ConfigureNode(instance, p.index, hostInstance)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.WithContext(ctx).Error(xerr.Error())
			chRes <- result{nil, xerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[%s] configuration successful.", hostLabel)
		chRes <- result{nil, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

type machineID struct {
	ID   string
	Name string
}

type taskDeleteNodeOnFailureParameters = machineID

// taskDeleteNodeOnFailure deletes a node when a failure occurred
func (instance *Cluster) taskDeleteNodeOnFailure(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		// Convert and validate params
		casted, ok := params.(taskDeleteNodeOnFailureParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeOnFailureParameters'")}
			return
		}

		node := casted

		hostInstance, xerr := LoadHost(ctx, instance.Service(), node.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				logrus.WithContext(ctx).Tracef("Node %s not found, deletion considered successful", node.Name)
				chRes <- result{nil, nil}
				return
			default:
				chRes <- result{nil, xerr}
				return
			}
		}

		xerr = deleteHostOnFailure(ctx, hostInstance)
		chRes <- result{nil, xerr}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskDeleteNodeParameters struct {
	node   *propertiesv3.ClusterNode
	master *Host
}

// taskDeleteNode deletes one node
func (instance *Cluster) taskDeleteNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	var xerr fail.Error

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		// Convert and validate params
		p, ok := params.(taskDeleteNodeParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeParameters'")}
			return
		}
		if p.node == nil {
			chRes <- result{nil, fail.InvalidParameterCannotBeNilError("params.node")}
			return
		}
		if p.node.NumericalID == 0 {
			chRes <- result{nil, fail.InvalidParameterError("params.node.NumericalID", "cannot be 0")}
			return
		}
		if p.node.ID == "" && p.node.Name == "" {
			chRes <- result{nil, fail.InvalidParameterError("params.node.ID|params.node.Name", "ID or Name must be set")}
			return
		}

		nodeName := p.node.Name
		if nodeName == "" {
			nodeName = p.node.ID
		}

		logrus.WithContext(ctx).Debugf("Deleting Node '%s'", nodeName)
		xerr = instance.deleteNode(ctx, p.node, p.master)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				logrus.WithContext(ctx).Debugf("Node %s not found, deletion considered successful", nodeName)
				chRes <- result{nil, nil}
				return
			default:
				chRes <- result{nil, xerr}
				return
			}
		}

		logrus.WithContext(ctx).Debugf("Successfully deleted Node '%s'", nodeName)
		chRes <- result{nil, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

// taskDeleteMaster deletes one master
func (instance *Cluster) taskDeleteMaster(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		// Convert and validate params
		p, ok := params.(taskDeleteNodeParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeParameters'")}
			return
		}
		if p.node == nil {
			chRes <- result{nil, fail.InvalidParameterError("params.node", "cannot be nil")}
			return
		}
		if p.node.ID == "" && p.node.Name == "" {
			chRes <- result{nil, fail.InvalidParameterError("params.node.ID|params.node.Name", "ID or Name must be set")}
			return
		}

		nodeRef := p.node.Name
		if nodeRef == "" {
			nodeRef = p.node.ID
		}

		host, xerr := LoadHost(ctx, instance.Service(), nodeRef)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				logrus.WithContext(ctx).Tracef("Master %s not found, deletion considered successful", p.node.Name)
				chRes <- result{nil, nil}
				return
			default:
				chRes <- result{nil, xerr}
				return
			}
		}

		logrus.WithContext(ctx).Debugf("Deleting Master '%s'", p.node.Name)
		xerr = instance.deleteMaster(ctx, host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				logrus.WithContext(ctx).Debugf("Master %s not found, deletion considered successful", p.node.Name)
				chRes <- result{nil, nil}
				return
			default:
				chRes <- result{nil, xerr}
				return
			}
		}

		logrus.WithContext(ctx).Debugf("Successfully deleted Master '%s'", p.node.Name)
		chRes <- result{nil, nil}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

type taskDeleteHostOnFailureParameters struct {
	host resources.Host
}

// taskDeleteHostOnFailure deletes a host
func (instance *Cluster) taskDeleteHostOnFailure(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		// Convert and validate params
		casted, ok := params.(taskDeleteHostOnFailureParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskDeleteHostOnFailureParameters'")}
			return
		}

		chRes <- result{nil, deleteHostOnFailure(ctx, casted.host)}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}

}

// deleteHostOnFailure deletes a Host with appropriate logs
func deleteHostOnFailure(ctx context.Context, instance resources.Host) fail.Error {
	prefix := "Cleaning up on failure, "
	hostName := instance.GetName()
	logrus.WithContext(ctx).Debugf(prefix + fmt.Sprintf("deleting Host '%s'", hostName))

	xerr := instance.Delete(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			logrus.WithContext(ctx).Tracef("Host %s not found, deletion considered successful", hostName)
			return nil
		default:
			return xerr
		}
	}

	logrus.WithContext(ctx).Debugf(prefix + fmt.Sprintf("successfully deleted Host '%s'", hostName))
	return nil
}

type taskUpdateClusterInventoryMasterParameters struct {
	ctx           context.Context
	master        resources.Host
	inventoryData string
}

// taskUpdateClusterInventoryMaster task to update a Host (master) ansible inventory
func (instance *Cluster) taskUpdateClusterInventoryMaster(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	inctx := task.Context()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  concurrency.TaskResult
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		// Convert and validate params
		casted, ok := params.(taskUpdateClusterInventoryMasterParameters)
		if !ok {
			chRes <- result{nil, fail.InvalidParameterError("params", "must be a 'taskUpdateClusterInventoryMasterParameters'")}
			return
		}

		xerr := instance.updateClusterInventoryMaster(ctx, casted.master, casted.inventoryData)
		chRes <- result{nil, xerr}

	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// updateClusterInventoryMaster updates a Host (master) ansible inventory
func (instance *Cluster) updateClusterInventoryMaster(inctx context.Context, master resources.Host, inventoryData string) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{xerr}
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
			fmt.Sprintf("sudo mv %s %s_inventory.py", rfcItem.Remote, target),
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
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}
