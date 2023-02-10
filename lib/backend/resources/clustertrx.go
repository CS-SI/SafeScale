package resources

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/consts"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netutils "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	clusterTransaction     = *clusterTransactionImpl
	clusterTransactionImpl struct {
		metadata.Transaction[*abstract.Cluster, *Cluster]
	}
)

//go:embed scripts/*
var ansibleScripts embed.FS

func newClusterTransaction(ctx context.Context, instance *Cluster) (*clusterTransactionImpl, fail.Error) {
	if instance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("instance")
	}

	trx, xerr := metadata.NewTransaction[*abstract.Cluster, *Cluster](ctx, instance)
	if xerr != nil {
		return nil, xerr
	}

	return &clusterTransactionImpl{trx}, nil
}

func inspectClusterMetadata(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster, *serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.Inspect[*abstract.Cluster](ctx, trx, callback)
}

func inspectClusterMetadataAbstract(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster) fail.Error) fail.Error {
	return metadata.InspectAbstract[*abstract.Cluster](ctx, trx, callback)
}

func inspectClusterMetadataProperty[P clonable.Clonable](ctx context.Context, trx clusterTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.InspectProperty[*abstract.Cluster, P](ctx, trx, property, callback)
}

func inspectClusterMetadataProperties(ctx context.Context, trx clusterTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.InspectProperties[*abstract.Cluster](ctx, trx, callback)
}

func alterClusterMetadata(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster, *serialize.JSONProperties) fail.Error) fail.Error {
	return alterClusterMetadata(ctx, trx, callback)
}

func alterClusterMetadataAbstract(ctx context.Context, trx clusterTransaction, callback func(*abstract.Cluster) fail.Error) fail.Error {
	return metadata.AlterAbstract[*abstract.Cluster](ctx, trx, callback)
}

func alterClusterMetadataProperty[P clonable.Clonable](ctx context.Context, trx clusterTransaction, property string, callback func(P) fail.Error) fail.Error {
	return metadata.AlterProperty[*abstract.Cluster, P](ctx, trx, property, callback)
}

func alterClusterMetadataProperties(ctx context.Context, trx clusterTransaction, callback func(*serialize.JSONProperties) fail.Error) fail.Error {
	return metadata.AlterProperties[*abstract.Cluster](ctx, trx, callback)
}

// IsNull ...
func (clusterTrx *clusterTransactionImpl) IsNull() bool {
	return clusterTrx == nil || clusterTrx.Transaction.IsNull()
}

// createCluster is the TaskAction that creates a Cluster
func (instance *Cluster) createCluster(inctx context.Context, clusterTrx clusterTransaction, params interface{}) fail.Error {
	req, ok := params.(abstract.ClusterRequest)
	if !ok {
		return fail.InvalidParameterError("params", "should be an abstract.ClusterRequest")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan fail.Error)
	go func() {
		defer close(chRes)

		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// Check if Cluster exists in metadata; if yes, error
			_, xerr := LoadCluster(ctx, req.Name)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					return xerr
				}
			} else {
				return fail.DuplicateError("a Cluster named '%s' already exist", req.Name)
			}

			// Create first metadata of Cluster after initialization
			xerr = instance.firstLight(ctx, clusterTrx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			cleanFailure := false
			// Starting from here, Delete metadata if exiting with error
			// but if the next cleaning steps fail, we must keep the metadata to try again, so we have the cleanFailure flag to detect that issue
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() && !cleanFailure {
					ctx := cleanupContextFrom(inctx)
					logrus.WithContext(ctx).Debugf("Cleaning up on %s, deleting metadata of Cluster '%s'...", ActionFromError(ferr), req.Name)
					clusterTrx.SilentTerminate(ctx)
					derr := instance.Core.Delete(ctx)
					if derr != nil {
						logrus.WithContext(context.Background()).Errorf("cleaning up on %s, failed to Delete metadata of Cluster '%s'", ActionFromError(ferr), req.Name)
						_ = ferr.AddConsequence(derr)
					} else {
						logrus.WithContext(ctx).Debugf("Cleaning up on %s, successfully deleted metadata of Cluster '%s'", ActionFromError(ferr), req.Name)
					}
				}
			}()

			// Obtain number of nodes to create
			_, privateNodeCount, _, xerr := instance.trxDetermineRequiredNodes(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
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

			gatewaysDef, mastersDef, nodesDef, xerr := instance.trxDetermineSizingRequirements(ctx, clusterTrx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			var (
				networkInstance *Network
				subnetInstance  *Subnet
			)
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && req.CleanOnFailure() && subnetInstance != nil && networkInstance != nil {
					ctx := cleanupContextFrom(inctx)
					logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleting Subnet '%s'...", subnetInstance.GetName())
					if derr := subnetInstance.Delete(jobapi.NewContextPropagatingJob(inctx)); derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Subnet is considered as a successful deletion, continue
							debug.IgnoreErrorWithContext(ctx, derr)
						default:
							cleanFailure = true
							logrus.WithContext(ctx).Errorf("Cleaning up on %s, failed to Delete Subnet '%s'", ActionFromError(ferr), subnetInstance.GetName())
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Subnet", ActionFromError(ferr)))
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
									logrus.WithContext(context.Background()).Errorf("cleaning up on %s, failed to Delete Network '%s'", ActionFromError(ferr), networkInstance.GetName())
									_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Network", ActionFromError(ferr)))
								}
							} else {
								logrus.WithContext(ctx).Debugf("Cleaning up on %s, successfully deleted Network '%s'", ActionFromError(ferr), networkInstance.GetName())
							}
						}
					}
				}
			}()

			// Create the Network and Subnet
			networkInstance, subnetInstance, xerr = instance.trxCreateNetworkingResources(ctx, clusterTrx, req, gatewaysDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
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
			xerr = instance.trxCreateHostResources(ctx, clusterTrx, subnetInstance, *mastersDef, *nodesDef, req.InitialNodeCount, ExtractFeatureParameters(req.FeatureParameters), req.KeepOnFailure)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			// configure Cluster as a whole
			xerr = instance.configureCluster(ctx, clusterTrx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
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
				return xerr
			}

			return nil
		}() // nolint
		chRes <- gerr
	}()

	select {
	case res := <-chRes:
		return res
	case <-ctx.Done():
		<-chRes // wait cleanup
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return fail.Wrap(inctx.Err())
	}
}

// firstLight contains the code leading to Cluster first metadata written
func (instance *Cluster) firstLight(inctx context.Context, clusterTrx clusterTransaction, req abstract.ClusterRequest) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan fail.Error)
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

			xerr = instance.Carry(ctx, ci)
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
		chRes <- gerr
	}()

	select {
	case res := <-chRes:
		return res
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

// trxCreateNetworkingResources creates the network and subnet for the Cluster
func (instance *Cluster) trxCreateNetworkingResources(
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

// trxCreateHostResources creates and configures hosts for the Cluster
func (instance *Cluster) trxCreateHostResources(
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
				_, xerr := instance.trxInstallGateway(ctx, clusterTrx, trxInstallGatewayParameters{host: primaryGateway, variables: parameters})
				return xerr
			})
			if haveSecondaryGateway {
				eg.Go(func() error {
					_, xerr := instance.trxInstallGateway(ctx, clusterTrx, trxInstallGatewayParameters{host: secondaryGateway, variables: parameters})
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

			// Starting from here, Delete masters if exiting with error and req.keepOnFailure is not true
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

			// Starting from here, if exiting with error, Delete nodes
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

type trxInstallGatewayParameters struct {
	host      *Host
	variables data.Map[string, any]
}

// trxInstallGateway installs necessary components on one gateway
func (instance *Cluster) trxInstallGateway(inctx context.Context, clusterTrx clusterTransaction, params trxInstallGatewayParameters) (_ interface{}, _ fail.Error) {
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
			xerr = instance.installNodeRequirements(ctx, clusterTrx, clusternodetype.Gateway, params.host, hostLabel)
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

// Regenerate ansible inventory
func (instance *Cluster) trxUpdateClusterInventory(inctx context.Context, clusterTrx clusterTransaction) fail.Error {
	// Check incoming parameters
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		logrus.WithContext(ctx).Infof("[Cluster %s] Update ansible inventory", instance.GetName())

		// Collect data
		featureAnsibleInventoryInstalled := false
		var masters []*Host
		var params = map[string]interface{}{
			"ClusterName":          "",
			"ClusterAdminUsername": "cladm",
			"ClusterAdminPassword": "",
			"PrimaryGatewayName":   fmt.Sprintf("gw-%s", instance.GetName()),
			"PrimaryGatewayIP":     "",
			"PrimaryGatewayPort":   "22",
			"SecondaryGatewayName": fmt.Sprintf("gw2-%s", instance.GetName()),
			"SecondaryGatewayIP":   "",
			"SecondaryGatewayPort": "22",
			"ClusterMasters":       rscapi.IndexedListOfClusterNodes{},
			"ClusterNodes":         rscapi.IndexedListOfClusterNodes{},
		}

		xerr := inspectClusterMetadata(ctx, clusterTrx, func(aci *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
			// Check if feature ansible is installed
			innerXErr := props.Inspect(clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
				featuresV1, innerErr := clonable.Cast[*propertiesv1.ClusterFeatures](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				_, featureAnsibleInventoryInstalled = featuresV1.Installed["ansible-for-cluster"]
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}
			if !featureAnsibleInventoryInstalled {
				return nil
			}

			// Collect get network config
			var networkCfg *propertiesv3.ClusterNetwork
			innerXErr = props.Inspect(clusterproperty.NetworkV3, func(p clonable.Clonable) fail.Error {
				networkV3, innerErr := clonable.Cast[*propertiesv3.ClusterNetwork](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				networkCfg = networkV3
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// Collect template data, list masters hosts
			// FIXME: Why that? aci.Name is declared as string, how could it be anything else and should need reflect to identify?
			if reflect.TypeOf(aci.Name).Kind() != reflect.String && aci.Name == "" {
				return fail.InconsistentError("Cluster name must be a not empty string")
			}

			params["Clustername"] = aci.Name
			params["ClusterAdminUsername"] = "cladm"
			params["ClusterAdminPassword"] = aci.AdminPassword
			params["PrimaryGatewayIP"] = networkCfg.GatewayIP
			if networkCfg.SecondaryGatewayIP != "" {
				params["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
			}

			return props.Inspect(clusterproperty.NodesV3, func(p clonable.Clonable) (ferr fail.Error) {
				nodesV3, innerErr := clonable.Cast[*propertiesv3.ClusterNodes](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				// Template params: gateways
				hostInstance, innerXErr := LoadHost(ctx, networkCfg.GatewayID)
				if innerXErr != nil {
					return fail.InconsistentError("Fail to load primary gateway '%s'", networkCfg.GatewayID)
				}

				hostTrx, innerXErr := newHostTransaction(ctx, hostInstance)
				if innerXErr != nil {
					return innerXErr
				}
				defer hostTrx.TerminateFromError(ctx, &ferr)

				innerXErr = inspectHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
					params["PrimaryGatewayPort"] = strconv.Itoa(int(ahc.SSHPort))
					if ahc.Name != "" {
						params["PrimaryGatewayName"] = ahc.Name
					}
					return nil
				})
				if innerXErr != nil {
					return fail.InconsistentError("Fail to load primary gateway '%s'", networkCfg.GatewayID)
				}

				if networkCfg.SecondaryGatewayIP != "" {
					hostInstance, innerXErr := LoadHost(ctx, networkCfg.SecondaryGatewayID)
					if innerXErr != nil {
						return fail.InconsistentError("Fail to load secondary gateway '%s'", networkCfg.SecondaryGatewayID)
					}

					hostTrx, innerXErr := newHostTransaction(ctx, hostInstance)
					if innerXErr != nil {
						return innerXErr
					}
					defer hostTrx.TerminateFromError(ctx, &ferr)

					innerXErr = inspectHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
						params["SecondaryGatewayPort"] = strconv.Itoa(int(ahc.SSHPort))
						if ahc.Name != "" {
							params["SecondaryGatewayName"] = ahc.Name
						}
						return nil
					})
					if innerXErr != nil {
						return fail.InconsistentError("Fail to load secondary gateway '%s'", networkCfg.SecondaryGatewayID)
					}
				}

				// Template params: masters
				nodes := make(rscapi.IndexedListOfClusterNodes, len(nodesV3.Masters))
				for _, v := range nodesV3.Masters {
					if node, found := nodesV3.ByNumericalID[v]; found {
						nodes[node.NumericalID] = node
						master, innerXErr := LoadHost(ctx, node.ID)
						if innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotFound:
								continue
							default:
								return fail.Wrap(innerXErr, "failed to load master '%s'", node.ID)
							}
						}
						if does, innerXErr := master.Exists(ctx); innerXErr == nil && does {
							masters = append(masters, master)
						}
					}
				}
				params["ClusterMasters"] = nodes

				// Template params: nodes
				nodes = make(rscapi.IndexedListOfClusterNodes, len(nodesV3.PrivateNodes))
				for _, v := range nodesV3.PrivateNodes {
					if node, found := nodesV3.ByNumericalID[v]; found {
						nodes[node.NumericalID] = node
					}
				}
				params["ClusterNodes"] = nodes
				return nil
			})
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			ar := result{xerr}
			chRes <- ar
			return
		}

		prerr := fmt.Sprintf("[Cluster %s] Update ansible inventory: ", instance.GetName())

		// Feature ansible found ?
		if !featureAnsibleInventoryInstalled {
			logrus.WithContext(ctx).Infof("%snothing to update (feature not installed)", prerr)
			ar := result{nil}
			chRes <- ar
			return
		}
		// Has at least one master ?
		if len(masters) == 0 {
			logrus.WithContext(ctx).Infof("%s nothing to update (no masters in cluster)", prerr)
			ar := result{nil}
			chRes <- ar
			return
		}

		tmplString, err := ansibleScripts.ReadFile("scripts/ansible_inventory.py")
		if err != nil {
			ar := result{fail.Wrap(err, "%s failed to load template 'ansible_inventory.py'", prerr)}
			chRes <- ar
			return
		}

		// --------- Build ansible inventory --------------
		fileName := fmt.Sprintf("cluster-inventory-%s.py", params["Clustername"])
		tmplCmd, err := template.Parse(fileName, string(tmplString))
		if err != nil {
			ar := result{fail.Wrap(err, "%s failed to parse template 'ansible_inventory.py'", prerr)}
			chRes <- ar
			return
		}

		dataBuffer := bytes.NewBufferString("")
		err = tmplCmd.Execute(dataBuffer, params)
		if err != nil {
			ar := result{fail.Wrap(err, "%s failed to execute template 'ansible_inventory.py'", prerr)}
			chRes <- ar
			return
		}

		// --------- Upload file for each master and test it (parallelized) --------------
		tg := new(errgroup.Group)
		for master := range masters {
			master := master
			logrus.WithContext(ctx).Infof("%s Update master %s", prerr, masters[master].GetName())

			tg.Go(func() error {
				_, err := instance.taskUpdateClusterInventoryMaster(ctx, taskUpdateClusterInventoryMasterParameters{
					ctx:           ctx,
					master:        masters[master],
					inventoryData: dataBuffer.String(),
					// clusterName:   params["Clustername"].(string),
				})
				return err
			})
		}

		xerr = fail.Wrap(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if withTimeout(xerr) {
				logrus.WithContext(ctx).Warnf("%s Timeouts ansible update inventory", prerr)
			}
			ar := result{xerr}
			chRes <- ar
			return
		}

		logrus.WithContext(ctx).Debugf("%s update inventory successful", prerr)

		ar := result{nil}
		chRes <- ar

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

// trxConfigureNodesFromList configures nodes from a list
func (instance *Cluster) trxConfigureNodesFromList(ctx context.Context, clusterTrx clusterTransaction, nodes []*propertiesv3.ClusterNode, parameters data.Map[string, any]) (ferr fail.Error) {
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	length := len(nodes)
	if length > 0 {
		eg := new(errgroup.Group)
		for i := 0; i < length; i++ {
			captured := i
			eg.Go(func() error {
				_, xerr := instance.taskConfigureNode(ctx, clusterTrx, nodes[captured], parameters)
				return xerr
			})
		}

		xerr := fail.Wrap(eg.Wait())
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

type trxCreateMasterParameters struct {
	masterDef     abstract.HostSizingRequirements
	timeout       time.Duration
	keepOnFailure bool
}

// trxCreateMaster creates one master
func (instance *Cluster) trxCreateMaster(inctx context.Context, clusterTrx clusterTransaction, params any) (_ interface{}, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	p, err := lang.Cast[trxCreateMasterParameters](params)
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
			// 			Delete(nodesV3.ByNumericalID, nodeIdx)
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
			defer subnetTrx.TerminateFromError(ctx, &ferr)

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
			xerr = instance.installNodeRequirements(ctx, clusterTrx, clusternodetype.Master, hostInstance, hostLabel)
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

// trxGetIdentity returns the identity of the Cluster
func trxGetIdentity(ctx context.Context, clusterTrx clusterTransaction) (_ abstract.Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var clusterIdentity abstract.Cluster
	xerr := inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
		clusterIdentity = *aci
		return nil
	})
	return clusterIdentity, xerr

}

// trxGetFlavor returns the flavor of the Cluster
func trxGetFlavor(ctx context.Context, clusterTrx clusterTransaction) (flavor clusterflavor.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aci, xerr := trxGetIdentity(ctx, clusterTrx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Flavor, nil
}

// trxGetComplexity returns the complexity of the Cluster
func trxGetComplexity(ctx context.Context, clusterTrx clusterTransaction) (_ clustercomplexity.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aci, xerr := trxGetIdentity(ctx, clusterTrx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Complexity, nil
}

// trxGetState returns the current state of the Cluster
// Uses the "maker" ForceGetState
func (instance *Cluster) trxGetState(inctx context.Context, clusterTrx clusterTransaction) (_ clusterstate.Enum, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  clusterstate.Enum
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		var state = clusterstate.Unknown
		makers := instance.localCache.makers
		if makers.GetState != nil {
			var xerr fail.Error
			state, xerr = makers.GetState(instance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{clusterstate.Unknown, xerr}
				return
			}

			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
				stateV1.State = state
				return nil
			})
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			} else {
				// State change has to be committed as soon as possible
				xerr = clusterTrx.Commit(ctx)
			}

			chRes <- result{state, xerr}
			return
		}

		xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
			stateV1, innerErr := clonable.Cast[*propertiesv1.ClusterState](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			state = stateV1.State
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			chRes <- result{clusterstate.Unknown, xerr}
			return
		}

		chRes <- result{state, nil}
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return clusterstate.Unknown, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return clusterstate.Unknown, fail.Wrap(inctx.Err())
	}
}

// trxListMasters is the not goroutine-safe equivalent of ListMasters, that does the real work
// Note: must be used with wisdom
func trxListMasters(inctx context.Context, clusterTrx clusterTransaction) (_ rscapi.IndexedListOfClusterNodes, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  rscapi.IndexedListOfClusterNodes
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var (
				list, emptyList rscapi.IndexedListOfClusterNodes
			)

			xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				list = make(rscapi.IndexedListOfClusterNodes, len(nodesV3.Masters))

				for _, v := range nodesV3.Masters {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{list, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// trxListMasterIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) trxListMasterIDs(inctx context.Context, clusterTrx clusterTransaction) (_ data.IndexedListOfStrings, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.IndexedListOfStrings
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var list data.IndexedListOfStrings
			emptyList := data.IndexedListOfStrings{}

			xerr := instance.trxBeingRemoved(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{emptyList, xerr}, xerr
			}

			xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
				nodesV3, innerErr := clonable.Cast[*propertiesv3.ClusterNodes](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
				for _, v := range nodesV3.Masters {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node.ID
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{list, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// trxListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (instance *Cluster) trxListMasterIPs(inctx context.Context, clusterTrx clusterTransaction) (_ data.IndexedListOfStrings, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.IndexedListOfStrings
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			emptyList := data.IndexedListOfStrings{}
			var list data.IndexedListOfStrings

			xerr := instance.trxBeingRemoved(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{emptyList, xerr}, xerr
			}

			xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
				for _, v := range nodesV3.Masters {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node.PrivateIP
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{list, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}

}

// trxListNodeIPs lists the IPs of the nodes in the Cluster
func (instance *Cluster) trxListNodeIPs(inctx context.Context, clusterTrx clusterTransaction) (_ data.IndexedListOfStrings, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.IndexedListOfStrings
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			emptyList := data.IndexedListOfStrings{}
			var outlist data.IndexedListOfStrings

			xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				list := make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
				for _, v := range nodesV3.PrivateNodes {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node.PrivateIP
					}
				}
				outlist = list
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}
			return result{outlist, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}

}

// unsafeFindAvailableMaster is the not go-routine-safe version of FindAvailableMaster, that does the real work
// Must be used with wisdom
func (instance *Cluster) trxFindAvailableMaster(inctx context.Context, clusterTrx clusterTransaction) (_ *Host, _ fail.Error) {
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
			var master *Host

			masters, xerr := trxListMasters(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			var lastError fail.Error
			lastError = fail.NotFoundError("no master found")
			master = nil
			for _, v := range masters {
				if v.ID == "" {
					continue
				}

				master, xerr = LoadHost(ctx, v.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}

				_, xerr = master.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *retry.ErrTimeout:
						lastError = xerr
						continue
					default:
						return result{nil, xerr}, xerr
					}
				}
				break
			}
			if master == nil {
				return result{nil, lastError}, lastError
			}

			return result{master, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}

}

// trxListNodes is the not goroutine-safe version of ListNodes and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) trxListNodes(inctx context.Context, clusterTrx clusterTransaction) (_ rscapi.IndexedListOfClusterNodes, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  rscapi.IndexedListOfClusterNodes
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			emptyList := rscapi.IndexedListOfClusterNodes{}
			var list rscapi.IndexedListOfClusterNodes

			xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
				nodesV3, innerErr := clonable.Cast[*propertiesv3.ClusterNodes](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				list = make(rscapi.IndexedListOfClusterNodes, len(nodesV3.PrivateNodes))
				for _, v := range nodesV3.PrivateNodes {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node
					}
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{list, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// unsafeListNodeIDs is the not goroutine-safe version of ListNodeIDs and no parameter validation, that does the real work
// Note: must be used wisely
func (instance *Cluster) trxListNodeIDs(inctx context.Context, clusterTrx clusterTransaction) (_ data.IndexedListOfStrings, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  data.IndexedListOfStrings
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			emptyList := data.IndexedListOfStrings{}

			xerr := instance.trxBeingRemoved(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{emptyList, xerr}, xerr
			}

			var outlist data.IndexedListOfStrings
			xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				list := make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
				for _, v := range nodesV3.PrivateNodes {
					if node, found := nodesV3.ByNumericalID[v]; found {
						list[node.NumericalID] = node.ID
					}
				}
				outlist = list
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{emptyList, xerr}, xerr
			}

			return result{outlist, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// trxFindAvailableNode is the package restricted, not goroutine-safe, no parameter validation version of FindAvailableNode, that does the real work
// Note: must be used wisely
func (instance *Cluster) trxFindAvailableNode(inctx context.Context, clusterTrx clusterTransaction) (node *Host, _ fail.Error) {
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

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			xerr = instance.trxBeingRemoved(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			list, xerr := instance.trxListNodes(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			node = nil
			found := false
			for _, v := range list {
				node, xerr = LoadHost(ctx, v.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}

				_, xerr = node.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *retry.ErrTimeout:
						continue
					default:
						return result{nil, xerr}, xerr
					}
				}
				found = true
				break
			}
			if !found {
				ar := result{nil, fail.NotAvailableError("failed to find available node")}
				return ar, ar.rErr
			}

			return result{node, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}
