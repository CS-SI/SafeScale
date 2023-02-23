package resources

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"math"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/consts"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/internal"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/internal/clusterflavors"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/internal/clusterflavors/boh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/internal/clusterflavors/k8s"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/system"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/json"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/davecgh/go-spew/spew"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
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

//go:embed internal/clusterflavors/scripts/*
var clusterFlavorScripts embed.FS

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
	return metadata.Alter[*abstract.Cluster](ctx, trx, callback)
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

// AddFeature allows to add a feature from cluster Transaction
// satisfies interface clusterflavors.ClusterTarget
func (clusterTrx *clusterTransactionImpl) AddFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (rscapi.Results, fail.Error) {
	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	feat, xerr := NewFeature(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Add(ctx, clusterTrx, vars, opts...)
}

// ComplementFeatureParameters configures parameters that are implicitly defined, based on target
// satisfies interface resources.Targetable
func (clusterTrx *clusterTransactionImpl) ComplementFeatureParameters(inctx context.Context, v data.Map[string, any]) (ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	svc, xerr := clusterTrx.Service()
	if xerr != nil {
		return xerr
	}

	identity, xerr := clusterTrx.getIdentity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["ClusterComplexity"] = strings.ToLower(identity.Complexity.String())
	v["ClusterFlavor"] = strings.ToLower(identity.Flavor.String())
	v["ClusterName"] = identity.Name
	v["ClusterAdminUsername"] = "cladm"
	v["ClusterAdminPassword"] = identity.AdminPassword
	if _, ok := v["Username"]; !ok {
		config, xerr := svc.ConfigurationOptions()
		if xerr != nil {
			return xerr
		}
		v["Username"] = config.OperatorUsername
		if v["username"] == "" {
			v["Username"] = abstract.DefaultUser
		}
	}
	networkCfg, xerr := clusterTrx.GetNetworkConfig(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["PrimaryGatewayIP"] = networkCfg.GatewayIP
	v["DefaultRouteIP"] = networkCfg.DefaultRouteIP
	v["GatewayIP"] = v["DefaultRouteIP"] // legacy ...
	v["PrimaryPublicIP"] = networkCfg.PrimaryPublicIP
	v["NetworkUsesVIP"] = networkCfg.SecondaryGatewayIP != ""
	v["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
	v["SecondaryPublicIP"] = networkCfg.SecondaryPublicIP
	v["EndpointIP"] = networkCfg.EndpointIP
	v["PublicIP"] = v["EndpointIP"] // legacy ...
	if _, ok := v["IPRanges"]; !ok {
		v["IPRanges"] = networkCfg.CIDR
	}
	v["CIDR"] = networkCfg.CIDR

	var cpV1 *propertiesv1.ClusterControlplane
	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.ControlPlaneV1, func(controlPlaneV1 *propertiesv1.ClusterControlplane) fail.Error {
		cpV1 = controlPlaneV1
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if cpV1.VirtualIP != nil && cpV1.VirtualIP.PrivateIP != "" {
		v["ClusterControlplaneUsesVIP"] = true
		v["ClusterControlplaneEndpointIP"] = cpV1.VirtualIP.PrivateIP
	} else {
		// Don't set ClusterControlplaneUsesVIP if there is no VIP... use IP of first available master instead
		master, xerr := clusterTrx.FindAvailableMaster(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		v["ClusterControlplaneEndpointIP"], xerr = master.GetPrivateIP(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		v["ClusterControlplaneUsesVIP"] = false
	}
	v["ClusterMasters"], xerr = clusterTrx.ListMasters(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	list := make([]string, 0, len(v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes) {
		list = append(list, v.Name)
	}
	v["ClusterMasterNames"] = list

	list = make([]string, 0, len(v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterMasters"].(rscapi.IndexedListOfClusterNodes) {
		list = append(list, v.ID)
	}
	v["ClusterMasterIDs"] = list

	v["ClusterMasterIPs"], xerr = clusterTrx.ListMasterIPs(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["ClusterNodes"], xerr = clusterTrx.ListNodes(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	list = make([]string, 0, len(v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes) {
		list = append(list, v.Name)
	}
	v["ClusterNodeNames"] = list

	list = make([]string, 0, len(v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes)))
	for _, v := range v["ClusterNodes"].(rscapi.IndexedListOfClusterNodes) {
		list = append(list, v.ID)
	}
	v["ClusterNodeIDs"] = list

	v["ClusterNodeIPs"], xerr = clusterTrx.ListNodeIPs(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// RegisterFeature registers an installed Feature in metadata of a Cluster
// satisfies interface resources.Targetable
func (clusterTrx *clusterTransactionImpl) RegisterFeature(ctx context.Context, feat *Feature, requiredBy *Feature, clusterContext bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if feat == nil {
		return fail.InvalidParameterCannotBeNilError("feat")
	}

	return alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
		item, ok := featuresV1.Installed[feat.GetName()]
		if !ok {
			requirements, innerXErr := feat.Dependencies(ctx)
			if innerXErr != nil {
				return innerXErr
			}

			item = propertiesv1.NewClusterInstalledFeature()
			item.Name = feat.GetName()
			item.FileName = feat.GetDisplayFilename(ctx)
			item.Requires = requirements
			featuresV1.Installed[item.Name] = item
		}
		if !valid.IsNil(requiredBy) {
			item.RequiredBy[requiredBy.GetName()] = struct{}{}
		}
		return nil
	})
}

// UnregisterFeature unregisters a Feature from Cluster metadata
// satisfies interface resources.Targetable
func (clusterTrx *clusterTransactionImpl) UnregisterFeature(inctx context.Context, feat string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	xerr := alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
		delete(featuresV1.Installed, feat)
		for _, v := range featuresV1.Installed {
			delete(v.RequiredBy, feat)
		}
		return nil
	})
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
	}
	return xerr
}

// InstallMethods returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = the highest preference)
// satisfies resources.Targetable interface
func (clusterTrx *clusterTransactionImpl) InstallMethods(ctx context.Context) (_ map[uint8]installmethod.Enum, ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	out := make(map[uint8]installmethod.Enum)

	internal.IncrementExpVar("cluster.cache.hit") // FIXME: ?
	return out, inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
		local, err := lang.Cast[*extraInAbstract](aci.Local)
		if err != nil {
			return fail.Wrap(err)
		}

		local.InstallMethods.Range(func(k, v interface{}) bool {
			var ok bool
			out[k.(uint8)], ok = v.(installmethod.Enum)
			return ok
		})
		return nil
	})
}

// TargetType returns the type of the target
// satisfies resources.Targetable interface
func (clusterTrx *clusterTransactionImpl) TargetType() featuretargettype.Enum {
	return featuretargettype.Cluster
}

// InstalledFeatures returns a list of installed features
func (clusterTrx *clusterTransactionImpl) InstalledFeatures(ctx context.Context) (_ []string, ferr fail.Error) {
	if valid.IsNull(clusterTrx) {
		return []string{}, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var out []string
	xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
		featuresV1, innerErr := lang.Cast[*propertiesv1.ClusterFeatures](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		for k := range featuresV1.Installed {
			out = append(out, k)
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return []string{}, xerr
	}
	return out, nil
}

// createCluster is the TaskAction that creates a Cluster
func (instance *Cluster) createCluster(inctx context.Context, params interface{}) fail.Error {
	if valid.IsNull(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

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
			clusterTrx, xerr := instance.firstLight(ctx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
			defer clusterTrx.TerminateFromError(ctx, &ferr)

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
			_, privateNodeCount, _, xerr := clusterTrx.determineRequiredNodes(ctx)
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

			gatewaysDef, mastersDef, nodesDef, xerr := clusterTrx.determineSizingRequirements(ctx, req)
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
			networkInstance, subnetInstance, xerr = clusterTrx.createNetworkingResources(ctx, req, gatewaysDef)
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
									_, err := clusterTrx.deleteNodeOnFailure(cleanupContextFrom(ctx), p)
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
				return xerr
			}

			// configure Cluster as a whole
			xerr = clusterTrx.configureCluster(ctx, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			// Sets nominal state of the new Cluster in metadata
			xerr = alterClusterMetadataProperties(ctx, clusterTrx, func(props *serialize.JSONProperties) fail.Error {
				// update metadata about disabled default features
				innerXErr := props.Alter(clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
					featuresV1, err := lang.Cast[*propertiesv1.ClusterFeatures](p)
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
					stateV1, err := lang.Cast[*propertiesv1.ClusterState](p)
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

			xerr = clusterTrx.updateClusterAnsibleInventory(ctx)
			if xerr != nil {
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

// createNetworkingResources creates the network and subnet for the Cluster
func (clusterTrx *clusterTransactionImpl) createNetworkingResources(
	ctx context.Context, req abstract.ClusterRequest, gatewaysDef *abstract.HostSizingRequirements,
) (_ *Network, _ *Subnet, ferr fail.Error) {

	ctx, cancel := context.WithCancel(ctx)
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
			svc, xerr := clusterTrx.Service()
			if xerr != nil {
				ar := result{nil, nil, xerr}
				return ar, ar.rErr
			}

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
						if derr := networkInstance.Delete(cleanupContextFrom(ctx) /*jobapi.NewContextPropagatingJob(ctx)*/); derr != nil {
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
					if derr := subnetInstance.Delete(cleanupContextFrom(ctx) /*jobapi.NewContextPropagatingJob(ctx)*/); derr != nil {
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

			cluID, _ := clusterTrx.GetID()
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
					ar := result{nil, nil, fail.Wrap(xerr, "failed to create Subnet '%s' in Network '%s'", req.Name, req.NetworkID)}
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
	case <-ctx.Done():
		cancel()
		<-chRes // wait for cleanup
		return nil, nil, fail.Wrap(ctx.Err())
	}
}

// createHostResources creates and configures hosts for the Cluster
func (instance *Cluster) createHostResources(
	ctx context.Context,
	clusterTrx clusterTransaction,
	subnet *Subnet,
	mastersDef abstract.HostSizingRequirements,
	nodesDef abstract.HostSizingRequirements,
	initialNodeCount uint,
	parameters data.Map[string, any],
	keepOnFailure bool,
) (_ fail.Error) {
	ctx, cancel := context.WithCancel(ctx)
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
				_, xerr := clusterTrx.InstallGateway(ctx, trxInstallGatewayParameters{host: primaryGateway, variables: parameters})
				return xerr
			})
			if haveSecondaryGateway {
				eg.Go(func() error {
					_, xerr := clusterTrx.InstallGateway(ctx, trxInstallGatewayParameters{host: secondaryGateway, variables: parameters})
					return xerr
				})
			}

			xerr = fail.Wrap(eg.Wait())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			masterCount, _, _, xerr := clusterTrx.determineRequiredNodes(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			// Starting from here, Delete masters if exiting with error and req.keepOnFailure is not true
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !keepOnFailure {
					// FIXME:
					masters, merr := clusterTrx.ListMasters(cleanupContextFrom(ctx))
					if merr != nil {
						_ = ferr.AddConsequence(merr)
						return
					}

					var list []machineID
					for _, mach := range masters {
						list = append(list, machineID{ID: mach.ID, Name: mach.Name})
					}

					// FIXME:
					svc, merr := instance.Service()
					if merr != nil {
						_ = ferr.AddConsequence(merr)
						return
					}

					hosts, merr := svc.ListHosts(cleanupContextFrom(ctx) /*jobapi.NewContextPropagatingJob(ctx)*/, false)
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
									_, err := clusterTrx.deleteNodeOnFailure(cleanupContextFrom(ctx) /*jobapi.NewContextPropagatingJob(ctx)*/, taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name, KeepOnFailure: keepOnFailure, Timeout: 2 * time.Minute})
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
				_, xerr := clusterTrx.createMasters(ctx, taskCreateMastersParameters{
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
				xerr := clusterTrx.configureGateway(ctx, primaryGateway)
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
					xerr := clusterTrx.configureGateway(ctx, secondaryGateway)
					if xerr != nil {
						return xerr
					}
					return nil
				})
			}
			egMas.Go(func() error {
				<-waitForMasters
				<-waitForBoth
				xerr := clusterTrx.configureMasters(ctx, parameters)
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

					nlist, derr := clusterTrx.ListNodes(cleanupContextFrom(ctx))
					if derr != nil {
						return
					}

					var list []machineID
					for _, mach := range nlist {
						list = append(list, machineID{ID: mach.ID, Name: mach.Name})
					}

					svc, merr := instance.Service()
					if merr != nil {
						_ = ferr.AddConsequence(merr)
						return
					}

					hosts, derr := svc.ListHosts(cleanupContextFrom(ctx), false)
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
									_, err := clusterTrx.deleteNodeOnFailure(cleanupContextFrom(ctx), taskDeleteNodeOnFailureParameters{ID: captured.ID, Name: captured.Name, KeepOnFailure: keepOnFailure, Timeout: 2 * time.Minute})
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
				_, xerr := clusterTrx.createNodes(ctx, taskCreateNodesParameters{
					count:         initialNodeCount,
					public:        false,
					nodesDef:      nodesDef,
					keepOnFailure: keepOnFailure,
				})
				if xerr != nil {
					return xerr
				}

				xerr = clusterTrx.configureNodes(ctx, parameters)
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
	case <-ctx.Done():
		cancel()
		<-chRes // wait for cleanup
		return fail.Wrap(ctx.Err())
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

// installGateway installs necessary components on one gateway
func (clusterTrx *clusterTransactionImpl) InstallGateway(inctx context.Context, params trxInstallGatewayParameters) (_ interface{}, _ fail.Error) {
	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	if params.host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	// variables, _ := data.FromMap(p.variables)
	variables := params.variables
	hostLabel := params.host.GetName()

	inctx, cancel := context.WithCancel(inctx)
	defer cancel()

	// FIXME: recycle concurrency.AmendID()
	if oldKey := inctx.Value("ID"); oldKey != nil {
		inctx = context.WithValue(inctx, "ID", fmt.Sprintf("%s/install/gateway/%s", oldKey, hostLabel)) // nolint
	}

	tracer := debug.NewTracer(inctx, tracing.ShouldTrace("resources.cluster"), params).WithStopwatch().Entering()
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

			svc, xerr := clusterTrx.Service()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			timings, xerr := svc.Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(inctx).Debugf("starting installation.")

			_, xerr = params.host.WaitSSHReady(inctx, timings.HostOperationTimeout())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Installs docker and docker-compose on gateway
			xerr = clusterTrx.installDocker(inctx, params.host, hostLabel, variables)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Installs dependencies as defined by Cluster Flavor (if it exists)
			xerr = clusterTrx.installNodeRequirements(inctx, clusternodetype.Gateway, params.host, hostLabel)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(inctx).Debugf("[%s] preparation successful", hostLabel)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// Regenerate ansible inventory
func (clusterTrx *clusterTransactionImpl) updateClusterAnsibleInventory(ctx context.Context) fail.Error {
	if valid.IsNull(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	logrus.WithContext(ctx).Infof("[Cluster %s] Update ansible inventory", clusterTrx.GetName())

	// Collect data
	featureAnsibleInventoryInstalled := false
	var masters []*Host
	var params = map[string]interface{}{
		"ClusterName":          "",
		"ClusterAdminUsername": "cladm",
		"ClusterAdminPassword": "",
		"PrimaryGatewayName":   fmt.Sprintf("gw-%s", clusterTrx.GetName()),
		"PrimaryGatewayIP":     "",
		"PrimaryGatewayPort":   "22",
		"SecondaryGatewayName": fmt.Sprintf("gw2-%s", clusterTrx.GetName()),
		"SecondaryGatewayIP":   "",
		"SecondaryGatewayPort": "22",
		"ClusterMasters":       rscapi.IndexedListOfClusterNodes{},
		"ClusterNodes":         rscapi.IndexedListOfClusterNodes{},
	}

	xerr := inspectClusterMetadata(ctx, clusterTrx, func(aci *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
		// Check if feature ansible is installed
		innerXErr := props.Inspect(clusterproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
			featuresV1, innerErr := lang.Cast[*propertiesv1.ClusterFeatures](p)
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
			networkV3, innerErr := lang.Cast[*propertiesv3.ClusterNetwork](p)
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
			nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
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
		return xerr
	}

	prerr := fmt.Sprintf("[Cluster %s] Update ansible inventory: ", clusterTrx.GetName())

	// Feature ansible found ?
	if !featureAnsibleInventoryInstalled {
		logrus.WithContext(ctx).Infof("%snothing to update (feature not installed)", prerr)
		return nil
	}

	// Has at least one master ?
	if len(masters) == 0 {
		logrus.WithContext(ctx).Infof("%s nothing to update (no masters in cluster)", prerr)
		return nil
	}

	tmplString, err := ansibleScripts.ReadFile("scripts/ansible_inventory.py")
	if err != nil {
		return fail.Wrap(err, "%s failed to load template 'ansible_inventory.py'", prerr)
	}

	// --------- Build ansible inventory --------------
	fileName := fmt.Sprintf("cluster-inventory-%s.py", params["Clustername"])
	tmplCmd, err := template.Parse(fileName, string(tmplString))
	if err != nil {
		return fail.Wrap(err, "%s failed to parse template 'ansible_inventory.py'", prerr)
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, params)
	if err != nil {
		return fail.Wrap(err, "%s failed to execute template 'ansible_inventory.py'", prerr)
	}

	// --------- Upload file for each master and test it (parallelized) --------------
	tg := new(errgroup.Group)
	for master := range masters {
		master := master
		logrus.WithContext(ctx).Infof("%s Update master %s", prerr, masters[master].GetName())

		tg.Go(func() error {
			return clusterTrx.updateClusterInventoryMaster(ctx, taskUpdateClusterInventoryMasterParameters{
				ctx:           ctx,
				master:        masters[master],
				inventoryData: dataBuffer.String(),
				// clusterName:   params["Clustername"].(string),
			})
		})
	}

	xerr = fail.Wrap(tg.Wait())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		if withTimeout(xerr) {
			logrus.WithContext(ctx).Warnf("%s Timeouts ansible update inventory", prerr)
		}
		return xerr
	}

	logrus.WithContext(ctx).Debugf("%s update inventory successful", prerr)

	return nil
}

// configureNodesFromList configures nodes from a list
func (clusterTrx *clusterTransactionImpl) configureNodesFromList(ctx context.Context, nodes []*propertiesv3.ClusterNode, parameters data.Map[string, any]) (ferr fail.Error) {
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	length := len(nodes)
	if length > 0 {
		eg := new(errgroup.Group)
		for i := 0; i < length; i++ {
			captured := i
			eg.Go(func() error {
				return clusterTrx.configureNode(ctx, nodes[captured], parameters)
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

// createMaster creates one master
func (clusterTrx *clusterTransactionImpl) createMaster(inctx context.Context, params any) (_ interface{}, ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if valid.IsNull(clusterTrx) {
		return nil, fail.InvalidParameterCannotBeNilError("clusterTrx")
	}
	p, err := lang.Cast[trxCreateMasterParameters](params)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	hostReq := abstract.HostRequest{}
	var xerr fail.Error
	hostReq.ResourceName, xerr = clusterTrx.BuildHostname(ctx, "master", clusternodetype.Master)
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

			sleepTime, xerr := clusterTrx.readRandomDelay(ctx)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}
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

			netCfg, xerr := clusterTrx.GetNetworkConfig(ctx)
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

			cluID, _ := clusterTrx.GetID()
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
			xerr = clusterTrx.installNodeRequirements(ctx, clusternodetype.Master, hostInstance, hostLabel)
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

// getIdentity returns the identity of the Cluster
func (clusterTrx *clusterTransactionImpl) getIdentity(ctx context.Context) (_ *abstract.Cluster, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var clusterIdentity *abstract.Cluster
	xerr := inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
		cloned, innerErr := clonable.CastedClone[*abstract.Cluster](aci)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		clusterIdentity = cloned
		return nil
	})
	return clusterIdentity, xerr
}

// GetFlavor returns the flavor of the Cluster
func (clusterTrx *clusterTransactionImpl) GetFlavor(ctx context.Context) (flavor clusterflavor.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aci, xerr := clusterTrx.getIdentity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Flavor, nil
}

// trxGetComplexity returns the complexity of the Cluster
func trxGetComplexity(ctx context.Context, clusterTrx clusterTransaction) (_ clustercomplexity.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	aci, xerr := clusterTrx.getIdentity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return 0, xerr
	}

	return aci.Complexity, nil
}

// getState returns the current state of the Cluster
// Uses the "maker" GetState
func (clusterTrx *clusterTransactionImpl) getState(inctx context.Context) (_ clusterstate.Enum, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  clusterstate.Enum
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		var (
			state  = clusterstate.Unknown
			makers clusterflavors.Makers
		)
		xerr := inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) (innerXErr fail.Error) {
			makers, innerXErr = clusterTrx.extractMakers(ctx)
			return innerXErr
		})
		if xerr != nil {
			chRes <- result{clusterstate.Unknown, xerr}
			return
		}
		if makers.GetState != nil {
			var xerr fail.Error
			state, xerr = makers.GetState(clusterTrx)
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

		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
			stateV1, innerErr := lang.Cast[*propertiesv1.ClusterState](p)
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

// ListMasters ...
func (clusterTrx *clusterTransactionImpl) ListMasters(inctx context.Context) (_ rscapi.IndexedListOfClusterNodes, _ fail.Error) {
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

// ListMasterIDs ...
func (clusterTrx *clusterTransactionImpl) ListMasterIDs(inctx context.Context) (_ data.IndexedListOfStrings, _ fail.Error) {
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

			xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
				nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
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

// ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (clusterTrx *clusterTransactionImpl) ListMasterIPs(ctx context.Context) (_ data.IndexedListOfStrings, ferr fail.Error) {
	select {
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	default:
	}

	defer fail.OnPanic(&ferr)
	emptyList := data.IndexedListOfStrings{}
	var list data.IndexedListOfStrings

	xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		list = make(data.IndexedListOfStrings, len(nodesV3.Masters))
		for _, v := range nodesV3.Masters {
			select {
			case <-ctx.Done():
				return fail.Wrap(ctx.Err())
			default:
			}

			if node, found := nodesV3.ByNumericalID[v]; found {
				list[node.NumericalID] = node.PrivateIP
			}
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return emptyList, xerr
	}

	return list, nil
}

// ListNodeIPs lists the IPs of the nodes in the Cluster
func (clusterTrx *clusterTransactionImpl) ListNodeIPs(ctx context.Context) (_ data.IndexedListOfStrings, _ fail.Error) {
	emptyList := data.IndexedListOfStrings{}
	var outlist data.IndexedListOfStrings

	xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		list := make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
		for _, v := range nodesV3.PrivateNodes {
			select {
			case <-ctx.Done():
				return fail.Wrap(ctx.Err())
			default:
			}

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
		return emptyList, xerr
	}
	return outlist, nil
}

// FindAvailableMaster finds an available master
func (clusterTrx *clusterTransactionImpl) FindAvailableMaster(ctx context.Context) (_ *Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	var master *Host

	masters, xerr := clusterTrx.ListMasters(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return nil, xerr
	}

	svc, xerr := myjob.Service()
	if xerr != nil {
		return nil, xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return nil, xerr
	}

	var lastError fail.Error
	lastError = fail.NotFoundError("no master found")
	master = nil
	for _, v := range masters {
		select {
		case <-ctx.Done():
			return nil, fail.Wrap(ctx.Err())
		default:
		}

		if v.ID == "" {
			continue
		}

		master, xerr = LoadHost(ctx, v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}

		_, xerr = master.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrTimeout:
				lastError = xerr
				continue
			default:
				return nil, xerr
			}
		}
		break
	}
	if master == nil {
		return nil, lastError
	}

	return master, nil
}

// ListNodes is the not goroutine-safe version of *Cluster.ListNodes and no parameter validation, that does the real work
func (clusterTrx *clusterTransactionImpl) ListNodes(inctx context.Context) (_ rscapi.IndexedListOfClusterNodes, _ fail.Error) {
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
				nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
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

// unsafeListNodeIDs is the real implementation of *Cluster.ListNodeIDs using metadata tranaction
func (clusterTrx *clusterTransactionImpl) ListNodeIDs(inctx context.Context) (_ data.IndexedListOfStrings, _ fail.Error) {
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

			var outlist data.IndexedListOfStrings
			xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
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

// FindAvailableNode is the real implementaton of *Cluster.FindAvailableNode using metadata transaction
func (clusterTrx *clusterTransactionImpl) FindAvailableNode(inctx context.Context) (node *Host, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type localresult struct {
		rTr  *Host
		rErr fail.Error
	}
	chRes := make(chan localresult)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ localresult, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			myjob, xerr := jobapi.FromContext(ctx)
			if xerr != nil {
				return localresult{nil, xerr}, xerr
			}

			svc, xerr := myjob.Service()
			if xerr != nil {
				return localresult{nil, xerr}, xerr
			}

			timings, xerr := svc.Timings()
			if xerr != nil {
				return localresult{nil, xerr}, xerr
			}

			list, xerr := clusterTrx.ListNodes(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{nil, xerr}, xerr
			}

			node = nil
			found := false
			for _, v := range list {
				node, xerr = LoadHost(ctx, v.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return localresult{nil, xerr}, xerr
				}

				_, xerr = node.WaitSSHReady(ctx, timings.SSHConnectionTimeout())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *retry.ErrTimeout:
						continue
					default:
						return localresult{nil, xerr}, xerr
					}
				}
				found = true
				break
			}
			if !found {
				ar := localresult{nil, fail.NotAvailableError("failed to find available node")}
				return ar, ar.rErr
			}

			return localresult{node, nil}, nil
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

// getGatewayIDs ...
func (clusterTrx *clusterTransactionImpl) getGatewayIDs(ctx context.Context) ([]string, fail.Error) {
	var gateways []string

	xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NetworkV3, func(networkV3 *propertiesv3.ClusterNetwork) fail.Error {
		if networkV3.GatewayID != "" {
			gateways = append(gateways, networkV3.GatewayID)
		}

		if networkV3.SecondaryGatewayID != "" {
			gateways = append(gateways, networkV3.SecondaryGatewayID)
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return gateways, nil
}

// joinNodesFromList makes nodes from a list join the Cluster
func (clusterTrx *clusterTransactionImpl) joinNodesFromList(ctx context.Context, nodes []*propertiesv3.ClusterNode) fail.Error {
	logrus.WithContext(ctx).Debugf("Joining nodes to Cluster...")

	// Joins to Cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending on the Cluster Flavor)
	var makers clusterflavors.Makers
	xerr := inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) (innerXErr fail.Error) {
		makers, innerXErr = clusterTrx.extractMakers(ctx)
		return innerXErr
	})
	if xerr != nil {
		return xerr
	}
	if makers.JoinNodeToCluster != nil {
		for _, v := range nodes {
			hostInstance, xerr := LoadHost(ctx, v.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = makers.JoinNodeToCluster(clusterTrx, hostInstance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// leaveNodesFromList makes nodes from a list leave the Cluster
func (clusterTrx *clusterTransactionImpl) leaveNodesFromList(ctx context.Context, hosts []*Host, selectedMaster *Host) (ferr fail.Error) {
	if selectedMaster == nil {
		return fail.InvalidParameterCannotBeNilError("selectedMaster")
	}

	logrus.WithContext(ctx).Debugf("Instructing nodes to leave Cluster...")

	// Un-joins from Cluster are done sequentially, experience shows too many (un)join at the same time
	// may fail (depending on the Cluster Flavor)
	makers, xerr := clusterTrx.extractMakers(ctx)
	if xerr != nil {
		return xerr
	}

	if makers.LeaveNodeFromCluster != nil {
		var xerr fail.Error
		for _, node := range hosts {
			xerr = makers.LeaveNodeFromCluster(ctx, clusterTrx, node, selectedMaster)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// BuildHostname builds a unique hostname in the Cluster
func (clusterTrx *clusterTransactionImpl) BuildHostname(ctx context.Context, core string, nodeType clusternodetype.Enum) (_ string, _ fail.Error) {
	var index int
	xerr := alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
		nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		switch nodeType {
		case clusternodetype.Node:
			nodesV3.PrivateLastIndex++
			index = nodesV3.PrivateLastIndex
		case clusternodetype.Master:
			nodesV3.MasterLastIndex++
			index = nodesV3.MasterLastIndex
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}
	return clusterTrx.GetName() + "-" + core + "-" + strconv.Itoa(index), nil
}

// GetNetworkConfig returns subnet configuration of the Cluster
func (clusterTrx *clusterTransactionImpl) GetNetworkConfig(ctx context.Context) (config *propertiesv3.ClusterNetwork, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NetworkV3, func(networkV3 *propertiesv3.ClusterNetwork) fail.Error {
		config = networkV3
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if config == nil {
		return nil, fail.InconsistentError("config should NOT be nil")
	}

	return config, nil
}

// Bootstrap (re)connects controller with the appropriate Makers
func (clusterTrx *clusterTransactionImpl) Bootstrap(ctx context.Context, flavor clusterflavor.Enum) (ferr fail.Error) {
	return alterClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
		local, err := lang.Cast[*extraInAbstract](aci.Local)
		if err != nil {
			return fail.Wrap(err)
		}

		switch flavor {
		case clusterflavor.BOH:
			local.Makers = boh.Makers
		case clusterflavor.K8S:
			local.Makers = k8s.Makers
		default:
			return fail.InvalidParameterError("unknown Cluster Flavor '%d'", flavor)
		}

		var index uint8
		if flavor == clusterflavor.K8S {
			index++
			local.InstallMethods.Store(index, installmethod.Helm)
		}

		index++
		local.InstallMethods.Store(index, installmethod.Bash)
		index++
		local.InstallMethods.Store(index, installmethod.None)
		return nil
	})
}

// installDocker installs docker and docker-compose
func (clusterTrx *clusterTransactionImpl) installDocker(inctx context.Context, host *Host, hostLabel string, params data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		dockerDisabled := false
		xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
		if xerr != nil {
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			chRes <- result{xerr}
			return
		}

		if dockerDisabled {
			chRes <- result{nil}
			return
		}

		// uses NewFeature() to let a chance to the user to use its own docker feature
		feat, xerr := NewFeature(ctx, "docker")
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		// params, _ := data.FromMap(params)
		r, xerr := feat.Add(ctx, host, params)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		reason := false
		if !r.IsSuccessful() {
			keys, xerr := r.Keys()
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
			for _, k := range keys {
				rk, xerr := r.PayloadOf(k)
				if xerr != nil {
					chRes <- result{xerr}
					return
				}

				if rk != nil && !rk.IsSuccessful() {
					msg := rk.ErrorMessage()
					if len(msg) == 0 {
						logrus.WithContext(ctx).Warnf("This is a false warning for %s !!: %s", k, msg)
					} else {
						reason = true
						logrus.WithContext(ctx).Warnf("This failed: %s with %s", k, spew.Sdump(rk))
					}
				}
			}

			if reason {
				chRes <- result{fail.NewError("[%s] failed to add feature 'docker' on host '%s': %s", hostLabel, host.GetName(), r.ErrorMessage())}
				return
			}
		}

		xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			featuresV1.Installed[feat.GetName()] = &propertiesv1.ClusterInstalledFeature{
				Name: feat.GetName(),
			}
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			chRes <- result{xerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[%s] feature 'docker' addition successful.", hostLabel)
		chRes <- result{nil}
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

// ExecuteScript executes the script template with the parameters on target Host
func (clusterTrx *clusterTransactionImpl) ExecuteScript(inctx context.Context, tmplName string, variables data.Map[string, any], host *Host) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if valid.IsNil(clusterTrx) {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if inctx == nil {
		return invalid, "", "", fail.InvalidParameterCannotBeNilError("inctx")
	}
	if tmplName == "" {
		return invalid, "", "", fail.InvalidParameterError("tmplName", "cannot be empty string")
	}
	if host == nil {
		return invalid, "", "", fail.InvalidParameterCannotBeNilError("host")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		a    int
		b    string
		c    string
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		svc, xerr := clusterTrx.Service()
		if xerr != nil {
			chRes <- result{invalid, "", "", xerr}
			return
		}

		timings, xerr := svc.Timings()
		if xerr != nil {
			chRes <- result{invalid, "", "", xerr}
			return
		}

		// Configures reserved_BashLibrary template var
		bashLibraryDefinition, xerr := system.BuildBashLibraryDefinition(timings)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{invalid, "", "", xerr}
			return
		}

		bashLibraryVariables, xerr := bashLibraryDefinition.ToMap()
		if xerr != nil {
			chRes <- result{invalid, "", "", xerr}
			return
		}

		variables["Revision"] = system.REV

		if len(variables) > 64*1024 {
			chRes <- result{invalid, "", "", fail.OverflowError(nil, 64*1024, "variables, value too large")}
			return
		}

		if len(bashLibraryVariables) > 64*1024 {
			chRes <- result{invalid, "", "", fail.OverflowError(nil, 64*1024, "bashLibraryVariables, value too large")}
			return
		}

		var fisize = uint64(len(variables) + len(bashLibraryVariables))
		finalVariables := make(data.Map[string, any], fisize)
		for k, v := range variables {
			finalVariables[k] = v
		}
		for k, v := range bashLibraryVariables {
			finalVariables[k] = v
		}

		script, path, xerr := realizeTemplate("internal/clusterflavors/scripts/"+tmplName, finalVariables, tmplName)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{invalid, "", "", fail.Wrap(xerr, "failed to realize template '%s'", tmplName)}
			return
		}

		hidesOutput := strings.Contains(script, "set +x\n")
		if hidesOutput {
			script = strings.Replace(script, "set +x\n", "\n", 1)
			script = strings.Replace(script, "exec 2>&1\n", "exec 2>&7\n", 1)
		}

		// Uploads the script into remote file
		rfcItem := Item{Remote: path}
		xerr = rfcItem.UploadString(ctx, script, host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{invalid, "", "", fail.Wrap(xerr, "failed to upload %s to %s", tmplName, host.GetName())}
			return
		}

		// executes remote file
		var cmd string
		if hidesOutput {
			cmd = fmt.Sprintf("sudo -- bash -c 'sync; chmod u+rx %s; captf=$(mktemp); bash -c \"BASH_XTRACEFD=7 %s 7>$captf 2>&7\"; rc=${PIPESTATUS}; cat $captf; rm $captf; exit ${rc}'", path, path)
		} else {
			cmd = fmt.Sprintf("sudo -- bash -c 'sync; chmod u+rx %s; bash -c %s; exit ${PIPESTATUS}'", path, path)
		}

		// recover current timeout settings
		connectionTimeout := timings.ConnectionTimeout()
		executionTimeout := timings.HostLongOperationTimeout()

		// If is 126, try again 6 times, if not return the error
		rounds := 10
		for {
			rc, stdout, stderr, err := host.Run(ctx, cmd, outputs.COLLECT, connectionTimeout, executionTimeout)
			if rc == 126 {
				logrus.WithContext(ctx).Debugf("Text busy happened")
			}

			if rc != 126 || rounds == 0 {
				if rc == 126 {
					logrus.WithContext(ctx).Warnf("Text busy killed the script")
				}
				chRes <- result{rc, stdout, stderr, err}
				return
			}

			if !(strings.Contains(stdout, "bad interpreter") || strings.Contains(stderr, "bad interpreter")) {
				if err != nil {
					if !strings.Contains(err.Error(), "bad interpreter") {
						chRes <- result{rc, stdout, stderr, err}
						return
					}
				} else {
					chRes <- result{rc, stdout, stderr, nil}
					return
				}
			}

			rounds--
			time.Sleep(timings.SmallDelay())
		}
	}()

	select {
	case res := <-chRes:
		return res.a, res.b, res.c, res.rErr
	case <-ctx.Done():
		return invalid, "", "", fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return invalid, "", "", fail.Wrap(inctx.Err())
	}
}

// installNodeRequirements ...
func (clusterTrx *clusterTransactionImpl) installNodeRequirements(inctx context.Context, nodeType clusternodetype.Enum, host *Host, hostLabel string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		netCfg, xerr := clusterTrx.GetNetworkConfig(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if netCfg == nil {
			chRes <- result{fail.InconsistentError("network cfg for cluster is nil")}
			return
		}

		svc, xerr := clusterTrx.Service()
		if xerr != nil {
			chRes <- result{fail.InconsistentError("network cfg for cluster is nil")}
			return
		}

		timings, xerr := svc.Timings()
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		params := data.NewMap[string, any]()
		if nodeType == clusternodetype.Master {
			tp, xerr := svc.TenantParameters()
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
			content := map[string]any{
				"tenants": []map[string]any{tp},
			}
			jsoned, err := json.MarshalIndent(content, "", "    ")
			err = debug.InjectPlannedError(err)
			if err != nil {
				chRes <- result{fail.Wrap(err)}
				return
			}
			params["reserved_TenantJSON"] = string(jsoned)

			// Finds the MetadataFolder where the current binary resides
			var (
				binaryDir string
				path      string
			)
			exe, _ := os.Executable()
			if exe != "" {
				binaryDir = filepath.Dir(exe)
			}

			_, _ = binaryDir, path
			/* FIXME: VPL: disable binaries upload until proper solution (does not work with different architectures between client and remote),
			               probably a feature safescale-binaries to build SafeScale from source...
					// Uploads safescale binary
					if binaryDir != "" {
						path = binaryDir + "/safescale"
					}
					if path == "" {
						path, err = exec.LookPath("safescale")
						err = debug.InjectPlannedError((err)
			if err != nil {
							return fail.Wrap(err, "failed to find local binary 'safescale', make sure its path is in environment variable PATH")
						}
					}

					retcode, stdout, stderr, xerr := host.Push(task, path, "/opt/safescale/bin/safescale", "root:root", "0755", temporal.ExecutionTimeout())
					if xerr != nil {
						return fail.Wrap(xerr, "failed to upload 'safescale' binary")
					}
					if retcode != 0 {
						output := stdout
						if output != "" && stderr != "" {
							output += "\n" + stderr
						} else if stderr != "" {
							output = stderr
						}
						return fail.NewError("failed to copy safescale binary to '%s:/opt/safescale/bin/safescale': retcode=%d, output=%s", host.GetName(), retcode, output)
					}

					// Uploads safescaled binary
					path = ""
					if binaryDir != "" {
						path = binaryDir + "/safescaled"
					}
					if path == "" {
						path, err = exec.LookPath("safescaled")
						err = debug.InjectPlannedError((err)
			if err != nil {
							return fail.Wrap(err, "failed to find local binary 'safescaled', make sure its path is in environment variable PATH")
						}
					}
					if retcode, stdout, stderr, xerr = host.Push(task, path, "/opt/safescale/bin/safescaled", "root:root", "0755", temporal.ExecutionTimeout()); xerr != nil {
						return fail.Wrap(xerr, "failed to submit content of 'safescaled' binary to host '%s'", host.GetName())
					}
					if retcode != 0 {
						output := stdout
						if output != "" && stderr != "" {
							output += "\n" + stderr
						} else if stderr != "" {
							output = stderr
						}
						return fail.NewError("failed to copy safescaled binary to '%s:/opt/safescale/bin/safescaled': retcode=%d, output=%s", host.GetName(), retcode, output)
					}
			*/
			// Optionally propagate SAFESCALE_METADATA_SUFFIX env vars to master
			if suffix := os.Getenv("SAFESCALE_METADATA_SUFFIX"); suffix != "" {
				cmdTmpl := "sudo sed -i '/^SAFESCALE_METADATA_SUFFIX=/{h;s/=.*/=%s/};${x;/^$/{s//SAFESCALE_METADATA_SUFFIX=%s/;H};x}' /etc/environment"
				cmd := fmt.Sprintf(cmdTmpl, suffix, suffix)
				retcode, stdout, stderr, xerr := host.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), 2*timings.HostLongOperationTimeout())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{fail.Wrap(xerr, "failed to submit content of SAFESCALE_METADATA_SUFFIX to Host '%s'", host.GetName())}
					return
				}
				if retcode != 0 {
					output := stdout
					if output != "" && stderr != "" {
						output += "\n" + stderr
					} else if stderr != "" {
						output = stderr
					}
					msg := fmt.Sprintf("failed to copy content of SAFESCALE_METADATA_SUFFIX to Host '%s': %s", host.GetName(), output)
					chRes <- result{fail.NewError(strprocess.Capitalize(msg))}
					return
				}
			}
		}

		// FIXME: reuse ComplementFeatureParameters?
		var dnsServers []string
		cfg, xerr := svc.ConfigurationOptions()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		dnsServers = cfg.DNSServers
		identity, xerr := clusterTrx.getIdentity(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		params["ClusterName"] = identity.Name
		params["DNSServerIPs"] = dnsServers
		params["MasterIPs"], xerr = clusterTrx.ListMasterIPs(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		params["ClusterAdminUsername"] = "cladm"
		params["ClusterAdminPassword"] = identity.AdminPassword
		params["DefaultRouteIP"] = netCfg.DefaultRouteIP
		params["EndpointIP"] = netCfg.EndpointIP
		params["IPRanges"] = netCfg.CIDR
		params["SSHPublicKey"] = identity.Keypair.PublicKey
		params["SSHPrivateKey"] = identity.Keypair.PrivateKey

		retcode, stdout, stderr, xerr := clusterTrx.ExecuteScript(ctx, "node_install_requirements.sh", params, host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{fail.Wrap(xerr, "[%s] system dependencies installation failed", hostLabel)}
			return
		}
		if retcode != 0 {
			xerr = fail.ExecutionError(nil, "failed to install common node dependencies")
			xerr.Annotate("retcode", retcode).Annotate("stdout", stdout).Annotate("stderr", stderr)
			chRes <- result{xerr}
			return
		}

		logrus.WithContext(ctx).Debugf("[%s] system dependencies installation successful.", hostLabel)
		chRes <- result{nil}
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

// realizeTemplate generates a file from box template with variables updated
func realizeTemplate(tmplName string, adata map[string]interface{}, fileName string) (string, string, fail.Error) {
	tmplString, err := clusterFlavorScripts.ReadFile(tmplName)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to load template")
	}

	tmplCmd, err := template.Parse(fileName, string(tmplString))
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to parse template")
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Option("missingkey=error").Execute(dataBuffer, adata)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to execute  template")
	}

	cmd := dataBuffer.String()
	remotePath := utils.TempFolder + "/" + fileName

	return cmd, remotePath, nil
}

type taskCreateNodeParameters struct {
	index         uint
	nodeDef       abstract.HostSizingRequirements
	timeout       time.Duration // Not used currently
	keepOnFailure bool
}

// createNode creates a node in the Cluster
func (clusterTrx *clusterTransactionImpl) createNode(inctx context.Context, params any) (_ interface{}, _ fail.Error) {
	var xerr fail.Error
	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	p, ok := params.(taskCreateNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be type 'taskCreateNodeParameters'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, xerr = clusterTrx.BuildHostname(ctx, "node", clusternodetype.Node)
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

			sleepTime, xerr := clusterTrx.readRandomDelay(ctx)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

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

			netCfg, xerr := clusterTrx.GetNetworkConfig(ctx)
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
			defer subnetTrx.TerminateFromError(ctx, &ferr)

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

			// here is the actual creation of the machine
			cluID, _ := clusterTrx.GetID()
			_, xerr = hostInstance.Create(ctx, hostReq, p.nodeDef, map[string]string{
				"type":      "node",
				"clusterID": cluID,
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure && hostInstance != nil {
					ctx := cleanupContextFrom(ctx)
					derr := hostInstance.Delete(ctx)
					if derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Host is considered as a successful deletion, continue
							debug.IgnoreErrorWithContext(ctx, derr)
						default:
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Host '%s'", ActionFromError(ferr), hostInstance.GetName()))
						}
					}
				}
			}()

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
			// 			Delete(nodesV3.PrivateNodeByName, hostInstance.GetName())
			// 			Delete(nodesV3.PrivateNodeByID, hid)
			// 			return nil
			// 		})
			// 		if derr != nil {
			// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove node '%s' from metadata of cluster '%s'", hostInstance.GetName(), instance.GetName()))
			// 		}
			// 	}
			// }()

			logrus.WithContext(ctx).Debugf(tracer.TraceMessage("[%s] Host installing node requirements...", hostLabel))

			xerr = clusterTrx.installNodeRequirements(ctx, clusternodetype.Node, hostInstance, hostLabel)
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

// configureNodes configures nodes
func (clusterTrx *clusterTransactionImpl) configureNodes(ctx context.Context, variables data.Map[string, any]) (ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()

	defer fail.OnPanic(&ferr)

	list, xerr := clusterTrx.ListNodes(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	clusterName := clusterTrx.GetName()
	if len(list) == 0 {
		return fail.NewError("[Cluster %s] node list cannot be empty.", clusterName)
	}
	for _, node := range list {
		if node.ID == "" {
			return fail.InvalidRequestError("cluster nodes cannot contain items with empty ID")
		}
	}

	logrus.WithContext(ctx).Debugf("[Cluster %s] configuring nodes...", clusterTrx.GetName())

	type cfgRes struct {
		who  string
		what interface{}
	}

	resCh := make(chan cfgRes, len(list))
	eg := new(errgroup.Group)
	for _, node := range list {
		capturedNode := node
		eg.Go(func() error {
			xerr := clusterTrx.configureNode(ctx, capturedNode, variables)
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
				what: capturedNode.Name,
			}

			return nil
		})
	}
	xerr = fail.Wrap(eg.Wait())
	if xerr != nil {
		return xerr
	}

	tgMap := make(map[string]interface{})
	close(resCh)
	for v := range resCh {
		tgMap[v.who] = v.what
	}

	logrus.WithContext(ctx).Debugf("[Cluster %s] nodes configuration successful: %v", clusterName, tgMap)
	return nil

}

// configureNode configure one node
func (clusterTrx *clusterTransactionImpl) configureNode(ctx context.Context, node *propertiesv3.ClusterNode, variables data.Map[string, any]) (ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if node == nil {
		return fail.InvalidParameterCannotBeNilError("params.Node")
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "('%s')", node.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	defer fail.OnPanic(&ferr)

	hostLabel := fmt.Sprintf("node (%s)", node.Name)
	logrus.WithContext(ctx).Debugf("[%s] starting configuration...", hostLabel)

	hostInstance, xerr := LoadHost(ctx, node.ID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		default:
			return fail.Wrap(xerr, "failed to get metadata of node '%s'", node.Name)
		}
	}

	does, xerr := hostInstance.Exists(ctx)
	if xerr != nil {
		return xerr
	}

	if !does {
		return nil
	}

	// Docker and docker-compose installation is mandatory on all nodes
	xerr = clusterTrx.installDocker(ctx, hostInstance, hostLabel, variables)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Now configures node specifically for Cluster flavor
	makers, xerr := clusterTrx.extractMakers(ctx)
	if xerr != nil {
		return xerr
	}

	if makers.ConfigureNode != nil {
		xerr = makers.ConfigureNode(clusterTrx, hostInstance)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.WithContext(ctx).Error(xerr.Error())
			return xerr
		}
	}

	logrus.WithContext(ctx).Debugf("[%s] configuration successful.", hostLabel)
	return nil
}

// taskConfigureGateway prepares one gateway
func (clusterTrx *clusterTransactionImpl) configureGateway(ctx context.Context, host *Host) (ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNull(host) {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	hostLabel := host.GetName()
	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/configure/gateway/%s", oldKey, hostLabel)) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "('%s')", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	defer fail.OnPanic(&ferr)

	logrus.WithContext(ctx).Debugf("starting configuration of gateway '%s'", hostLabel)

	makers, xerr := clusterTrx.extractMakers(ctx)
	if xerr != nil {
		return xerr
	}

	if makers.ConfigureGateway != nil {
		xerr := makers.ConfigureGateway(clusterTrx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	logrus.WithContext(ctx).Debugf("[%s] configuration successful in [%s].", hostLabel, tracer.Stopwatch().String())
	return nil
}

type taskCreateMastersParameters struct {
	count         uint
	mastersDef    abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateMasters creates masters
func (clusterTrx *clusterTransactionImpl) createMasters(inctx context.Context, params taskCreateMastersParameters) (_ interface{}, _ fail.Error) {
	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if params.count < 1 {
		return nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	if params.count == 0 {
		logrus.WithContext(ctx).Debugf("[Cluster %s] no masters to create.", clusterTrx.GetName())
		return nil, nil
	}

	type localresult struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan localresult)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ localresult, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc, xerr := clusterTrx.Service()
			if xerr != nil {
				return localresult{nil, xerr}, xerr
			}

			timings, xerr := svc.Timings()
			if xerr != nil {
				return localresult{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("Creating %d master%s...", params.count, strprocess.Plural(params.count))

			timeout := time.Duration(params.count) * timings.HostCreationTimeout() // FIXME: OPP This became the timeout for the whole cluster creation....
			winSize := 8
			cfg, xerr := svc.ConfigurationOptions()
			if xerr == nil {
				winSize = cfg.ConcurrentMachineCreationLimit
			}

			var listMasters []StdResult
			masterChan := make(chan StdResult, params.count)
			err := runWindow(ctx, params.count, uint(math.Min(float64(params.count), float64(winSize))), timeout, masterChan, clusterTrx.createMaster, trxCreateMasterParameters{
				masterDef:     params.mastersDef,
				timeout:       timings.HostCreationTimeout(),
				keepOnFailure: params.keepOnFailure,
			})
			if err != nil {
				close(masterChan)
				return localresult{nil, fail.Wrap(err)}, fail.Wrap(err)
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
			return localresult{listMasters, nil}, nil
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

// taskConfigureMasters configure masters
func (clusterTrx *clusterTransactionImpl) configureMasters(inctx context.Context, variables data.Map[string, any]) fail.Error {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()

	chRes := make(chan fail.Error)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			clusterName := clusterTrx.GetName()
			logrus.WithContext(ctx).Debugf("[Cluster %s] Configuring masters...", clusterName)

			masters, xerr := clusterTrx.ListMasters(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
			if len(masters) == 0 {
				return fail.NewError("[Cluster %s] master list cannot be empty.", clusterName)
			}

			for _, master := range masters {
				if master.ID == "" {
					return fail.InvalidParameterError("masters", "cannot contain items with empty ID")
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

					xerr = clusterTrx.configureMaster(ctx, host, variables)
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
				return xerr
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] masters configuration successful", clusterName)
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
		cancel()
		<-chRes
		return fail.Wrap(inctx.Err())
	}
}

// configureMaster configures one master
func (clusterTrx *clusterTransactionImpl) configureMaster(ctx context.Context, host *Host, variables data.Map[string, any]) (ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNull(host) {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	hostName := host.GetName()
	defer func() {
		if ferr != nil {
			ferr = fail.Wrap(ferr, "failed to configure master '%s'", hostName)
		}
	}()
	defer fail.OnPanic(&ferr)

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/configure/master/%s", oldKey, hostName)) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "('%s')", hostName).WithStopwatch().Entering()
	defer tracer.Exiting()

	started := time.Now()
	logrus.WithContext(ctx).Debugf("starting configuration of master '%s'...", hostName)

	does, xerr := host.Exists(ctx)
	if xerr != nil {
		return xerr
	}

	if !does {
		return nil
	}

	// install docker feature (including docker-compose)
	hostLabel := fmt.Sprintf("master (%s)", hostName)
	xerr = clusterTrx.installDocker(ctx, host, hostLabel, variables)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Configure master for flavor
	makers, xerr := clusterTrx.extractMakers(ctx)
	if xerr != nil {
		return xerr
	}

	if makers.ConfigureMaster != nil {
		xerr = makers.ConfigureMaster(clusterTrx, host)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		logrus.WithContext(ctx).Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
	}

	return nil
}

type taskCreateNodesParameters struct {
	count         uint
	public        bool
	nodesDef      abstract.HostSizingRequirements
	keepOnFailure bool
}

// createNodes creates nodes
func (clusterTrx *clusterTransactionImpl) createNodes(inctx context.Context, params taskCreateNodesParameters) (_ any, _ fail.Error) {
	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	// validate params
	if params.count < 1 {
		return nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d, %v)", params.count, params.public).WithStopwatch().Entering()
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

			svc, xerr := clusterTrx.Service()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}
			timings, xerr := svc.Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("Creating %d node%s...", params.count, strprocess.Plural(params.count))

			timeout := time.Duration(params.count) * timings.HostCreationTimeout()

			winSize := 8
			if cfg, xerr := svc.ConfigurationOptions(); xerr == nil {
				winSize = cfg.ConcurrentMachineCreationLimit
			}

			var listNodes []StdResult
			nodesChan := make(chan StdResult, params.count)

			err := runWindow(ctx, params.count, uint(math.Min(float64(params.count), float64(winSize))), timeout, nodesChan, clusterTrx.createNode, taskCreateNodeParameters{
				nodeDef:       params.nodesDef,
				timeout:       timings.HostOperationTimeout(),
				keepOnFailure: params.keepOnFailure,
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
					_, xerr = clusterTrx.deleteNodeWithContext(ctx, v.Content.(*propertiesv3.ClusterNode), nil)
					debug.IgnoreErrorWithContext(ctx, xerr)
					continue
				}
				listNodes = append(listNodes, v)
			}

			logrus.WithContext(ctx).Debugf("%d node%s creation successful.", params.count, strprocess.Plural(params.count))
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

// configureCluster ...
// params contains a data.Map with primary and secondary getGateway hosts
func (clusterTrx *clusterTransactionImpl) configureCluster(inctx context.Context, req abstract.ClusterRequest) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
	defer tracer.Exiting()

	logrus.WithContext(ctx).Infof("[Cluster %s] configuring Cluster...", clusterTrx.GetName())
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			logrus.WithContext(ctx).Errorf("[Cluster %s] configuration failed: %s", clusterTrx.GetName(), ferr.Error())
		} else {
			logrus.WithContext(ctx).Infof("[Cluster %s] configuration successful.", clusterTrx.GetName())
		}
	}()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		// FIXME: OPP This should use instance.AddFeature instead

		// Install reverse-proxy feature on Cluster (gateways)
		parameters := ExtractFeatureParameters(req.FeatureParameters)
		xerr := clusterTrx.installReverseProxy(ctx, parameters)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		// Install remote-desktop feature on Cluster (all masters)
		xerr = clusterTrx.installRemoteDesktop(ctx, parameters)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			// Break execution flow only if the Feature cannot be run (file transfer, Host unreachable, ...), not if it ran but has failed
			if annotation, found := xerr.Annotation("ran_but_failed"); !found || !annotation.(bool) {
				chRes <- result{xerr}
				return
			}
		}

		// Install ansible feature on Cluster (all masters)
		xerr = clusterTrx.installAnsible(ctx, parameters)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		// configure what has to be done Cluster-wide
		makers, xerr := clusterTrx.extractMakers(ctx)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}
		internal.IncrementExpVar("cluster.cache.hit")
		if makers.ConfigureCluster != nil {
			chRes <- result{makers.ConfigureCluster(ctx, clusterTrx, parameters)}
			return
		}

		chRes <- result{nil}
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

// determineRequiredNodes ...
func (clusterTrx *clusterTransactionImpl) determineRequiredNodes(ctx context.Context) (uint, uint, uint, fail.Error) {
	makers, xerr := clusterTrx.extractMakers(ctx)
	if xerr != nil {
		return 0, 0, 0, xerr
	}

	if makers.MinimumRequiredServers != nil {
		g, m, n, xerr := makers.MinimumRequiredServers(func() *abstract.Cluster { out, _ := clusterTrx.getIdentity(ctx); return out }())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return 0, 0, 0, xerr
		}

		return g, m, n, nil
	}

	return 0, 0, 0, nil
}

// extractMakers returns the Makers store in abstract.Cluster local data
func (clusterTrx *clusterTransactionImpl) extractMakers(ctx context.Context) (clusterflavors.Makers, fail.Error) {
	var makers clusterflavors.Makers
	xerr := inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
		local, err := lang.Cast[*extraInAbstract](aci.Local)
		if err != nil {
			return fail.Wrap(err)
		}

		makers = local.Makers
		return nil
	})
	return makers, xerr
}

// determineSizingRequirements calculates the sizings needed for the hosts of the Cluster
func (clusterTrx *clusterTransactionImpl) determineSizingRequirements(inctx context.Context, req abstract.ClusterRequest) (
	_ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, _ *abstract.HostSizingRequirements, xerr fail.Error,
) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type localresult struct {
		aa   *abstract.HostSizingRequirements
		ab   *abstract.HostSizingRequirements
		ac   *abstract.HostSizingRequirements
		rErr fail.Error
	}
	chRes := make(chan localresult)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ localresult, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var (
				gatewaysDefault     *abstract.HostSizingRequirements
				mastersDefault      *abstract.HostSizingRequirements
				nodesDefault        *abstract.HostSizingRequirements
				imageQuery, imageID string
			)

			svc, xerr := clusterTrx.Service()
			if xerr != nil {
				return localresult{nil, nil, nil, xerr}, xerr
			}

			// Determine default image
			imageQuery = req.NodesDef.Image
			if imageQuery == "" {
				cfg, xerr := svc.ConfigurationOptions()
				if xerr != nil {
					xerr := fail.Wrap(xerr, "failed to get configuration options")
					return localresult{nil, nil, nil, xerr}, xerr
				}
				imageQuery = cfg.DefaultImage
			}
			makers, xerr := clusterTrx.extractMakers(ctx)
			if xerr != nil {
				return localresult{nil, nil, nil, xerr}, xerr
			}

			if imageQuery == "" && makers.DefaultImage != nil {
				imageQuery = makers.DefaultImage(clusterTrx)
			}
			if imageQuery == "" {
				imageQuery = consts.DEFAULTOS
			}

			_, imageID, xerr = determineImageID(ctx, svc, imageQuery)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{nil, nil, nil, xerr}, xerr
			}

			// Determine getGateway sizing
			if makers.DefaultGatewaySizing != nil {
				gatewaysDefault = complementSizingRequirements(nil, makers.DefaultGatewaySizing(clusterTrx))
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
						return localresult{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr := svc.FindTemplateBySizing(ctx, *gatewaysDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{nil, nil, nil, xerr}, xerr
			}

			gatewaysDef.Template = tmpl.ID

			// Determine master sizing
			if makers.DefaultMasterSizing != nil {
				mastersDefault = complementSizingRequirements(nil, makers.DefaultMasterSizing(clusterTrx))
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
						return localresult{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr = svc.FindTemplateBySizing(ctx, *mastersDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{nil, nil, nil, xerr}, xerr
			}

			mastersDef.Template = tmpl.ID

			// Determine node sizing
			if makers.DefaultNodeSizing != nil {
				nodesDefault = complementSizingRequirements(nil, makers.DefaultNodeSizing(clusterTrx))
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
						return localresult{nil, nil, nil, xerr}, xerr
					}
				}
			}

			tmpl, xerr = svc.FindTemplateBySizing(ctx, *nodesDef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{nil, nil, nil, xerr}, xerr
			}
			nodesDef.Template = tmpl.ID

			// Updates property
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.DefaultsV2, func(defaultsV2 *propertiesv2.ClusterDefaults) fail.Error { // nolint
				defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*gatewaysDef)
				defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*mastersDef)
				defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*nodesDef)
				defaultsV2.Image = imageQuery
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return localresult{nil, nil, nil, xerr}, xerr
			}

			return localresult{gatewaysDef, mastersDef, nodesDef, nil}, nil
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

// ExtractNetworkingInfo returns the ID of the network from properties, taking care of ascending compatibility
func (clusterTrx *clusterTransactionImpl) ExtractNetworkingInfo(ctx context.Context) (networkInstance *Network, deleteNetwork bool, subnetInstance *Subnet, ferr fail.Error) {
	networkInstance, subnetInstance = nil, nil
	deleteNetwork = false

	xerr := inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NetworkV3, func(networkV3 *propertiesv3.ClusterNetwork) (innerXErr fail.Error) {
		if networkV3.SubnetID != "" {
			if subnetInstance, innerXErr = LoadSubnet(ctx, networkV3.NetworkID, networkV3.SubnetID); innerXErr != nil {
				return innerXErr
			}
		}

		if networkV3.NetworkID != "" {
			networkInstance, innerXErr = LoadNetwork(ctx, networkV3.NetworkID)
			if innerXErr != nil {
				return innerXErr
			}
			deleteNetwork = networkV3.CreatedNetwork
		}
		if networkV3.SubnetID != "" {
			subnetInstance, innerXErr = LoadSubnet(ctx, networkV3.NetworkID, networkV3.SubnetID)
			if innerXErr != nil {
				return innerXErr
			}
			if networkInstance == nil {
				networkInstance, innerXErr = subnetInstance.InspectNetwork(ctx)
				if innerXErr != nil {
					return innerXErr
				}
			}
			deleteNetwork = networkV3.CreatedNetwork
		}

		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, deleteNetwork, nil, xerr
	}

	return networkInstance, deleteNetwork, subnetInstance, nil
}

// Delete does the work to Delete Cluster
func (clusterTrx *clusterTransactionImpl) Delete(inctx context.Context) (_ fail.Error) {
	if valid.IsNil(clusterTrx) {
		xerr := fail.InvalidInstanceError()
		return xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type localresult struct {
		rErr fail.Error
	}
	chRes := make(chan localresult)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ localresult, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var cleaningErrors []error

			// Special treatment for cluster state, it must be updated, so we need to first rollback changes then alter state followed by a commit
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					derr := clusterTrx.Rollback(ctx)
					if derr != nil {
						_ = ferr.AddConsequence(derr)
					}

					ctx := jobapi.NewContextPropagatingJob(inctx)
					derr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.StateV1, func(stateV1 *propertiesv1.ClusterState) fail.Error {
						stateV1.State = clusterstate.Degraded
						return nil
					})
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to set Cluster state to DEGRADED", ActionFromError(ferr)))
					} else {
						derr = clusterTrx.Commit(ctx)
						if derr != nil {
							_ = ferr.AddConsequence(derr)
						}
					}
				}
			}()

			var (
				all            map[uint]*propertiesv3.ClusterNode
				nodes, masters []uint
			)
			// Mark the Cluster as Removed and get nodes from properties
			xerr := alterClusterMetadataProperties(ctx, clusterTrx, func(props *serialize.JSONProperties) fail.Error {
				// Updates Cluster state to mark Cluster as Removing
				innerXErr := props.Alter(clusterproperty.StateV1, func(p clonable.Clonable) fail.Error {
					stateV1, innerErr := lang.Cast[*propertiesv1.ClusterState](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					stateV1.State = clusterstate.Removed
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				return props.Inspect(clusterproperty.NodesV3, func(p clonable.Clonable) fail.Error {
					nodesV3, innerErr := lang.Cast[*propertiesv3.ClusterNodes](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					nodes = nodesV3.PrivateNodes
					masters = nodesV3.Masters
					all = nodesV3.ByNumericalID
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			xerr = clusterTrx.Commit(ctx)
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			masterCount, nodeCount := len(masters), len(nodes)
			if masterCount+nodeCount > 0 {
				egKill := new(errgroup.Group)

				foundSomething := false
				for _, v := range nodes {
					v := v
					if n, ok := all[v]; ok {
						foundSomething = true

						egKill.Go(func() error {
							_, err := clusterTrx.deleteNodeWithContext(cleanupContextFrom(ctx), n, nil)
							return err
						})
					}
				}

				for _, v := range masters {
					v := v
					if n, ok := all[v]; ok {
						foundSomething = true

						egKill.Go(func() error {
							return clusterTrx.deleteMaster(cleanupContextFrom(ctx), n.ID)
						})
					}
				}

				if foundSomething {
					xerr = fail.Wrap(egKill.Wait())
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						cleaningErrors = append(cleaningErrors, xerr)
					}
				}
			}
			if len(cleaningErrors) > 0 {
				xerr = fail.Wrap(fail.NewErrorList(cleaningErrors), "failed to Delete Hosts")
				return localresult{xerr}, xerr
			}

			// From here, make sure there is nothing in nodesV3.ByNumericalID; if there is something, Delete all the remaining
			xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				all = nodesV3.ByNumericalID
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			allCount := len(all)
			if allCount > 0 {
				egKill := new(errgroup.Group)

				for _, v := range all {
					v := v
					egKill.Go(func() error {
						_, err := clusterTrx.deleteNodeWithContext(cleanupContextFrom(ctx), v, nil)
						return err
					})
				}

				xerr = fail.Wrap(egKill.Wait())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					cleaningErrors = append(cleaningErrors, xerr)
				}
				if len(cleaningErrors) > 0 {
					xerr = fail.Wrap(fail.NewErrorList(cleaningErrors), "failed to Delete Hosts")
					return localresult{xerr}, xerr
				}
			}

			// --- Deletes the Network, Subnet and gateway ---
			networkInstance, deleteNetwork, subnetInstance, xerr := clusterTrx.ExtractNetworkingInfo(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// missing Network and Subnet is considered as a successful deletion, continue
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					return localresult{xerr}, xerr
				}
			}

			svc, xerr := clusterTrx.Service()
			if xerr != nil {
				return localresult{xerr}, xerr
			}
			timings, xerr := svc.Timings()
			if xerr != nil {
				return localresult{xerr}, xerr
			}

			if subnetInstance != nil && !valid.IsNil(subnetInstance) {
				subnetName := subnetInstance.GetName()
				logrus.WithContext(ctx).Debugf("Cluster Deleting Subnet '%s'", subnetName)
				xerr = retry.WhileUnsuccessfulWithHardTimeout(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						innerXErr := subnetInstance.Delete(cleanupContextFrom(ctx))
						if innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotAvailable, *fail.ErrNotFound:
								return retry.StopRetryError(innerXErr)
							default:
								return innerXErr
							}
						}
						return nil
					},
					timings.NormalDelay(),
					timings.HostOperationTimeout(),
				)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						debug.IgnoreErrorWithContext(ctx, xerr)
					case *fail.ErrTimeout, *fail.ErrAborted:
						nerr := fail.Wrap(fail.Cause(xerr))
						switch nerr.(type) {
						case *fail.ErrNotFound:
							// Subnet not found, considered as a successful deletion and continue
							debug.IgnoreErrorWithContext(ctx, nerr)
						default:
							xerr = fail.Wrap(nerr, "failed to Delete Subnet '%s'", subnetName)
							return localresult{xerr}, xerr
						}
					default:
						xerr = fail.Wrap(xerr, "failed to Delete Subnet '%s'", subnetName)
						return localresult{xerr}, xerr
					}
				}
			}

			if networkInstance != nil && !valid.IsNil(networkInstance) && deleteNetwork {
				networkName := networkInstance.GetName()
				logrus.WithContext(ctx).Debugf("Deleting Network '%s'...", networkName)
				xerr = retry.WhileUnsuccessfulWithHardTimeout(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						innerXErr := networkInstance.Delete(cleanupContextFrom(ctx))
						if innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotFound, *fail.ErrInvalidRequest:
								return retry.StopRetryError(innerXErr)
							default:
								return innerXErr
							}
						}
						return nil
					},
					timings.NormalDelay(),
					timings.HostOperationTimeout(),
				)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// network not found, considered as a successful deletion and continue
						debug.IgnoreErrorWithContext(ctx, xerr)
					case *retry.ErrStopRetry:
						xerr = fail.Wrap(xerr.Cause(), "stopping retries")
						return localresult{xerr}, xerr
					case *retry.ErrTimeout:
						xerr = fail.Wrap(xerr.Cause(), "timeout")
						return localresult{xerr}, xerr
					default:
						xerr = fail.Wrap(xerr, "failed to Delete Network '%s'", networkName)
						logrus.WithContext(ctx).Errorf(xerr.Error())
						return localresult{xerr}, xerr
					}
				}
				logrus.WithContext(ctx).Infof("Network '%s' successfully deleted.", networkName)
			}

			return localresult{nil}, nil // nolint
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer cleanup
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer cleanup
		return fail.Wrap(inctx.Err())
	}
}

// deleteNode deletes a node
func (clusterTrx *clusterTransactionImpl) deleteNode(inctx context.Context, node *propertiesv3.ClusterNode, master *Host) (_ fail.Error) {
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

			tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster")).Entering()
			defer tracer.Exiting()

			nodeRef := node.ID
			if nodeRef == "" {
				nodeRef = node.Name
			}

			// Identify the node to Delete and remove it preventively from metadata
			xerr := alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				delete(nodesV3.ByNumericalID, node.NumericalID)

				if found, indexInSlice := containsClusterNode(nodesV3.PrivateNodes, node.NumericalID); found {
					length := len(nodesV3.PrivateNodes)
					if indexInSlice < length-1 {
						nodesV3.PrivateNodes = append(nodesV3.PrivateNodes[:indexInSlice], nodesV3.PrivateNodes[indexInSlice+1:]...)
					} else {
						nodesV3.PrivateNodes = nodesV3.PrivateNodes[:indexInSlice]
					}
				}
				delete(nodesV3.PrivateNodeByID, node.ID)
				delete(nodesV3.PrivateNodeByName, node.Name)
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{xerr}, xerr
			}

			// VPL: trx.Rollback should take care of not saving metadata on failure, so this code becomes useless
			// // Starting from here, restore node in Cluster metadata if exiting with error
			// defer func() {
			// 	ferr = debug.InjectPlannedFail(ferr)
			// 	if ferr != nil {
			// 		derr := alterClusterMetadataProperty(jobapi.NewContextPropagatingJob(inctx), trx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
			// 			nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
			// 			if node.Name != "" {
			// 				nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
			// 			}
			// 			if node.ID != "" {
			// 				nodesV3.PrivateNodeByID[node.ID] = node.NumericalID
			// 			}
			// 			nodesV3.ByNumericalID[node.NumericalID] = node
			// 			return nil
			// 		})
			// 		if derr != nil {
			// 			logrus.WithContext(context.Background()).Errorf("failed to restore node ownership in Cluster")
			// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to restore node ownership in Cluster metadata", ActionFromError(ferr)))
			// 		}
			// 	}
			// }()

			// Deletes node
			hostInstance, xerr := LoadHost(ctx, nodeRef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Host already deleted, consider as a success, continue
					return result{nil}, nil // nolint
				default:
					return result{xerr}, xerr
				}
			}

			xerr = clusterTrx.Commit(ctx)
			if xerr != nil {
				return result{xerr}, xerr
			}

			// host still exists, leave it from Cluster, if master is not null
			if master != nil && !valid.IsNil(master) {
				xerr = clusterTrx.leaveNodesFromList(ctx, []*Host{hostInstance}, master)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{xerr}, xerr
				}

				var makers clusterflavors.Makers
				xerr = inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
					local, err := lang.Cast[*extraInAbstract](aci.Local)
					if err != nil {
						return fail.Wrap(err)
					}

					makers = local.Makers
					return nil
				})
				if xerr != nil {
					return result{xerr}, xerr
				}
				internal.IncrementExpVar("cluster.cache.hit")
				if makers.UnconfigureNode != nil {
					xerr = makers.UnconfigureNode(clusterTrx, hostInstance, master)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return result{xerr}, xerr
					}
				}
			}

			// Finally Delete host
			xerr = hostInstance.Delete(cleanupContextFrom(ctx))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Host seems already deleted, so it's a success
				default:
					return result{xerr}, xerr
				}
			}

			return result{nil}, nil // nolint
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer cleanup
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer cleanup
		return fail.Wrap(inctx.Err())
	}
}

// deleteMaster deletes the master specified by its ID
func (clusterTrx *clusterTransactionImpl) deleteMaster(ctx context.Context, hostID string) (ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostID == "" {
		return fail.InvalidParameterCannotBeNilError("hostID")
	}

	// FIXME: Bad idea, the first thing to go must be the resource, then the metadata; if not we can have zombie instances without metadata (it happened)
	// which means that the code doing the "restore" never worked

	// Removes master from Cluster properties
	xerr := alterClusterMetadataProperty(cleanupContextFrom(ctx), clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
		numericalID, found := nodesV3.MasterByID[hostID]
		if !found {
			return abstract.ResourceNotFoundError("master", hostID)
		}

		delete(nodesV3.ByNumericalID, numericalID)
		delete(nodesV3.MasterByID, hostID)
		if found, indexInSlice := containsClusterNode(nodesV3.Masters, numericalID); found {
			length := len(nodesV3.Masters)
			if indexInSlice < length-1 {
				nodesV3.Masters = append(nodesV3.Masters[:indexInSlice], nodesV3.Masters[indexInSlice+1:]...)
			} else {
				nodesV3.Masters = nodesV3.Masters[:indexInSlice]
			}
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	hostInstance, xerr := LoadHost(ctx, hostID)
	if xerr != nil {
		return xerr
	}

	xerr = hostInstance.Delete(ctx)
	if xerr != nil {
		return xerr
	}

	return nil
}

// installReverseProxy installs reverseproxy
func (clusterTrx *clusterTransactionImpl) installReverseProxy(inctx context.Context, params data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	identity, xerr := clusterTrx.getIdentity(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	dockerDisabled := false
	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
		_, dockerDisabled = featuresV1.Disabled["docker"]
		return nil
	})
	if xerr != nil {
		return xerr
	}

	if dockerDisabled {
		return nil
	}

	clusterName := identity.Name
	disabled := false
	xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
		_, disabled = featuresV1.Disabled["reverseproxy"]
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if disabled {
		logrus.WithContext(ctx).Infof("[Cluster %s] reverseproxy (feature 'edgeproxy4subnet' not installed because disabled", clusterName)
		return nil
	}

	logrus.WithContext(ctx).Debugf("[Cluster %s] adding feature 'edgeproxy4subnet'", clusterName)
	feat, xerr := NewFeature(ctx, "edgeproxy4subnet")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// params, _ := data.FromMap(params)
	results, xerr := feat.Add(ctx, clusterTrx, params)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if !results.IsSuccessful() {
		return fail.NewError("[Cluster %s] failed to add '%s': %s", clusterName, feat.GetName(), results.ErrorMessage())
	}

	xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
		featuresV1.Installed[feat.GetName()] = &propertiesv1.ClusterInstalledFeature{
			Name: feat.GetName(),
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, callstack.WhereIsThis())
	}

	logrus.WithContext(ctx).Debugf("[Cluster %s] feature '%s' added successfully", clusterName, feat.GetName())
	return nil
}

// installRemoteDesktop installs feature remotedesktop on all masters of the Cluster
func (clusterTrx *clusterTransactionImpl) installRemoteDesktop(inctx context.Context, params data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		identity, xerr := clusterTrx.getIdentity(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		dockerDisabled := false
		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, dockerDisabled = featuresV1.Disabled["docker"]
			return nil
		})
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if dockerDisabled {
			chRes <- result{nil}
			return
		}

		disabled := false
		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, disabled = featuresV1.Disabled["remotedesktop"]
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		if !disabled {
			logrus.WithContext(ctx).Debugf("[Cluster %s] adding feature 'remotedesktop'", identity.Name)

			feat, xerr := NewFeature(ctx, "remotedesktop")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			// Adds remotedesktop feature on Cluster (ie masters)
			// params, _ := data.FromMap(params)
			params["Username"] = "cladm"
			params["Password"] = identity.AdminPassword

			// FIXME: Bug mitigations
			params["GuacamolePort"] = 63011
			params["TomcatPort"] = 9009

			r, xerr := feat.Add(ctx, clusterTrx, params)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.IsSuccessful() {
				xerr = fail.NewError("[Cluster %s] failed to add 'remotedesktop' failed: %s", identity.Name, r.ErrorMessage())
				_ = xerr.Annotate("ran_but_failed", true)
				chRes <- result{xerr}
				return
			}

			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
				featuresV1.Installed["remotedesktop"] = &propertiesv1.ClusterInstalledFeature{
					Name: "remotedesktop",
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				chRes <- result{xerr}
				return
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] feature 'remotedesktop' added successfully", identity.Name)
		}

		chRes <- result{nil}
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

// installAnsible installs feature ansible on all masters of the Cluster
func (clusterTrx *clusterTransactionImpl) installAnsible(inctx context.Context, params data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		identity, xerr := clusterTrx.getIdentity(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		disabled := false
		xerr = inspectClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
			_, disabled = featuresV1.Disabled["ansible"]
			return nil
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			chRes <- result{xerr}
			return
		}

		if !disabled {
			logrus.WithContext(ctx).Debugf("[Cluster %s] adding feature 'ansible'", identity.Name)

			// 1st, Feature 'ansible'
			feat, xerr := NewFeature(ctx, "ansible")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			// Adds ansible feature on Cluster (ie masters)
			// params, _ := data.FromMap(params)
			params["Username"] = "cladm"
			params["Password"] = identity.AdminPassword
			r, xerr := feat.Add(ctx, clusterTrx, params)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.IsSuccessful() {
				chRes <- result{fail.NewError("[Cluster %s] failed to add 'ansible': %s", identity.Name, r.ErrorMessage())}
				return
			}
			logrus.WithContext(ctx).Debugf("[Cluster %s] feature 'ansible' added successfully", identity.Name)

			// 2nd, Feature 'ansible-for-cluster' (which does the necessary for a dynamic inventory)
			feat, xerr = NewFeature(ctx, "ansible-for-cluster")
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			r, xerr = feat.Add(ctx, clusterTrx, params)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}

			if !r.IsSuccessful() {
				chRes <- result{fail.NewError("[Cluster %s] failed to add 'ansible-for-cluster': %s", identity.Name, r.ErrorMessage())}
				return
			}

			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.FeaturesV1, func(featuresV1 *propertiesv1.ClusterFeatures) fail.Error {
				featuresV1.Installed["ansible-for-cluster"] = &propertiesv1.ClusterInstalledFeature{
					Name: "ansible-for-cluster",
				}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				chRes <- result{xerr}
				return
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] feature 'ansible-for-cluster' added successfully", identity.Name)
		}
		chRes <- result{nil}
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

func containsClusterNode(list []uint, numericalID uint) (bool, int) {
	var idx int
	found := false
	for i, v := range list {
		if v == numericalID {
			found = true
			idx = i
			break
		}
	}
	return found, idx
}

// StopHost instruct the Cloud Provider to stop the host
func (clusterTrx *clusterTransactionImpl) StopHost(ctx context.Context, hostID string) (ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostID")
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	defer fail.OnPanic(&ferr)

	svc, xerr := clusterTrx.Service()
	if xerr != nil {
		return xerr
	}

	xerr = svc.StopHost(ctx, hostID, false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) { // nolint
		case *fail.ErrDuplicate: // A host already stopped is considered as a successful run
			logrus.WithContext(ctx).Tracef("host duplicated, stopping considered as a success")
			debug.IgnoreErrorWithContext(ctx, xerr)
			return nil
		default:
			return xerr
		}
	}

	// -- refresh state of host --
	hostInstance, xerr := LoadHost(ctx, hostID)
	if xerr != nil {
		return xerr
	}

	_, xerr = hostInstance.ForceGetState(ctx)
	return xerr
}

// StartHost instructs the Cloud Provider to start the Host
func (clusterTrx *clusterTransactionImpl) StartHost(ctx context.Context, hostID string) (ferr fail.Error) {
	if valid.IsNil(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if hostID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("hostID")
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/start/host/%s", oldKey, hostID)) // nolint
	}

	defer fail.OnPanic(&ferr)

	svc, xerr := clusterTrx.Service()
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	xerr = svc.StartHost(ctx, hostID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) { // nolint
		case *fail.ErrDuplicate: // A host already started is considered as a successful run
			logrus.WithContext(ctx).Tracef("host duplicated, start considered as a success")
			debug.IgnoreErrorWithContext(ctx, xerr)
			return nil
		}
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// -- refresh state of host --
	hostInstance, xerr := LoadHost(ctx, hostID)
	if xerr != nil {
		return xerr
	}

	_, xerr = hostInstance.WaitSSHReady(ctx, timings.HostOperationTimeout())
	if xerr != nil {
		return xerr
	}

	_, xerr = hostInstance.ForceGetState(ctx)
	return xerr
}

type taskDeleteNodeOnFailureParameters struct {
	ID            string
	Name          string
	KeepOnFailure bool
	Timeout       time.Duration
}

// deleteNodeOnFailure deletes a node when a failure occurred
func (clusterTrx *clusterTransactionImpl) deleteNodeOnFailure(inctx context.Context, params taskDeleteNodeOnFailureParameters) (_ interface{}, _ fail.Error) {
	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
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

			svc, xerr := clusterTrx.Service()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			hostInstance, xerr := LoadHost(ctx, params.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					_ = svc.DeleteHost(ctx, params.ID)
					return result{nil, nil}, nil
				default:
					return result{nil, xerr}, xerr
				}
			}

			xerr = hostInstance.Delete(ctx)
			_ = svc.DeleteHost(ctx, params.ID)
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
		return nil, fail.TimeoutError(fmt.Errorf("timeout trying to Delete node on failure"), params.Timeout)
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

func (clusterTrx *clusterTransactionImpl) deleteNodeWithContext(inctx context.Context, node *propertiesv3.ClusterNode, master *Host) (_ interface{}, _ fail.Error) {
	if valid.IsNil(clusterTrx) {
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
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/Delete/node/%s", oldKey, node.Name)) // nolint
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

			svc, xerr := clusterTrx.Service()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// FIXME: This is another mitigation....
			trueNodeID := node.ID

			logrus.WithContext(ctx).Debugf("Deleting Node...")
			xerr = clusterTrx.deleteNode(ctx, node, master)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					return result{nil, xerr}, xerr
				}
			}

			// kill zombies (instances without metadata)
			_ = svc.DeleteHost(ctx, trueNodeID)

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

type taskUpdateClusterInventoryMasterParameters struct {
	ctx           context.Context
	master        *Host
	inventoryData string
}

// updateClusterInventoryMaster updates a Host (master) ansible inventory
func (clusterTrx *clusterTransactionImpl) updateClusterInventoryMaster(ctx context.Context, param taskUpdateClusterInventoryMasterParameters) (ferr fail.Error) {
	if valid.IsNull(clusterTrx) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	select {
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	default:
	}

	defer fail.OnPanic(&ferr)

	svc, xerr := clusterTrx.Service()
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	master := param.master
	inventoryData := param.inventoryData
	does, xerr := master.Exists(ctx)
	if xerr != nil {
		return xerr
	}
	if !does {
		return nil
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
	prerr := fmt.Sprintf("[Cluster %s, master %s] Ansible inventory update: ", clusterTrx.GetName(), master.GetName())
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
		return fail.Wrap(xerr, "%sfail to clean previous temporaries", prerr)
	}
	if retcode != 0 {
		xerr := fail.NewError("%sfail to clean previous temporaries", prerr)
		xerr.Annotate("cmd", cmd)
		xerr.Annotate("stdout", stdout)
		xerr.Annotate("stderr", stderr)
		xerr.Annotate("retcode", retcode)
		return xerr
	}

	// Upload new inventory
	xerr = rfcItem.UploadString(ctx, inventoryData, master)
	if xerr != nil {
		return fail.Wrap(xerr, "%supload fail", prerr)
	}

	// Run update commands
	for a, acmd := range commands {
		i, cmd := a, acmd
		retcode, stdout, stderr, xerr = master.Run(ctx, cmd, outputs.COLLECT, connTimeout, delay)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return fail.Wrap(xerr, errmsg[i])
		}
		if retcode != 0 {
			xerr := fail.NewError(errmsg[i])
			xerr.Annotate("cmd", cmd)
			xerr.Annotate("stdout", stdout)
			xerr.Annotate("stderr", stderr)
			xerr.Annotate("retcode", retcode)
			return xerr
		}
	}

	return nil
}

type machineID struct {
	ID   string
	Name string
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
	count uint,
	windowSize uint,
	timeout time.Duration,
	uat chan StdResult,
	runner func(context.Context, interface{}) (interface{}, fail.Error), data interface{},
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

			res, err := runner(treeCtx, data)
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

// AddNodes adds several nodes
func (clusterTrx *clusterTransactionImpl) AddNodes(ctx context.Context, count uint, def abstract.HostSizingRequirements, parameters data.Map[string, any], keepOnFailure bool) (_ []*Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(clusterTrx) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "must be an int > 0")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d)", count)
	defer tracer.Entering().Exiting()

	var (
		hostImage             string
		nodeDefaultDefinition *propertiesv2.HostSizingRequirements
	)
	xerr := inspectClusterMetadata(ctx, clusterTrx, func(_ *abstract.Cluster, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(clusterproperty.DefaultsV3) {
			return props.Inspect(clusterproperty.DefaultsV3, func(p clonable.Clonable) fail.Error {
				defaultsV3, innerErr := lang.Cast[*propertiesv3.ClusterDefaults](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				nodeDefaultDefinition = &defaultsV3.NodeSizing
				hostImage = defaultsV3.Image

				// merge FeatureParameters in parameters, the latter keeping precedence over the former
				for k, v := range ExtractFeatureParameters(defaultsV3.FeatureParameters) {
					if _, ok := parameters[k]; !ok {
						parameters[k] = v
					}
				}

				return nil
			})
		}

		// Cluster may have been created before ClusterDefaultV3, so still support this property
		return props.Inspect(clusterproperty.DefaultsV2, func(p clonable.Clonable) fail.Error {
			defaultsV2, innerErr := lang.Cast[*propertiesv2.ClusterDefaults](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			nodeDefaultDefinition = &defaultsV2.NodeSizing
			hostImage = defaultsV2.Image
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	nodeDef := complementHostDefinition(def, *nodeDefaultDefinition)
	if def.Image != "" {
		hostImage = def.Image
	}

	svc, xerr := clusterTrx.Service()
	_, nodeDef.Image, xerr = determineImageID(ctx, svc, hostImage)
	if xerr != nil {
		return nil, xerr
	}

	var (
		nodes []*propertiesv3.ClusterNode
	)

	timings, xerr := svc.Timings()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	timeout := time.Duration(count) * timings.HostCreationTimeout() // More than enough
	winSize := 8
	cfg, xerr := svc.ConfigurationOptions()
	if xerr == nil {
		winSize = cfg.ConcurrentMachineCreationLimit
	}

	// for OVH, we have to ignore the errors and keep trying until we have 'count'
	nodesChan := make(chan StdResult, count)
	err := runWindow(ctx, count, uint(math.Min(float64(count), float64(winSize))), timeout, nodesChan, clusterTrx.createNode, taskCreateNodeParameters{
		nodeDef:       nodeDef,
		timeout:       timings.HostCreationTimeout(),
		keepOnFailure: keepOnFailure,
	})
	if err != nil {
		close(nodesChan)
		return nil, fail.Wrap(err)
	}

	close(nodesChan)
	for v := range nodesChan {
		if v.Err != nil {
			continue
		}
		if v.ToBeDeleted {
			_, xerr = clusterTrx.deleteNodeWithContext(cleanupContextFrom(ctx), v.Content.(*propertiesv3.ClusterNode), nil)
			debug.IgnoreErrorWithContext(ctx, xerr)
			continue
		}
		nodes = append(nodes, v.Content.(*propertiesv3.ClusterNode))
	}

	// Starting from here, if exiting with error, Delete created nodes if allowed (cf. keepOnFailure)
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !keepOnFailure && len(nodes) > 0 {
			egDeletion := new(errgroup.Group)

			for _, v := range nodes {
				v := v
				egDeletion.Go(func() error {
					_, err := clusterTrx.deleteNodeWithContext(cleanupContextFrom(ctx), v, nil)
					return err
				})
			}
			derr := fail.Wrap(egDeletion.Wait())
			derr = debug.InjectPlannedFail(derr)
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	// configure what has to be done Cluster-wide
	var makers clusterflavors.Makers
	xerr = inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
		local, err := lang.Cast[*extraInAbstract](aci.Local)
		if err != nil {
			return fail.Wrap(err)
		}

		makers = local.Makers
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	if makers.ConfigureCluster != nil {
		xerr = makers.ConfigureCluster(ctx, clusterTrx, parameters)
		if xerr != nil {
			return nil, xerr
		}
	}
	internal.IncrementExpVar("cluster.cache.hit")

	// Now configure new nodes
	xerr = clusterTrx.configureNodesFromList(ctx, nodes, parameters)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// At last join nodes to Cluster
	xerr = clusterTrx.joinNodesFromList(ctx, nodes)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	hosts := make([]*Host, 0, len(nodes))
	for _, v := range nodes {
		hostInstance, xerr := LoadHost(ctx, v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hosts = append(hosts, hostInstance)
	}

	xerr = clusterTrx.updateClusterAnsibleInventory(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return hosts, nil
}

// complementHostDefinition complements req with default values if needed
func complementHostDefinition(req abstract.HostSizingRequirements, def propertiesv2.HostSizingRequirements) abstract.HostSizingRequirements {
	if def.MinCores > 0 && req.MinCores == 0 {
		req.MinCores = def.MinCores
	}
	if def.MaxCores > 0 && req.MaxCores == 0 {
		req.MaxCores = def.MaxCores
	}
	if def.MinRAMSize > 0.0 && req.MinRAMSize == 0.0 {
		req.MinRAMSize = def.MinRAMSize
	}
	if def.MaxRAMSize > 0.0 && req.MaxRAMSize == 0.0 {
		req.MaxRAMSize = def.MaxRAMSize
	}
	if def.MinDiskSize > 0 && req.MinDiskSize == 0 {
		req.MinDiskSize = def.MinDiskSize
	}
	if req.MinGPU <= 0 && def.MinGPU > 0 {
		req.MinGPU = def.MinGPU
	}
	if req.MinCPUFreq == 0 && def.MinCPUFreq > 0 {
		req.MinCPUFreq = def.MinCPUFreq
	}
	if req.MinCores <= 0 {
		req.MinCores = 2
	}
	if req.MaxCores <= 0 {
		req.MaxCores = 4
	}
	if req.MinRAMSize <= 0.0 {
		req.MinRAMSize = 7.0
	}
	if req.MaxRAMSize <= 0.0 {
		req.MaxRAMSize = 16.0
	}
	if req.MinDiskSize <= 0 {
		req.MinDiskSize = 50
	}

	return req
}

// startRandomDelayGenerator starts a go-routine to generate random delays
func (clusterTrx *clusterTransactionImpl) startRandomDelayGenerator(ctx context.Context, min, max int) fail.Error {
	chint := make(chan int)
	mrand.Seed(time.Now().UnixNano())

	randomDelayTask := func() {
		defer close(chint)
		if min == max {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					chint <- min
				}
			}
		} else {
			value := max - min
			for {
				select {
				case <-ctx.Done():
					return
				default:
					chint <- mrand.Intn(value) + min // nolint
				}
			}
		}
	}
	go randomDelayTask()

	return alterClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
		local, innerErr := lang.Cast[*extraInAbstract](aci.Local)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		local.RandomDelayCh = chint
		return nil
	})
}

// readRandomDelay reads the next delay calculated by go routine started in startRandomDelayGenerator()
func (clusterTrx *clusterTransactionImpl) readRandomDelay(ctx context.Context) (int, fail.Error) {
	var delay int
	xerr := inspectClusterMetadataAbstract(ctx, clusterTrx, func(aci *abstract.Cluster) fail.Error {
		local, innerErr := lang.Cast[*extraInAbstract](aci.Local)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		if local.RandomDelayCh == nil {
			return fail.NotAvailableError("channel is not built")
		}

		delay = <-local.RandomDelayCh
		return nil
	})
	if xerr != nil {
		return 0, xerr
	}

	return delay, nil
}
