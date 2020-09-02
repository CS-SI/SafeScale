/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
    "bytes"
    "encoding/json"
    "fmt"
    "reflect"
    "strconv"
    "strings"
    "time"

    rice "github.com/GeertJohan/go.rice"
    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/protocol"
    "github.com/CS-SI/SafeScale/lib/server/iaas"
    "github.com/CS-SI/SafeScale/lib/server/resources"
    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterflavor"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/clusternodetype"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterstate"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
    flavors "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors"
    "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors/boh"
    "github.com/CS-SI/SafeScale/lib/server/resources/operations/clusterflavors/k8s"
    "github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
    propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
    propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
    "github.com/CS-SI/SafeScale/lib/utils"
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/data"
    "github.com/CS-SI/SafeScale/lib/utils/debug"
    "github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
    "github.com/CS-SI/SafeScale/lib/utils/retry"
    "github.com/CS-SI/SafeScale/lib/utils/serialize"
    "github.com/CS-SI/SafeScale/lib/utils/strprocess"
    "github.com/CS-SI/SafeScale/lib/utils/template"
    "github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
    // Path is the path to use to reach Cluster Definitions/Metadata
    clustersFolderName = "clusters"
)

// Cluster is the implementation of resources.Cluster interface
type cluster struct {
    *core
    concurrency.TaskedLock `json:"-"`
    abstract.ClusterIdentity

    installMethods      map[uint8]installmethod.Enum
    lastStateCollection time.Time
    service             iaas.Service
    makers              flavors.Makers
}

func nullCluster() *cluster {
    return &cluster{core: nullCore()}
}

// NewCluster ...
func NewCluster(task concurrency.Task, svc iaas.Service) (_ resources.Cluster, xerr fail.Error) {
    if task.IsNull() {
        return nullCluster(), fail.InvalidParameterError("task", "cannot be nil")
    }
    if svc == nil {
        return nullCluster(), fail.InvalidParameterError("svc", "cannot be nil")
    }
    defer fail.OnPanic(&xerr)

    core, xerr := newCore(svc, "cluster", clustersFolderName, &abstract.ClusterIdentity{})
    if xerr != nil {
        return nullCluster(), xerr
    }

    return &cluster{core: core}, nil
}

// LoadCluster ...
func LoadCluster(task concurrency.Task, svc iaas.Service, name string) (_ resources.Cluster, xerr fail.Error) {
    if task.IsNull() {
        return nullCluster(), fail.InvalidParameterError("task", "cannot be nil")
    }
    if svc == nil {
        return nullCluster(), fail.InvalidParameterError("svc", "cannot be nil")
    }
    if name == "" {
        return nullCluster(), fail.InvalidParameterError("name", "cannot be empty string")
    }
    defer fail.OnPanic(&xerr)

    anon, xerr := NewCluster(task, svc)
    if xerr != nil {
        return nullCluster(), xerr
    }
    instance := anon.(*cluster)

    if xerr = instance.Read(task, name); xerr != nil {
        return nullCluster(), xerr
    }

    // From here, we can deal with legacy
    if xerr = instance.upgradePropertyNodesIfNeeded(task); xerr != nil {
        return nullCluster(), xerr
    }

    return instance, nil
}

// upgradePropertyNodesIfNeeded upgrades current Nodes property to last Nodes property (currently NodesV2)
func (c *cluster) upgradePropertyNodesIfNeeded(task concurrency.Task) fail.Error {
    xerr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        if !props.Lookup(clusterproperty.NodesV2) {
            // Replace NodesV1 by NodesV2 properties
            return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
                nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
                if !ok {
                    return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                return props.Alter(task, clusterproperty.NodesV1, func(clonable data.Clonable) fail.Error {
                    nodesV1, ok := clonable.(*propertiesv1.ClusterNodes)
                    if !ok {
                        return fail.InconsistentError("'*propertiesv1.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
                    }
                    for _, i := range nodesV1.Masters {
                        nodesV2.GlobalLastIndex++

                        node := &propertiesv2.ClusterNode{
                            ID:          i.ID,
                            NumericalID: nodesV2.GlobalLastIndex,
                            Name:        i.Name,
                            PrivateIP:   i.PrivateIP,
                            PublicIP:    i.PublicIP,
                        }
                        nodesV2.Masters = append(nodesV2.Masters, node)
                    }
                    for _, i := range nodesV1.PrivateNodes {
                        nodesV2.GlobalLastIndex++

                        node := &propertiesv2.ClusterNode{
                            ID:          i.ID,
                            NumericalID: nodesV2.GlobalLastIndex,
                            Name:        i.Name,
                            PrivateIP:   i.PrivateIP,
                            PublicIP:    i.PublicIP,
                        }
                        nodesV2.PrivateNodes = append(nodesV2.PrivateNodes, node)
                    }
                    nodesV2.MasterLastIndex = nodesV1.MasterLastIndex
                    nodesV2.PrivateLastIndex = nodesV1.PrivateLastIndex
                    // nodesV1 = &propertiesv1.ClusterNodes{}
                    return nil
                })
            })
        }
        return nil
    })
    return xerr
}

// IsNull tells if the instance represents a null value of cluster
// Satisfies interface data.NullValue
func (c *cluster) IsNull() bool {
    return c == nil || c.core.IsNull()
}

// GetName returns the name if the cluster
// Satisfies interface data.Identifiable
func (c *cluster) GetName() string {
    return c.core.GetName()
}

// GetID returns the name of the cluster
// Satisfies interface data.Identifiable
func (c *cluster) GetID() string {
    return c.core.GetName()
}

// Create creates the necessary infrastructure of the Cluster
func (c *cluster) Create(task concurrency.Task, req abstract.ClusterRequest) (xerr fail.Error) {
    if c.IsNull() {
        return fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer temporal.NewStopwatch().OnExitLogInfo(
        fmt.Sprintf("Starting creation of infrastructure of cluster '%s'...", req.Name),
        fmt.Sprintf("Ending creation of infrastructure of cluster '%s'", req.Name),
    )()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage("failed to create cluster infrastructure:"))
    defer fail.OnPanic(&xerr)

    // Creates first metadata of cluster after initialization
    if xerr = c.firstLight(task, req); xerr != nil {
        return xerr
    }

    // Starting from here, delete metadata if exiting with error
    defer func() {
        if xerr != nil && !req.KeepOnFailure {
            derr := c.core.Delete(task)
            if derr != nil {
                logrus.Errorf("after failure, cleanup failed to delete cluster metadata")
                _ = xerr.AddConsequence(derr)
            }
        }
    }()

    // defer func() {
    // 	if err != nil {
    // 		finalState = clusterstate.Error
    // 	} else {
    // 		finalState = clusterstate.Created
    // 	}
    // }()

    // Define the sizing requirements for cluster hosts
    gatewaysDef, mastersDef, nodesDef, xerr := c.defineSizingRequirements(task, req)
    if xerr != nil {
        return xerr
    }

    // Create the rn
    rn, xerr := c.createNetwork(task, req, gatewaysDef)
    if xerr != nil {
        return xerr
    }
    // req.NetworkID = rn.GetID()

    defer func() {
        if xerr != nil && !req.KeepOnFailure {
            derr := rn.Delete(task)
            if derr != nil {
                _ = xerr.AddConsequence(derr)
            }
        }
    }()

    // Creates and configures hosts
    if xerr = c.createHosts(task, rn, *mastersDef, *nodesDef, req.KeepOnFailure); xerr != nil {
        return xerr
    }

    // Starting from here, exiting with err deletes hosts if req.KeepOnFailure is false
    defer func() {
        if xerr != nil && !req.KeepOnFailure {
            tg, tgerr := concurrency.NewTaskGroup(task)
            if tgerr != nil {
                _ = xerr.AddConsequence(tgerr)
            } else {
                list, merr := c.ListMasterIDs(task)
                if merr != nil {
                    _ = xerr.AddConsequence(merr)
                } else {
                    for _, v := range list {
                        _, tgerr = tg.StartInSubtask(c.taskDeleteHost, data.Map{"host": v})
                        if tgerr != nil {
                            _ = xerr.AddConsequence(tgerr)
                        }
                    }
                }

                list, merr = c.ListNodeIDs(task)
                if merr != nil {
                    _ = xerr.AddConsequence(merr)
                } else {
                    for _, v := range list {
                        _, tgerr = tg.StartInSubtask(c.taskDeleteHost, data.Map{"host": v})
                        if tgerr != nil {
                            _ = xerr.AddConsequence(tgerr)
                        }
                    }
                }

                _, _, tgerr = tg.WaitGroupFor(temporal.GetLongOperationTimeout())
                if tgerr != nil {
                    _ = xerr.AddConsequence(tgerr)
                }
            }

        }
    }()

    primaryGateway, xerr := rn.GetGateway(task, true)
    if xerr != nil {
        return xerr
    }
    secondaryGateway, xerr := rn.GetGateway(task, false)
    if xerr != nil {
        return xerr
    }

    // At the end, configure cluster as a whole
    xerr = c.configureCluster(task, data.Map{
        "PrimaryGateway":   primaryGateway,
        "SecondaryGateway": secondaryGateway,
    })
    if xerr != nil {
        return xerr
    }

    return nil
}

// firstLight contains the code leading to cluster first metadata written
func (c *cluster) firstLight(task concurrency.Task, req abstract.ClusterRequest) fail.Error {
    if c.IsNull() {
        return fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }
    // FIXME: validate parameters

    // Initializes instance
    ci := abstract.NewClusterIdentity()
    ci.Name = req.Name
    ci.Flavor = req.Flavor
    ci.Complexity = req.Complexity
    xerr := c.Carry(task, ci)
    if xerr != nil {
        return xerr
    }

    return c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        innerXErr := props.Alter(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
            featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            // VPL: For now, always disable addition of feature proxycache
            featuresV1.Disabled["proxycache"] = struct{}{}
            for k := range req.DisabledDefaultFeatures {
                featuresV1.Disabled[k] = struct{}{}
            }
            return nil
        })
        if innerXErr != nil {
            return fail.Wrap(innerXErr, "failed to disable feature 'proxycache'")
        }
        // ENDVPL

        // Sets initial state of the new cluster and create metadata
        innerXErr = props.Alter(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.GetState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            stateV1.State = clusterstate.Creating
            return nil
        })
        if innerXErr != nil {
            return fail.Wrap(innerXErr, "failed to set initial state of cluster")
        }

        // sets default sizing from req
        innerXErr = props.Alter(task, clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
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

        // FUTURE: sets the cluster composition (when we will be able to manage cluster spread on several tenants...)
        innerXErr = props.Alter(task, clusterproperty.CompositeV1, func(clonable data.Clonable) fail.Error {
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
        kp, innerXErr := c.service.CreateKeyPair(kpName)
        if innerXErr != nil {
            return innerXErr
        }
        c.ClusterIdentity.Keypair = kp

        // Generate needed password for account cladm
        cladmPassword, innerErr := utils.GeneratePassword(16)
        if innerErr != nil {
            return fail.ToError(innerErr)
        }

        // Sets identity
        c.ClusterIdentity.Name = req.Name
        c.ClusterIdentity.Flavor = req.Flavor
        c.ClusterIdentity.Complexity = req.Complexity
        c.ClusterIdentity.AdminPassword = cladmPassword

        // Links maker based on Flavor
        innerXErr = c.Bootstrap(task)
        if innerXErr != nil {
            return innerXErr
        }
        return nil
    })
}

// defineSizings calculates the sizings needed for the hosts of the cluster
func (c *cluster) defineSizingRequirements(task concurrency.Task, req abstract.ClusterRequest) (
    *abstract.HostSizingRequirements, *abstract.HostSizingRequirements, *abstract.HostSizingRequirements, fail.Error,
) {

    var (
        gatewaysDefault *abstract.HostSizingRequirements
        mastersDefault  *abstract.HostSizingRequirements
        nodesDefault    *abstract.HostSizingRequirements
        imageID         string
    )

    // Determine default image
    imageID = req.NodesDef.Image
    if imageID == "" && c.makers.DefaultImage != nil {
        imageID = c.makers.DefaultImage(task, c)
    }
    if imageID == "" {
        imageID = "Ubuntu 18.04"
    }

    // Determine getGateway sizing
    if c.makers.DefaultGatewaySizing != nil {
        gatewaysDefault = complementSizingRequirements(nil, c.makers.DefaultGatewaySizing(task, c))
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
    gatewaysDef := complementSizingRequirements(&req.GatewaysDef, *gatewaysDefault)
    gatewaysDef.Image = imageID

    // Determine master sizing
    if c.makers.DefaultMasterSizing != nil {
        mastersDefault = complementSizingRequirements(nil, c.makers.DefaultMasterSizing(task, c))
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
    // Note: no way yet to define master sizing from cli...
    mastersDef := complementSizingRequirements(&req.MastersDef, *mastersDefault)
    mastersDef.Image = imageID

    // Determine node sizing
    if c.makers.DefaultNodeSizing != nil {
        nodesDefault = complementSizingRequirements(nil, c.makers.DefaultNodeSizing(task, c))
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
    // nodesDefault.ImageID = imageID
    nodesDef := complementSizingRequirements(&req.NodesDef, *nodesDefault)
    nodesDef.Image = imageID

    xerr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
            defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*gatewaysDef)
            defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*mastersDef)
            defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*nodesDef)
            defaultsV2.Image = imageID
            return nil
        })
    })
    if xerr != nil {
        return nil, nil, nil, xerr
    }

    return gatewaysDef, mastersDef, nodesDef, nil
}

// createNetwork creates the network for the cluster
func (c *cluster) createNetwork(
    task concurrency.Task,
    req abstract.ClusterRequest, gatewaysDef *abstract.HostSizingRequirements,
) (_ resources.Network, xerr fail.Error) {

    // Determine if getGateway Failover must be set
    caps := c.service.GetCapabilities()
    gwFailoverDisabled := req.Complexity == clustercomplexity.Small || !caps.PrivateVirtualIP
    for k := range req.DisabledDefaultFeatures {
        if k == "gateway-failover" {
            gwFailoverDisabled = true
            break
        }
    }

    // Creates network
    logrus.Debugf("[cluster %s] creating network 'net-%s'", req.Name, req.Name)
    req.Name = strings.ToLower(req.Name)
    networkName := "net-" + req.Name
    networkReq := abstract.NetworkRequest{
        Name:  networkName,
        CIDR:  req.CIDR,
        HA:    !gwFailoverDisabled,
        Image: gatewaysDef.Image,
    }

    network, xerr := NewNetwork(c.service)
    if xerr != nil {
        return nil, xerr
    }
    xerr = network.Create(task, networkReq, "", gatewaysDef)
    if xerr != nil {
        return nil, xerr
    }

    defer func() {
        if xerr != nil && !req.KeepOnFailure {
            derr := network.Delete(task)
            if derr != nil {
                _ = xerr.AddConsequence(derr)
            }
        }
    }()

    // Updates cluster metadata, propertiesv2.ClusterNetwork
    xerr = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
            networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            primaryGateway, innerXErr := network.GetGateway(task, true)
            if innerXErr != nil {
                return innerXErr
            }
            var secondaryGateway resources.Host
            if !gwFailoverDisabled {
                secondaryGateway, innerXErr = network.GetGateway(task, false)
                if innerXErr != nil {
                    if _, ok := innerXErr.(*fail.ErrNotFound); !ok {
                        return innerXErr
                    }
                }
            }
            networkV2.NetworkID = network.GetID()
            networkV2.CIDR = req.CIDR
            networkV2.GatewayID = primaryGateway.GetID()
            if networkV2.GatewayIP, innerXErr = primaryGateway.GetPrivateIP(task); innerXErr != nil {
                return innerXErr
            }
            if networkV2.DefaultRouteIP, innerXErr = network.GetDefaultRouteIP(task); innerXErr != nil {
                return innerXErr
            }
            if networkV2.EndpointIP, innerXErr = network.GetEndpointIP(task); innerXErr != nil {
                return innerXErr
            }
            if networkV2.PrimaryPublicIP, innerXErr = primaryGateway.GetPublicIP(task); innerXErr != nil {
                return innerXErr
            }
            if !gwFailoverDisabled {
                networkV2.SecondaryGatewayID = secondaryGateway.GetID()
                if networkV2.SecondaryGatewayIP, innerXErr = secondaryGateway.GetPrivateIP(task); innerXErr != nil {
                    return innerXErr
                }
                if networkV2.SecondaryPublicIP, innerXErr = secondaryGateway.GetPublicIP(task); innerXErr != nil {
                    return innerXErr
                }
            }
            return nil
        })
    })
    if xerr != nil {
        return nil, xerr
    }

    logrus.Debugf("[cluster %s] network '%s' creation successful.", req.Name, networkName)
    return network, nil
}

// createHosts creates and configures hosts for the cluster
func (c *cluster) createHosts(
    task concurrency.Task,
    network resources.Network,
    mastersDef abstract.HostSizingRequirements,
    nodesDef abstract.HostSizingRequirements,
    keepOnFailure bool,
) (xerr fail.Error) {

    gwFailoverDisabled := network.HasVirtualIP(task)

    primaryGateway, xerr := network.GetGateway(task, true)
    if xerr != nil {
        return xerr
    }
    secondaryGateway, xerr := network.GetGateway(task, false)
    if xerr != nil {
        if _, ok := xerr.(*fail.ErrNotFound); !ok {
            return xerr
        }
    }

    if _, xerr = primaryGateway.WaitSSHReady(task, temporal.GetExecutionTimeout()); xerr != nil {
        return fail.Wrap(xerr, "wait for remote ssh service to be ready")
    }

    // Loads secondary gateway metadata
    if secondaryGateway != nil {
        if _, xerr = secondaryGateway.WaitSSHReady(task, temporal.GetExecutionTimeout()); xerr != nil {
            return fail.Wrap(xerr, "wait for remote ssh service to be ready")
        }
    }

    masterCount, privateNodeCount, _, xerr := c.determineRequiredNodes(task)
    if xerr != nil {
        return xerr
    }

    var (
        primaryGatewayStatus, secondaryGatewayStatus fail.Error
        mastersStatus, privateNodesStatus            fail.Error
        primaryGatewayTask, secondaryGatewayTask     concurrency.Task
    )

    // Step 1: starts gateway installation plus masters creation plus nodes creation
    primaryGatewayTask, xerr = task.StartInSubtask(c.taskInstallGateway, primaryGateway)
    if xerr != nil {
        return xerr
    }
    if secondaryGateway != nil {
        if secondaryGatewayTask, xerr = task.StartInSubtask(c.taskInstallGateway, secondaryGateway); xerr != nil {
            return xerr
        }
    }
    mastersTask, xerr := task.StartInSubtask(c.taskCreateMasters, data.Map{
        "count":     masterCount,
        "masterDef": mastersDef,
        "nokeep":    !keepOnFailure,
    })
    if xerr != nil {
        return xerr
    }

    privateNodesTask, xerr := task.StartInSubtask(c.taskCreateNodes, data.Map{
        "count":   privateNodeCount,
        "public":  false,
        "nodeDef": nodesDef,
        "nokeep":  !keepOnFailure,
    })
    if xerr != nil {
        return xerr
    }

    // Step 2: awaits gateway installation end and masters installation end
    if _, primaryGatewayStatus = primaryGatewayTask.Wait(); primaryGatewayStatus != nil {
        if abortMasterErr := mastersTask.Abort(); abortMasterErr != nil {
            _ = primaryGatewayStatus.AddConsequence(abortMasterErr)
        }
        if abortNodesErr := privateNodesTask.Abort(); abortNodesErr != nil {
            _ = primaryGatewayStatus.AddConsequence(abortNodesErr)
        }
        return primaryGatewayStatus
    }
    if secondaryGateway != nil && secondaryGatewayTask != nil {
        if _, secondaryGatewayStatus = secondaryGatewayTask.Wait(); secondaryGatewayStatus != nil {
            if abortMasterErr := mastersTask.Abort(); abortMasterErr != nil {
                _ = secondaryGatewayStatus.AddConsequence(abortMasterErr)
            }
            if abortNodesErr := privateNodesTask.Abort(); abortNodesErr != nil {
                _ = secondaryGatewayStatus.AddConsequence(abortNodesErr)
            }
            return secondaryGatewayStatus
        }
    }

    // Starting from here, delete masters if exiting with error and req.KeepOnFailure is not true
    defer func() {
        if xerr != nil && !keepOnFailure {
            list, merr := c.ListMasterIDs(task)
            if merr != nil {
                _ = xerr.AddConsequence(merr)
            } else {
                tg, tgerr := concurrency.NewTaskGroup(task)
                if tgerr != nil {
                    _ = xerr.AddConsequence(tgerr)
                } else {
                    for _, v := range list {
                        _, _ = tg.StartInSubtask(c.taskDeleteHost, data.Map{"host": v})
                    }
                    _, _, derr := tg.WaitGroupFor(temporal.GetLongOperationTimeout())
                    if derr != nil {
                        _ = xerr.AddConsequence(derr)
                    }
                }
            }
        }
    }()

    _, mastersStatus = mastersTask.Wait()
    if mastersStatus != nil {
        abortNodesErr := privateNodesTask.Abort()
        if abortNodesErr != nil {
            _ = mastersStatus.AddConsequence(abortNodesErr)
        }
        return mastersStatus
    }

    // Step 3: run (not start so no parallelism here) gateway configuration (needs MasterIPs so masters must be installed first)
    // Configure getGateway(s) and waits for the result
    if primaryGatewayTask, xerr = task.StartInSubtask(c.taskConfigureGateway, primaryGateway); xerr != nil {
        return xerr
    }
    if !gwFailoverDisabled {
        if secondaryGatewayTask, xerr = task.StartInSubtask(c.taskConfigureGateway, secondaryGateway); xerr != nil {
            return xerr
        }
    }
    if _, primaryGatewayStatus = primaryGatewayTask.Wait(); primaryGatewayStatus != nil {
        if !gwFailoverDisabled {
            if secondaryGatewayTask != nil {
                if secondaryGatewayErr := secondaryGatewayTask.Abort(); secondaryGatewayErr != nil {
                    _ = primaryGatewayStatus.AddConsequence(secondaryGatewayErr)
                }
            }
        }
        return primaryGatewayStatus
    }

    if !gwFailoverDisabled {
        if secondaryGatewayTask != nil {
            if _, secondaryGatewayStatus = secondaryGatewayTask.Wait(); secondaryGatewayStatus != nil {
                return secondaryGatewayStatus
            }
        }
    }

    // Step 4: configure masters (if masters created successfully and gateway configure successfully)
    if _, mastersStatus = task.RunInSubtask(c.taskConfigureMasters, nil); mastersStatus != nil {
        return mastersStatus
    }

    defer func() {
        if xerr != nil && !keepOnFailure {
            list, merr := c.ListNodeIDs(task)
            if merr != nil {
                _ = xerr.AddConsequence(merr)
            } else {
                tg, tgerr := concurrency.NewTaskGroup(task)
                if tgerr != nil {
                    _ = xerr.AddConsequence(tgerr)
                } else {
                    for _, v := range list {
                        _, _ = tg.StartInSubtask(c.taskDeleteHost, data.Map{"host": v})
                    }
                    _, _, derr := tg.WaitGroupFor(temporal.GetLongOperationTimeout())
                    if derr != nil {
                        _ = xerr.AddConsequence(derr)
                    }
                }
            }
        }
    }()

    // Step 5: awaits nodes creation
    if _, privateNodesStatus = privateNodesTask.Wait(); privateNodesStatus != nil {
        return privateNodesStatus
    }

    // Step 6: Starts nodes configuration, if all masters and nodes
    // have been created and gateway has been configured with success
    if _, privateNodesStatus = task.RunInSubtask(c.taskConfigureNodes, nil); privateNodesStatus != nil {
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
        // if finalDef.ImageID == "" {
        // 	finalDef.ImageId = def.ImageId
        // }

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

// Serialize converts cluster data to JSON
// satisfies interface data.Serializable
func (c *cluster) Serialize(task concurrency.Task) ([]byte, fail.Error) {
    if c.IsNull() {
        return []byte{}, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }

    c.SafeRLock(task)
    defer c.SafeRUnlock(task)

    r, err := json.Marshal(c)
    return r, fail.ToError(err)
}

// Deserialize reads json code and reinstantiates cluster
// satisfies interface data.Serializable
func (c *cluster) Deserialize(task concurrency.Task, buf []byte) (xerr fail.Error) {
    if c.IsNull() {
        return fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }
    if len(buf) == 0 {
        return fail.InvalidParameterError("buf", "cannot be empty []byte")
    }

    defer fail.OnPanic(&xerr) // json.Unmarshal may panic

    c.SafeLock(task)
    defer c.SafeUnlock(task)

    err := json.Unmarshal(buf, c)
    return fail.ToError(err)
}

// Bootstrap (re)connects controller with the appropriate Makers
func (c *cluster) Bootstrap(task concurrency.Task) (xerr fail.Error) {
    if c.IsNull() {
        return fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }

    defer fail.OnPanic(&xerr) // c.Lock()/Unlock() may panic

    c.SafeLock(task)
    defer c.SafeUnlock(task)

    switch c.ClusterIdentity.Flavor {
    case clusterflavor.BOH:
        c.makers = boh.Makers
    case clusterflavor.K8S:
        c.makers = k8s.Makers
    default:
        return fail.NotImplementedError("unknown cluster Flavor '%d'", c.ClusterIdentity.Flavor)
    }
    return nil
}

// Browse walks through cluster folder and executes a callback for each entry
func (c *cluster) Browse(task concurrency.Task, callback func(*abstract.ClusterIdentity) fail.Error) fail.Error {
    // c cannot be nil but can be Null value
    // this means we can call Browse() on a new (as returned by NewCluster()) instance without first loading it
    if c == nil {
        return fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be null")
    }
    if callback == nil {
        return fail.InvalidParameterError("callback", "cannot be nil")
    }

    return c.core.BrowseFolder(task, func(buf []byte) fail.Error {
        aci := abstract.NewClusterIdentity()
        if xerr := aci.Deserialize(buf); xerr != nil {
            return xerr
        }
        return callback(aci)
    })
}

// GetIdentity returns the identity of the cluster
func (c *cluster) GetIdentity(task concurrency.Task) (abstract.ClusterIdentity, fail.Error) {
    if c.IsNull() {
        return abstract.ClusterIdentity{}, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return abstract.ClusterIdentity{}, fail.InvalidParameterError("task", "cannot be nil")
    }

    c.SafeRLock(task)
    defer c.SafeRUnlock(task)

    return c.ClusterIdentity, nil
}

// Identity returns the identity of the cluster
// Intended to be used when c, task are notiously not nil (because previously checked)
func (c *cluster) Identity(task concurrency.Task) abstract.ClusterIdentity {
    identity, _ := c.GetIdentity(task)
    return identity
}

// GetFlavor returns the flavor of the cluster
//
// satisfies interface cluster.Controller
func (c *cluster) GetFlavor(task concurrency.Task) (flavor clusterflavor.Enum, xerr fail.Error) {
    if c.IsNull() {
        return 0, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return 0, fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

    c.SafeRLock(task)
    defer c.SafeRUnlock(task)

    return c.ClusterIdentity.Flavor, nil
}

// Flavor returns the flavor of the cluster
// Intended to be used when c, task are notoriously not nil (because previously checked)
// satisfies interface cluster.Controller
func (c *cluster) Flavor(task concurrency.Task) (flavor clusterflavor.Enum) {
    flavor, _ = c.GetFlavor(task)
    return flavor
}

// GetComplexity returns the complexity of the cluster
// satisfies interface cluster.Controller
func (c *cluster) GetComplexity(task concurrency.Task) (complexity clustercomplexity.Enum, xerr fail.Error) {
    if c.IsNull() {
        return 0, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return 0, fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

    c.SafeRLock(task)
    defer c.SafeRUnlock(task)

    return c.ClusterIdentity.Complexity, nil
}

// Complexity returns the complexity of the cluster
// Intended to be used when c, task are notoriously not nim (because previously checked)
// satisfies interface cluster.Controller
func (c *cluster) Complexity(task concurrency.Task) (complexity clustercomplexity.Enum) {
    complexity, _ = c.GetComplexity(task)
    return complexity
}

// GetAdminPassword returns the password of the cluster admin account
// satisfies interface cluster.Controller
func (c *cluster) GetAdminPassword(task concurrency.Task) (adminPassword string, xerr fail.Error) {
    if c.IsNull() {
        return "", fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return "", fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    c.SafeRLock(task)
    defer c.SafeRUnlock(task)

    return c.ClusterIdentity.AdminPassword, nil
}

// AdminPassword returns the password of the cluster admin account
// Intended to be used when c, task are notoriously not nil
// satisfies interface resources.Cluster
func (c *cluster) AdminPassword(task concurrency.Task) (adminPassword string) {
    adminPassword, _ = c.GetAdminPassword(task)
    return adminPassword
}

// GetKeyPair returns the key pair used in the cluster
// satisfies interface cluster.Controller
func (c *cluster) GetKeyPair(task concurrency.Task) (keyPair abstract.KeyPair, xerr fail.Error) {
    keyPair = abstract.KeyPair{}
    if c.IsNull() {
        return keyPair, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return keyPair, fail.InvalidParameterError("task", "cannot be nil")
    }

    c.SafeRLock(task)
    defer c.SafeRUnlock(task)

    return *c.ClusterIdentity.Keypair, nil
}

// KeyPair returns the key pair used in the cluster
// Intended to be used when c, task are notoriously not nil (because previously checked)
// satisfies interface cluster.Controller
func (c *cluster) KeyPair(task concurrency.Task) abstract.KeyPair {
    keyPair, _ := c.GetKeyPair(task)
    return keyPair
}

// GetNetworkConfig returns network configuration of the cluster
// satisfies interface cluster.Controller
func (c *cluster) GetNetworkConfig(task concurrency.Task) (config *propertiesv2.ClusterNetwork, xerr fail.Error) {
    config = &propertiesv2.ClusterNetwork{}
    if c.IsNull() {
        return config, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return config, fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    xerr = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        if props.Lookup(clusterproperty.NetworkV2) {
            return props.Inspect(task, clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
                networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
                if !ok {
                    return fail.InconsistentError("'*propertiesv2.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                config = networkV2
                return nil
            })
        }
        innerErr := props.Inspect(task, clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
            networkV1 := clonable.(*propertiesv1.ClusterNetwork)
            config = &propertiesv2.ClusterNetwork{
                NetworkID: networkV1.NetworkID,
                CIDR:      networkV1.CIDR,
                // GatewayID:      networkV1.GatewayID,
                // GatewayIP:      networkV1.GatewayIP,
                // DefaultRouteIP: networkV1.GatewayIP,
                // EndpointIP:     networkV1.PublicIP,
            }
            return nil
        })
        if innerErr != nil {
            return innerErr
        }

        return props.Alter(task, clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
            networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            _ = networkV2.Replace(config)
            return nil
        })
    })
    return config, xerr
}

// NetworkConfig returns network configuration of the cluster
// Intended to be used when c, task are notoriously not nil (because previously checked)
// satisfies interface resources.Cluster
func (c *cluster) NetworkConfig(task concurrency.Task) (config *propertiesv2.ClusterNetwork) {
    config, _ = c.GetNetworkConfig(task)
    return config
}

// Start starts the cluster
// satisfies interface cluster.cluster.Controller
func (c *cluster) Start(task concurrency.Task) (xerr fail.Error) {
    if c.IsNull() {
        return fail.InvalidInstanceError()
    }

    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
    defer fail.OnPanic(&xerr)

    // If the cluster is in state Stopping or Stopped, do nothing
    var prevState clusterstate.Enum
    prevState, xerr = c.State(task)
    if xerr != nil {
        return xerr
    }
    if prevState == clusterstate.Stopping || prevState == clusterstate.Stopped {
        return nil
    }

    // If the cluster is in state Starting, wait for it to finish its start procedure
    if prevState == clusterstate.Starting {
        xerr = retry.WhileUnsuccessfulDelay5Seconds(
            func() error {
                state, innerErr := c.State(task)
                if innerErr != nil {
                    return innerErr
                }
                if state == clusterstate.Nominal || state == clusterstate.Degraded {
                    return nil
                }
                return fail.NewError("current state of cluster is '%s'", state.String())
            },
            5*time.Minute, // FIXME: static timeout
        )
        if xerr != nil {
            if _, ok := xerr.(*retry.ErrTimeout); ok {
                xerr = fail.Wrap(xerr, "timeout waiting cluster to become started")
            }
            return xerr
        }
        return nil
    }

    if prevState != clusterstate.Stopped {
        return fail.NotAvailableError("failed to start cluster because of it's current state: %s", prevState.String())
    }

    // First mark cluster to be in state Starting
    xerr = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            stateV1.State = clusterstate.Starting
            return nil
        })
    })
    if xerr != nil {
        return xerr
    }

    var (
        nodes                         []*propertiesv2.ClusterNode
        masters                       []*propertiesv2.ClusterNode
        gatewayID, secondaryGatewayID string
    )

    // Then start it and mark it as STARTED on success
    xerr = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        innerErr := props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            masters = nodesV2.Masters
            nodes = nodesV2.PrivateNodes
            return nil
        })
        if innerErr != nil {
            return fail.Wrap(innerErr, "failed to get list of hosts")
        }
        if props.Lookup(clusterproperty.NetworkV2) {
            innerErr = props.Inspect(task, clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
                networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
                if !ok {
                    return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                gatewayID = networkV2.GatewayID
                secondaryGatewayID = networkV2.SecondaryGatewayID
                return nil
            })
        } else {
            // Legacy...
            innerErr = props.Inspect(task, clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
                networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
                if !ok {
                    return fail.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                gatewayID = networkV1.GatewayID
                return nil
            })
        }
        if innerErr != nil {
            return innerErr
        }

        // Mark cluster as state Starting
        return props.Alter(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.GetState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            stateV1.State = clusterstate.Starting
            return nil
        })
    })
    if xerr != nil {
        return xerr
    }

    // Start gateway(s)
    taskGroup, xerr := concurrency.NewTaskGroup(task)
    if xerr != nil {
        return xerr
    }
    if _, xerr = taskGroup.Start(c.taskStartHost, gatewayID); xerr != nil {
        return xerr
    }
    if secondaryGatewayID != "" {
        if _, xerr = taskGroup.Start(c.taskStartHost, secondaryGatewayID); xerr != nil {
            return xerr
        }
    }
    // Start masters
    for _, n := range masters {
        if _, xerr = taskGroup.Start(c.taskStartHost, n.ID); xerr != nil {
            return xerr
        }
    }
    // Start nodes
    for _, n := range nodes {
        if _, xerr = taskGroup.Start(c.taskStartHost, n.ID); xerr != nil {
            return xerr
        }
    }
    if _, xerr = taskGroup.WaitGroup(); xerr != nil {
        return xerr
    }

    return c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.GetState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            stateV1.State = clusterstate.Nominal
            return nil
        })
    })
}

// Stop stops the cluster
func (c *cluster) Stop(task concurrency.Task) (xerr fail.Error) {
    if c == nil {
        return fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    // If the cluster is stopped, do nothing
    var prevState clusterstate.Enum
    prevState, xerr = c.State(task)
    if xerr != nil {
        return xerr
    }
    if prevState == clusterstate.Stopped {
        return nil
    }

    // If the cluster is already stopping, wait for it to terminate the procedure
    if prevState == clusterstate.Stopping {
        xerr = retry.WhileUnsuccessfulDelay5Seconds(
            func() error {
                state, innerErr := c.State(task)
                if innerErr != nil {
                    return innerErr
                }
                if state != clusterstate.Stopped {
                    return fail.NotAvailableError("current state of cluster is '%s'", state.String())
                }
                return nil
            },
            5*time.Minute, // FIXME: static timeout
        )
        if xerr != nil {
            if _, ok := xerr.(*retry.ErrTimeout); ok {
                xerr = fail.Wrap(xerr, "timeout waiting cluster transitioning from state Stopping to Stopped")
            }
            return xerr
        }
        return nil
    }

    // If the cluster is not in state Nominal or Degraded, can't stop
    if prevState != clusterstate.Nominal && prevState != clusterstate.Degraded {
        return fail.NotAvailableError("failed to stop cluster because of it's current state: %s", prevState.String())
    }

    // First mark cluster to be in state Stopping
    xerr = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.GetState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            stateV1.State = clusterstate.Stopping
            return nil
        })
    })
    if xerr != nil {
        return xerr
    }

    // Then stop it and mark it as STOPPED on success
    return c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        var (
            nodes                         []*propertiesv2.ClusterNode
            masters                       []*propertiesv2.ClusterNode
            gatewayID, secondaryGatewayID string
        )
        innerErr := props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            masters = nodesV2.Masters
            nodes = nodesV2.PrivateNodes
            return nil
        })
        if innerErr != nil {
            return fail.Wrap(innerErr, "failed to get list of hosts")
        }

        if props.Lookup(clusterproperty.NetworkV2) {
            innerErr = props.Inspect(task, clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
                networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
                if !ok {
                    return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                gatewayID = networkV2.GatewayID
                secondaryGatewayID = networkV2.SecondaryGatewayID
                return nil
            })
        } else {
            // Legacy ...
            innerErr = props.Inspect(task, clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
                networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
                if !ok {
                    return fail.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                gatewayID = networkV1.GatewayID
                return nil
            })
        }
        if innerErr != nil {
            return innerErr
        }

        // Stop nodes
        taskGroup, innerErr := concurrency.NewTaskGroup(task)
        if innerErr != nil {
            return innerErr
        }

        for _, n := range nodes {
            if _, innerErr = taskGroup.Start(c.taskStopHost, n.ID); innerErr != nil {
                return innerErr
            }
        }
        // Stop masters
        for _, n := range masters {
            if _, innerErr = taskGroup.Start(c.taskStopHost, n.ID); innerErr != nil {
                return innerErr
            }
        }
        // Stop gateway(s)
        if _, innerErr = taskGroup.Start(c.taskStopHost, gatewayID); innerErr != nil {
            return innerErr
        }
        if secondaryGatewayID != "" {
            if _, innerErr = taskGroup.Start(c.taskStopHost, secondaryGatewayID); innerErr != nil {
                return innerErr
            }
        }

        if _, innerErr = taskGroup.WaitGroup(); innerErr != nil {
            return innerErr
        }

        return props.Alter(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.GetState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            stateV1.State = clusterstate.Stopped
            return nil
        })
    })
}

// GetState returns the current state of the Cluster
// Uses the "maker" ForceGetState from Foreman
func (c *cluster) State(task concurrency.Task) (state clusterstate.Enum, xerr fail.Error) {
    state = clusterstate.Unknown
    if c == nil {
        return state, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return state, fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))
    defer fail.OnPanic(&xerr)

    if c.makers.GetState != nil {
        state, xerr = c.makers.GetState(task, c)
    } else {
        state = clusterstate.Unknown
        xerr = fail.NotImplementedError("cluster maker does not define 'ForceGetState'")
    }
    if xerr != nil {
        return clusterstate.Unknown, xerr
    }
    return state, c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            stateV1.State = state
            c.lastStateCollection = time.Now()
            return nil
        })
    })
}

// AddNode adds a node
//
// satisfies interface cluster.Controller
func (c *cluster) AddNode(task concurrency.Task, def *abstract.HostSizingRequirements, image string) (_ resources.Host, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    if def == nil {
        return nil, fail.InvalidParameterError("def", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    nodes, xerr := c.AddNodes(task, 1, def, image)
    if xerr != nil {
        return nil, xerr
    }

    return nodes[0], nil
}

// AddNodes adds several nodes
func (c *cluster) AddNodes(task concurrency.Task, count int, def *abstract.HostSizingRequirements, image string) (_ []resources.Host, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    if count <= 0 {
        return nil, fail.InvalidParameterError("count", "must be an int > 0")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d)", count)
    defer tracer.Entering().Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

    var hostImage string
    xerr = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        if !props.Lookup(clusterproperty.DefaultsV2) {
            // If property.DefaultsV2 is not found but there is a property.DefaultsV1, converts it to DefaultsV2
            return props.Inspect(task, clusterproperty.DefaultsV1, func(clonable data.Clonable) fail.Error {
                defaultsV1, ok := clonable.(*propertiesv1.ClusterDefaults)
                if !ok {
                    return fail.InconsistentError("'*propertiesv1.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                return props.Alter(task, clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
                    defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
                    if !ok {
                        return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
                    }
                    convertDefaultsV1ToDefaultsV2(defaultsV1, defaultsV2)
                    return nil
                })
            })
        }
        return nil
    })
    if xerr != nil {
        return nil, xerr
    }

    var nodeDef *propertiesv2.HostSizingRequirements
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
            defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            nodeDef = &defaultsV2.NodeSizing
            hostImage = defaultsV2.Image
            return nil
        })
    })
    if xerr != nil {
        return nil, xerr
    }
    nodeDef = complementHostDefinition(def, *nodeDef)

    var (
        nodeTypeStr string
        errors      []string
        hosts       []resources.Host
    )

    timeout := temporal.GetExecutionTimeout() + time.Duration(count)*time.Minute

    var subtasks []concurrency.Task
    for i := 0; i < count; i++ {
        subtask, xerr := task.StartInSubtask(c.taskCreateNode, data.Map{
            "index":   i + 1,
            "nodeDef": nodeDef,
            "image":   hostImage,
            "timeout": timeout,
            "nokeep":  false,
        })
        if xerr != nil {
            return nil, xerr
        }
        subtasks = append(subtasks, subtask)
    }
    for _, s := range subtasks {
        res, err := s.Wait()
        if err != nil {
            errors = append(errors, err.Error())
        } else {
            hosts = append(hosts, res.(resources.Host))
        }
    }

    // Starting from here, delete nodes if exiting with error
    newHosts := hosts
    defer func() {
        if xerr != nil {
            if len(newHosts) > 0 {
                derr := c.deleteHosts(task, newHosts)
                if derr != nil {
                    logrus.Errorf("failed to delete nodes after failure to expand cluster")
                }
                _ = xerr.AddConsequence(derr)
            }
        }
    }()

    if len(errors) > 0 {
        xerr = fail.NewError("errors occurred on %s node%s addition: %s", nodeTypeStr, strprocess.Plural(uint(len(errors))), strings.Join(errors, "\n"))
        return nil, xerr
    }

    // Now configure new nodes
    if xerr = c.configureNodesFromList(task, hosts); xerr != nil {
        return nil, xerr
    }

    // At last join nodes to cluster
    if xerr = c.joinNodesFromList(task, hosts); xerr != nil {
        return nil, xerr
    }

    return hosts, nil
}

// complementHostDefinition complements req with default values if needed
func complementHostDefinition(req *abstract.HostSizingRequirements, def propertiesv2.HostSizingRequirements) *propertiesv2.HostSizingRequirements {
    var finalDef propertiesv2.HostSizingRequirements
    if req == nil {
        finalDef = def
    } else {
        finalDef = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*req)

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
        // if finalDef.ImageId == "" {
        // 	finalDef.ImageId = def.ImageId
        // }

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

func convertDefaultsV1ToDefaultsV2(defaultsV1 *propertiesv1.ClusterDefaults, defaultsV2 *propertiesv2.ClusterDefaults) {
    defaultsV2.Image = defaultsV1.Image
    defaultsV2.GatewaySizing = propertiesv2.HostSizingRequirements{
        MinCores:    defaultsV1.GatewaySizing.Cores,
        MinCPUFreq:  defaultsV1.GatewaySizing.CPUFreq,
        MinGPU:      defaultsV1.GatewaySizing.GPUNumber,
        MinRAMSize:  defaultsV1.GatewaySizing.RAMSize,
        MinDiskSize: defaultsV1.GatewaySizing.DiskSize,
        Replaceable: defaultsV1.GatewaySizing.Replaceable,
    }
    defaultsV2.MasterSizing = propertiesv2.HostSizingRequirements{
        MinCores:    defaultsV1.MasterSizing.Cores,
        MinCPUFreq:  defaultsV1.MasterSizing.CPUFreq,
        MinGPU:      defaultsV1.MasterSizing.GPUNumber,
        MinRAMSize:  defaultsV1.MasterSizing.RAMSize,
        MinDiskSize: defaultsV1.MasterSizing.DiskSize,
        Replaceable: defaultsV1.MasterSizing.Replaceable,
    }
    defaultsV2.NodeSizing = propertiesv2.HostSizingRequirements{
        MinCores:    defaultsV1.NodeSizing.Cores,
        MinCPUFreq:  defaultsV1.NodeSizing.CPUFreq,
        MinGPU:      defaultsV1.NodeSizing.GPUNumber,
        MinRAMSize:  defaultsV1.NodeSizing.RAMSize,
        MinDiskSize: defaultsV1.NodeSizing.DiskSize,
        Replaceable: defaultsV1.NodeSizing.Replaceable,
    }
}

// DeleteLastNode deletes the last added node and returns its name
func (c *cluster) DeleteLastNode(task concurrency.Task) (node *propertiesv2.ClusterNode, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    selectedMaster, xerr := c.FindAvailableMaster(task)
    if xerr != nil {
        return nil, xerr
    }

    // Removed reference of the node from cluster
    xerr = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        innerErr := props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            node = nodesV2.PrivateNodes[len(nodesV2.PrivateNodes)-1]
            return nil
        })
        if innerErr != nil {
            return innerErr
        }
        return c.DeleteSpecificNode(task, node.ID, selectedMaster.GetID())
    })
    if xerr != nil {
        return nil, xerr
    }
    return node, nil
}

// DeleteSpecificNode deletes a node identified by its GetID
func (c *cluster) DeleteSpecificNode(task concurrency.Task, hostID string, selectedMasterID string) (xerr fail.Error) {
    if c == nil {
        return fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return fail.InvalidParameterError("task", "cannot be nil")
    }
    if hostID == "" {
        return fail.InvalidParameterError("hostID", "cannot be empty string")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    var selectedMaster resources.Host
    if selectedMasterID == "" {
        selectedMaster, xerr = c.FindAvailableMaster(task)
        if xerr != nil {
            return xerr
        }
    }

    // Identifies the node to delete and remove it preventively from metadata
    var node *propertiesv2.ClusterNode
    xerr = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            found, idx := containsClusterNode(nodesV2.PrivateNodes, hostID)
            if !found {
                return fail.NotFoundError("failed to find host '%s'", hostID)
            }
            node = nodesV2.PrivateNodes[idx]

            length := len(nodesV2.PrivateNodes)
            if idx < length-1 {
                nodesV2.PrivateNodes = append(nodesV2.PrivateNodes[:idx], nodesV2.PrivateNodes[idx+1:]...)
            } else {
                nodesV2.PrivateNodes = nodesV2.PrivateNodes[:idx]
            }
            return nil
        })
    })
    if xerr != nil {
        return xerr
    }

    // Starting from here, restore node in cluster metadata if exiting with error
    defer func() {
        if xerr != nil {
            derr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
                return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
                    nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
                    if !ok {
                        return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
                    }
                    nodesV2.PrivateNodes = append(nodesV2.PrivateNodes, node)
                    return nil
                })
            })
            if derr != nil {
                logrus.Errorf("failed to restore node ownership in cluster")
            }
            _ = xerr.AddConsequence(derr)
        }
    }()

    // Deletes node
    return c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        // Leave node from cluster, if selectedMasterID isn't empty
        if selectedMasterID != "" {
            if innerErr := c.leaveNodesFromList(task, []string{node.ID}, selectedMaster); innerErr != nil {
                return innerErr
            }
        }
        host, innerErr := LoadHost(task, c.service, node.ID)
        if innerErr != nil {
            return innerErr
        }
        if c.makers.UnconfigureNode != nil {
            if innerErr = c.makers.UnconfigureNode(task, c, host, selectedMaster); innerErr != nil {
                return innerErr
            }
        }

        // Finally delete host
        if innerErr = host.Delete(task); innerErr != nil {
            if _, ok := innerErr.(*fail.ErrNotFound); ok {
                // host seems already deleted, so it's a success
                return nil
            }
            return innerErr
        }
        return nil
    })
}

// ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
func (c *cluster) ListMasters(task concurrency.Task) (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnPanic(&xerr)
    defer fail.OnExitLogError(&xerr, "failed to get list of masters")

    list = resources.IndexedListOfClusterNodes{}
    xerr = c.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            for _, v := range nodesV2.Masters {
                host, innerErr := LoadHost(task, c.service, v.ID)
                if innerErr != nil {
                    return innerErr
                }
                list[v.NumericalID] = host
            }
            return nil
        })
    })
    return list, xerr
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (c *cluster) ListMasterNames(task concurrency.Task) (list data.IndexedListOfStrings, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnPanic(&xerr)

    list = data.IndexedListOfStrings{}
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            for _, v := range nodesV2.Masters {
                list[v.NumericalID] = v.Name
            }
            return nil
        })
    })
    if xerr != nil {
        return nil, xerr
    }
    return list, nil
}

// ListMasterIDs lists the IDs of masters (if there is such masters in the flavor...)
func (c *cluster) ListMasterIDs(task concurrency.Task) (list data.IndexedListOfStrings, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnExitLogError(&xerr, "failed to get list of master IDs")
    defer fail.OnPanic(&xerr)

    list = data.IndexedListOfStrings{}
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            for _, v := range nodesV2.Masters {
                list[v.NumericalID] = v.ID
            }
            return nil
        })
    })
    return list, xerr
}

// ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (c *cluster) ListMasterIPs(task concurrency.Task) (list data.IndexedListOfStrings, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnExitLogError(&xerr, "failed to get list of master IPs")
    defer fail.OnPanic(&xerr)

    list = data.IndexedListOfStrings{}
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            for _, v := range nodesV2.Masters {
                list[v.NumericalID] = v.PrivateIP
            }
            return nil
        })
    })
    return list, xerr
}

// FindAvailableMaster returns GetID of the first master available to execute order
// satisfies interface cluster.cluster.Controller
func (c *cluster) FindAvailableMaster(task concurrency.Task) (master resources.Host, xerr fail.Error) {
    master = nil
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnPanic(&xerr)

    found := false
    masters, err := c.ListMasters(task)
    if err != nil {
        return nil, err
    }

    var lastError error
    svc := c.GetService()
    for _, v := range masters {
        master, err = LoadHost(task, svc, v.GetID())
        if err != nil {
            return nil, err
        }

        _, err = master.WaitSSHReady(task, temporal.GetConnectSSHTimeout())
        if err != nil {
            if _, ok := err.(*retry.ErrTimeout); ok {
                lastError = err
                continue
            }
            return nil, err
        }
        found = true
        break
    }
    if !found {
        return nil, fail.NotAvailableError("failed to find available master: %v", lastError)
    }
    return master, nil
}

// ListNodes lists node instances corresponding to the nodes in the cluster
// satisfies interface cluster.Controller
func (c *cluster) ListNodes(task concurrency.Task) (list resources.IndexedListOfClusterNodes, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnPanic(&xerr)

    list = resources.IndexedListOfClusterNodes{}
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            for _, v := range nodesV2.PrivateNodes {
                host, innerErr := LoadHost(task, c.service, v.ID)
                if innerErr != nil {
                    return innerErr
                }
                list[v.NumericalID] = host
            }
            return nil
        })
    })
    if xerr != nil {
        return nil, xerr
    }
    return list, nil
}

// ListNodeNames lists the names of the nodes in the Cluster
func (c *cluster) ListNodeNames(task concurrency.Task) (list data.IndexedListOfStrings, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnPanic(&xerr)

    list = data.IndexedListOfStrings{}
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            for _, v := range nodesV2.PrivateNodes {
                list[v.NumericalID] = v.Name
            }
            return nil
        })
    })
    if xerr != nil {
        // logrus.Errorf("failed to get list of node IDs: %v", err)
        return nil, xerr
    }
    return list, xerr
}

// ListNodeIDs lists IDs of the nodes in the cluster
func (c *cluster) ListNodeIDs(task concurrency.Task) (list data.IndexedListOfStrings, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnPanic(&xerr)

    list = data.IndexedListOfStrings{}
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            for _, v := range nodesV2.PrivateNodes {
                list[v.NumericalID] = v.ID
            }
            return nil
        })
    })
    if xerr != nil {
        return nil, xerr
    }
    return list, xerr
}

// ListNodeIPs lists the IPs of the nodes in the cluster
// satisfies interface cluster.cluster.Controller
func (c *cluster) ListNodeIPs(task concurrency.Task) (list data.IndexedListOfStrings, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task == nil {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnExitLogError(&xerr, "failed to get list of node IP addresses")
    defer fail.OnPanic(&xerr)

    list = data.IndexedListOfStrings{}
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            for _, v := range nodesV2.PrivateNodes {
                list[v.NumericalID] = v.PrivateIP
            }
            return nil
        })
    })
    if xerr != nil {
        return nil, xerr
    }
    return list, nil
}

// FindAvailableNode returns node instance of the first node available to execute order
// satisfies interface cluster.cluster.Controller
func (c *cluster) FindAvailableNode(task concurrency.Task) (node resources.Host, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task == nil {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
    defer fail.OnPanic(&xerr)

    list, err := c.ListNodes(task)
    if err != nil {
        return nil, err
    }

    found := false
    for _, v := range list {
        _, err = v.WaitSSHReady(task, temporal.GetConnectSSHTimeout())
        if err != nil {
            if _, ok := err.(*retry.ErrTimeout); ok {
                continue
            }
            return nil, err
        }
        found = true
        node = v
        break
    }
    if !found {
        return nil, fail.NotAvailableError("failed to find available node")
    }
    return node, nil
}

// LookupNode tells if the GetID of the host passed as parameter is a node
// satisfies interface cluster.cluster.Controller
func (c *cluster) LookupNode(task concurrency.Task, ref string) (found bool, xerr fail.Error) {
    if c == nil {
        return false, fail.InvalidInstanceError()
    }
    if ref == "" {
        return false, fail.InvalidParameterError("ref", "cannot be empty string")
    }
    if task == nil {
        return false, fail.InvalidParameterError("task", "cannot be nil")
    }
    defer fail.OnPanic(&xerr)

    var host resources.Host
    if host, xerr = LoadHost(task, c.service, ref); xerr != nil {
        return false, xerr
    }
    hostID := host.GetID()

    found = false
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            found, _ = containsClusterNode(nodesV2.PrivateNodes, hostID)
            return nil
        })
    })
    return found, xerr
}

// CountNodes counts the nodes of the cluster
// satisfies interface cluster.cluster.Controller
func (c *cluster) CountNodes(task concurrency.Task) (count uint, xerr fail.Error) {
    if c == nil {
        return 0, fail.InvalidInstanceError()
    }
    if task == nil {
        return 0, fail.InvalidParameterError("task", "cannot be nil")
    }

    defer fail.OnExitLogError(&xerr, debug.NewTracer(task, tracing.ShouldTrace("cluster")).TraceMessage())

    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            count = uint(len(nodesV2.PrivateNodes))
            return nil
        })
    })
    if xerr != nil {
        xerr = fail.Wrap(xerr, "failed to count nodes")
        return 0, xerr
    }
    return count, nil
}

// Node returns a node based on its GetID
func (c *cluster) Node(task concurrency.Task, hostID string) (host resources.Host, xerr fail.Error) {
    if c == nil {
        return nil, fail.InvalidInstanceError()
    }
    if task == nil {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    if hostID == "" {
        return nil, fail.InvalidParameterError("hostID", "cannot be empty string")
    }

    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%s)", hostID)
    defer tracer.Entering().Exiting()
    defer fail.OnExitLogError(&xerr, "failed to get node identified by '%s'", hostID)
    defer fail.OnPanic(&xerr)

    found := false
    xerr = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            found, _ = containsClusterNode(nodesV2.PrivateNodes, hostID)
            return nil
        })
    })
    if xerr != nil {
        return nil, xerr
    }
    if !found {
        return nil, fail.NotFoundError("failed to find node '%s' in Cluster '%s'", hostID, c.GetName)
    }
    return LoadHost(task, c.GetService(), hostID)
}

// deleteMaster deletes the master specified by its GetID
func (c *cluster) deleteMaster(task concurrency.Task, hostID string) fail.Error {
    if c == nil {
        return fail.InvalidInstanceError()
    }
    if hostID == "" {
        return fail.InvalidParameterError("hostID", "cannot be empty string")
    }

    var master *propertiesv2.ClusterNode
    // Removes master from cluster properties
    xerr := c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            found, idx := containsClusterNode(nodesV2.Masters, hostID)
            if !found {
                return abstract.ResourceNotFoundError("host", hostID)
            }
            master = nodesV2.Masters[idx]
            if idx < len(nodesV2.Masters)-1 {
                nodesV2.Masters = append(nodesV2.Masters[:idx], nodesV2.Masters[idx+1:]...)
            } else {
                nodesV2.Masters = nodesV2.Masters[:idx]
            }
            return nil
        })
    })
    if xerr != nil {
        return xerr
    }

    // Starting from here, restore master in cluster properties if exiting with error
    defer func() {
        if xerr != nil {
            derr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
                return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
                    nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
                    if !ok {
                        return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
                    }
                    nodesV2.Masters = append(nodesV2.Masters, master)
                    return nil
                })
            })
            if derr != nil {
                logrus.Errorf("After failure, cleanup failed to restore master '%s' in cluster", master.Name)
                _ = xerr.AddConsequence(derr)
            }
        }
    }()

    // Finally delete host
    return c.service.DeleteHost(master.ID)
}

// Delete allows to destroy infrastructure of cluster
// satisfies interface cluster.Controller
func (c *cluster) Delete(task concurrency.Task) fail.Error {
    if c == nil {
        return fail.InvalidInstanceError()
    }
    if task == nil {
        return fail.InvalidParameterError("task", "cannot be nil")
    }

    xerr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        // Updates cluster state to mark cluster as Removing
        return props.Alter(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            stateV1.State = clusterstate.Removed
            return nil
        })
    })
    if xerr != nil {
        return xerr
    }

    taskDeleteNode := func(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
        xerr := c.DeleteSpecificNode(t, params.(string), "")
        return nil, xerr
    }

    taskDeleteMaster := func(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
        xerr := c.deleteMaster(t, params.(string))
        return nil, xerr
    }

    var cleaningErrors []error

    // deletes the cluster
    xerr = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        // Deletes the nodes
        list, innerErr := c.ListNodes(task)
        if innerErr != nil {
            return innerErr
        }
        length := uint(len(list))
        if length > 0 {
            subtasks := make([]concurrency.Task, 0, length)
            for i := uint(0); i < length; i++ {
                subtask, innerErr := task.StartInSubtask(taskDeleteNode, list[i])
                if innerErr != nil {
                    cleaningErrors = append(cleaningErrors, fail.Wrap(innerErr, "failed to start deletion of node '%s'", list[i].GetName()))
                    break
                }
                subtasks = append(subtasks, subtask)
            }
            for _, s := range subtasks {
                _, subErr := s.Wait()
                if subErr != nil {
                    cleaningErrors = append(cleaningErrors, subErr)
                }
            }
        }

        // Delete the Masters
        list, innerErr = c.ListMasters(task)
        if innerErr != nil {
            cleaningErrors = append(cleaningErrors, innerErr)
            return fail.NewErrorList(cleaningErrors)
        }
        length = uint(len(list))
        if length > 0 {
            subtasks := make([]concurrency.Task, 0, length)
            for i := uint(0); i < length; i++ {
                subtask, innerErr := task.StartInSubtask(taskDeleteMaster, list[i])
                if innerErr != nil {
                    cleaningErrors = append(cleaningErrors, fail.Wrap(innerErr, "failed to start deletion of master '%s'", list[i].GetName()))
                    break
                }
                subtasks = append(subtasks, subtask)
            }
            for _, s := range subtasks {
                _, subErr := s.Wait()
                if subErr != nil {
                    cleaningErrors = append(cleaningErrors, subErr)
                }
            }
        }

        // Deletes the network and gateway
        networkID := ""
        if props.Lookup(clusterproperty.NetworkV2) {
            innerErr = props.Inspect(task, clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
                networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
                if !ok {
                    return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                networkID = networkV2.NetworkID
                return nil
            })
        } else {
            innerErr = props.Inspect(task, clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
                networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
                if !ok {
                    return fail.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                networkID = networkV1.NetworkID
                return nil
            })
        }
        if innerErr != nil {
            cleaningErrors = append(cleaningErrors, innerErr)
            return innerErr
        }

        network, innerErr := LoadNetwork(task, c.GetService(), networkID)
        if innerErr != nil {
            cleaningErrors = append(cleaningErrors, innerErr)
            return innerErr
        }
        return retry.WhileUnsuccessfulDelay5SecondsTimeout(
            func() error {
                return network.Delete(task)
            },
            temporal.GetHostTimeout(),
        )
    })
    if xerr != nil {
        return fail.NewErrorList(cleaningErrors)
    }

    return c.core.Delete(task)
}

// func deleteNodes(task concurrency.Task, svc iaas.GetService, nodes []*propertiesv2.ClusterNode) {
// 	length := len(nodes)
// 	if length > 0 {
// 		subtasks := make([]concurrency.Task, 0, length)
// 		for i := 0; i < length; i++ {
// 			host, err := LoadHost(task, svc, nodes[i].GetID)
// 			if err != nil {
// 				subtasks[i] = nil
// 				logrus.Errorf(err.Error())
// 				continue
// 			}
// 			subtask, err := task.StartInSubtask(
// 				func(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
// 					return nil, host.Delete(task)
// 				},
// 				nil,
// 			)
// 			if err != nil {
// 				subtasks[i] = nil
// 				logrus.Errorf(err.Error())
// 				continue
// 			}
// 			subtasks[i] = subtask
// 		}
// 		for i := 0; i < length; i++ {
// 			if subtasks[i] != nil {
// 				state, err := subtasks[i].Wait()
// 				if err != nil {
// 					logrus.Errorf(err.Error())
// 				}
// 				if state != nil {
// 					logrus.Errorf("after failure, cleanup failed to delete node '%s': %v", nodes[i].GetName, state)
// 				}
// 			}
// 		}
// 	}
// }

func containsClusterNode(list []*propertiesv2.ClusterNode, hostID string) (bool, int) {
    var idx int
    found := false
    for i, v := range list {
        if v.ID == hostID {
            found = true
            idx = i
            break
        }
    }
    return found, idx
}

// unconfigureMaster executes what has to be done to remove Master from Cluster
func (c *cluster) unconfigureMaster(task concurrency.Task, host resources.Host) fail.Error {
    if c.makers.UnconfigureMaster != nil {
        return c.makers.UnconfigureMaster(task, c, host)
    }
    // Not finding a callback isn't an error, so return nil in this case
    return nil
}

// configureCluster ...
// params contains a data.Map with primary and secondary getGateway hosts
func (c *cluster) configureCluster(task concurrency.Task, _ concurrency.TaskParameters) (xerr fail.Error) {
    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    logrus.Infof("[cluster %s] configuring cluster...", c.GetName())
    defer func() {
        if xerr == nil {
            logrus.Infof("[cluster %s] configuration successful.", c.GetName())
        } else {
            logrus.Errorf("[cluster %s] configuration failed: %s", c.GetName(), xerr.Error())
        }
    }()

    // Installs reverseproxy feature on cluster (gateways)
    if xerr = c.installReverseProxy(task); xerr != nil {
        return xerr
    }

    // Installs remotedesktop feature on cluster (all masters)
    if xerr = c.installRemoteDesktop(task); xerr != nil {
        return xerr
    }

    // configure what has to be done cluster-wide
    if c.makers.ConfigureCluster != nil {
        return c.makers.ConfigureCluster(task, c)
    }
    // Not finding a callback isn't an error, so return nil in this case
    return nil
}

func (c *cluster) determineRequiredNodes(task concurrency.Task) (uint, uint, uint, fail.Error) {
    if c.makers.MinimumRequiredServers != nil {
        a, b, c, xerr := c.makers.MinimumRequiredServers(task, c)
        if xerr != nil {
            return 0, 0, 0, xerr
        }
        return a, b, c, nil
    }
    return 0, 0, 0, nil
}

// uploadTemplateToFile uploads a template named 'tmplName' coming from rice 'box' in a file to a remote host
func realizeTemplate(box *rice.Box, tmplName string, data map[string]interface{}, fileName string) (string, string, fail.Error) {
    if box == nil {
        return "", "", fail.InvalidParameterError("box", "cannot be nil!")
    }
    tmplString, err := box.String(tmplName)
    if err != nil {
        return "", "", fail.Wrap(err, "failed to load template")
    }
    tmplCmd, err := template.Parse(fileName, tmplString)
    if err != nil {
        return "", "", fail.Wrap(err, "failed to parse template")
    }
    dataBuffer := bytes.NewBufferString("")
    err = tmplCmd.Execute(dataBuffer, data)
    if err != nil {
        return "", "", fail.Wrap(err, "failed to realize template")
    }
    cmd := dataBuffer.String()
    remotePath := utils.TempFolder + "/" + fileName

    return cmd, remotePath, nil
}

// configureNodesFromList configures nodes from a list
func (c *cluster) configureNodesFromList(task concurrency.Task, hosts []resources.Host) (xerr fail.Error) {
    tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).Entering()
    defer tracer.Exiting()
    defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

    var (
        hostID string
        errs   []error
    )

    var subtasks []concurrency.Task
    length := len(hosts)
    for i := 0; i < length; i++ {
        subtask, xerr := task.StartInSubtask(c.taskConfigureNode, data.Map{
            "index": uint(i + 1),
            "host":  hosts[i],
        })
        if xerr != nil {
            break
        }
        subtasks = append(subtasks, subtask)
    }
    // Deals with the metadata read failure
    if xerr != nil {
        errs = append(errs, fail.Wrap(xerr, "failed to get metadata of host '%s'", hostID))
    }

    for _, s := range subtasks {
        _, state := s.Wait()
        if state != nil {
            errs = append(errs, state)
        }
    }
    if len(errs) > 0 {
        return fail.NewErrorList(errs)
    }
    return nil
}

// joinNodesFromList makes nodes from a list join the cluster
func (c *cluster) joinNodesFromList(task concurrency.Task, hosts []resources.Host) fail.Error {
    if c.makers.JoinNodeToCluster == nil {
        // configure what has to be done cluster-wide
        if c.makers.ConfigureCluster != nil {
            return c.makers.ConfigureCluster(task, c)
        }
    }

    logrus.Debugf("Joining nodes to cluster...")

    // VPL: not used anymore, flavor SWARM has to disappear
    // master, xerr := c.FindAvailableMaster(task)
    // if xerr != nil {
    // 	return fail.Wrap(xerr, "failed to join workers to Docker Swarm")
    // }
    // joinCmd, xerr := c.getSwarmJoinCommand(task, master, true)
    // if xerr != nil {
    // 	return xerr
    // }
    // ENDVPL

    // Joins to cluster is done sequentially, experience shows too many join at the same time
    // may fail (depending of the cluster Flavor)
    if c.makers.JoinMasterToCluster != nil {
        for _, host := range hosts {
            // VPL: not used anymore, flavor SWARM has to disappear
            // retcode, _, stderr, xerr := host.Run(task, joinCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
            // if xerr != nil || retcode != 0 {
            // 	return fail.NewError("failed to join host '%s' to swarm as worker: %s", host.GetName(), stderr)
            // }
            // nodeLabel := "docker node update " + host.GetName() + " --label-add safescale.host.role=node"
            // retcode, _, stderr, xerr = master.Run(task, nodeLabel, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
            // if xerr != nil || retcode != 0 {
            // 	return fail.NewError("failed to add label to docker Swarm worker '%s': %s", host.GetName(), stderr)
            // }
            // ENDVPL
            if xerr := c.makers.JoinNodeToCluster(task, c, host); xerr != nil {
                return xerr
            }
        }
    }

    return nil
}

// VPL: not used anymore
// // leaveMastersFromList makes masters from a list leave the cluster
// func (c *cluster) leaveMastersFromList(task concurrency.Task, hosts []string) fail.Error {
//	if c.makers.LeaveMasterFromCluster == nil {
//		return nil
//	}
//
//	logrus.Debugf("Making Masters leaving cluster...")
//
//	// Joins to cluster is done sequentially, experience shows too many join at the same time
//	// may fail (depending of the cluster Flavor)
//	for _, hostID := range hosts {
//		host, xerr := LoadHost(task, c.service, hostID)
//		if xerr != nil {
//			return xerr
//		}
//		if xerr = c.makers.LeaveMasterFromCluster(task, c, host); xerr != nil {
//			return xerr
//		}
//	}
//
//	return nil
// }

// leaveNodesFromList makes nodes from a list leave the cluster
func (c *cluster) leaveNodesFromList(task concurrency.Task, hosts []string, selectedMaster resources.Host) (xerr fail.Error) {
    logrus.Debugf("Instructing nodes to leave cluster...")

    if selectedMaster == nil {
        if selectedMaster, xerr = c.FindAvailableMaster(task); xerr != nil {
            return xerr
        }
    }

    // Unjoins from cluster are done sequentially, experience shows too many join at the same time
    // may fail (depending of the cluster Flavor)
    for _, hostID := range hosts {
        host, xerr := LoadHost(task, c.service, hostID)
        if xerr != nil {
            // If host seems deleted, consider leaving as a success
            if _, ok := xerr.(*fail.ErrNotFound); ok {
                continue
            }
            return xerr
        }

        if c.makers.LeaveNodeFromCluster != nil {
            if xerr = c.makers.LeaveNodeFromCluster(task, c, host, selectedMaster); xerr != nil {
                return xerr
            }
        }
    }

    return nil
}

// VPL: not used anymore, flavor SWARM has to disappear
// // leaveNodeFromSwarm unregisters properly a node from docker Swarm
// func (c *cluster) leaveNodeFromSwarm(task concurrency.Task, host, selectedMaster resources.Host) (xerr fail.Error) {
// 	if selectedMaster == nil {
// 		selectedMaster, xerr = c.FindAvailableMaster(task)
// 		if xerr != nil {
// 			return xerr
// 		}
// 	}
//
// 	// Check worker is member of the Swarm
// 	cmd := fmt.Sprintf("docker node ls --format \"{{.Hostname}}\" --filter \"name=%s\" | grep -i %s", host.GetName(), host.GetName())
// 	retcode, _, _, xerr := selectedMaster.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
// 	if xerr != nil {
// 		return xerr
// 	}
// 	if retcode != 0 {
// 		// node is already expelled from Docker Swarm
// 		return nil
// 	}
// 	// node is a worker in the Swarm: 1st ask worker to leave Swarm
// 	cmd = "docker swarm leave"
// 	retcode, _, stderr, xerr := host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
// 	if xerr != nil {
// 		return xerr
// 	}
// 	if retcode != 0 {
// 		return fail.NewError("failed to make node '%s' leave swarm: %s", host.GetName(), stderr)
// 	}
//
// 	// 2nd: wait the Swarm worker to appear as down from Swarm master
// 	cmd = fmt.Sprintf("docker node ls --format \"{{.Status}}\" --filter \"name=%s\" | grep -i down", host.GetName())
// 	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
// 		func() error {
// 			retcode, _, _, xerr := selectedMaster.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
// 			if xerr != nil {
// 				return xerr
// 			}
// 			if retcode != 0 {
// 				return fail.NotAvailableError("'%s' not in Down state", host.GetName())
// 			}
// 			return nil
// 		},
// 		temporal.GetHostTimeout(),
// 	)
// 	if retryErr != nil {
// 		switch retryErr.(type) {
// 		case *retry.ErrTimeout:
// 			return fail.Wrap(retryErr, "SWARM worker '%s' didn't reach 'Down' state after %v", host.GetName(), temporal.GetHostTimeout())
// 		default:
// 			return fail.Wrap(retryErr, "SWARM worker '%s' didn't reach 'Down' state", host.GetName())
// 		}
// 	}
//
// 	// 3rd, ask master to remove node from Swarm
// 	cmd = fmt.Sprintf("docker node rm %s", host.GetName())
// 	retcode, _, stderr, xerr = selectedMaster.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
// 	if xerr != nil {
// 		return xerr
// 	}
// 	if retcode != 0 {
// 		return fail.NewError("failed to remove worker '%s' from Swarm on master '%s': %s", host.GetName(), selectedMaster.GetName(), stderr)
// 	}
// 	return nil
// }
// ENDVPL

// getNodeInstallationScript ...
func (c *cluster) getNodeInstallationScript(task concurrency.Task, nodeType clusternodetype.Enum) (string, map[string]interface{}) {
    if c.makers.GetNodeInstallationScript != nil {
        return c.makers.GetNodeInstallationScript(task, c, nodeType)
    }
    return "", map[string]interface{}{}
}

// BuildHostname builds a unique hostname in the Cluster
func (c *cluster) buildHostname(task concurrency.Task, core string, nodeType clusternodetype.Enum) (cluid string, xerr fail.Error) {
    var index int

    defer fail.OnPanic(&xerr)

    // Locks for write the manager extension...

    xerr = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
        return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
            nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            switch nodeType {
            case clusternodetype.Node:
                nodesV2.PrivateLastIndex++
                index = nodesV2.PrivateLastIndex
            case clusternodetype.Master:
                nodesV2.MasterLastIndex++
                index = nodesV2.MasterLastIndex
            }
            return nil
        })
    })
    if xerr != nil {
        return "", xerr
    }
    return c.GetName() + "-" + core + "-" + strconv.Itoa(index), nil
}

func (c *cluster) deleteHosts(task concurrency.Task, hosts []resources.Host) fail.Error {
    tg, xerr := concurrency.NewTaskGroupWithParent(task)
    if xerr != nil {
        return xerr
    }
    errors := make([]error, 0, len(hosts)+1)
    for _, h := range hosts {
        if _, xerr = tg.StartInSubtask(c.taskDeleteHost, h); xerr != nil {
            errors = append(errors, xerr)
        }
    }
    _, xerr = tg.WaitGroup()
    if xerr != nil {
        errors = append(errors, xerr)
    }
    return fail.NewErrorList(errors)
}

func (c *cluster) ToProtocol(task concurrency.Task) (*protocol.ClusterResponse, fail.Error) {
    out := &protocol.ClusterResponse{}
    xerr := c.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
        ci, ok := clonable.(*abstract.ClusterIdentity)
        if !ok {
            return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
        }
        out.Identity = converters.ClusterIdentityFromAbstractToProtocol(*ci)

        innerXErr := props.Inspect(task, clusterproperty.ControlPlaneV1, func(clonable data.Clonable) fail.Error {
            controlplaneV1, ok := clonable.(*propertiesv1.ClusterControlplane)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.ClusterControlplane' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            out.Controlplane = converters.ClusterControlplaneFromPropertyToProtocol(*controlplaneV1)
            return nil
        })
        if innerXErr != nil {
            return innerXErr
        }

        innerXErr = props.Inspect(task, clusterproperty.CompositeV1, func(clonable data.Clonable) fail.Error {
            compositeV1, ok := clonable.(*propertiesv1.ClusterComposite)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.ClusterComposite' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            out.Composite = converters.ClusterCompositeFromPropertyToProtocol(*compositeV1)
            return nil
        })
        if innerXErr != nil {
            return innerXErr
        }

        if props.Lookup(clusterproperty.DefaultsV2) {
            innerXErr = props.Inspect(task, clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
                defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
                if !ok {
                    return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                _ = defaultsV2 // TODO: fix code
                return nil
            })
        } else {
            // Legacy
            innerXErr = props.Inspect(task, clusterproperty.DefaultsV1, func(clonable data.Clonable) fail.Error {
                defaultsV1, ok := clonable.(*propertiesv1.ClusterDefaults)
                if !ok {
                    return fail.InconsistentError("'*propertiesv1.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                _ = defaultsV1 // TODO: fix code
                return nil
            })
        }
        if innerXErr != nil {
            return innerXErr
        }

        if props.Lookup(clusterproperty.NetworkV2) {
            innerXErr = props.Inspect(task, clusterproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
                networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
                if !ok {
                    return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                _ = networkV2 // TODO: fix code
                return nil
            })
        } else {
            // Legacy
            innerXErr = props.Inspect(task, clusterproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
                networkV1, ok := clonable.(*propertiesv1.ClusterDefaults)
                if !ok {
                    return fail.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                _ = networkV1 // TODO: fix code
                return nil
            })
        }
        if innerXErr != nil {
            return innerXErr
        }

        if props.Lookup(clusterproperty.NodesV2) {
            innerXErr = props.Inspect(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
                nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
                if !ok {
                    return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                _ = nodesV2 // TODO: fix code
                return nil
            })
        } else {
            // Legacy
            innerXErr = props.Inspect(task, clusterproperty.NodesV1, func(clonable data.Clonable) fail.Error {
                nodesV1, ok := clonable.(*propertiesv1.ClusterNodes)
                if !ok {
                    return fail.InconsistentError("'*propertiesv1.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
                }
                _ = nodesV1 // TODO: fix code
                return nil
            })
        }
        if innerXErr != nil {
            return innerXErr
        }

        innerXErr = props.Inspect(task, clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
            featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
            if !ok {
                return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            _ = featuresV1 // TODO: fix code
            return nil
        })
        if innerXErr != nil {
            return innerXErr
        }

        return props.Inspect(task, clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
            stateV1, ok := clonable.(*propertiesv1.ClusterState)
            if !ok {
                return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
            }
            out.State = protocol.ClusterState(stateV1.State)
            return nil
        })
    })
    if xerr != nil {
        return nil, xerr
    }
    return out, nil
}
