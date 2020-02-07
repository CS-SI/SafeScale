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

package clusters

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// Path is the path to use to reach Cluster Definitions/Metadata
	clustersFolderName = "clusters"
)

// Cluster is the implementation of resources.Cluster interface
type cluster struct {
	Identity abstracts.ClusterIdentity

	*operations.Core `json:"-"`
	properties     *serialize.JSONProperties

	installMethods      map[uint8]installmethod.Enum
	lastStateCollection time.Time
	service iaas.Service
	makers  Makers
	concurrency.TaskedLock `json:"-"`
}

// New ...
func New(task concurrency.task, svc iaas.Service) (cluster *cluster, err error) {
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nil, scerr.InvalidParameterError("svc", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	core, err := operations.NewCore(svc, "cluster", clustersFolderName)
	if err != nil {
		return nil, err
	}

	return &cluster{Core: core}, nil
}


// Create creates the necessary infrastructure of the Cluster
func (c *cluster) Create(task concurrency.Task, req abstracts.ClusterRequest) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting creation of infrastructure of cluster '%s'...", req.Name),
		fmt.Sprintf("Ending creation of infrastructure of cluster '%s'", req.Name),
	)()
	defer scerr.OnExitLogError(tracer.TraceMessage("failed to create cluster infrastructure:"), &err)()
	defer scerr.OnPanic(&err)()

	finalState := clusterstate.Unknown

	// Creates first metadata of cluster after initialization
	err = c.firstLight(task, req)
	if err != nil {
		return err
	}

	// Starting from here, delete metadata if exiting with error
	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := c.Core.Delete(task)
			if derr != nil {
				logrus.Errorf("after failure, cleanup failed to delete cluster metadata")
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
	gatewaysDef, mastersDef, nodesDef := c.defineSizingRequirements(task, req)

	// Create the network
	network, err := c.createNetwork(task, req)
	if err != nil {
		return err
	}
	// req.NetworkID = network.ID()

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := network.Delete(task)
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Creates and configures hosts
	err = c.createHosts(task, req, network)
	if err != nil {
		return nil, err
	}

	// Starting from here, exiting with err deletes hosts if req.KeepOnFailure is false
	defer func() {
		if err != nil && !req.KeepOnFailure {
			tg, tgerr := concurrency.NewTaskGroup(task)
			if tgerr != nil {
				err = scerr.AddConsequence(err, tgerr)
			} else {
				list, merr := c.ListMasterIDs(task)
				if merr != nil {
					err = scerr.AddConsequence(err, merr)
				} else {
					for _, v := range list {
						tgerr = tg.StartInSubTask(taskDeleteHost, data.Map{"host": v})
						if tgerr != nil {
							err = scerr.AddConsequence(err, tgerr)
						}
					}
				}

				list, merr = c.ListNodeIDs(task)
				if merr != nil {
					err = scerr.AddConsequence(err, merr)
				} else {
					for _, v := range list {
						tgerr = tg.StartInSubTask(taskDeleteHost, data.Map{"host": v})
						if tgerr != nil {
							err = scerr.AddConsequence(err, tgerr)
						}
					}
				}

				tgerr = tg.WaitFor(temporal.GetLongExecutionTimeout())
				if tgerr != nil {
					err = scerr.AddConsequence(err, tgerr)
				}
			}

		}
	}()

	// At the end, configure cluster as a whole
	err = c.configureCluster(task, data.Map{
		"PrimaryGateway":   primaryGateway,
		"SecondaryGateway": secondaryGateway,
	})
	if err != nil {
		return err
	}

	return nil
}

// firstLight contains the code leading to cluster first metadata written
func (c *cluster) firstLight(task concurrency.Task, req Request) error {
	// Metadata is not yet written to object storage, we can go directly to properties
	props, err := c.properties(task)
	if err != nil {
		return err
	}
	// finalState := clusterstate.Unknown

	// VPL: For now, always disable addition of feature proxycache-client
	err = return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) error {
		featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
		if !ok {
			return scerr.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		featuresV1.Disabled["proxycache"] = struct{}{}
		return nil
	})
	if err != nil {
		return scerr.Wrap(err, "failed to disable feature 'proxycache'")
	}
	// ENDVPL

	// Sets initial state of the new cluster and create metadata
	err = props.Alter(clusterproperty.StateV1, func(clonable interface{}) error {
		stateV1, ok := clonable.(*clusterpropsv1.State)
		if !ok {
			return scerr.InconsistentError("'*propsv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		stateV1.State = clusterstate.Creating
		return nil
	})
	if err != nil {
		return scerr.Wrap(err, "failed to set initial state of cluster")
	}

	// sets default sizing from req
	err = props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) error {
		defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
		if !ok {
			return scerr.InconsistentError("'*propertiesv2.Defaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		defaultsV2.GatewaySizing = srvutils.FromProtocolHostSizing(*req.GatewaysDef.Sizing)
		defaultsV2.MasterSizing = srvutils.FromProtocolHostSizing(*req.MastersDef.Sizing)
		defaultsV2.NodeSizing = srvutils.FromProtocolHostSizing(*req.NodesDef.Sizing)
		// FIXME: how to recover image ID from construct() ?
		// defaultsV2.Image = imageID
		return nil
	})
	if err != nil {
		return err
	}

	// FUTURE: sets the cluster composition (when we will be able to manage cluster spread on several tenants...)
	err = props.Alter(clusterproperty.CompositeV1, func(clonable data.Clonable) error {
		compositeV1, ok := clonable.(*propertiesv1.ClusterComposite)
		if !ok {
			return scerr.InconsistentError("'*propertiesv1.ClusterComposite' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		compositeV1.Tenants = []string{req.Tenant}
		return nil
	})
	if err != nil {
		return err
	}

	// Create a KeyPair for the user cladm
	kpName = "cluster_" + req.Name + "_cladm_key"
	kp, err = svc.CreateKeyPair(kpName)
	if err != nil {
		return err
	}
	c.Identity.Keypair = kp

	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return err
	}

	// Sets identity
	c.Identity.Name = req.Name
	c.Identity.Flavor = req.Flavor
	c.Identity.Complexity = req.Complexity
	c.Identity.AdminPassword = cladmPassword

	// Links maker based on Flavor
	err = c.Bootstrap()
	if err != nil {
		return err
	}

	// Writes the metadata for the first time
	return c.Carry(task, c)
}

// defineSizings calculates the sizings needed for the hosts of the cluster
func (c *cluster) defineSizingRequirements(
	task concurrency.Task, req Request
) (*resources.SizingRequirements, *resources.SizingRequirements, *resources.SizingRequirements, error) {
	var (
		gatewaysDefault *resources.SizingRequirements
		mastersDefault *resources.SizingRequirements
		nodesDefault *resources.SizingRequirements
		imageID string
	)

	// Determine default image
	if req.NodesDef != nil {
		imageID = req.NodesDef.ImageId
	}
	if imageID == "" && c.makers.DefaultImage != nil {
		imageID = c.makers.DefaultImage(task, b)
	}
	if imageID == "" {
		imageID = "Ubuntu 18.04"
	}

	// Determine Gateway sizing
	if c.makers.DefaultGatewaySizing != nil {
		gatewaysDefault = complementSizingRequirements(nil, c.makers.DefaultGatewaySizing(task, c))
	} else {
		gatewaysDefault = resources.SizingRequirements{
			MinCores:    2,
			MaxCores:    4,
			MinRAMSize:  7.0,
			MaxRAMSize:  16.0,
			MinDiskSize: 50,
			MinGPU:      -1,
		}
	}
	gatewaysDefault.ImageId = imageID
	gatewaysDef := complementSizingRequirements(req.GatewaysDef, gatewaysDefault)

	// Determine master sizing
	if c.makers.DefaultMasterSizing != nil {
		mastersDefault = complementSizingRequirements(nil, c.makers.DefaultMasterSizing(task, c))
	} else {
		mastersDefault = resources.SizingRequirements{
			MinCores:    4,
			MaxCores:    8,
			MinRAMSize:  15.0,
			MaxRAMSize:  32.0,
			MinDiskSize: 100,
			MinGPU:      -1,
		}
	}
	// Note: no way yet to define master sizing from cli...
	mastersDefault.ImageId = imageID
	mastersDef := complementSizingRequirements(req.MastersDef, mastersDefault)

	// Determine node sizing
	if c.makers.DefaultNodeSizing != nil {
		nodesDefault = complementSizingRequirements(nil, c.makers.DefaultNodeSizing(task, c))
	} else {
		nodesDefault = resources.SizingRequirements{
			MinCores:    4,
			MaxCores:    8,
			MinRAMSize:  15.0,
			MaxRAMSize:  32.0,
			MinDiskSize: 100,
			MinGPU:      -1,
		}
	}
	nodesDefault.ImageId = imageID
	nodesDef := complementSizingRequirements(req.NodesDef, nodesDefault)

	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			defaultsV2.GatewaySizing = *gatewaysDef.Sizing
			defaultsV2.MasterSizing = *mastersDef.Sizing
			defaultsV2.NodeSizing = *nodesDef.Sizing
			defaultsV2.Image = imageID
			return nil
		})
		if innerErr != nil {
			return innerErr
		}
	})
	if err != nil {
		nil, nil, nil, return err
	}

	return gatewaysDef, mastersDef, nodesDef, nil
}

// createNetwork creates the network for the cluster
func (c *cluster) createNetwork(task, req) (resources.Network, error) {
	// Determine if Gateway Failover must be set
	caps := c.service.Capabilities()
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
	sizing := srvutils.FromHostDefinitionToGatewayDefinition(gatewaysDef)
	def := resources.NetworkDefinition{
		Name:     networkName,
		Cidr:     req.CIDR,
		Gateway:  &sizing,
		FailOver: !gwFailoverDisabled,
	}

	network, err := networkfactory.New(task)
	if err != nil {
		return nil, err
	}
	err = network.Create(def, temporal.GetExecutionTimeout())
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := network.Delete(task, temporal.GetExecutionTimeout())
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Updates cluster metadata, propertiesv2.ClusterNetwork
	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
			networkV2, ok := v.(*propertiesv2.ClusterNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			primaryGateway, innerErr := network.PrimaryGateway()
			if innerErr != nil {
				return innerErr
			}
			var secondaryGateway resources.Host
			if !gatewayFailoverDisabled {
				secondaryGateway, innerErr = network.SecondaryGateway()
				if innerErr != nil {
					if _, ok := innerErr.(*scerr.ErrNotFound); !ok {
						return innerErr
					}
				}
			}
			networkV2.NetworkID = network.ID()
			networkV2.CIDR = req.CIDR
			networkV2.GatewayID = primaryGateway.ID()
			networkV2.GatewayIP = primaryGateway.PrivateIP()
			if !gwFailoverDisabled {
				networkV2.SecondaryGatewayID = secondaryGateway.ID()
				networkV2.SecondaryGatewayIP = secondaryGateway.PrivateIP()
				networkV2.DefaultRouteIP = network.VirtualIp.PrivateIP
				// VPL: no public IP on VIP yet... use the primary gateway public ip for now
				// networkV2.EndpointIP = network.VirtualIP.PublicIP
				networkV2.EndpointIP = primaryGateway.PublicIP()
				networkV2.PrimaryPublicIP = networkV2.EndpointIP
				networkV2.SecondaryPublicIP = secondaryGateway.PublicIP()
			} else {
				networkV2.DefaultRouteIP = primaryGateway.PrivateIP()
				networkV2.EndpointIP = primaryGateway.PublicIP()
				networkV2.PrimaryPublicIP = networkV2.EndpointIP
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[cluster %s] network '%s' creation successful.", req.Name, networkName)
	return network, nil
}

// createHosts creates and configures hosts for the cluster
func (c *cluster) createHosts(task concurrency.Task, req Request, network resources.Network) error {
	primaryGateway, err := network.PrimaryGateway()
	if err != nil {
		return err
	}
	secondaryGateway, err := network.SecondaryGateway()
	if err != nil {
		if _, ok := err.(*scerr.ErrNotFound); !ok {
			return err
		}
	}

	err = primaryGateway.WaitSSHReady(temporal.GetExecutionTimeout())
	if err != nil {
		return scerr.Wrap(err, "wait for remote ssh service to be ready")
	}

	// Loads secondary gateway metadata
	if secondaryGateway != nil {
		err = secondaryGateway.WaitSSHReady(temporal.GetExecutionTimeout())
		if err != nil {
			return scerr.Wrap(err, "wait for remote ssh service to be ready")
		}
	}

	var (
		mastersDef *abstracts.HostSizing
		nodesDef *abstracts.HostSizing
	)
	props, err := c.pmake croperties(task)
	if err != nil {
		return err
	}
	err = props.Inspect(clusterproperty.DefaultsV2, func(clonable data.Clonable) error {
		defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
		if !ok {
			return scerr.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		mastersDef = defaultsV2.MasterSizing
		nodesDef = defaultsV2.NodeSizing
		return nil
	})
	if err != nil {
		return err
	}

	masterCount, privateNodeCount, _ := c.determineRequiredNodes(task)
	var (
		primaryGatewayStatus   error
		secondaryGatewayStatus error
		mastersStatus          error
		privateNodesStatus     error
		secondaryGatewayTask   concurrency.Task
	)

	// Step 1: starts gateway installation plus masters creation plus nodes creation
	primaryGatewayTask, err := task.StartInSubTask(b.taskInstallGateway, primaryGateway)
	if err != nil {
		return err
	}
	if secondaryGateway != nil {
		secondaryGatewayTask, err = task.StartInSubTask(b.taskInstallGateway, secondaryGateway)
		if err != nil {
			return err
		}
	}
	mastersTask, err := task.StartInSubTask(b.taskCreateMasters, data.Map{
		"count":     masterCount,
		"masterDef": mastersDef,
		"nokeep":    !req.KeepOnFailure,
	})
	if err != nil {
		return err
	}

	privateNodesTask, err := task.StartInSubTask(b.taskCreateNodes, data.Map{
		"count":   privateNodeCount,
		"public":  false,
		"nodeDef": nodesDef,
		"nokeep":  !req.KeepOnFailure,
	})
	if err != nil {
		return err
	}

	// Step 2: awaits gateway installation end and masters installation end
	_, primaryGatewayStatus = primaryGatewayTask.Wait()
	if primaryGatewayStatus != nil {
		abortMasterErr := mastersTask.Abort()
		if abortMasterErr != nil {
			primaryGatewayStatus = scerr.AddConsequence(primaryGatewayStatus, abortMasterErr)
		}
		abortNodesErr := privateNodesTask.Abort()
		if abortNodesErr != nil {
			primaryGatewayStatus = scerr.AddConsequence(primaryGatewayStatus, abortNodesErr)
		}
		return primaryGatewayStatus
	}
	if secondaryGateway != nil && secondaryGatewayTask != nil {
		_, secondaryGatewayStatus = secondaryGatewayTask.Wait()
		if secondaryGatewayStatus != nil {
			abortMasterErr := mastersTask.Abort()
			if abortMasterErr != nil {
				secondaryGatewayStatus = scerr.AddConsequence(secondaryGatewayStatus, abortMasterErr)
			}
			abortNodesErr := privateNodesTask.Abort()
			if abortNodesErr != nil {
				secondaryGatewayStatus = scerr.AddConsequence(secondaryGatewayStatus, abortNodesErr)
			}
			return secondaryGatewayStatus
		}
	}

	// Starting from here, delete masters if exiting with error and req.KeepOnFailure is not true
	defer func() {
		if err != nil && !req.KeepOnFailure {
			list, merr := c.ListMasterIDs(task)
			if merr != nil {
				err = scerr.AddConsequence(err, merr)
			} else {
				tg, err := concurrency.NewTaskGroup(task)
				if tgerr != nil {
					err = scerr.AddConsequence(err, tgerr)
				} else {
					for _, v := range list {
						tg.StartInSubTask(taskDeleteHost, data.Map{"host": v})
					}
					derr := tg.WaitFor(temporal.GetLongExecutionTimeout())
					if derr != nil {
						err = scerr.AddConsequence(err, derr)
					}
				}
			}
		}
	}()

	_, mastersStatus = mastersTask.Wait()
	if mastersStatus != nil {
		abortNodesErr := privateNodesTask.Abort()
		if abortNodesErr != nil {
			mastersStatus = scerr.AddConsequence(mastersStatus, abortNodesErr)
		}
		return mastersStatus
	}

	// Step 3: run (not start so no parallelism here) gateway configuration (needs MasterIPs so masters must be installed first)
	// Configure Gateway(s) and waits for the result
	primaryGatewayTask, err = task.StartInSubTask(b.taskConfigureGateway, srvutils.ToPBHost(primaryGateway))
	if err != nil {
		return err
	}
	if !gwFailoverDisabled {
		secondaryGatewayTask, err = task.StartInSubTask(b.taskConfigureGateway, srvutils.ToPBHost(secondaryGateway))
		if err != nil {
			return err
		}
	}
	_, primaryGatewayStatus = primaryGatewayTask.Wait()
	if primaryGatewayStatus != nil {
		if !gwFailoverDisabled {
			if secondaryGatewayTask != nil {
				secondaryGatewayErr := secondaryGatewayTask.Abort()
				if secondaryGatewayErr != nil {
					primaryGatewayStatus = scerr.AddConsequence(primaryGatewayStatus, secondaryGatewayErr)
				}
			}
		}
		return primaryGatewayStatus
	}

	if !gwFailoverDisabled {
		if secondaryGatewayTask != nil {
			_, secondaryGatewayStatus = secondaryGatewayTask.Wait()
			if secondaryGatewayStatus != nil {
				return secondaryGatewayStatus
			}
		}
	}

	// Step 4: configure masters (if masters created successfully and gateway configure successfully)
	_, mastersStatus = task.RunInSubTask(c.taskConfigureMasters, nil)
	if mastersStatus != nil {
		return mastersStatus
	}

	defer func() {
		if err != nil && !req.KeepOnFailure {
			list, merr := c.ListNodeIDs(task)
			if merr != nil {
				err = scerr.AddConsequence(err, merr)
			} else {
				tg, err := concurrency.NewTaskGroup(task)
				if tgerr != nil {
					err = scerr.AddConsequence(err, tgerr)
				} else {
					for _, v := range list {
						tg.StartInSubTask(taskDeleteHost, data.Map{"host": v})
					}
					derr := tg.WaitFor(temporal.GetLongExecutionTimeout())
					if derr != nil {
						err = scerr.AddConsequence(err, derr)
					}
				}
			}
		}
	}()

	// Step 5: awaits nodes creation
	_, privateNodesStatus = privateNodesTask.Wait()
	if privateNodesStatus != nil {
		return privateNodesStatus
	}

	// Step 6: Starts nodes configuration, if all masters and nodes
	// have been created and gateway has been configured with success
	_, privateNodesStatus = task.RunInSubTask(c.taskConfigureNodes, nil)
	if privateNodesStatus != nil {
		return privateNodesStatus
	}

	return nil
}

// complementSizingRequirements complements req with default values if needed
func complementSizingRequirements(req *resources.SizingRequirements, def resources.SizingRequirements) *resources.SizingRequirements {
	var finalDef resources.SizingRequirements
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
		if finalDef.MinCpuFreq == 0 && def.MinCpuFreq > 0 {
			finalDef.MinCpuFreq = def.MinCpuFreq
		}
		if finalDef.ImageId == "" {
			finalDef.ImageId = def.ImageId
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
		if finalDef.MaxRAMmSize <= 0.0 {
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
func (c *cluster) Serialize() ([]byte, error) {
	return serialize.ToJSON(c)
}

// Deserialize reads json code and reinstantiates cluster
// satisfies interface data.Serializable
func (c *cluster) Deserialize(buf []byte) error {
	return serialize.FromJSON(buf, c)
}

// Boostrap (re)connects controller with the appropriate Makers
func (c *cluster) Bootstrap(task concurrency.Task) error {
	c.Lock(task)
	defer c.Unlock(task)

	switch c.Flavor {
	case clusterflavor.BOH:
		c.makers = boh.Makers
	case clusterflavor.K8S:
		c.makers = k8s.Makers
	default:
		return scerr.NotImplementedError("unknown cluster Flavor '%d'", int(c.Flavor))
	}
	return nil
}

// Browse walks through cluster folder and executes a callback for each entry
func (c *cluster) Browse(task concurrency.Task, callback func([]byte) error) error {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	return c.Core.Browse(task, callback)
}

// Identity returns the identity of the cluster
func (c *cluster) Identity(task concurrency.Task) (identity resources.ClusterIdentity, err error) {
	if c == nil {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	err = c.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		rc, ok := clonable.(cluster.Controller)
		if ok != nil {
			return scerr.InconsistentError("'cluster.Controller' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		identity = rc.Identity(task)
		return nil
	})
}

// Flavor returns the flavor of the cluster
//
// satisfies interface cluster.Controller
func (c *cluster) Flavor(task concurrency.Task) (flavor ClusterFlavor.Enum, err error) {
	if c == nil {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = c.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		ctrl, ok := clonable.(cluster.Controller)
		if !ok {
			return scerr.InconsistentError("'cluster.Controller' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		var inErr error
		flavor, inErr = ctrl.Flavor()
		return inErr
	})
	if err != nil {
		return 0, err
	}
	return flavor, nil
}

// Complexity returns the complexity of the cluster
// satisfies interface cluster.Controller
func (c *cluster) Complexity(task concurrency.Task) (complexity clustercomplexity.Enum, err error) {
	if c == nil {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = c.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		controller, ok := clonable.(cluster.Controller)
		if !ok {
			return scerr.InconsistentError("'cluster.Controller' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		var inErr error
		complexity, inErr = controller.Complexity()
		return inErr
	})
	if err != nil {
		return 0, err
	}
	return complexity, nil
}

// AdminPassword returns the password of the cluster admin account
// satisfies interface cluster.Controller
func (c *cluster) AdminPassword(task concurrency.Task) (adminPassword string, err error) {
	if oc == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = c.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		controller, ok := clonable.(cluster.Controller)
		if !ok {
			return scerr.InconsistentError("'cluster.Controller' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		var inErr error
		adminPassword, inErr = controller.AdminPassword()
		return inErr
	})
	return adminPassword, err
}

// KeyPair returns the key pair used in the cluster
// satisfies interface cluster.Controller
func (c *cluster) KeyPair(task concurrency.Task) (keyPair abstracts.KeyPair, err error) {
	if c == nil {
		return keyPair, scerr.InvalidInstanceError()
	}
	if task == nil {
		return keyPair, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = c.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		controller, ok := clonable.(cluster.Controller)
		if !ok {
			return scerr.InconsistentError("'cluster.Controller' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		var inErr error
		keyPair, inErr = controller.KeyPair()
		return inErr
	})
	return keyPair, err
}

// NetworkConfig returns network configuration of the cluster
// satisfies interface cluster.Controller
func (c *Cluster) NetworkConfig(task concurrency.Task) (config *propertiesv1.Network, err error) {
	if c == nil {
		return cfg, scerr.InvalidInstanceError()
	}
	if task == nil {
		return cfg, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if c.Properties.Lookup(Property.NetworkV2) {
		_ = c.Properties.Inspect(Property.NetworkV2, func(clonable data.Clonable) error {
			networkV2, ok := clonable.(*propertiesv2.Network)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			config = networkV2
			return nil
		})
	} else {
		err = c.Alter(func(clonable data.Clonable) error {
			err = c.Properties.Inspect(Property.NetworkV1, func(v data.Clonable) error {
				networkV1 := v.(*propertiesv1.Network)
				config = &propertiesv2.Network{
					NetworkID:      networkV1.NetworkID,
					CIDR:           networkV1.CIDR,
					GatewayID:      networkV1.GatewayID,
					GatewayIP:      networkV1.GatewayIP,
					DefaultRouteIP: networkV1.GatewayIP,
					EndpointIP:     networkV1.PublicIP,
				}
				return nil
			})
			if err != nil {
				return err
			}
			return c.Properties.Alter(Property.NetworkV1, func(clonable data.Clonable) error {
				networkV2, ok := clonable.(*propertiesv2.Network)
				if !ok {
					return scerr.InconsistentError("'*propertiesv2.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				_ = networkV2.Replace(config)
				return nil
			})
		})
		if err != nil {
			return nil, err
		}
	}

	return config, nil
}

// properties returns the extension of the cluster
//
// satisfies interface cluster.Controller
func (c *Cluster) properties(task concurrency.Task) (props *serialize.JSONProperties, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	c.lock.RLock(task)
	defer c.lock.RUnlock(task)
	return nil, c.properties
}

// Start starts the cluster
// satisfies interface cluster.cluster.Controller
func (c *Cluster) Start(task concurrency.Task) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	defer scerr.OnPanic(&err)()

	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// If the cluster is in state Stopping or Stopped, do nothing
	var prevState ClusterState
	prevState, err = c.State(task)
	if err != nil {
		return err
	}
	if prevState == clusterstate.Stopping || prevState == clusterstate.Stopped {
		return nil
	}

	// If the cluster is in state Starting, wait for it to finish its start procedure
	if prevState == ClusterState.Starting {
		err = retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				state, inErr := c.State(task)
				if inErr != nil {
					return inErr
				}
				if state == ClusterState.Nominal || state == ClusterState.Degraded {
					return nil
				}
				return fmt.Errorf("current state of cluster is '%s'", state.String())
			},
			5*time.Minute, // FIXME: static timeout
		)
		if err != nil {
			switch err.(type) {
			case retry.ErrTimeout:
				err := scerr.Wrap(err, "timeout waiting cluster to become started")
			}
			return err
		}
		return nil
	}

	if prevState != ClusterState.Stopped {
		return scerr.NotAvailableError("failed to start cluster because of it's current state: %s", prevState.String())
	}

	// First mark cluster to be in state Starting
	err = c.Alter(task, func(clonable data.Clonable) error {
		return c.Properties.Alter(Property.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*clusterpropertiesv1.State)
			if !ok {
				return scerr.InconsistentError("'*clusterpropertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = ClusterState.Starting
		})
	})
	if err != nil {
		return err
	}

	// Then start it and mark it as STARTED on success
	return c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		var (
			nodes                         []*propertiesv2.Node
			masters                       []*propertiesv2.Node
			gatewayID, secondaryGatewayID string
		)
		err = props.Inspect(Property.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			masters = nodesV2.Masters
			nodes = nodesV2.PrivateNodes
			return nil
		})
		if err != nil {
			return fmt.Errorf("failed to get list of hosts: %v", err)
		}
		if props.Lookup(clusterproperty.NetworkV2) {
			err = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
				networkV2, ok := clonable.(*propertiesv2.Network)
				if !ok {
					return scerr.InconsistentError("'*propertiesv2.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				gatewayID = networkV2.GatewayID
				secondaryGatewayID = networkV2.SecondaryGatewayID
				return nil
			})
		} else {
			err = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) error {
				networkV1, ok := clonable.(*propertiesv1.Network)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				gatewayID = networkV1.GatewayID
				return nil
			})
		}
		if err != nil [
			return err
		}

		// Mark cluster as state Starting
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.State)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Starting
			return nil
		})

	})
	if err != nil {
		return err
	}

	// Start gateway(s)
	taskGroup, err := concurrency.NewTaskGroup(task)
	if err != nil {
		return err
	}
	_, err = taskGroup.Start(c.taskStartHost, gatewayID)
	if err != nil {
		return err
	}
	if secondaryGatewayID != "" {
		_, err = taskGroup.Start(c.taskStartHost, secondaryGatewayID)
		if err != nil {
			return err
		}
	}
	// Start masters
	for _, n := range masters {
		_, err = taskGroup.Start(c.taskStartHost, n.ID)
		if err != nil {
			return err
		}
	}
	// Start nodes
	for _, n := range nodes {
		_, err = taskGroup.Start(c.taskStartHost, n.ID)
		if err != nil {
			return err
		}
	}
	_, err = taskGroup.Wait()
	if err != nil {
		return err
	}

	return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
		stateV1, ok := clonable.(*propertiesv1.State)
		if !ok {
			return scerr.InconcistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		stateV1.State = clusterstate.Nominal
		return nil
	})
}

// Stop stops the cluster
func (c *Cluster) Stop(task concurrency.Task) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// If the cluster is stopped, do nothing
	var prevState clusterstate
	prevState, err = c.State(task)
	if err != nil {
		return err
	}
	if prevState == clusterstate.Stopped {
		return nil
	}

	// If the cluster is already stopping, wait for it to terminate the procedure
	if prevState == clusterstate.Stopping {
		err = retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				state, innerErr := c.State(task)
				if innerErr != nil {
					return innerErr
				}
				if state != clusterstate.Stopped {
					return scerr.NotAvailableError("current state of cluster is '%s'", state.String())
				}
				return nil
			},
			5*time.Minute, // FIXME: static timeout
		)
		if err != nil {
			switch err.(type) {
			case retry.ErrTimeout:
				err := scerr.Wrap(err, "timeout waiting cluster transitioning from state Stopping to Stopped")
			}
			return err
		}
		return nil
	}

	// If the cluster is not in state Nominal or Degraded, can't stop
	if prevState != clusterstate.Nominal || prevState != clusterstate.Degraded {
		return scerr.NotAvailableError("failed to stop cluster because of it's current state: %s", prevState.String())
	}

	// First mark cluster to be in state Stopping
	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := (*clusterpropertiesv1.State)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Stopping
		})
	})
	if err != nil {
		return err
	}

	// Then stop it and mark it as STOPPED on success
	return c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		var (
			nodes                         []*propertiesv2.Node
			masters                       []*propertiesv2.Node
			gatewayID, secondaryGatewayID string
		)
		inErr := props.Inspect(clusterproperty.NodesV2, func(v interface{}) error {
			nodesV2, ok := v.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			masters = nodesV2.Masters
			nodes = nodesV2.PrivateNodes
			return nil
		})
		if inErr != nil {
			return scerr.Wrap(inErr, "failed to get list of hosts")
		}

		if props.Lookup(clusterproperty.NetworkV2) {
			inErr = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
				networkV2, ok := clonable.(*propertiesv2.Network)
				if !ok {
					return scerr.InconsistentError("'*propertiesv2.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				gatewayID = networkV2.GatewayID
				secondaryGatewayID = networkV2.SecondaryGatewayID
				return nil
			})
		} else {
			inErr = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) error {
				networkV1, ok := clonable.(*propertiesv1.Network)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				gatewayID = networkV1.GatewayID
				return nil
			})
		}
		if inErr != nil {
			return inErr
		}

		// Stop nodes
		taskGroup, inErr := concurrency.NewTaskGroup(task)
		if inErr != nil {
			return inErr
		}

		for _, n := range nodes {
			_, inErr = taskGroup.Start(c.taskStopHost, n.ID)
			if inErr != nil {
				return inErr
			}
		}
		// Stop masters
		for _, n := range masters {
			_, inErr = taskGroup.Start(c.taskStopHost, n.ID)
			if inErr != nil {
				return inErr
			}
		}
		// Stop gateway(s)
		_, inErr = taskGroup.Start(c.taskStopHost, gatewayID)
		if inErr != nil {
			return inErr
		}
		if secondaryGatewayID != "" {
			_, inErr = taskGroup.Start(c.taskStopHost, secondaryGatewayID)
			if inErr != nil {
				return inErr
			}
		}

		_, inErr = taskGroup.Wait()
		if inErr != nil {
			return inErr
		}

		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.State)
			if !ok {
				return scerr.InconcistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Stopped
			return nil
		})
	})
}

// State returns the current state of the Cluster
// Uses the "maker" GetState from Foreman
func (c *Cluster) State(task concurrency.Task) (state clusterstate.Enum, err error) {
	state = clusterstate.Unknown
	if c == nil {
		return state, scerr.InvalidInstanceError()
	}
	if task == nil {
		return state, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()


	if b.makers.GetState != nil {
		state, err = b.makers.GetState(task, b)
	} else {
		state = clusterstate.Unknown
		err = fmt.Errorf("no maker defined for 'GetState'")
	}
	if err != nil {
		return clusterstate.Unknown, fmt.Errorf("no maker defined for 'GetState'")
	}
	return state, c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			// FIXME: validate cast
			stateV1 := clonable.(*propsv1.State)
			stateV1.State = state
			c.lastStateCollection = time.Now()
			return nil
		})
	})
}

// AddNode adds a node
//
// satisfies interface cluster.Controller
func (c *Cluster) AddNode(task concurrency.Task, def *abstracts.HostDefinition) (_ *Host, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if def == nil {
		return nil, scerr.InvalidParameterError("def", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	nodes, err := c.AddNodes(task, 1, def)
	if err != nil {
		return nil, err
	}

	svc := c.Service()
	return LoadHost(task, svc, nodes[0].ID)
}

// AddNodes adds several nodes
func (c *Cluster) AddNodes(task concurrency.Task, count int, def *abstracts.HostDefinition) (_ []*propertiesv1.Node, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if count < 1 {
		return nil, scerr.InvalidParameterError("count", "cannot be an integer less than 1")
	}
	if def == nil {
		return nil, scerr.InvalidParameterError("def", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%d)", count), true)
	defer tracer.GoingIn().OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	nodeDef := complementHostDefinition(req, abstracts.HostDefinition{})
	var hostImage string

	properties := c.Properties
	if !properties.Lookup(Property.DefaultsV2) {
		err = c.Alter(task, func(clonable data.Clonable) error {
			return properties.Inspect(Property.DefaultsV1, func(clonable data.Clonable) error {
				defaultsV1, ok := clonable.(*propertiesv1.Defaults)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.Defaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return properties.Alter(Property.DefaultsV2, func(clonable data.Clonable) error {
					defaultsV2, ok := clonable.(*propertiesv2.Defaults)
					if !ok {
						return scerr.InconsistentError("'*propertiesv2.Defaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					convertDefaultsV1ToDefaultsV2(defaultsV1, defaultsV2)
					return nil
				})
			})
		})
		if err != nil {
			return nil, err
		}
	}
	err = properties.Inspect(Property.DefaultsV2, func(clonable data.Clonable) error {
		defaultsV2, ok := v.(*propertiesv2.Defaults)
		if !ok {
			return scerr.InconsistentError("'*propertiesv2.Defaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		sizing := srvutils.ToPBHostSizing(defaultsV2.NodeSizing)
		nodeDef.Sizing = &sizing
		hostImage = defaultsV2.Image
		return nil
	})
	if err != nil {
		return nil, err
	}

	if nodeDef.ImageId == "" {
		nodeDef.ImageId = hostImage
	}

	var (
		nodeType    NodeType.Enum
		nodeTypeStr string
		errors      []string
	)
	netCfg, err := c.NetworkConfig(task)
	if err != nil {
		return nil, err
	}
	nodeDef.Network = netCfg.NetworkID

	var nodes []*propertiesv1.Node
	err = c.Alter(task, func(clonable data.Clonable) error {
		ctrl, ok := clonable.(*cluster.Controller)
		if !ok {
			return scerr.InconsistentError("'c*luster.Controller' was expected, '%s' is provided", reflect.TypeOf(clonable).String())
		}
		var innerErr error
		nodes, inErr = ctrl.AddNodes(task, count, def)
		if inErr != nil {
			return inErr
		}

		defer func() {
			if inErr != nil {
				deleteNodes(task, oc.Service(), nodes)
			}
		}()

		inErr = properties.Alter(Property.NodesV1, func(clonable data.Clonable) error {
			nodesV1, ok := clonable.(*propertiesv1.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// for _, node := range nodes {
			nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, nodes...)
			// }
			return nil
		})
		if inErr != nil {
			return inErr
		}
		return ctrl.EnlistNodes(task, nodes)
	})
	if err != nil {
		return nil, err
	}
	return nodes, err
}

// complementHostDefinition complements req with default values if needed
func complementHostDefinition(req *abstracts.HostDefinition, def abstracts.HostDefinition) *abstracts.HostDefinition {
	var finalDef abstracts.HostDefinition
	if req == nil {
		finalDef = def
	} else {
		finalDef = *req
		finalDef.Sizing = &abstracts.HostSizing{}
		*finalDef.Sizing = *req.Sizing

		if def.Sizing.MinCpuCount > 0 && finalDef.Sizing.MinCpuCount == 0 {
			finalDef.Sizing.MinCpuCount = def.Sizing.MinCpuCount
		}
		if def.Sizing.MaxCpuCount > 0 && finalDef.Sizing.MaxCpuCount == 0 {
			finalDef.Sizing.MaxCpuCount = def.Sizing.MaxCpuCount
		}
		if def.Sizing.MinRamSize > 0.0 && finalDef.Sizing.MinRamSize == 0.0 {
			finalDef.Sizing.MinRamSize = def.Sizing.MinRamSize
		}
		if def.Sizing.MaxRamSize > 0.0 && finalDef.Sizing.MaxRamSize == 0.0 {
			finalDef.Sizing.MaxRamSize = def.Sizing.MaxRamSize
		}
		if def.Sizing.MinDiskSize > 0 && finalDef.Sizing.MinDiskSize == 0 {
			finalDef.Sizing.MinDiskSize = def.Sizing.MinDiskSize
		}
		if finalDef.Sizing.GpuCount <= 0 && def.Sizing.GpuCount > 0 {
			finalDef.Sizing.GpuCount = def.Sizing.GpuCount
		}
		if finalDef.Sizing.MinCpuFreq == 0 && def.Sizing.MinCpuFreq > 0 {
			finalDef.Sizing.MinCpuFreq = def.Sizing.MinCpuFreq
		}
		if finalDef.ImageId == "" {
			finalDef.ImageId = def.ImageId
		}

		if finalDef.Sizing.MinCpuCount <= 0 {
			finalDef.Sizing.MinCpuCount = 2
		}
		if finalDef.Sizing.MaxCpuCount <= 0 {
			finalDef.Sizing.MaxCpuCount = 4
		}
		if finalDef.Sizing.MinRamSize <= 0.0 {
			finalDef.Sizing.MinRamSize = 7.0
		}
		if finalDef.Sizing.MaxRamSize <= 0.0 {
			finalDef.Sizing.MaxRamSize = 16.0
		}
		if finalDef.Sizing.MinDiskSize <= 0 {
			finalDef.Sizing.MinDiskSize = 50
		}
	}

	return &finalDef
}

func convertDefaultsV1ToDefaultsV2(defaultsV1 *propertiesv1.Defaults, defaultsV2 *propertiesv2.Defaults) {
	defaultsV2.Image = defaultsV1.Image
	defaultsV2.MasterSizing = abstracts.SizingRequirements{
		MinCores:    defaultsV1.MasterSizing.Cores,
		MinFreq:     defaultsV1.MasterSizing.CPUFreq,
		MinGPU:      defaultsV1.MasterSizing.GPUNumber,
		MinRAMSize:  defaultsV1.MasterSizing.RAMSize,
		MinDiskSize: defaultsV1.MasterSizing.DiskSize,
		Replaceable: defaultsV1.MasterSizing.Replaceable,
	}
	defaultsV2.NodeSizing = abstracts.SizingRequirements{
		MinCores:    defaultsV1.NodeSizing.Cores,
		MinFreq:     defaultsV1.NodeSizing.CPUFreq,
		MinGPU:      defaultsV1.NodeSizing.GPUNumber,
		MinRAMSize:  defaultsV1.NodeSizing.RAMSize,
		MinDiskSize: defaultsV1.NodeSizing.DiskSize,
		Replaceable: defaultsV1.NodeSizing.Replaceable,
	}
}

// DeleteLastNode deletes the last added node and returns its name
func (c *Cluster) DeleteLastNode(task concurrency.Task) (node *propertiesv1.Node, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	selectedMaster, err := c.FindAvailableMaster(task)
	if err != nil {
		return nil, err
	}

	// Removed reference of the node from cluster
	err = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		// ctrl, ok := clonable.(*cluster.Controller)
		// if !ok {
		// 	return scerr.InconsistentError("'*cluster.Controller' expected, '%s' provided", reflect.TypeOf(clonable).String())
		// }

		inErr = props.Inspect(clusterproperty.NodesV1, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			node = nodesV2.PrivateNodes[len(nodesV2.PrivateNodes)-1]
			return nil
		})
		if inErr != nil {
			return inErr
		}
		return c.DeleteSpecificNode(task, node.ID, selectedMaster.ID)
	})
	if err != nil {
		return nil, err
	}
	return node, nil
}

// DeleteSpecificNode deletes a node identified by its ID
func (c *Cluster) DeleteSpecificNode(task concurrency.Task, hostID string, selectedMasterID string) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, "", false).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if selectedMasterID == "" {
		selectedMaster, inErr = c.FindAvailableMaster(task)
		if err != nil {
			return inErr
		}
		selectedMasterID = selectedMaster.ID
	}

	// Identifies the node to delete and remove it preventively from metadata
	var node *propertiesv2.Node
	err = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		inErr := props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			found, idx := contains(nodesV2.PrivateNodes, hostID)
			if !found {
				return scerr.NotFoundError("failed to find host '%s'", hostID)
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
	if err != nil {
		return nil
	}

	// Starting from here, restore node in cluster metadata if exiting with error
	defer func() {
		if err != nil {
			derr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
				return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
					nodesV2, ok := v.(*propertiesv2.Nodes)
					if !ok {
						return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					nodesV2.PrivateNodes = append(nodesV2.PrivateNodes, node)
					return nil
				})
			})
			if derr != nil {
				logrus.Errorf("failed to restore node ownership in cluster")
			}
			err = scerr.AddConsequence(err, derr)
		}
	}()

	// Deletes node
	return c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		// Leave node from cluster, if selectedMasterID isn't empty
		if selectedMasterID != "" {
			err = c.foreman.leaveNodesFromList(task, []string{node.ID}, selectedMasterID)
			if err != nil {
				return err
			}
		}
		host, err := hostfactory.Load(task, c.service, node.ID)
		if err != nil {
			return err
		}
		if b.makers.UnconfigureNode != nil {
			err = b.makers.UnconfigureNode(task, b, host, selectedMasterID)
			if err != nil {
				return err
			}
		}

		// Finally delete host
		err = host.Delete(task)
		if err != nil {
			if _, ok := err.(*scerr.ErrNotFound); ok {
				// host seems already deleted, so it's a success (handles the case where )
				return nil
			}
			return err
		}
		return nil
	})
}

// ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
func (c *Cluster) ListMasters(task concurrency.Task) (list resources.IndexedListOfClusterNodes, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	list = resources.IndexedListOfClusterNodes{}
	err = c.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV2.Masters {
				list[v.NumericalID] = v
			}
			return nil
		})
	})
	if err != nil {
		logrus.Errorf("failed to get list of masters: %v", err)
		return list, err
	}
	return list, err
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (c *Cluster) ListMasterNames(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	list = data.IndexedListOfStrings{}
	err = c.Inspect(task, func(_ data.Clonable, props *serialier.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV2.Masters {
				list[v.NumericalID] = v.Name
			}
			return nil
		})
	})
	if err != nil {
		// logrus.Errorf("failed to get list of master names: %v", err)
		return nil, err
	}
	return list, nil
}

// ListMasterIDs lists the IDs of masters (if there is such masters in the flavor...)
func (c *Cluster) ListMasterIDs(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	list = data.IndexedListOfStrings{}
	err = c.Inspect(task, func(_ data.Clonable, props *serialier.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV2.Masters {
				list[v.NumericalID] = v.ID
			}
			return nil
		})
	})
	if err != nil {
		return nil, scerr.Wrap(err, "failed to get list of master IDs")
	}
	return list, nil
}

// ListMasterIPs lists the IPs of masters (if there is such masters in the flavor...)
func (c *Cluster) ListMasterIPs(task concurrency.Task) (list []string, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	list = []string{}
	err = c.Inspect(task, func(_ data.Clonable, props *serialier.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV2.Masters {
				list[v.NumericalID] = v.PrivateIP
			}
			return nil
		})
	})
	if err != nil {
		logrus.Errorf("failed to get list of master IPs: %v", err)
		return nil, err
	}
	return list, err
}

// FindAvailableMaster returns ID of the first master available to execute order
// satisfies interface cluster.cluster.Controller
func (c *Cluster) FindAvailableMaster(task concurrency.Task) (master *propertiesv2.Node, err error) {
	master = nil
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	found := false
	masters, err := c.ListMasters(task)
	if err != nil {
		return nil, err
	}

	var lastError error
	svc := c.Service()
	for _, v = range masters {
		host, err := hostfactory.LoadHost(task, svc, v.ID)
		if err != nil {
			return nil, err
		}

		_, err = host.WaitServerReady(task, "ready", temporal.GetConnectSSHTimeout())
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				lastError = err
				continue
			}
			return nil, err
		}
		found = true
		master = m
		break
	}
	if !found {
		return nil, fmt.Errorf("failed to find available master: %v", lastError)
	}
	return master, nil
}

// ListNodes lists node instances corresponding to the nodes in the cluster
// satisfies interface cluster.Controller
func (c *Cluster) ListNodes(task concurrency.Task) (list resources.IndexedListOfClusterNodes, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	list = resources.IndexedListOfClusterNodes{}
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV2.PrivateNodes {
				list[v.NumericalID] = v.Name
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return list, nil
}

// ListNodeNames lists the names of the nodes in the Cluster
func (c *Cluster) ListNodeNames(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	list = data.IndexedListOfStrings{}
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV2.PrivateNodes {
				list[v.NumericalID] = v.Name
			}
			return nil
		})
	})
	if err != nil {
		// logrus.Errorf("failed to get list of node IDs: %v", err)
		return nil, err
	}
	return list, err
}

// ListNodeIDs lists IDs of the nodes in the cluster
func (c *Cluster) ListNodeIDs(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	list = data.IndexedListOfStrings{}
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV2.PrivateNodes {
				list[v.NumericalID] = v.ID
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return list, err
}

// ListNodeIPs lists the IPs of the nodes in the cluster
// satisfies interface cluster.cluster.Controller
func (c *Cluster) ListNodeIPs(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnExitLogError("failed to get list of node IP addresses", &err)()
	defer scerr.OnPanic(&err)()

	list = data.IndexedListOfStrings{}
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes).PrivateNodes
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, i := range nodesV2 {
				list[v.NumericalID] = i.PrivateIP
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return list, nil
}

// FindAvailableNode returns node instance of the first node available to execute order
// satisfies interface cluster.cluster.Controller
func (c *Cluster) FindAvailableNode(task concurrency.Task) (node *propertiesv2.Node, err error) {
	if c == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	list, err := c.ListNodes(task)
	if err != nil {
		return nil, err
	}

	found := false
	svc := c.Service()
	for _, v := range list {
		host, err := hostfactory.Load(task, svc, v.ID)
		if err != nil {
			return nil, err
		}

		err = host.WaitServerReady(task, "ready", temporal.GetConnectSSHTimeout())
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
			return nil, err
		}
		found = true
		node = n
		break
	}
	if !found {
		return nil, fmt.Errorf("failed to find available node")
	}
	return node, nil
}

// LookupNode tells if the ID of the host passed as parameter is a node
// satisfies interface cluster.cluster.Controller
func (c *Cluster) LookupNode(task concurrency.Task, ref string) (found bool, err error) {
	if c == nil {
		return false, scerr.InvalidInstanceError()
	}
	if ref == "" {
		return false, scerr.InvalidParameterError("ref", "cannot be empty string")
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	found = false
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconcistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			found, _ = contains(nodesV2.PrivateNodes, hostID)
			return nil
		})
	})
	return found, err
}

// CountNodes counts the nodes of the cluster
// satisfies interface cluster.cluster.Controller
func (c *Cluster) CountNodes(task concurrency.Task) (count uint, err error) {
	if c == nil {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer scerr.OnExitLogError(concurrency.NewTracer(task, "", concurrency.IsLogActive("Trace.Controller")).TraceMessage(""), &err)()

	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			count = uint(len(nodesV2.PrivateNodes))
			return nil
		})
	})
	if err != nil {
		err = scerr.Wrap(err, "failed to count nodes")
		return 0, err
	}
	return count, nil
}

// Node returns a node based on its ID
func (c *Cluster) Node(task concurrency.Task, hostID string) (host resources.Host, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if hostID == "" {
		return nil, scerr.InvalidParameterError("hostID", "cannot be empty string")
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%s)", hostID), true)
	defer tracer.GoingIn().OnExitTrace()()
	defer scerr.OnExitLogError(fmt.Sprintf("failed to get node identified by '%s'", hostID), &err)()
	defer scerr.OnPanic(&err)()

	found := false
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			found, _ = contains(nodesV2.PrivateNodes, hostID)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("failed to find node '%s' in Cluster '%s'", hostID, c.Name)
	}
	return hostfactory.Load(task, c.Service(), hostID)
}

// deleteMaster deletes the master specified by its ID
func (c *Cluster) deleteMaster(task concurrency.Task, hostID string) error {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	var master *propertiesv1.Node
	// Removes master from cluster properties
	err := c.Alter(task, func(clonable data.Clonable) error {
		return c.Properties.Alter(Property.NodesV1, func(clonable data.Clonable) error {
			nodesV1, ok := clonable.(*propertiesv1.Nodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			found, idx := contains(nodesV1.Masters, hostID)
			if !found {
				return scerr.ResourceNotFoundError("host", hostID)
			}
			master = nodesV1.Masters[idx]
			if idx < len(nodesV1.Masters)-1 {
				nodesV1.Masters = append(nodesV1.Masters[:idx], nodesV1.Masters[idx+1:]...)
			} else {
				nodesV1.Masters = nodesV1.Masters[:idx]
			}
			return nil
		})
	})
	if err != nil {
		return err
	}

	// Starting from here, restore master in cluster properties if exiting with error
	defer func() {
		if err != nil {
			derr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
				return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
						nodesV2 := clonable.(*propertiesv2.Nodes)
						nodesV2.Masters = append(nodesV2.Masters, master)
						return nil
					})
				}
			})
			if derr != nil {
				logrus.Errorf("After failure, cleanup failed to restore master '%s' in cluster", master.Name)
			}
		}
	}()

	// Finally delete host
	return c.service.DeleteHost(master.ID)
}

// Delete allows to destroy infrastructure of cluster
// satisfies interface cluster.Controller
func (c *Cluster) Delete(task concurrency.Task) error {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	err := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		// Updates cluster state to mark cluster as Removing
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.State)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Removed
			return nil
		})
	})
	if err != nil {
		return err
	}

	taskDeleteNode := func(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
		err := c.DeleteSpecificNode(t, params.(string), "")
		return nil, err
	}

	taskDeleteMaster := func(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
		err := c.deleteMaster(t, params.(string))
		return nil, err
	}

	var cleaningErrors []error

	// deletes the cluster
	err = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		// Deletes the nodes
		list, innerErr := c.ListNodes(task)
		if err != nil {
			return innerErr
		}
		length := len(list)
		if length > 0 {
			subtasks := make([]concurrency.Task, 0, length)
			for i := 0; i < length; i++ {
				subtask, innerErr = task.StartInSubtask(taskDeleteNode, list[i])
				if innerErr != nil {
					cleaningErrors = append(cleaningErrors, scerr.Wrap(innerErr, fmt.Sprintf("failed to start deletion of node '%s'", list[i].Name)))
					break
				}
				subtasks = append(subtasks, subtask)
			}
			for _, s := range subtasks {
				_, subErr = s.Wait()
				if subErr != nil {
					cleaningErrors = append(cleaningErrors, subErr)
				}
			}
		}

		// Delete the Masters
		list, innerErr = c.ListMasters(task)
		if innerErr != nil {
			cleaningErrors = append(cleaningErrors, innerErr)
			return scerr.ErrListError(cleaningErrors)
		}
		length = len(list)
		if length > 0 {
			subtasks := make([]concurrency.Task, 0, length)
			for i := 0; i < length; i++ {
				subtask, innerErr = task.StartInSubTask(taskDeleteMaster, list[i])
				if innerErr != nil {
					cleaningErrors = append(cleaningErrors, scerr.Wrap(innerErr, fmt.Sprintf("failed to start deletion of master '%s'", list[i].Name)))
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
		// c.RLock(task)
		networkID := ""
		if props.Lookup(clusterproperty.NetworkV2) {
			err = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
				// FIXME: validate cast
				networkID = clonable.(*propertiesv2.Network).NetworkID
				return nil
			})
		} else {
			err = props.Inspect(Property.NetworkV1, func(clonable data.Clonable) error {
				// FIXME: validate cast
				networkID = clonable.(*propertiesv1.Network).NetworkID
				return nil
			})
		}
		// c.RUnlock(task)
		if innerErr != nil {
			cleaningErrors = append(cleaningErrors, err)
			return innerErr
		}

		network, innerErr := networkfactory.Load(task, c.Service(), networkID)
		if innerErr != nil {
			cleaningErrors = append(cleaningErrors, err)
			return innerErr
		}
		return retry.WhileUnsuccessfulDelay5SecondsTimeout(
			func() error {
				return network.Delete(task)
			},
			temporal.GetHostTimeout(),
		)
	})
	if err != nil {
		return scerr.ErrListError(cleaningErrors)
	}

	return c.core.Delete(task)
}

func deleteNodes(task concurrency.Task, svc iaas.Service, nodes []*propertiesv2.Node) {
	length := len(nodes)
	if length > 0 {
		subtasks := make([]concurrency.Task, 0, length)
		for i := 0; i < length; i++ {
			host, err := hostfactory.Load(task, svc, nodes[i].ID)
			if err != nil {
				subtasks[i] = nil
				logrus.Errorf(err.Error())
				continue
			}
			subtask, err := task.New().Start(
				func(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
					return nil, host.Delete(task)
				},
				nil,
			)
			if err != nil {
				subtasks[i] = nil
				logrus.Errorf(err.Error())
				continue
			}
			subtasks[i] = subtask
		}
		for i := 0; i < length; i++ {
			if subtasks[i] != nil {
				state := subtasks[i].Wait()
				if state != nil {
					logrus.Errorf("after failure, cleanup failed to delete node '%s': %v", nodes[i].Name, state)
				}
			}
		}
	}
}

func contains(list []*propertiesv2.Node, hostID string) (bool, int) {
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
func (b *foreman) unconfigureMaster(task concurrency.Task, pbHost *protocol.Host) error {
	if b.makers.UnconfigureMaster != nil {
		return b.makers.UnconfigureMaster(task, b, pbHost)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// configureCluster ...
// params contains a data.Map with primary and secondary Gateway hosts
func (c *cluster) configureCluster(task concurrency.Task, params concurrency.TaskParameters) (err error) {
	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Infof("[cluster %s] configuring cluster...", b.cluster.Name)
	defer func() {
		if err == nil {
			logrus.Infof("[cluster %s] configuration successful.", b.cluster.Name)
		} else {
			logrus.Errorf("[cluster %s] configuration failed: %s", b.cluster.Name, err.Error())
		}
	}()

	err = c.createSwarm(task, params)
	if err != nil {
		return err
	}

	// Installs reverseproxy feature on cluster (gateways)
	err = c.installReverseProxy(task)
	if err != nil {
		return err
	}

	// Installs remotedesktop feature on cluster (all masters)
	err = c.installRemoteDesktop(task)
	if err != nil {
		return err
	}

	// configure what has to be done cluster-wide
	if c.makers.ConfigureCluster != nil {
		return c.makers.ConfigureCluster(task, b)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

func (c *cluster) determineRequiredNodes(task concurrency.Task) (uint, uint, uint) {
	if c.makers.MinimumRequiredServers != nil {
		return c.makers.MinimumRequiredServers(task, c)
	}
	return 0, 0, 0
}

// createSwarm configures cluster
func (c *cluster) createSwarm(task concurrency.Task, params concurrency.TaskParameters) (err error) {

	var (
		p                                = data.Map{}
		ok                               bool
		primaryGateway, secondaryGateway *abstracts.Host
	)

	if params == nil {
		return scerr.InvalidParameterError("params", "cannot be nil")
	}

	if p, ok = params.(data.Map); !ok {
		return scerr.InvalidParameterError("params", "must be a data.Map")
	}
	if primaryGateway, ok = p["PrimaryGateway"].(*abstracts.Host); !ok || primaryGateway == nil {
		return scerr.InvalidParameterError("params", "params['PrimaryGateway'] must be defined and cannot be nil")
	}
	secondaryGateway, ok = p["SecondaryGateway"].(*abstracts.Host)
	if !ok {
		logrus.Debugf("secondary gateway not configured")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	clientInstance := client.New()
	clientHost := clientInstance.Host
	clientSSH := clientInstance.SSH

	// Join masters in Docker Swarm as managers
	joinCmd := ""
	masters, err := c.ListMasterIDs(task)
	if err != nil {
		return err
	}
	for _, hostID := range masters {
		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		if joinCmd == "" {
			retcode, _, _, err := clientSSH.Run(task, hostID, "docker swarm init && docker node update "+host.Name+" --label-add safescale.host.role=master",
				client.DefaultConnectionTimeout, client.DefaultExecutionTimeout) // FIXME This should use task context
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to init docker swarm")
			}
			retcode, token, stderr, err := clientSSH.Run(task, hostID, "docker swarm join-token manager -q", client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to generate token to join swarm as manager: %s", stderr)
			}
			token = strings.Trim(token, "\n")
			joinCmd = fmt.Sprintf("docker swarm join --token %s %s", token, host.PrivateIp)
		} else {
			masterJoinCmd := joinCmd + " && docker node update " + host.Name + " --label-add safescale.host.role=master"
			retcode, _, stderr, err := clientSSH.Run(task, hostID, masterJoinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to join host '%s' to swarm as manager: %s", host.Name, stderr)
			}
		}
	}

	master, err := c.FindAvailableMaster(task)
	if err != nil {
		return fmt.Errorf("failed to find an available docker manager: %v", err)
	}
	selectedMaster, err := clientHost.Inspect(master.ID, client.DefaultExecutionTimeout)
	if err != nil {
		return fmt.Errorf("failed to get metadata of docker manager: %s", err.Error())
	}

	// build command to join Docker Swarm as workers
	joinCmd, err = c.getSwarmJoinCommand(task, selectedMaster, true)
	if err != nil {
		return err
	}

	// Join private node in Docker Swarm as workers
	list, err := c.ListNodeIDs(task)
	if err != nil {
		return err
	}
	for _, hostID := range list {
		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		retcode, _, stderr, err := clientSSH.Run(task, hostID, joinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", host.Name, stderr)
		}
		labelCmd := "docker node update " + host.Name + " --label-add safescale.host.role=node"
		retcode, _, stderr, err = clientSSH.Run(task, selectedMaster.Id, labelCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to label swarm worker '%s' as node: %s", host.Name, stderr)
		}
	}

	// Join gateways in Docker Swarm as workers
	retcode, _, stderr, err := clientSSH.Run(task, primaryGateway.ID, joinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", primaryGateway.Name, stderr)
	}
	labelCmd := "docker node update " + primaryGateway.Name + " --label-add safescale.host.role=gateway"
	retcode, _, stderr, err = clientSSH.Run(task, selectedMaster.Id, labelCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to label docker Swarm worker '%s' as gateway: %s", primaryGateway.Name, stderr)
	}

	if secondaryGateway != nil {
		retcode, _, stderr, err := clientSSH.Run(task, secondaryGateway.ID, joinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", primaryGateway.Name, stderr)
		}
		labelCmd := "docker node update " + secondaryGateway.Name + " --label-add safescale.host.role=gateway"
		retcode, _, stderr, err = clientSSH.Run(task, selectedMaster.Id, labelCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to label docker swarm worker '%s' as gateway: %s", secondaryGateway.Name, stderr)
		}
	}

	return nil
}

// getSwarmJoinCommand builds the command to obtain swarm token
func (c *cluster) getSwarmJoinCommand(task concurrency.Task, selectedMaster *protocol.Host, worker bool) (string, error) {
	clientInstance := client.New()
	var memberType string
	if worker {
		memberType = "worker"
	} else {
		memberType = "manager"
	}

	tokenCmd := fmt.Sprintf("docker swarm join-token %s -q", memberType)
	retcode, token, stderr, err := clientInstance.SSH.Run(task, selectedMaster.Id, tokenCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return "", fmt.Errorf("failed to generate token to join swarm as worker: %s", stderr)
	}
	token = strings.Trim(token, "\n")
	return fmt.Sprintf("docker swarm join --token %s %s", token, selectedMaster.PrivateIp), nil
}

// uploadTemplateToFile uploads a template named 'tmplName' coming from rice 'box' in a file to a remote host
func realizeTemplate(
	box *rice.Box, funcMap map[string]interface{}, tmplName string, data map[string]interface{},
	fileName string,
) (string, string, error) {

	if box == nil {
		return "", "", scerr.InvalidParameterError("box", "cannot be nil!")
	}
	tmplString, err := box.String(tmplName)
	if err != nil {
		return "", "", fmt.Errorf("failed to load template: %s", err.Error())
	}
	tmplCmd, err := txttmpl.New(fileName).Funcs(template.MergeFuncs(funcMap, false)).Parse(tmplString)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse template: %s", err.Error())
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, data)
	if err != nil {
		return "", "", fmt.Errorf("failed to realize template: %s", err.Error())
	}
	cmd := dataBuffer.String()
	remotePath := srvutils.TempFolder + "/" + fileName

	return cmd, remotePath, nil
}

func uploadScriptToFileInHost(script string, hostID string, fileName string) error {
	host, err := client.New().Host.Inspect(hostID, temporal.GetExecutionTimeout())
	if err != nil {
		return fmt.Errorf("failed to get host information: %s", err)
	}

	err = srvutils.UploadStringToRemoteFile(script, host, fileName, "", "", "")
	if err != nil {
		return err
	}

	return nil
}

// configureNodesFromList configures nodes from a list
func (c *cluster) configureNodesFromList(task concurrency.Task, hosts []string) (err error) {
	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		host   *protocol.Host
		hostID string
		errs   []string
	)

	var subtasks []concurrency.Task
	clientHost := client.New().Host
	length := len(hosts)
	for i := 0; i < length; i++ {
		host, err = clientHost.Inspect(hosts[i], temporal.GetExecutionTimeout())
		if err != nil {
			break
		}
		subtask, err := task.StartInSubTask(c.taskConfigureNode, data.Map{
			"index": uint(i + 1),
			"host":  host,
		})
		if err != nil {
			break
		}
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	if err != nil {
		errs = append(errs, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf(strings.Join(errs, "\n"))
	}
	return nil
}

// joinNodesFromList makes nodes from a list join the cluster
func (c *cluster) joinNodesFromList(task concurrency.Task, hosts []string) error {
	if c.makers.JoinNodeToCluster == nil {
		// configure what has to be done cluster-wide
		if c.makers.ConfigureCluster != nil {
			return c.makers.ConfigureCluster(task, b)
		}
	}

	logrus.Debugf("Joining nodes to cluster...")

	clientInstance := client.New()
	clientHost := clientInstance.Host
	clientSSH := clientInstance.SSH

	master, err := c.FindAvailableMaster(task)
	if err != nil {
		return fmt.Errorf("failed to join workers to Docker Swarm: %v", err)
	}
	selectedMaster, err := clientHost.Inspect(master.ID, client.DefaultExecutionTimeout)
	if err != nil {
		return fmt.Errorf("failed to get metadata of host: %s", err.Error())
	}
	joinCmd, err := c.getSwarmJoinCommand(task, selectedMaster, true)
	if err != nil {
		return err
	}

	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			return err
		}

		retcode, _, stderr, err := clientSSH.Run(task, pbHost.Id, joinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", pbHost.Name, stderr)
		}
		nodeLabel := "docker node update " + pbHost.Name + " --label-add safescale.host.role=node"
		retcode, _, stderr, err = clientSSH.Run(task, selectedMaster.Id, nodeLabel, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to add label to docker Swarm worker '%s': %s", pbHost.Name, stderr)
		}

		if c.makers.JoinMasterToCluster != nil {
			err = c.makers.JoinNodeToCluster(task, b, pbHost)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// leaveMastersFromList makes masters from a list leave the cluster
func (c *cluster) leaveMastersFromList(task concurrency.Task, public bool, hosts []string) error {
	if c.makers.LeaveMasterFromCluster == nil {
		return nil
	}

	logrus.Debugf("Making Masters leaving cluster...")

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			return err
		}
		err = c.makers.LeaveMasterFromCluster(task, c, pbHost)
		if err != nil {
			return err
		}
	}

	return nil
}

// leaveNodesFromList makes nodes from a list leave the cluster
func (c *cluster) leaveNodesFromList(task concurrency.Task, hosts []string, selectedMasterID string) error {
	logrus.Debugf("Instructing nodes to leave cluster...")

	if selectedMasterID == "" {
		master, err := c.FindAvailableMaster(task)
		if err != nil {
			return err
		}
		selectedMasterID = master.ID
	}

	clientHost := client.New().Host

	// Unjoins from cluster are done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			// If host seems deleted, consider leaving as a success
			if _, ok := err.(*scerr.ErrNotFound); ok {
				continue
			}
			return err
		}

		if c.makers.LeaveNodeFromCluster != nil {
			err = c.makers.LeaveNodeFromCluster(task, c, pbHost, selectedMasterID)
			if err != nil {
				return err
			}
		}

		err = c.leaveNodeFromSwarm(task, pbHost, selectedMasterID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *cluster) leaveNodeFromSwarm(task concurrency.Task, pbHost *protocol.Host, selectedMasterID string) error {
	if selectedMasterID == "" {
		var err error
		master, err := c.FindAvailableMaster(task)
		if err != nil {
			return err
		}
		selectedMasterID = master.ID
	}

	clientSSH := client.New().SSH

	// Check worker is member of the Swarm
	cmd := fmt.Sprintf("docker node ls --format \"{{.Hostname}}\" --filter \"name=%s\" | grep -i %s", pbHost.Name, pbHost.Name)
	retcode, _, _, err := clientSSH.Run(task, selectedMasterID, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		// node is already expelled from Docker Swarm
		return nil
	}
	// node is a worker in the Swarm: 1st ask worker to leave Swarm
	cmd = "docker swarm leave"
	retcode, _, stderr, err := clientSSH.Run(task, pbHost.Id, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to make node '%s' leave swarm: %s", pbHost.Name, stderr)
	}

	// 2nd: wait the Swarm worker to appear as down from Swarm master
	cmd = fmt.Sprintf("docker node ls --format \"{{.Status}}\" --filter \"name=%s\" | grep -i down", pbHost.Name)
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			retcode, _, _, err := clientSSH.Run(task, selectedMasterID, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("'%s' not in Down state", pbHost.Name)
			}
			return nil
		},
		temporal.GetHostTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			return fmt.Errorf("SWARM worker '%s' didn't reach 'Down' state after %v", pbHost.Name, temporal.GetHostTimeout())
		default:
			return fmt.Errorf("SWARM worker '%s' didn't reach 'Down' state: %v", pbHost.Name, retryErr)
		}
	}

	// 3rd, ask master to remove node from Swarm
	cmd = fmt.Sprintf("docker node rm %s", pbHost.Name)
	retcode, _, stderr, err = clientSSH.Run(task, selectedMasterID, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to remove worker '%s' from Swarm on master '%s': %s", pbHost.Name, selectedMasterID, stderr)
	}
	return nil
}

// getNodeInstallationScript ...
func (c *cluster) getNodeInstallationScript(task concurrency.Task, nodeType NodeType.Enum) (string, map[string]interface{}) {
	if c.makers.GetNodeInstallationScript != nil {
		return c.makers.GetNodeInstallationScript(task, c, nodeType)
	}
	return "", map[string]interface{}{}
}

// BuildHostname builds a unique hostname in the Cluster
func (c *cluster) buildHostname(task concurrency.Task, core string, nodeType NodeType.Enum) (cluid string, err error) {
	var index int

	defer scerr.OnPanic(&err)()

	// Locks for write the manager extension...

	err := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			// FIXME: validate cast
			nodesV2 := clonable.(*propertiesv2.Nodes)
			switch nodeType {
			case NodeType.Node:
				nodesV2.PrivateLastIndex++
				index = nodesV2.PrivateLastIndex
			case NodeType.Master:
				nodesV2.MasterLastIndex++
				index = nodesV2.MasterLastIndex
			}
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return c.Identity(task).Name + "-" + core + "-" + strconv.Itoa(index), nil
}