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
	"fmt"
	"reflect"
	"strconv"
	"strings"
	txttmpl "text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

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
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
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
	*Core
	abstract.ClusterIdentity

	installMethods         map[uint8]installmethod.Enum
	lastStateCollection    time.Time
	service                iaas.Service
	makers                 flavors.Makers
	concurrency.TaskedLock `json:"-"`
}

func nullCluster() *cluster {
	return &cluster{Core: nullCore()}
}

// NewCluster ...
func NewCluster(task concurrency.Task, svc iaas.Service) (_ resources.Cluster, err error) {
	if task == nil {
		return nullCluster(), scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullCluster(), scerr.InvalidParameterError("svc", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	core, err := NewCore(svc, "cluster", clustersFolderName)
	if err != nil {
		return nullCluster(), err
	}

	return &cluster{Core: core}, nil
}

// LoadCluster ...
func LoadCluster(task concurrency.Task, svc iaas.Service, name string) (_ resources.Cluster, err error) {
	if task == nil {
		return nullCluster(), scerr.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nullCluster(), scerr.InvalidParameterError("svc", "cannot be nil")
	}
	if name == "" {
		return nullCluster(), scerr.InvalidParameterError("name", "cannot be empty string")
	}
	defer scerr.OnPanic(&err)()

	anon, err := NewCluster(task, svc)
	if err != nil {
		return nullCluster(), err
	}
	instance := anon.(*cluster)

	err = instance.Read(task, name)
	if err != nil {
		return nullCluster(), err
	}

	// From here, we can deal with legacy
	err = instance.upgradePropertyNodesIfNeeded(task)
	if err != nil {
		return nullCluster(), err
	}

	return instance, nil
}

// upgradePropertyNodesIfNeeded upgrades current Nodes property to last Nodes property (currently NodesV2)
func (c *cluster) upgradePropertyNodesIfNeeded(task concurrency.Task) error {
	return c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		if !props.Lookup(clusterproperty.NodesV2) {
			// Replace NodesV1 by NodesV2 properties
			return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
				nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
				if !ok {
					return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return props.Alter(clusterproperty.NodesV1, func(clonable data.Clonable) error {
					nodesV1, ok := clonable.(*propertiesv1.ClusterNodes)
					if !ok {
						return scerr.InconsistentError("'*propertiesv1.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
}

// IsNull tells if the instance represents a null value of cluster
func (c *cluster) IsNull() bool {
	return c == nil || c.Core.IsNull()
}

// // VPL: ambiguous candidate on GetName(), didn't find where yet...
// // GetName returns the name if the cluster
// func (c *cluster) GetName() string {
// 	return c.Core.Name()
// }
//
// // GetID returns the name of the cluster (there is no ID, but data.Identityable wants ID()
// func (c *cluster) GetID() string {
// 	return c.Core.Name()
// }

// Create creates the necessary infrastructure of the Cluster
func (c *cluster) Create(task concurrency.Task, req abstract.ClusterRequest) (err error) {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting creation of infrastructure of cluster '%s'...", req.Name),
		fmt.Sprintf("Ending creation of infrastructure of cluster '%s'", req.Name),
	)()
	defer scerr.OnExitLogError(tracer.TraceMessage("failed to create cluster infrastructure:"), &err)()
	defer scerr.OnPanic(&err)()

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
	gatewaysDef, mastersDef, nodesDef, err := c.defineSizingRequirements(task, req)

	// Create the network
	network, err := c.createNetwork(task, req, gatewaysDef)
	if err != nil {
		return err
	}
	// req.NetworkID = network.GetID()

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := network.Delete(task)
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Creates and configures hosts
	err = c.createHosts(task, network, *mastersDef, *nodesDef, req.KeepOnFailure)
	if err != nil {
		return err
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
						_, tgerr = tg.StartInSubtask(c.taskDeleteHost, data.Map{"host": v})
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
						_, tgerr = tg.StartInSubtask(c.taskDeleteHost, data.Map{"host": v})
						if tgerr != nil {
							err = scerr.AddConsequence(err, tgerr)
						}
					}
				}

				_, _, tgerr = tg.WaitGroupFor(temporal.GetLongOperationTimeout())
				if tgerr != nil {
					err = scerr.AddConsequence(err, tgerr)
				}
			}

		}
	}()

	primaryGateway, err := network.GetGateway(task, true)
	if err != nil {
		return err
	}
	secondaryGateway, err := network.GetGateway(task, false)
	if err != nil {
		return err
	}

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
func (c *cluster) firstLight(task concurrency.Task, req abstract.ClusterRequest) error {
	// FIXME: validate parameters

	err := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		// VPL: For now, always disable addition of feature proxycache-client
		innerErr := props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			featuresV1.Disabled["proxycache"] = struct{}{}
			return nil
		})
		if innerErr != nil {
			return scerr.Wrap(innerErr, "failed to disable feature 'proxycache'")
		}
		// ENDVPL

		// Sets initial state of the new cluster and create metadata
		innerErr = props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Creating
			return nil
		})
		if innerErr != nil {
			return scerr.Wrap(innerErr, "failed to set initial state of cluster")
		}

		// sets default sizing from req
		innerErr = props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Defaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*req.GatewaysDef)
			defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*req.MastersDef)
			defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*req.NodesDef)
			defaultsV2.Image = req.NodesDef.Image
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		// FUTURE: sets the cluster composition (when we will be able to manage cluster spread on several tenants...)
		innerErr = props.Alter(clusterproperty.CompositeV1, func(clonable data.Clonable) error {
			compositeV1, ok := clonable.(*propertiesv1.ClusterComposite)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterComposite' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			compositeV1.Tenants = []string{req.Tenant}
			return nil
		})
		if innerErr != nil {
			return innerErr
		}

		// Create a KeyPair for the user cladm
		kpName := "cluster_" + req.Name + "_cladm_key"
		kp, innerErr := c.service.CreateKeyPair(kpName)
		if innerErr != nil {
			return innerErr
		}
		c.ClusterIdentity.Keypair = kp

		// Generate needed password for account cladm
		cladmPassword, err := utils.GeneratePassword(16)
		if err != nil {
			return err
		}

		// Sets identity
		c.ClusterIdentity.Name = req.Name
		c.ClusterIdentity.Flavor = req.Flavor
		c.ClusterIdentity.Complexity = req.Complexity
		c.ClusterIdentity.AdminPassword = cladmPassword

		// Links maker based on Flavor
		return c.Bootstrap(task)
	})
	if err != nil {
		return err
	}

	// Writes the metadata for the first time
	return c.Carry(task, c)
}

// defineSizings calculates the sizings needed for the hosts of the cluster
func (c *cluster) defineSizingRequirements(task concurrency.Task, req abstract.ClusterRequest) (
	*abstract.HostSizingRequirements, *abstract.HostSizingRequirements, *abstract.HostSizingRequirements, error,
) {

	var (
		gatewaysDefault *abstract.HostSizingRequirements
		mastersDefault  *abstract.HostSizingRequirements
		nodesDefault    *abstract.HostSizingRequirements
		imageID         string
	)

	// Determine default image
	if req.NodesDef != nil {
		imageID = req.NodesDef.Image
	}
	if imageID == "" && c.makers.DefaultImage != nil {
		imageID = c.makers.DefaultImage(task, c)
	}
	if imageID == "" {
		imageID = "Ubuntu 18.04"
	}

	// Determine Gateway sizing
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
	gatewaysDef := complementSizingRequirements(req.GatewaysDef, *gatewaysDefault)
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
	mastersDef := complementSizingRequirements(req.MastersDef, *mastersDefault)
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
	nodesDef := complementSizingRequirements(req.NodesDef, *nodesDefault)
	nodesDef.Image = imageID

	err := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			defaultsV2.GatewaySizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*gatewaysDef)
			defaultsV2.MasterSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*mastersDef)
			defaultsV2.NodeSizing = *converters.HostSizingRequirementsFromAbstractToPropertyV2(*nodesDef)
			defaultsV2.Image = imageID
			return nil
		})
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return gatewaysDef, mastersDef, nodesDef, nil
}

// createNetwork creates the network for the cluster
func (c *cluster) createNetwork(
	task concurrency.Task,
	req abstract.ClusterRequest, gatewaysDef *abstract.HostSizingRequirements,
) (resources.Network, error) {

	// Determine if Gateway Failover must be set
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

	network, err := NewNetwork(c.service)
	if err != nil {
		return nil, err
	}
	err = network.Create(task, networkReq, "", gatewaysDef)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := network.Delete(task)
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Updates cluster metadata, propertiesv2.ClusterNetwork
	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
			networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			primaryGateway, innerErr := network.GetGateway(task, true)
			if innerErr != nil {
				return innerErr
			}
			var secondaryGateway resources.Host
			if !gwFailoverDisabled {
				secondaryGateway, innerErr = network.GetGateway(task, false)
				if innerErr != nil {
					if _, ok := innerErr.(scerr.ErrNotFound); !ok {
						return innerErr
					}
				}
			}
			networkV2.NetworkID = network.SafeGetID()
			networkV2.CIDR = req.CIDR
			networkV2.GatewayID = primaryGateway.SafeGetID()
			if networkV2.GatewayIP, innerErr = primaryGateway.GetPrivateIP(task); innerErr != nil {
				return innerErr
			}
			if networkV2.DefaultRouteIP, innerErr = network.GetDefaultRouteIP(task); innerErr != nil {
				return innerErr
			}
			if networkV2.EndpointIP, innerErr = network.GetEndpointIP(task); innerErr != nil {
				return innerErr
			}
			if networkV2.PrimaryPublicIP, innerErr = primaryGateway.GetPublicIP(task); innerErr != nil {
				return innerErr
			}
			if !gwFailoverDisabled {
				networkV2.SecondaryGatewayID = secondaryGateway.SafeGetID()
				if networkV2.SecondaryGatewayIP, innerErr = secondaryGateway.GetPrivateIP(task); innerErr != nil {
					return innerErr
				}
				if networkV2.SecondaryPublicIP, innerErr = secondaryGateway.GetPublicIP(task); innerErr != nil {
					return innerErr
				}
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
func (c *cluster) createHosts(
	task concurrency.Task,
	network resources.Network,
	mastersDef abstract.HostSizingRequirements,
	nodesDef abstract.HostSizingRequirements,
	keepOnFailure bool,
) error {

	gwFailoverDisabled := network.HasVirtualIP()

	primaryGateway, err := network.GetGateway(task, true)
	if err != nil {
		return err
	}
	secondaryGateway, err := network.GetGateway(task, false)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); !ok {
			return err
		}
	}

	_, err = primaryGateway.WaitSSHReady(task, temporal.GetExecutionTimeout())
	if err != nil {
		return scerr.Wrap(err, "wait for remote ssh service to be ready")
	}

	// Loads secondary gateway metadata
	if secondaryGateway != nil {
		_, err = secondaryGateway.WaitSSHReady(task, temporal.GetExecutionTimeout())
		if err != nil {
			return scerr.Wrap(err, "wait for remote ssh service to be ready")
		}
	}

	masterCount, privateNodeCount, _, err := c.determineRequiredNodes(task)
	if err != nil {
		return err
	}

	var (
		primaryGatewayStatus   error
		secondaryGatewayStatus error
		mastersStatus          error
		privateNodesStatus     error
		secondaryGatewayTask   concurrency.Task
	)

	// Step 1: starts gateway installation plus masters creation plus nodes creation
	primaryGatewayTask, err := task.StartInSubtask(c.taskInstallGateway, primaryGateway)
	if err != nil {
		return err
	}
	if secondaryGateway != nil {
		secondaryGatewayTask, err = task.StartInSubtask(c.taskInstallGateway, secondaryGateway)
		if err != nil {
			return err
		}
	}
	mastersTask, err := task.StartInSubtask(c.taskCreateMasters, data.Map{
		"count":     masterCount,
		"masterDef": mastersDef,
		"nokeep":    !keepOnFailure,
	})
	if err != nil {
		return err
	}

	privateNodesTask, err := task.StartInSubtask(c.taskCreateNodes, data.Map{
		"count":   privateNodeCount,
		"public":  false,
		"nodeDef": nodesDef,
		"nokeep":  !keepOnFailure,
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
		if err != nil && !keepOnFailure {
			list, merr := c.ListMasterIDs(task)
			if merr != nil {
				err = scerr.AddConsequence(err, merr)
			} else {
				tg, tgerr := concurrency.NewTaskGroup(task)
				if tgerr != nil {
					err = scerr.AddConsequence(err, tgerr)
				} else {
					for _, v := range list {
						_, _ = tg.StartInSubtask(c.taskDeleteHost, data.Map{"host": v})
					}
					_, _, derr := tg.WaitGroupFor(temporal.GetLongOperationTimeout())
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
	primaryGatewayTask, err = task.StartInSubtask(c.taskConfigureGateway, primaryGateway)
	if err != nil {
		return err
	}
	if !gwFailoverDisabled {
		secondaryGatewayTask, err = task.StartInSubtask(c.taskConfigureGateway, secondaryGateway)
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
	_, mastersStatus = task.RunInSubtask(c.taskConfigureMasters, nil)
	if mastersStatus != nil {
		return mastersStatus
	}

	defer func() {
		if err != nil && !keepOnFailure {
			list, merr := c.ListNodeIDs(task)
			if merr != nil {
				err = scerr.AddConsequence(err, merr)
			} else {
				tg, tgerr := concurrency.NewTaskGroup(task)
				if tgerr != nil {
					err = scerr.AddConsequence(err, tgerr)
				} else {
					for _, v := range list {
						_, _ = tg.StartInSubtask(c.taskDeleteHost, data.Map{"host": v})
					}
					_, _, derr := tg.WaitGroupFor(temporal.GetLongOperationTimeout())
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
	_, privateNodesStatus = task.RunInSubtask(c.taskConfigureNodes, nil)
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
func (c *cluster) Serialize() ([]byte, error) {
	if c.IsNull() {
		return []byte{}, scerr.InvalidInstanceError()
	}
	return serialize.ToJSON(c)
}

// Deserialize reads json code and reinstantiates cluster
// satisfies interface data.Serializable
func (c *cluster) Deserialize(buf []byte) error {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	return serialize.FromJSON(buf, c)
}

// Boostrap (re)connects controller with the appropriate Makers
func (c *cluster) Bootstrap(task concurrency.Task) (err error) {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)() // c.Lock()/Unlock() may panic

	c.SafeLock(task)
	defer c.SafeUnlock(task)

	switch c.ClusterIdentity.Flavor {
	case clusterflavor.BOH:
		c.makers = boh.Makers
	case clusterflavor.K8S:
		c.makers = k8s.Makers
	default:
		return scerr.NotImplementedError("unknown cluster Flavor '%d'", c.ClusterIdentity.Flavor)
	}
	return nil
}

// Browse walks through cluster folder and executes a callback for each entry
func (c *cluster) Browse(task concurrency.Task, callback func([]byte) error) error {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if callback == nil {
		return scerr.InvalidParameterError("callback", "cannot be nil")
	}

	return c.Core.BrowseFolder(task, callback)
}

// GetIdentity returns the identity of the cluster
func (c *cluster) GetIdentity(task concurrency.Task) (identity abstract.ClusterIdentity, err error) {
	if c.IsNull() {
		return abstract.ClusterIdentity{}, scerr.InvalidInstanceError()
	}
	if task == nil {
		return abstract.ClusterIdentity{}, scerr.InvalidParameterError("task", "cannot be nil")
	}

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	return c.ClusterIdentity, nil
}

// SafeGetIdentity returns the identity of the cluster
// Intended to be used when c, task are notiously not nil (because previously checked)
func (c *cluster) SafeGetIdentity(task concurrency.Task) abstract.ClusterIdentity {
	identity, _ := c.GetIdentity(task)
	return identity
}

// GetFlavor returns the flavor of the cluster
//
// satisfies interface cluster.Controller
func (c *cluster) GetFlavor(task concurrency.Task) (flavor clusterflavor.Enum, err error) {
	if c.IsNull() {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	return c.ClusterIdentity.Flavor, nil
}

// SafeGetFlavor returns the flavor of the cluster
// Intended to be used when c, task are notoriously not nil (because previously checked)
// satisfies interface cluster.Controller
func (c *cluster) SafeGetFlavor(task concurrency.Task) (flavor clusterflavor.Enum) {
	flavor, _ = c.GetFlavor(task)
	return flavor
}

// GetComplexity returns the complexity of the cluster
// satisfies interface cluster.Controller
func (c *cluster) GetComplexity(task concurrency.Task) (complexity clustercomplexity.Enum, err error) {
	if c.IsNull() {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	return c.ClusterIdentity.Complexity, nil
}

// SafeGetComplexity returns the complexity of the cluster
// Intended to be used when c, task are notoriously not nim (because previously checked)
// satisfies interface cluster.Controller
func (c *cluster) SafeGetComplexity(task concurrency.Task) (complexity clustercomplexity.Enum) {
	complexity, _ = c.GetComplexity(task)
	return complexity
}

// GetAdminPassword returns the password of the cluster admin account
// satisfies interface cluster.Controller
func (c *cluster) GetAdminPassword(task concurrency.Task) (adminPassword string, err error) {
	if c.IsNull() {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	return c.ClusterIdentity.AdminPassword, nil
}

// SafeGetAdminPassword returns the password of the cluster admin account
// Intended to be used when c, task are notoriously not nil
// satisfies interface resources.Cluster
func (c *cluster) SafeGetAdminPassword(task concurrency.Task) (adminPassword string) {
	adminPassword, _ = c.GetAdminPassword(task)
	return adminPassword
}

// GetKeyPair returns the key pair used in the cluster
// satisfies interface cluster.Controller
func (c *cluster) GetKeyPair(task concurrency.Task) (keyPair abstract.KeyPair, err error) {
	keyPair = abstract.KeyPair{}
	if c.IsNull() {
		return keyPair, scerr.InvalidInstanceError()
	}
	if task == nil {
		return keyPair, scerr.InvalidParameterError("task", "cannot be nil")
	}

	c.SafeRLock(task)
	defer c.SafeRUnlock(task)

	return *c.ClusterIdentity.Keypair, nil
}

// GetKeyPair returns the key pair used in the cluster
// Intended to be used when c, task are notoriously not nil (because previously checked)
// satisfies interface cluster.Controller
func (c *cluster) SafeGetKeyPair(task concurrency.Task) abstract.KeyPair {
	keyPair, _ := c.GetKeyPair(task)
	return keyPair
}

// GetNetworkConfig returns network configuration of the cluster
// satisfies interface cluster.Controller
func (c *cluster) GetNetworkConfig(task concurrency.Task) (config *propertiesv2.ClusterNetwork, err error) {
	config = &propertiesv2.ClusterNetwork{}
	if c.IsNull() {
		return config, scerr.InvalidInstanceError()
	}
	if task == nil {
		return config, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		if props.Lookup(clusterproperty.NetworkV2) {
			return props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
				networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv2.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				config = networkV2
				return nil
			})
		}
		err = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) error {
			networkV1 := clonable.(*propertiesv1.ClusterNetwork)
			config = &propertiesv2.ClusterNetwork{
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

		return props.Alter(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
			networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_ = networkV2.Replace(config)
			return nil
		})
	})
	return config, err
}

// SafeGetNetworkConfig returns network configuration of the cluster
// Intended to be used when c, task are notoriously not nil (because previously checked)
// satisfies interface resources.Cluster
func (c *cluster) SafeGetNetworkConfig(task concurrency.Task) (config *propertiesv2.ClusterNetwork) {
	config, _ = c.GetNetworkConfig(task)
	return config
}

// Start starts the cluster
// satisfies interface cluster.cluster.Controller
func (c *cluster) Start(task concurrency.Task) (err error) {
	if c.IsNull() {
		return scerr.InvalidInstanceError()
	}

	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	// If the cluster is in state Stopping or Stopped, do nothing
	var prevState clusterstate.Enum
	prevState, err = c.State(task)
	if err != nil {
		return err
	}
	if prevState == clusterstate.Stopping || prevState == clusterstate.Stopped {
		return nil
	}

	// If the cluster is in state Starting, wait for it to finish its start procedure
	if prevState == clusterstate.Starting {
		err = retry.WhileUnsuccessfulDelay5Seconds(
			func() error {
				state, inErr := c.State(task)
				if inErr != nil {
					return inErr
				}
				if state == clusterstate.Nominal || state == clusterstate.Degraded {
					return nil
				}
				return fmt.Errorf("current state of cluster is '%s'", state.String())
			},
			5*time.Minute, // FIXME: static timeout
		)
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				err = scerr.Wrap(err, "timeout waiting cluster to become started")
			}
			return err
		}
		return nil
	}

	if prevState != clusterstate.Stopped {
		return scerr.NotAvailableError("failed to start cluster because of it's current state: %s", prevState.String())
	}

	// First mark cluster to be in state Starting
	err = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Starting
			return nil
		})
	})
	if err != nil {
		return err
	}

	var (
		nodes                         []*propertiesv2.ClusterNode
		masters                       []*propertiesv2.ClusterNode
		gatewayID, secondaryGatewayID string
	)

	// Then start it and mark it as STARTED on success
	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		innerErr := props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			masters = nodesV2.Masters
			nodes = nodesV2.PrivateNodes
			return nil
		})
		if innerErr != nil {
			return fmt.Errorf("failed to get list of hosts: %v", err)
		}
		if props.Lookup(clusterproperty.NetworkV2) {
			innerErr = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
				networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				gatewayID = networkV2.GatewayID
				secondaryGatewayID = networkV2.SecondaryGatewayID
				return nil
			})
		} else {
			err = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) error {
				networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				gatewayID = networkV1.GatewayID
				return nil
			})
		}
		if innerErr != nil {
			return innerErr
		}

		// Mark cluster as state Starting
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
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
	_, err = taskGroup.WaitGroup()
	if err != nil {
		return err
	}

	return c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Nominal
			return nil
		})
	})
}

// Stop stops the cluster
func (c *cluster) Stop(task concurrency.Task) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// If the cluster is stopped, do nothing
	var prevState clusterstate.Enum
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
			if _, ok := err.(retry.ErrTimeout); ok {
				err = scerr.Wrap(err, "timeout waiting cluster transitioning from state Stopping to Stopped")
			}
			return err
		}
		return nil
	}

	// If the cluster is not in state Nominal or Degraded, can't stop
	if prevState != clusterstate.Nominal && prevState != clusterstate.Degraded {
		return scerr.NotAvailableError("failed to stop cluster because of it's current state: %s", prevState.String())
	}

	// First mark cluster to be in state Stopping
	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Stopping
			return nil
		})
	})
	if err != nil {
		return err
	}

	// Then stop it and mark it as STOPPED on success
	return c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		var (
			nodes                         []*propertiesv2.ClusterNode
			masters                       []*propertiesv2.ClusterNode
			gatewayID, secondaryGatewayID string
		)
		inErr := props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
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
				networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				gatewayID = networkV2.GatewayID
				secondaryGatewayID = networkV2.SecondaryGatewayID
				return nil
			})
		} else {
			inErr = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) error {
				networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
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

		_, inErr = taskGroup.WaitGroup()
		if inErr != nil {
			return inErr
		}

		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.State' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Stopped
			return nil
		})
	})
}

// State returns the current state of the Cluster
// Uses the "maker" GetState from Foreman
func (c *cluster) State(task concurrency.Task) (state clusterstate.Enum, err error) {
	state = clusterstate.Unknown
	if c == nil {
		return state, scerr.InvalidInstanceError()
	}
	if task == nil {
		return state, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	if c.makers.GetState != nil {
		state, err = c.makers.GetState(task, c)
	} else {
		state = clusterstate.Unknown
		err = fmt.Errorf("no maker defined for 'GetState'")
	}
	if err != nil {
		return clusterstate.Unknown, fmt.Errorf("no maker defined for 'GetState'")
	}
	return state, c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
func (c *cluster) AddNode(task concurrency.Task, def *abstract.HostSizingRequirements, image string) (_ resources.Host, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if def == nil {
		return nil, scerr.InvalidParameterError("def", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	nodes, err := c.AddNodes(task, 1, def, image)
	if err != nil {
		return nil, err
	}

	return nodes[0], nil
}

// AddNodes adds several nodes
func (c *cluster) AddNodes(task concurrency.Task, count int, def *abstract.HostSizingRequirements, image string) (_ []resources.Host, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if count <= 0 {
		return nil, scerr.InvalidParameterError("count", "must be an int > 0")
	}

	tracer := concurrency.NewTracer(task, true, "(%d)", count)
	defer tracer.Entering().OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var hostImage string
	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		if !props.Lookup(clusterproperty.DefaultsV2) {
			// If property.DefaultsV2 is not found but there is a property.DefaultsV1, converts it to DefaultsV2
			return props.Inspect(clusterproperty.DefaultsV1, func(clonable data.Clonable) error {
				defaultsV1, ok := clonable.(*propertiesv1.ClusterDefaults)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return props.Alter(clusterproperty.DefaultsV2, func(clonable data.Clonable) error {
					defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
					if !ok {
						return scerr.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					convertDefaultsV1ToDefaultsV2(defaultsV1, defaultsV2)
					return nil
				})
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var nodeDef *propertiesv2.HostSizingRequirements
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.DefaultsV2, func(clonable data.Clonable) error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			nodeDef = &defaultsV2.NodeSizing
			hostImage = defaultsV2.Image
			return nil
		})
	})
	if err != nil {
		return nil, err
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
		subtask, err := task.StartInSubtask(c.taskCreateNode, data.Map{
			"index":   i + 1,
			"nodeDef": nodeDef,
			"image":   hostImage,
			"timeout": timeout,
			"nokeep":  false,
		})
		if err != nil {
			return nil, err
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
		if err != nil {
			if len(newHosts) > 0 {
				derr := c.deleteHosts(task, newHosts)
				if derr != nil {
					logrus.Errorf("failed to delete nodes after failure to expand cluster")
				}
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	if len(errors) > 0 {
		err = fmt.Errorf("errors occurred on %s node%s addition: %s", nodeTypeStr, strprocess.Plural(uint(len(errors))), strings.Join(errors, "\n"))
		return nil, err
	}

	// Now configure new nodes
	err = c.configureNodesFromList(task, hosts)
	if err != nil {
		return nil, err
	}

	// At last join nodes to cluster
	err = c.joinNodesFromList(task, hosts)
	if err != nil {
		return nil, err
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
func (c *cluster) DeleteLastNode(task concurrency.Task) (node *propertiesv2.ClusterNode, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(nil, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	selectedMaster, err := c.FindAvailableMaster(task)
	if err != nil {
		return nil, err
	}

	// Removed reference of the node from cluster
	err = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		inErr := props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			node = nodesV2.PrivateNodes[len(nodesV2.PrivateNodes)-1]
			return nil
		})
		if inErr != nil {
			return inErr
		}
		return c.DeleteSpecificNode(task, node.ID, selectedMaster.SafeGetID())
	})
	if err != nil {
		return nil, err
	}
	return node, nil
}

// DeleteSpecificNode deletes a node identified by its ID
func (c *cluster) DeleteSpecificNode(task concurrency.Task, hostID string, selectedMasterID string) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, false, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var selectedMaster resources.Host
	if selectedMasterID == "" {
		selectedMaster, err = c.FindAvailableMaster(task)
		if err != nil {
			return err
		}
	}

	// Identifies the node to delete and remove it preventively from metadata
	var node *propertiesv2.ClusterNode
	err = c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			found, idx := containsClusterNode(nodesV2.PrivateNodes, hostID)
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
					nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
					if !ok {
						return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
			err = c.leaveNodesFromList(task, []string{node.ID}, selectedMaster)
			if err != nil {
				return err
			}
		}
		host, err := LoadHost(task, c.service, node.ID)
		if err != nil {
			return err
		}
		if c.makers.UnconfigureNode != nil {
			err = c.makers.UnconfigureNode(task, c, host, selectedMaster)
			if err != nil {
				return err
			}
		}

		// Finally delete host
		err = host.Delete(task)
		if err != nil {
			if _, ok := err.(scerr.ErrNotFound); ok {
				// host seems already deleted, so it's a success (handles the case where )
				return nil
			}
			return err
		}
		return nil
	})
}

// ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
func (c *cluster) ListMasters(task concurrency.Task) (list resources.IndexedListOfClusterNodes, err error) {
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
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
	if err != nil {
		logrus.Errorf("failed to get list of masters: %v", err)
		return list, err
	}
	return list, err
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (c *cluster) ListMasterNames(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
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
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
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
func (c *cluster) ListMasterIDs(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
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
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
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
func (c *cluster) ListMasterIPs(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
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
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
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
func (c *cluster) FindAvailableMaster(task concurrency.Task) (master resources.Host, err error) {
	master = nil
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	found := false
	masters, err := c.ListMasters(task)
	if err != nil {
		return nil, err
	}

	var lastError error
	svc := c.SafeGetService()
	for _, v := range masters {
		master, err = LoadHost(task, svc, v.SafeGetID())
		if err != nil {
			return nil, err
		}

		_, err = master.WaitSSHReady(task, temporal.GetConnectSSHTimeout())
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				lastError = err
				continue
			}
			return nil, err
		}
		found = true
		break
	}
	if !found {
		return nil, fmt.Errorf("failed to find available master: %v", lastError)
	}
	return master, nil
}

// ListNodes lists node instances corresponding to the nodes in the cluster
// satisfies interface cluster.Controller
func (c *cluster) ListNodes(task concurrency.Task) (list resources.IndexedListOfClusterNodes, err error) {
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
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
	if err != nil {
		return nil, err
	}
	return list, nil
}

// ListNodeNames lists the names of the nodes in the Cluster
func (c *cluster) ListNodeNames(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
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
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
func (c *cluster) ListNodeIDs(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
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
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
func (c *cluster) ListNodeIPs(task concurrency.Task) (list data.IndexedListOfStrings, err error) {
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
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV2.PrivateNodes {
				list[v.NumericalID] = v.PrivateIP
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
func (c *cluster) FindAvailableNode(task concurrency.Task) (node resources.Host, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	list, err := c.ListNodes(task)
	if err != nil {
		return nil, err
	}

	found := false
	for _, v := range list {
		_, err = v.WaitSSHReady(task, temporal.GetConnectSSHTimeout())
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
			return nil, err
		}
		found = true
		node = v
		break
	}
	if !found {
		return nil, fmt.Errorf("failed to find available node")
	}
	return node, nil
}

// LookupNode tells if the ID of the host passed as parameter is a node
// satisfies interface cluster.cluster.Controller
func (c *cluster) LookupNode(task concurrency.Task, ref string) (found bool, err error) {
	if c == nil {
		return false, scerr.InvalidInstanceError()
	}
	if ref == "" {
		return false, scerr.InvalidParameterError("ref", "cannot be empty string")
	}
	if task == nil {
		return false, scerr.InvalidParameterError("task", "cannot be nil")
	}
	defer scerr.OnPanic(&err)()

	var host resources.Host
	host, err = LoadHost(task, c.service, ref)
	if err != nil {
		return false, err
	}
	hostID := host.SafeGetID()

	found = false
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			found, _ = containsClusterNode(nodesV2.PrivateNodes, hostID)
			return nil
		})
	})
	return found, err
}

// CountNodes counts the nodes of the cluster
// satisfies interface cluster.cluster.Controller
func (c *cluster) CountNodes(task concurrency.Task) (count uint, err error) {
	if c == nil {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer scerr.OnExitLogError(concurrency.NewTracer(task, debug.IfTrace("cluster"), "").TraceMessage(""), &err)()

	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
func (c *cluster) Node(task concurrency.Task, hostID string) (host resources.Host, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return nil, scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(task, true, "(%s)", hostID)
	defer tracer.Entering().OnExitTrace()()
	defer scerr.OnExitLogError(fmt.Sprintf("failed to get node identified by '%s'", hostID), &err)()
	defer scerr.OnPanic(&err)()

	found := false
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			found, _ = containsClusterNode(nodesV2.PrivateNodes, hostID)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("failed to find node '%s' in Cluster '%s'", hostID, c.Name)
	}
	return LoadHost(task, c.SafeGetService(), hostID)
}

// deleteMaster deletes the master specified by its ID
func (c *cluster) deleteMaster(task concurrency.Task, hostID string) error {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	var master *propertiesv2.ClusterNode
	// Removes master from cluster properties
	err := c.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.Nodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
	if err != nil {
		return err
	}

	// Starting from here, restore master in cluster properties if exiting with error
	defer func() {
		if err != nil {
			derr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
				return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
					nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
					if !ok {
						return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					nodesV2.Masters = append(nodesV2.Masters, master)
					return nil
				})
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
func (c *cluster) Delete(task concurrency.Task) error {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	err := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		// Updates cluster state to mark cluster as Removing
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
		length := uint(len(list))
		if length > 0 {
			subtasks := make([]concurrency.Task, 0, length)
			for i := uint(0); i < length; i++ {
				subtask, innerErr := task.StartInSubtask(taskDeleteNode, list[i])
				if innerErr != nil {
					cleaningErrors = append(cleaningErrors, scerr.Wrap(innerErr, "failed to start deletion of node '%s'", list[i].SafeGetName()))
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
			return scerr.ErrListError(cleaningErrors)
		}
		length = uint(len(list))
		if length > 0 {
			subtasks := make([]concurrency.Task, 0, length)
			for i := uint(0); i < length; i++ {
				subtask, innerErr := task.StartInSubtask(taskDeleteMaster, list[i])
				if innerErr != nil {
					cleaningErrors = append(cleaningErrors, scerr.Wrap(innerErr, "failed to start deletion of master '%s'", list[i].SafeGetName()))
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
			err = props.Inspect(clusterproperty.NetworkV2, func(clonable data.Clonable) error {
				networkV2, ok := clonable.(*propertiesv2.ClusterNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				networkID = networkV2.NetworkID
				return nil
			})
		} else {
			err = props.Inspect(clusterproperty.NetworkV1, func(clonable data.Clonable) error {
				networkV1, ok := clonable.(*propertiesv1.ClusterNetwork)
				if !ok {
					return scerr.InconsistentError("'*propertiesv1.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				networkID = networkV1.NetworkID
				return nil
			})
		}
		if innerErr != nil {
			cleaningErrors = append(cleaningErrors, err)
			return innerErr
		}

		network, innerErr := LoadNetwork(task, c.SafeGetService(), networkID)
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

	return c.Core.Delete(task)
}

// func deleteNodes(task concurrency.Task, svc iaas.Service, nodes []*propertiesv2.ClusterNode) {
// 	length := len(nodes)
// 	if length > 0 {
// 		subtasks := make([]concurrency.Task, 0, length)
// 		for i := 0; i < length; i++ {
// 			host, err := LoadHost(task, svc, nodes[i].ID)
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
// 					logrus.Errorf("after failure, cleanup failed to delete node '%s': %v", nodes[i].Name, state)
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
func (c *cluster) unconfigureMaster(task concurrency.Task, host resources.Host) error {
	if c.makers.UnconfigureMaster != nil {
		return c.makers.UnconfigureMaster(task, c, host)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// configureCluster ...
// params contains a data.Map with primary and secondary Gateway hosts
func (c *cluster) configureCluster(task concurrency.Task, params concurrency.TaskParameters) (err error) {
	tracer := concurrency.NewTracer(task, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Infof("[cluster %s] configuring cluster...", c.SafeGetName())
	defer func() {
		if err == nil {
			logrus.Infof("[cluster %s] configuration successful.", c.SafeGetName())
		} else {
			logrus.Errorf("[cluster %s] configuration failed: %s", c.SafeGetName(), err.Error())
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
		return c.makers.ConfigureCluster(task, c)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

func (c *cluster) determineRequiredNodes(task concurrency.Task) (uint, uint, uint, error) {
	if c.makers.MinimumRequiredServers != nil {
		a, b, c, err := c.makers.MinimumRequiredServers(task, c)
		if err != nil {
			return 0, 0, 0, err
		}
		return a, b, c, nil
	}
	return 0, 0, 0, nil
}

// createSwarm configures cluster
func (c *cluster) createSwarm(task concurrency.Task, params concurrency.TaskParameters) (err error) {

	var (
		p                                data.Map
		ok                               bool
		primaryGateway, secondaryGateway resources.Host
	)

	if params == nil {
		return scerr.InvalidParameterError("params", "cannot be nil")
	}

	if p, ok = params.(data.Map); !ok {
		return scerr.InvalidParameterError("params", "must be a data.Map")
	}
	if primaryGateway, ok = p["PrimaryGateway"].(resources.Host); !ok || primaryGateway == nil {
		return scerr.InvalidParameterError("params", "params['PrimaryGateway'] must be defined and cannot be nil")
	}
	secondaryGateway, ok = p["SecondaryGateway"].(resources.Host)
	if !ok {
		logrus.Debugf("secondary gateway not configured")
	}

	tracer := concurrency.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Join masters in Docker Swarm as managers
	joinCmd := ""
	masters, err := c.ListMasters(task)
	if err != nil {
		return err
	}
	for _, master := range masters {
		if joinCmd == "" {
			retcode, _, _, err := master.Run(task, "docker swarm init && docker node update "+master.SafeGetName()+" --label-add safescale.host.role=master",
				outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to init docker swarm")
			}
			retcode, token, stderr, err := master.Run(task, "docker swarm join-token manager -q", outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if err != nil || retcode != 0 {
				return scerr.NewError(nil, nil, "failed to generate token to join swarm as manager: %s", stderr)
			}
			token = strings.Trim(token, "\n")
			ip, err := master.GetPrivateIP(task)
			if err != nil {
				return err
			}
			joinCmd = fmt.Sprintf("docker swarm join --token %s %s", token, ip)
		} else {
			masterJoinCmd := joinCmd + " && docker node update " + master.SafeGetName() + " --label-add safescale.host.role=master"
			retcode, _, stderr, err := master.Run(task, masterJoinCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to join host '%s' to swarm as manager: %s", master.SafeGetName(), stderr)
			}
		}
	}

	master, err := c.FindAvailableMaster(task)
	if err != nil {
		return fmt.Errorf("failed to find an available docker manager: %v", err)
	}

	// build command to join Docker Swarm as workers
	joinCmd, err = c.getSwarmJoinCommand(task, master, true)
	if err != nil {
		return err
	}

	// Join private node in Docker Swarm as workers
	nodes, err := c.ListNodes(task)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		retcode, _, stderr, err := node.Run(task, joinCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", node.SafeGetName(), stderr)
		}
		labelCmd := "docker node update " + node.SafeGetName() + " --label-add safescale.host.role=node"
		retcode, _, stderr, err = master.Run(task, labelCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to label swarm worker '%s' as node: %s", node.SafeGetName(), stderr)
		}
	}

	// Join gateways in Docker Swarm as workers
	retcode, _, stderr, err := primaryGateway.Run(task, joinCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", primaryGateway.SafeGetName(), stderr)
	}
	labelCmd := "docker node update " + primaryGateway.SafeGetName() + " --label-add safescale.host.role=gateway"
	retcode, _, stderr, err = master.Run(task, labelCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to label docker Swarm worker '%s' as gateway: %s", primaryGateway.SafeGetName(), stderr)
	}

	if secondaryGateway != nil {
		retcode, _, stderr, err := secondaryGateway.Run(task, joinCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", primaryGateway.SafeGetName(), stderr)
		}
		labelCmd := "docker node update " + secondaryGateway.SafeGetName() + " --label-add safescale.host.role=gateway"
		retcode, _, stderr, err = master.Run(task, labelCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to label docker swarm worker '%s' as gateway: %s", secondaryGateway.SafeGetName(), stderr)
		}
	}

	return nil
}

// getSwarmJoinCommand builds the command to obtain swarm token
func (c *cluster) getSwarmJoinCommand(task concurrency.Task, selectedMaster resources.Host, worker bool) (string, error) {
	var memberType string
	if worker {
		memberType = "worker"
	} else {
		memberType = "manager"
	}

	masterIP, err := selectedMaster.GetPrivateIP(task)
	if err != nil {
		return "", err
	}

	tokenCmd := fmt.Sprintf("docker swarm join-token %s -q", memberType)
	retcode, token, stderr, err := selectedMaster.Run(task, tokenCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil || retcode != 0 {
		return "", fmt.Errorf("failed to generate token to join swarm as worker: %s", stderr)
	}
	token = strings.Trim(token, "\n")
	return fmt.Sprintf("docker swarm join --token %s %s", token, masterIP), nil
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
		return "", "", scerr.Wrap(err, "failed to load template")
	}
	tmplCmd, err := txttmpl.New(fileName).Funcs(template.MergeFuncs(funcMap, false)).Parse(tmplString)
	if err != nil {
		return "", "", scerr.Wrap(err, "failed to parse template")
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, data)
	if err != nil {
		return "", "", scerr.Wrap(err, "failed to realize template")
	}
	cmd := dataBuffer.String()
	remotePath := utils.TempFolder + "/" + fileName

	return cmd, remotePath, nil
}

// configureNodesFromList configures nodes from a list
func (c *cluster) configureNodesFromList(task concurrency.Task, hosts []resources.Host) (err error) {
	tracer := concurrency.NewTracer(task, true, "").Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		hostID string
		errs   []string
	)

	var subtasks []concurrency.Task
	length := len(hosts)
	for i := 0; i < length; i++ {
		subtask, err := task.StartInSubtask(c.taskConfigureNode, data.Map{
			"index": uint(i + 1),
			"host":  hosts[i],
		})
		if err != nil {
			break
		}
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	if err != nil {
		errs = append(errs, fmt.Sprintf("failed to get metadata of host '%s': %s", hostID, err.Error()))
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
func (c *cluster) joinNodesFromList(task concurrency.Task, hosts []resources.Host) error {
	if c.makers.JoinNodeToCluster == nil {
		// configure what has to be done cluster-wide
		if c.makers.ConfigureCluster != nil {
			return c.makers.ConfigureCluster(task, c)
		}
	}

	logrus.Debugf("Joining nodes to cluster...")

	master, err := c.FindAvailableMaster(task)
	if err != nil {
		return fmt.Errorf("failed to join workers to Docker Swarm: %v", err)
	}
	joinCmd, err := c.getSwarmJoinCommand(task, master, true)
	if err != nil {
		return err
	}

	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, host := range hosts {
		retcode, _, stderr, err := host.Run(task, joinCmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", host.SafeGetName(), stderr)
		}
		nodeLabel := "docker node update " + host.SafeGetName() + " --label-add safescale.host.role=node"
		retcode, _, stderr, err = master.Run(task, nodeLabel, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to add label to docker Swarm worker '%s': %s", host.SafeGetName(), stderr)
		}

		if c.makers.JoinMasterToCluster != nil {
			err = c.makers.JoinNodeToCluster(task, c, host)
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

	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		host, err := LoadHost(task, c.service, hostID)
		if err != nil {
			return err
		}
		err = c.makers.LeaveMasterFromCluster(task, c, host)
		if err != nil {
			return err
		}
	}

	return nil
}

// leaveNodesFromList makes nodes from a list leave the cluster
func (c *cluster) leaveNodesFromList(task concurrency.Task, hosts []string, selectedMaster resources.Host) error {
	logrus.Debugf("Instructing nodes to leave cluster...")

	var err error
	if selectedMaster == nil {
		selectedMaster, err = c.FindAvailableMaster(task)
		if err != nil {
			return err
		}
	}

	clusterFlavor := c.SafeGetFlavor(task)

	// Unjoins from cluster are done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		host, err := LoadHost(task, c.service, hostID)
		if err != nil {
			// If host seems deleted, consider leaving as a success
			if _, ok := err.(scerr.ErrNotFound); ok {
				continue
			}
			return err
		}

		if c.makers.LeaveNodeFromCluster != nil {
			err = c.makers.LeaveNodeFromCluster(task, c, host, selectedMaster)
			if err != nil {
				return err
			}
		}

		if clusterFlavor != clusterflavor.K8S {
			err = c.leaveNodeFromSwarm(task, host, selectedMaster)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// leaveNodeFromSwarm unregisters properly a node from docker Swarm
func (c *cluster) leaveNodeFromSwarm(task concurrency.Task, host, selectedMaster resources.Host) error {
	if selectedMaster == nil {
		var err error
		selectedMaster, err = c.FindAvailableMaster(task)
		if err != nil {
			return err
		}
	}

	// Check worker is member of the Swarm
	cmd := fmt.Sprintf("docker node ls --format \"{{.Hostname}}\" --filter \"name=%s\" | grep -i %s", host.SafeGetName(), host.SafeGetName())
	retcode, _, _, err := selectedMaster.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	if retcode != 0 {
		// node is already expelled from Docker Swarm
		return nil
	}
	// node is a worker in the Swarm: 1st ask worker to leave Swarm
	cmd = "docker swarm leave"
	retcode, _, stderr, err := host.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to make node '%s' leave swarm: %s", host.SafeGetName(), stderr)
	}

	// 2nd: wait the Swarm worker to appear as down from Swarm master
	cmd = fmt.Sprintf("docker node ls --format \"{{.Status}}\" --filter \"name=%s\" | grep -i down", host.SafeGetName())
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			retcode, _, _, err := selectedMaster.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("'%s' not in Down state", host.SafeGetName())
			}
			return nil
		},
		temporal.GetHostTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrTimeout:
			return fmt.Errorf("SWARM worker '%s' didn't reach 'Down' state after %v", host.SafeGetName(), temporal.GetHostTimeout())
		default:
			return fmt.Errorf("SWARM worker '%s' didn't reach 'Down' state: %v", host.SafeGetName(), retryErr)
		}
	}

	// 3rd, ask master to remove node from Swarm
	cmd = fmt.Sprintf("docker node rm %s", host.SafeGetName())
	retcode, _, stderr, err = selectedMaster.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to remove worker '%s' from Swarm on master '%s': %s", host.SafeGetName(), selectedMaster.SafeGetName(), stderr)
	}
	return nil
}

// getNodeInstallationScript ...
func (c *cluster) getNodeInstallationScript(task concurrency.Task, nodeType clusternodetype.Enum) (string, map[string]interface{}) {
	if c.makers.GetNodeInstallationScript != nil {
		return c.makers.GetNodeInstallationScript(task, c, nodeType)
	}
	return "", map[string]interface{}{}
}

// BuildHostname builds a unique hostname in the Cluster
func (c *cluster) buildHostname(task concurrency.Task, core string, nodeType clusternodetype.Enum) (cluid string, err error) {
	var index int

	defer scerr.OnPanic(&err)()

	// Locks for write the manager extension...

	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
	if err != nil {
		return "", err
	}
	return c.SafeGetName() + "-" + core + "-" + strconv.Itoa(index), nil
}

func (c *cluster) deleteHosts(task concurrency.Task, hosts []resources.Host) error {
	tg, err := concurrency.NewTaskGroupWithParent(task)
	if err != nil {
		return err
	}
	errors := make([]error, 0, len(hosts)+1)
	for _, h := range hosts {
		_, err = tg.StartInSubtask(c.taskDeleteHost, h)
		if err != nil {
			errors = append(errors, err)
		}
	}
	_, err = tg.WaitGroup()
	if err != nil {
		errors = append(errors, err)
	}
	return scerr.ErrListError(errors)
}
