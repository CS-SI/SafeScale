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

package control

import (
	"fmt"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/utils/debug"

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	clusterpropsv2 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v2"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/server/cluster/identity"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Controller contains the information about a cluster
type Controller struct {
	identity.Identity
	Properties *serialize.JSONProperties `json:"properties,omitempty"` // Properties contains additional info about the cluster

	foreman  *foreman
	metadata *Metadata
	service  iaas.Service

	lastStateCollection time.Time

	concurrency.TaskedLock
}

// NewController ...
func NewController(svc iaas.Service) (*Controller, error) {
	metadata, err := NewMetadata(svc)
	if err != nil {
		return nil, err
	}
	return &Controller{
		service:    svc,
		metadata:   metadata,
		Properties: serialize.NewJSONProperties("clusters"),
		TaskedLock: concurrency.NewTaskedLock(),
	}, nil
}

func (c *Controller) replace(task concurrency.Task, src *Controller) {
	c.Lock(task)
	defer c.Unlock(task)

	//	(&c.Identity).Replace(&src.Identity)
	c.Properties = src.Properties
}

// Restore restores full ability of a Cluster controller by binding with appropriate Foreman
func (c *Controller) Restore(task concurrency.Task, f Foreman) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if f == nil {
		return scerr.InvalidParameterError("f", "cannot be nil")
	}

	c.Lock(task)
	defer c.Unlock(task)
	c.foreman = f.(*foreman)
	return nil
}

// Create creates the necessary infrastructure of the Cluster
func (c *Controller) Create(task concurrency.Task, req Request, f Foreman) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if f == nil {
		return scerr.InvalidParameterError("f", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting creation of infrastructure of cluster '%s'...", req.Name),
		fmt.Sprintf("Ending creation of infrastructure of cluster '%s'", req.Name),
	)()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	c.Lock(task)

	err = c.Properties.LockForWrite(property.FeaturesV1).ThenUse(
		func(clonable data.Clonable) error {
			featuresV1 := clonable.(*clusterpropsv1.Features)
			// VPL: For now, always disable addition of feature proxycache
			featuresV1.Disabled["proxycache"] = struct{}{}
			// ENDVPL
			for k := range req.DisabledDefaultFeatures {
				featuresV1.Disabled[k] = struct{}{}
			}
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to store disabled feature: %v", err)
		return err
	}

	c.foreman = f.(*foreman)
	c.Unlock(task)
	return c.foreman.construct(task, req)
}

// GetService returns the service from the provider
func (c *Controller) GetService(task concurrency.Task) iaas.Service {
	var err error
	defer scerr.OnExitLogError(debug.NewTracer(task, "", false).TraceMessage(""), &err)()

	if c == nil {
		err = scerr.InvalidInstanceError()
		return nil
	}

	c.RLock(task)
	defer c.RUnlock(task)
	return c.service
}

// GetIdentity returns the core data of a cluster
func (c *Controller) GetIdentity(task concurrency.Task) identity.Identity {
	if c == nil {
		return identity.Identity{}
	}
	if task == nil {
		return identity.Identity{}
	}

	var err error
	defer scerr.OnExitLogError(debug.NewTracer(task, "", false).TraceMessage(""), &err)()

	if c == nil {
		err = scerr.InvalidInstanceError()
		return identity.Identity{}
	}

	c.RLock(task)
	defer c.RUnlock(task)
	return c.Identity
}

// GetProperties returns the properties of the cluster
func (c *Controller) GetProperties(task concurrency.Task) *serialize.JSONProperties {
	if task == nil {
		return nil
	}

	var err error
	defer scerr.OnExitLogError(debug.NewTracer(task, "", false).TraceMessage(""), &err)()

	if c == nil {
		err = scerr.InvalidInstanceError()
		return nil
	}

	c.RLock(task)
	defer c.RUnlock(task)
	return c.Properties
}

// GetNetworkConfig returns the network configuration of the cluster
func (c *Controller) GetNetworkConfig(task concurrency.Task) (_ clusterpropsv2.Network, err error) {
	config := clusterpropsv2.Network{}
	if c == nil {
		return config, scerr.InvalidInstanceError()
	}
	if task == nil {
		return config, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer scerr.OnExitLogError(debug.NewTracer(task, "", false).TraceMessage(""), &err)()

	if c == nil {
		return config, scerr.InvalidInstanceError()
	}

	c.RLock(task)
	if c.Properties.Lookup(property.NetworkV2) {
		_ = c.Properties.LockForRead(property.NetworkV2).ThenUse(
			func(clonable data.Clonable) error {
				config = *(clonable.(*clusterpropsv2.Network))
				return nil
			},
		)
	} else {
		_ = c.Properties.LockForRead(property.NetworkV1).ThenUse(
			func(clonable data.Clonable) error {
				networkV1 := clonable.(*clusterpropsv1.Network)
				config = clusterpropsv2.Network{
					NetworkID:      networkV1.NetworkID,
					CIDR:           networkV1.CIDR,
					GatewayID:      networkV1.GatewayID,
					GatewayIP:      networkV1.GatewayIP,
					DefaultRouteIP: networkV1.GatewayIP,
					EndpointIP:     networkV1.PublicIP,
				}
				return nil
			},
		)
	}
	c.RUnlock(task)
	return config, nil
}

// CountNodes returns the number of nodes in the cluster
func (c *Controller) CountNodes(task concurrency.Task) (_ uint, err error) {
	if c == nil {
		return 0, scerr.InvalidInstanceError()
	}
	if task == nil {
		return 0, scerr.InvalidParameterError("task", "cannot be nil")
	}

	defer scerr.OnExitLogError(debug.NewTracer(task, "", false).TraceMessage(""), &err)()

	var count uint

	c.RLock(task)
	err = c.GetProperties(task).LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			count = uint(len(clonable.(*clusterpropsv1.Nodes).PrivateNodes))
			return nil
		},
	)
	c.RUnlock(task)
	if err != nil {
		log.Debugf("failed to count nodes: %v", err)
	}
	return count, nil
}

// ListMasters lists the names of the master nodes in the Cluster
func (c *Controller) ListMasters(task concurrency.Task) []*clusterpropsv1.Node {
	var list []*clusterpropsv1.Node
	if task == nil {
		return list
	}

	c.RLock(task)
	defer c.RUnlock(task)

	err := c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			list = clonable.(*clusterpropsv1.Nodes).Masters
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to get list of master names: %v", err)
	}
	return list
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (c *Controller) ListMasterNames(task concurrency.Task) []string {
	var list []string
	if task == nil {
		return list
	}

	c.RLock(task)
	defer c.RUnlock(task)

	err := c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes).Masters
			for _, v := range nodesV1 {
				list = append(list, v.Name)
			}
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to get list of master names: %v", err)
	}
	return list
}

// ListMasterIDs lists the IDs of the master nodes in the Cluster
func (c *Controller) ListMasterIDs(task concurrency.Task) []string {
	var list []string
	if task == nil {
		return list
	}

	c.RLock(task)
	defer c.RUnlock(task)

	err := c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes).Masters
			for _, v := range nodesV1 {
				list = append(list, v.ID)
			}
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to get list of master IDs: %v", err) // FIXME Don't hide errors, return them
	}
	return list
}

// ListMasterIPs lists the IP addresses of the master nodes in the Cluster
func (c *Controller) ListMasterIPs(task concurrency.Task) []string {
	var list []string
	if task == nil {
		return list
	}

	c.RLock(task)
	defer c.RUnlock(task)

	err := c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes).Masters
			for _, v := range nodesV1 {
				list = append(list, v.PrivateIP)
			}
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to get list of master IPs: %v", err)
	}
	return list
}

// ListNodes lists the nodes in the Cluster
func (c *Controller) ListNodes(task concurrency.Task) []*clusterpropsv1.Node {
	var list []*clusterpropsv1.Node
	if task == nil {
		return list
	}
	c.RLock(task)
	defer c.RUnlock(task)

	err := c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			list = clonable.(*clusterpropsv1.Nodes).PrivateNodes
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to get list of node IDs: %v", err)
	}
	return list
}

// ListNodeNames lists the names of the nodes in the Cluster
func (c *Controller) ListNodeNames(task concurrency.Task) []string {
	var list []string
	if task == nil {
		return list
	}

	c.RLock(task)
	defer c.RUnlock(task)

	err := c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes).PrivateNodes
			for _, v := range nodesV1 {
				list = append(list, v.Name)
			}
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to get list of node IDs: %v", err)
	}
	return list
}

// ListNodeIDs lists the IDs of the nodes in the Cluster
func (c *Controller) ListNodeIDs(task concurrency.Task) []string {
	var list []string
	if task == nil {
		return list
	}

	c.RLock(task)
	defer c.RUnlock(task)

	err := c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes).PrivateNodes
			for _, v := range nodesV1 {
				list = append(list, v.ID)
			}
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to get list of node IDs: %v", err)
	}
	return list
}

// ListNodeIPs lists the IP addresses of the nodes in the Cluster
func (c *Controller) ListNodeIPs(task concurrency.Task) []string {
	var list []string
	if task == nil {
		return list
	}
	c.RLock(task)
	defer c.RUnlock(task)

	err := c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes).PrivateNodes
			for _, v := range nodesV1 {
				list = append(list, v.PrivateIP)
			}
			return nil
		},
	)
	if err != nil {
		log.Errorf("failed to get list of node IP addresses: %v", err)
	}
	return list
}

// GetNode returns a node based on its ID
func (c *Controller) GetNode(task concurrency.Task, hostID string) (host *pb.Host, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if hostID == "" {
		return nil, scerr.InvalidParameterError("hostID", "cannot be empty string")
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%s)", hostID), true)
	defer tracer.GoingIn().OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	c.RLock(task)
	defer c.RUnlock(task)

	found := false
	err = c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes)
			// found, _ := findNodeByID(nodesV1.PublicNodes, hostID)
			// if !found {
			found, _ = findNodeByID(nodesV1.PrivateNodes, hostID)
			// }
			return nil
		},
	)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("failed to find node '%s' in Cluster '%s'", hostID, c.Name)
	}
	return client.New().Host.Inspect(hostID, temporal.GetExecutionTimeout())
}

// SearchNode tells if an host ID corresponds to a node of the Cluster
func (c *Controller) SearchNode(task concurrency.Task, hostID string) bool {
	if task == nil {
		return false
	}

	c.RLock(task)
	defer c.RUnlock(task)

	found := false
	_ = c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			found, _ = findNodeByID(clonable.(*clusterpropsv1.Nodes).PrivateNodes, hostID)
			return nil
		},
	)
	return found
}

// FindAvailableMaster returns the ID of the first master available for execution
func (c *Controller) FindAvailableMaster(task concurrency.Task) (result string, err error) {
	if c == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	masterID := ""
	found := false
	clientHost := client.New().Host
	masterIDs := c.ListMasterIDs(task)

	var lastError error

	for _, masterID = range masterIDs {
		sshCfg, err := clientHost.SSHConfig(masterID)
		if err != nil {
			lastError = err
			log.Errorf("failed to get ssh config for master '%s': %s", masterID, err.Error())
			continue
		}
		_, err = sshCfg.WaitServerReady("ready", temporal.GetConnectSSHTimeout())
		if err != nil {
			lastError = err
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
			return "", err
		}
		found = true
		break
	}
	if !found {
		return "", scerr.NotAvailableError(fmt.Sprintf("failed to find available master: %v", lastError))
	}
	return masterID, nil
}

// FindAvailableNode returns the ID of a node available
func (c *Controller) FindAvailableNode(task concurrency.Task) (id string, err error) {
	if c == nil {
		return "", scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostID := ""
	found := false
	clientHost := client.New().Host
	var lastError error
	list := c.ListNodeIDs(task)
	for _, hostID = range list {
		sshCfg, err := clientHost.SSHConfig(hostID)
		if err != nil {
			log.Errorf("failed to get ssh config of node '%s': %s", hostID, err.Error())
			lastError = err
			continue
		}
		_, err = sshCfg.WaitServerReady("ready", temporal.GetConnectSSHTimeout())
		if err != nil {
			lastError = err
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
			return "", err
		}
		found = true
		break
	}
	if !found {
		return "", scerr.NotAvailableError(fmt.Sprintf("failed to find available node: %v", lastError))
	}
	return hostID, nil
}

// UpdateMetadata writes Cluster config in Object Storage
func (c *Controller) UpdateMetadata(task concurrency.Task, updatefn func() error) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	c.Lock(task)
	defer c.Unlock(task)

	c.metadata.Acquire()
	defer c.metadata.Release()

	err = c.metadata.Reload(task)
	if err != nil {
		return err
	}
	if c.metadata.Written() {
		mc, err := c.metadata.Get()
		if err != nil {
			return err
		}
		c.replace(task, mc)
	} else {
		c.metadata.Carry(task, c)
	}

	if updatefn != nil {
		err := updatefn()
		if err != nil {
			return err
		}
	}
	return c.metadata.Write()
}

// DeleteMetadata removes Cluster metadata from Object Storage
func (c *Controller) DeleteMetadata(task concurrency.Task) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	c.Lock(task)
	defer c.Unlock(task)

	c.metadata.Acquire()
	defer c.metadata.Release()

	return c.metadata.Delete()
}

func findNodeByID(list []*clusterpropsv1.Node, ID string) (bool, int) {
	var idx int
	found := false
	for i, v := range list {
		if v.ID == ID {
			found = true
			idx = i
			break
		}
	}
	return found, idx
}

func findNodeByName(list []*clusterpropsv1.Node, name string) (bool, int) {
	var idx int
	found := false
	for i, v := range list {
		if v.Name == name {
			found = true
			idx = i
			break
		}
	}
	return found, idx
}

func deleteNodeFromListByID(list []*clusterpropsv1.Node, ID string) (*clusterpropsv1.Node, error) {
	length := len(list)
	found, idx := findNodeByID(list, ID)
	if !found {
		return nil, scerr.NotFoundError(fmt.Sprintf("failed to find node with ID '%s'", ID))
	}
	node := list[idx]
	if idx < length-1 {
		list = append(list[:idx], list[idx+1:]...)
	} else {
		list = list[:idx]
	}
	return node, nil
}

func deleteNodeFromListByName(list []*clusterpropsv1.Node, name string) (*clusterpropsv1.Node, error) {
	length := len(list)
	found, idx := findNodeByName(list, name)
	if !found {
		return nil, scerr.NotFoundError(fmt.Sprintf("failed to find node with name '%s'", name))
	}
	node := list[idx]
	if idx < length-1 {
		list = append(list[:idx], list[idx+1:]...)
	} else {
		list = list[:idx]
	}
	return node, nil
}

// Serialize converts cluster data to JSON
func (c *Controller) Serialize() ([]byte, error) {
	return serialize.ToJSON(c)
}

// Deserialize reads json code and reinstantiates cluster
func (c *Controller) Deserialize(buf []byte) error {
	return serialize.FromJSON(buf, c)
}

// AddNode adds one node
func (c *Controller) AddNode(task concurrency.Task, req *pb.HostDefinition) (string, error) {
	// No log enforcement here, delegated to AddNodes()

	hosts, err := c.AddNodes(task, 1, req)
	if err != nil {
		return "", err
	}
	return hosts[0], nil
}

func (c *Controller) getImageAndNodeDescriptionUsedInClusterFromMetadata(task concurrency.Task) (_ string, _ *pb.HostDefinition, err error) {
	if c == nil {
		return "", nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return "", nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	c.RLock(task)
	defer c.RUnlock(task)

	var hostImage string
	nodeDef := &pb.HostDefinition{}
	properties := c.GetProperties(task)
	if !properties.Lookup(property.DefaultsV2) {
		// If property.DefaultsV2 is not found but there is a property.DefaultsV1, converts it to DefaultsV2
		err := properties.LockForRead(property.DefaultsV1).ThenUse(
			func(clonable data.Clonable) error {
				defaultsV1 := clonable.(*clusterpropsv1.Defaults)
				return c.UpdateMetadata(
					task, func() error {
						return properties.LockForWrite(property.DefaultsV2).ThenUse(
							func(clonable data.Clonable) error {
								defaultsV2 := clonable.(*clusterpropsv2.Defaults)
								convertDefaultsV1ToDefaultsV2(defaultsV1, defaultsV2)
								return nil
							},
						)
					},
				)
			},
		)
		if err != nil {
			return "", nodeDef, err
		}
	}

	err = properties.LockForRead(property.DefaultsV2).ThenUse(
		func(clonable data.Clonable) error {
			defaultsV2 := clonable.(*clusterpropsv2.Defaults)
			sizing := srvutils.ToPBHostSizing(defaultsV2.NodeSizing)
			nodeDef.Sizing = sizing
			hostImage = defaultsV2.Image
			return nil
		},
	)
	if err != nil {
		return "", nodeDef, err
	}

	return hostImage, nodeDef, nil
}

// AddNodes adds <count> nodes
func (c *Controller) AddNodes(task concurrency.Task, count int, req *pb.HostDefinition) (hosts []string, err error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}
	if count <= 0 {
		return nil, scerr.InvalidParameterError("count", "must be an int > 0")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%d)", count), true)
	defer tracer.GoingIn().OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// retrieve cluster characteristics
	hostImage, nodeDef, err := c.getImageAndNodeDescriptionUsedInClusterFromMetadata(task)
	if err != nil {
		return hosts, err
	}

	nodeDef = complementHostDefinition(req, nodeDef)
	if nodeDef.ImageId == "" {
		nodeDef.ImageId = hostImage
	}

	var (
		// nodeType    NodeType.Enum
		nodeTypeStr string
		errors      []string
	)
	netCfg, err := c.GetNetworkConfig(task)
	if err != nil {
		return nil, err
	}
	nodeDef.Network = netCfg.NetworkID

	timeout := temporal.GetExecutionTimeout() + time.Duration(count)*time.Minute

	creationFailed := false

	var subtasks []concurrency.Task
	for i := 0; i < count; i++ {
		subtask, err := task.New()
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(
			c.foreman.taskCreateNode, data.Map{
				"index": i + 1,
				// "type":    nodeType,
				"nodeDef": nodeDef,
				"timeout": timeout,
				"nokeep":  true,
			},
		)
		if err != nil {
			log.Warnf("failure creating node: %v", err)
			creationFailed = true
			errors = append(errors, err.Error())
			break
		}
		subtasks = append(subtasks, subtask)
	}

	if creationFailed {
		for _, s := range subtasks {
			err := s.Abort()
			if err != nil {
				errors = append(errors, err.Error())
			}
		}
	} else {
		// FIXME: Improvements: don't wait blocking with for, use channels and use abort when a Wait fails
		// VPL: I need to be convinced this improvement is worth the risk the possible code complexity growth...
		for _, s := range subtasks {
			result, err := s.Wait()
			if err != nil {
				errors = append(errors, err.Error())
			} else {
				hostId := result.(string)
				if hostId != "" {
					hosts = append(hosts, hostId)
				}
			}
		}
	}

	// Starting from here, delete nodes if exiting with error
	newHosts := hosts
	defer func() {
		if err != nil && len(newHosts) > 0 && !req.KeepOnFailure {
			log.Warnf("Running taskDeleteNode after all")
			var subtasks []concurrency.Task
			for _, v := range newHosts {
				subtask, tErr := task.New()
				if tErr != nil {
					err = scerr.AddConsequence(err, tErr)
					continue
				}
				subtask, tErr = subtask.Start(c.foreman.taskDeleteNode, v)
				if tErr != nil {
					err = scerr.AddConsequence(err, tErr)
					continue
				}
				subtasks = append(subtasks, subtask)
			}

			for _, s := range subtasks {
				_, state := s.Wait()
				if state != nil {
					err = scerr.AddConsequence(err, state)
				}
			}
		}
	}()

	if len(errors) > 0 {
		err = fmt.Errorf(
			"errors occurred on %s node%s addition: %s", nodeTypeStr, utils.Plural(len(errors)),
			strings.Join(errors, "\n"),
		)
		return nil, err
	}

	// Now configure new nodes
	err = c.foreman.configureNodesFromList(task, hosts)
	if err != nil {
		log.Debugf("failure configuring nodes after being added...")
		return nil, err
	}

	// At last join nodes to cluster
	err = c.foreman.joinNodesFromList(task, hosts)
	if err != nil {
		log.Debugf("failure joining nodes after successful addition and configuration...")
		return nil, err
	}

	return hosts, nil
}

func convertDefaultsV1ToDefaultsV2(defaultsV1 *clusterpropsv1.Defaults, defaultsV2 *clusterpropsv2.Defaults) {
	defaultsV2.Image = defaultsV1.Image
	defaultsV2.MasterSizing = resources.SizingRequirements{
		MinCores:    defaultsV1.MasterSizing.Cores,
		MinFreq:     defaultsV1.MasterSizing.CPUFreq,
		MinGPU:      defaultsV1.MasterSizing.GPUNumber,
		MinRAMSize:  defaultsV1.MasterSizing.RAMSize,
		MinDiskSize: defaultsV1.MasterSizing.DiskSize,
		Replaceable: defaultsV1.MasterSizing.Replaceable,
	}
	defaultsV2.NodeSizing = resources.SizingRequirements{
		MinCores:    defaultsV1.NodeSizing.Cores,
		MinFreq:     defaultsV1.NodeSizing.CPUFreq,
		MinGPU:      defaultsV1.NodeSizing.GPUNumber,
		MinRAMSize:  defaultsV1.NodeSizing.RAMSize,
		MinDiskSize: defaultsV1.NodeSizing.DiskSize,
		Replaceable: defaultsV1.NodeSizing.Replaceable,
	}
}

// GetState returns the current state of the Cluster
func (c *Controller) GetState(task concurrency.Task) (state clusterstate.Enum, err error) {
	if c == nil {
		return clusterstate.Unknown, scerr.InvalidInstanceError()
	}
	if task == nil {
		return clusterstate.Unknown, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	now := time.Now()
	var collectInterval time.Duration

	c.RLock(task)
	err = c.Properties.LockForRead(property.StateV1).ThenUse(
		func(clonable data.Clonable) error {
			stateV1 := clonable.(*clusterpropsv1.State)
			collectInterval = stateV1.StateCollectInterval
			state = stateV1.State
			return nil
		},
	)
	c.RUnlock(task)
	if err != nil {
		return 0, err
	}
	if now.After(c.lastStateCollection.Add(collectInterval)) {
		return c.ForceGetState(task)
	}
	return state, nil
}

// ForceGetState returns the current state of the Cluster
// Uses the "maker" GetState from Foreman
func (c *Controller) ForceGetState(task concurrency.Task) (state clusterstate.Enum, err error) {
	if c == nil {
		return clusterstate.Unknown, scerr.InvalidInstanceError()
	}
	if task == nil {
		return clusterstate.Unknown, scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	state, err = c.foreman.getState(task)
	if err != nil {
		return clusterstate.Unknown, err
	}

	err = c.UpdateMetadata(
		task, func() error {
			return c.Properties.LockForWrite(property.StateV1).ThenUse(
				func(clonable data.Clonable) error {
					stateV1 := clonable.(*clusterpropsv1.State)
					stateV1.State = state
					c.lastStateCollection = time.Now()
					return nil
				},
			)
		},
	)
	return state, err
}

// deleteMaster deletes the master specified by its ID
func (c *Controller) wipeMaster(task concurrency.Task, hostID string) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%s)", hostID), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Finally delete host
	err = client.New().Host.Delete([]string{hostID}, temporal.GetLongOperationTimeout())
	if err != nil {
		return err
	}

	return nil
}

// deleteMaster deletes the master specified by its ID
func (c *Controller) deleteMaster(task concurrency.Task, hostID string) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%s)", hostID), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Removes master from cluster metadata
	var master *clusterpropsv1.Node
	err = c.UpdateMetadata(
		task, func() error {
			return c.Properties.LockForWrite(property.NodesV1).ThenUse(
				func(clonable data.Clonable) error {
					nodesV1 := clonable.(*clusterpropsv1.Nodes)

					// found, idx := findNodeByID(nodesV1.Masters, hostID)
					// if !found {
					//	return resources.ResourceNotFoundError("host", hostID)
					// }
					// master = nodesV1.Masters[idx]
					// if idx < len(nodesV1.Masters)-1 {
					//	nodesV1.Masters = append(nodesV1.Masters[:idx], nodesV1.Masters[idx+1:]...)
					// } else {
					//	nodesV1.Masters = nodesV1.Masters[:idx]
					// }
					var innerErr error
					master, innerErr = deleteNodeFromListByID(nodesV1.Masters, hostID)
					if innerErr != nil {
						switch innerErr.(type) {
						case scerr.ErrNotFound:
							return resources.ResourceNotFoundError("host", hostID)
						default:
							return err
						}
					}
					return nil
				},
			)
		},
	)
	if err != nil {
		return err
	}

	// Starting from here, restore master in cluster metadata if exiting with error
	defer func() {
		if err != nil {
			derr := c.UpdateMetadata(
				task, func() error {
					return c.Properties.LockForWrite(property.NodesV1).ThenUse(
						func(clonable data.Clonable) error {
							nodesV1 := clonable.(*clusterpropsv1.Nodes)
							nodesV1.Masters = append(nodesV1.Masters, master)
							return nil
						},
					)
				},
			)
			if derr != nil {
				log.Errorf("failed to restore node ownership in cluster")
			}
			err = scerr.AddConsequence(err, derr)
		}
	}()

	// Finally delete host
	err = client.New().Host.Delete([]string{master.ID}, temporal.GetLongOperationTimeout())
	if err != nil {
		return err
	}

	return nil
}

// DeleteLastNode deletes the last Agent node added
func (c *Controller) DeleteLastNode(task concurrency.Task, selectedMaster string) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("('%s')", selectedMaster), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var node *clusterpropsv1.Node

	// Removed reference of the node from cluster metadata
	c.RLock(task)
	err = c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes)
			node = nodesV1.PrivateNodes[len(nodesV1.PrivateNodes)-1]
			return nil
		},
	)
	c.RUnlock(task)
	if err != nil {
		return err
	}

	if selectedMaster == "" {
		selectedMaster, err = c.FindAvailableMaster(task)
		if err != nil {
			errDelNode := c.deleteNode(task, node, "")
			err = scerr.AddConsequence(err, errDelNode)
			return err
		}
	}

	return c.deleteNode(task, node, selectedMaster)
}

// DeleteSpecificNode deletes the node specified by its ID
func (c *Controller) WipeSpecificNode(task concurrency.Task, hostID string, selectedMaster string) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%s)", hostID), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Delete node
	// Finally delete host

	err = client.New().Host.Delete([]string{hostID}, temporal.GetLongOperationTimeout())
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			// host seems already deleted, so it's a success :-)
			return nil
		}
		return err
	}

	return nil
}

// DeleteSpecificNode deletes the node specified by its ID
func (c *Controller) DeleteSpecificNode(task concurrency.Task, hostID string, selectedMaster string) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if hostID == "" {
		return scerr.InvalidParameterError("hostID", "cannot be empty string")
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%s)", hostID), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		node *clusterpropsv1.Node
	)

	c.RLock(task)
	err = c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes)
			var (
				idx   int
				found bool
			)
			if found, idx = findNodeByID(nodesV1.PrivateNodes, hostID); !found {
				return scerr.NotFoundError(fmt.Sprintf("failed to find node '%s'", hostID))
			}
			node = nodesV1.PrivateNodes[idx]
			return nil
		},
	)
	c.RUnlock(task)
	if err != nil {
		return err
	}

	// search for an available master if cluster is running
	if selectedMaster == "" {
		state, err := c.GetState(task)
		if err != nil {
			return err
		}
		switch state {
		case clusterstate.Created, clusterstate.Degraded, clusterstate.Nominal, clusterstate.Starting:
			selectedMaster, err = c.FindAvailableMaster(task)
			if err != nil {
				errDelNode := c.deleteNode(task, node, "")
				err = scerr.AddConsequence(err, errDelNode)
				return err
			}
		}
	}

	// Delete node
	return c.deleteNode(task, node, selectedMaster)
}

// deleteNode deletes the node specified by its ID
func (c *Controller) deleteNode(task concurrency.Task, node *clusterpropsv1.Node, selectedMaster string) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if node == nil {
		return scerr.InvalidParameterError("node", "cannot be nil")
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%s, '%s')", node.Name, selectedMaster), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostExist := true

	// Do not remove a node with volume(s) attached
	mh, err := metadata.LoadHost(c.GetService(task), node.ID)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound:
			// If host is not found, deletion is considered a success, but we continue to update metadata
			hostExist = false
		default:
			return err
		}
	} else {
		host, err := mh.Get()
		if err != nil {
			return err
		}
		err = host.Properties.LockForRead(hostproperty.VolumesV1).ThenUse(
			func(clonable data.Clonable) error {
				nAttached := len(clonable.(*propsv1.HostVolumes).VolumesByID)
				if nAttached > 0 {
					return fmt.Errorf("host has %d volume%s attached", nAttached, utils.Plural(nAttached))
				}
				return nil
			},
		)
		if err != nil {
			return scerr.InvalidRequestError(
				fmt.Sprintf(
					"cannot delete node '%s' because of attached volumes: %v", host.Name, err,
				),
			)
		}
	}

	// Removes node from cluster metadata (done before really deleting node to prevent operations on the node in parallel)
	err = c.UpdateMetadata(
		task, func() error {
			return c.Properties.LockForWrite(property.NodesV1).ThenUse(
				func(clonable data.Clonable) error {
					nodesV1 := clonable.(*clusterpropsv1.Nodes)
					var innerErr error
					node, innerErr = deleteNodeFromListByID(nodesV1.PrivateNodes, node.ID)
					if innerErr != nil {
						return err
					}
					// length := len(nodesV1.PrivateNodes)
					// _, idx := findNodeByID(nodesV1.PrivateNodes, node.ID)
					// if idx < length-1 {
					//    nodesV1.PrivateNodes = append(nodesV1.PrivateNodes[:idx], nodesV1.PrivateNodes[idx+1:]...)
					// } else {
					//    nodesV1.PrivateNodes = nodesV1.PrivateNodes[:idx]
					// }
					return nil
				},
			)
		},
	)
	if err != nil {
		return err
	}

	// Starting from here, restore node in cluster metadata if exiting with error
	defer func() {
		if err != nil && hostExist {
			derr := c.UpdateMetadata(
				task, func() error {
					return c.Properties.LockForWrite(property.NodesV1).ThenUse(
						func(clonable data.Clonable) error {
							nodesV1 := clonable.(*clusterpropsv1.Nodes)
							nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, node)
							return nil
						},
					)
				},
			)
			if derr != nil {
				log.Errorf("failed to restore node ownership in cluster")
			}
			err = scerr.AddConsequence(err, derr)
		}
	}()

	// Leave node from cluster (for example leave Docker SWARM), if selectedMaster isn't empty
	if hostExist && selectedMaster != "" {
		err = c.foreman.leaveNodesFromList(task, []string{node.ID}, selectedMaster)
		if err != nil {
			return err
		}

		// Unconfigure node
		err = c.foreman.unconfigureNode(task, node.ID, selectedMaster)
		if err != nil {
			return err
		}
	}

	// Host may have mounted volume, we must detach it before being able to remove the host

	// Finally delete host
	if hostExist {
		err = client.New().Host.Delete([]string{node.ID}, temporal.GetLongOperationTimeout())
		if err != nil {
			if _, ok := err.(scerr.ErrNotFound); ok {
				// host seems already deleted, so it's a success :-)
				return nil
			}
			return err
		}
	}

	return nil
}

// Delete destroys everything related to the infrastructure built for the Cluster
func (c *Controller) Delete(task concurrency.Task) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return c.foreman.destruct(task)
}

// Wipe allows to destroy infrastructure of cluster, forcing destruction of resources and ignoring errors
func (c *Controller) Wipe(task concurrency.Task) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return c.foreman.wipe(task)
}

// Stop stops the Cluster is its current state is compatible
func (c *Controller) Stop(task concurrency.Task) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	state, _ := c.ForceGetState(task)
	switch state {
	case clusterstate.Stopping, clusterstate.Stopped:
		return nil
	case clusterstate.Starting, clusterstate.Created, clusterstate.Nominal, clusterstate.Degraded:
		// continue
	default:
		return fmt.Errorf("failed to stop Cluster because of it's current state: %s", state.String())
	}

	// Updates metadata to mark the cluster as Stopping
	err = c.UpdateMetadata(
		task, func() error {
			return c.Properties.LockForWrite(property.StateV1).ThenUse(
				func(clonable data.Clonable) error {
					clonable.(*clusterpropsv1.State).State = clusterstate.Stopping
					return nil
				},
			)
		},
	)
	if err != nil {
		return err
	}

	// Stops the resources of the cluster

	var (
		nodes                         []*clusterpropsv1.Node
		masters                       []*clusterpropsv1.Node
		gatewayID, secondaryGatewayID string
	)
	c.RLock(task)
	err = c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes)
			masters = nodesV1.Masters
			nodes = nodesV1.PrivateNodes
			return nil
		},
	)
	c.RUnlock(task)
	if err != nil {
		return fmt.Errorf("failed to get list of hosts: %v", err)
	}
	c.RLock(task)
	if c.Properties.Lookup(property.NetworkV2) {
		err = c.Properties.LockForRead(property.NetworkV2).ThenUse(
			func(clonable data.Clonable) error {
				networkV2 := clonable.(*clusterpropsv2.Network)
				gatewayID = networkV2.GatewayID
				secondaryGatewayID = networkV2.SecondaryGatewayID
				return nil
			},
		)
	} else {
		err = c.Properties.LockForRead(property.NetworkV1).ThenUse(
			func(clonable data.Clonable) error {
				gatewayID = clonable.(*clusterpropsv1.Network).GatewayID
				return nil
			},
		)
	}
	c.RUnlock(task)
	if err != nil {
		return err
	}

	// Stop nodes
	taskGroup, err := concurrency.NewTaskGroup(task)
	if err != nil {
		return err
	}

	// FIXME: Log errors and introduce status

	for _, n := range nodes {
		_, _ = taskGroup.Start(c.taskStopHost, n.ID)
	}
	// Stop masters
	for _, n := range masters {
		_, _ = taskGroup.Start(c.taskStopHost, n.ID)
	}
	// Stop gateway(s)
	_, _ = taskGroup.Start(c.taskStopHost, gatewayID)
	if secondaryGatewayID != "" {
		_, _ = taskGroup.Start(c.taskStopHost, secondaryGatewayID)
	}

	_, err = taskGroup.WaitGroup()
	if err != nil {
		return err
	}

	// Updates metadata to mark the cluster as Stopped
	return c.UpdateMetadata(
		task, func() error {
			return c.Properties.LockForWrite(property.StateV1).ThenUse(
				func(clonable data.Clonable) error {
					clonable.(*clusterpropsv1.State).State = clusterstate.Stopped
					return nil
				},
			)
		},
	)
}

func (c *Controller) taskStopHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	hostID := params.(string)
	if hostID == "" {
		return nil, scerr.InvalidParameterError("params", "can not be an empty string")
	}

	// Check host, to start it only if it's not in start state
	state, err := c.service.GetHostState(hostID)
	if err != nil {
		return nil, err
	}
	switch state {
	case hoststate.STOPPED, hoststate.STOPPING:
		return nil, nil
	case hoststate.ERROR, hoststate.TERMINATED:
		return nil, scerr.InvalidRequestError(
			fmt.Sprintf(
				"cannot stop host '%s' due to its current state: %s", hostID, state.String(),
			),
		)
	default:
		return nil, c.service.StopHost(params.(string))
	}

}

// Start starts the Cluster
func (c *Controller) Start(task concurrency.Task) (err error) {
	if c == nil {
		return scerr.InvalidInstanceError()
	}
	if task == nil {
		return scerr.InvalidParameterError("task", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	state, err := c.ForceGetState(task)
	if err != nil {
		return err
	}
	switch state {
	case clusterstate.Nominal, clusterstate.Degraded, clusterstate.Starting, clusterstate.Created:
		return nil
	case clusterstate.Stopping, clusterstate.Stopped:
		// Continue
	default:
		return fmt.Errorf("failed to start Cluster because of it's current state: %s", state.String())
	}

	// Updates metadata to mark the cluster as Starting
	err = c.UpdateMetadata(
		task, func() error {
			return c.Properties.LockForWrite(property.StateV1).ThenUse(
				func(clonable data.Clonable) error {
					clonable.(*clusterpropsv1.State).State = clusterstate.Starting
					return nil
				},
			)
		},
	)
	if err != nil {
		return err
	}

	// Starts the resources of the cluster
	var (
		nodes                         []*clusterpropsv1.Node
		masters                       []*clusterpropsv1.Node
		gatewayID, secondaryGatewayID string
	)
	c.RLock(task)
	err = c.Properties.LockForRead(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes)
			masters = nodesV1.Masters
			nodes = nodesV1.PrivateNodes
			return nil
		},
	)
	c.RUnlock(task)
	if err != nil {
		return fmt.Errorf("failed to get list of hosts: %v", err)
	}
	c.RLock(task)
	if c.Properties.Lookup(property.NetworkV2) {
		err = c.Properties.LockForRead(property.NetworkV2).ThenUse(
			func(clonable data.Clonable) error {
				networkV2 := clonable.(*clusterpropsv2.Network)
				gatewayID = networkV2.GatewayID
				secondaryGatewayID = networkV2.SecondaryGatewayID
				return nil
			},
		)
	} else {
		err = c.Properties.LockForRead(property.NetworkV1).ThenUse(
			func(clonable data.Clonable) error {
				gatewayID = clonable.(*clusterpropsv1.Network).GatewayID
				return nil
			},
		)
	}
	c.RUnlock(task)
	if err != nil {
		return err
	}

	// Start gateway(s)
	taskGroup, err := concurrency.NewTaskGroup(task)
	if err != nil {
		return err
	}
	_, _ = taskGroup.Start(c.taskStartHost, gatewayID)
	if secondaryGatewayID != "" {
		_, _ = taskGroup.Start(c.taskStartHost, secondaryGatewayID)
	}
	// Start masters
	for _, n := range masters {
		_, _ = taskGroup.Start(c.taskStartHost, n.ID)
	}
	// Start nodes
	for _, n := range nodes {
		_, _ = taskGroup.Start(c.taskStartHost, n.ID)
	}
	_, err = taskGroup.WaitGroup()
	if err != nil {
		return err
	}

	// Updates metadata to mark the cluster as Stopped
	return c.UpdateMetadata(
		task, func() error {
			return c.Properties.LockForWrite(property.StateV1).ThenUse(
				func(clonable data.Clonable) error {
					clonable.(*clusterpropsv1.State).State = clusterstate.Nominal
					return nil
				},
			)
		},
	)
}

func (c *Controller) taskStartHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	hostID := params.(string)
	if hostID == "" {
		return nil, scerr.InvalidParameterError("params", "can not be an empty string")
	}

	// Check host, to start it only if it's not in start state
	state, err := c.service.GetHostState(hostID)
	if err != nil {
		return nil, err
	}
	switch state {
	case hoststate.STARTED, hoststate.STARTING:
		return nil, nil
	case hoststate.ERROR, hoststate.TERMINATED:
		return nil, scerr.InvalidRequestError(
			fmt.Sprintf(
				"cannot stop host '%s' due to its current state: %s", hostID, state.String(),
			),
		)
	default:
		return nil, c.service.StartHost(hostID)
	}
}

// // sanitize tries to rebuild manager struct based on what is available on ObjectStorage
// func (c *Controller) Sanitize(data *Metadata) error {

// 	core := data.Get()
// 	instance := &Cluster{
// 		Core:     core,
// 		metadata: data,
// 	}
// 	instance.reset()

// 	if instance.manager == nil {
// 		var mgw *providermetadata.Gateway
// 		mgw, err := providermetadata.LoadGateway(svc, instance.Core.NetworkID)
// 		if err != nil {
// 			return err
// 		}
// 		gw := mgw.Get()
// 		hm := providermetadata.NewHost(svc)
// 		hosts := []*resources.Host{}
// 		err = hm.Browse(func(h *resources.Host) error {
// 			if strings.HasPrefix(h.Name, instance.Core.Name+"-") {
// 				hosts = append(hosts, h)
// 			}
// 			return nil
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		if len(hosts) == 0 {
// 			return fmt.Errorf("failed to find hosts belonging to cluster")
// 		}

// 		// We have hosts, fill the manager
// 		masterIDs := []string{}
// 		masterIPs := []string{}
// 		privateNodeIPs := []string{}
// 		publicNodeIPs := []string{}
// 		defaultNetworkIP := ""
// 		err = gw.Properties.LockForRead(Hostproperty.NetworkV1).ThenUse(func(v interface{}) error {
// 			hostNetworkV1 := v.(*propsv1.HostNetwork)
// 			defaultNetworkIP = hostNetworkV1.IPv4Addresses[hostNetworkV1.DefaultNetworkID]
// 			for _, h := range hosts {
// 				if strings.HasPrefix(h.Name, instance.Core.Name+"-master-") {
// 					masterIDs = append(masterIDs, h.ID)
// 					masterIPs = append(masterIPs, defaultNetworkIP)
// 				} else if strings.HasPrefix(h.Name, instance.Core.Name+"-node-") {
// 					privateNodeIPs = append(privateNodeIPs, defaultNetworkIP)
// 				} else if strings.HasPrefix(h.Name, instance.Core.Name+"-pubnode-") {
// 					publicNodeIPs = append(privateNodeIPs, defaultNetworkIP)
// 				}
// 			}
// 			return nil
// 		})
// 		if err != nil {
// 			return fmt.Errorf("failed to update metadata of cluster '%s': %s", instance.Core.Name, err.Error())
// 		}

// 		newManager := &managerData{
// 			BootstrapID:      gw.ID,
// 			BootstrapIP:      defaultNetworkIP,
// 			MasterIDs:        masterIDs,
// 			MasterIPs:        masterIPs,
// 			PrivateNodeIPs:   privateNodeIPs,
// 			PublicNodeIPs:    publicNodeIPs,
// 			MasterLastIndex:  len(masterIDs),
// 			PrivateLastIndex: len(privateNodeIPs),
// 			PublicLastIndex:  len(publicNodeIPs),
// 		}
// 		log.Debugf("updating metadata...\n")
// 		err = instance.updateMetadata(func() error {
// 			instance.manager = newManager
// 			return nil
// 		})
// 		if err != nil {
// 			return fmt.Errorf("failed to update metadata of cluster '%s': %s", instance.Core.Name, err.Error())
// 		}
// 	}
// 	return nil
// }
