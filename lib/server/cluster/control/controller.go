/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	clusterpropsv2 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v2"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/lib/server/cluster/identity"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
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
func NewController(svc iaas.Service) *Controller {
	metadata, err := NewMetadata(svc)
	if err != nil {
		panic("failed to create metadata object")
	}
	return &Controller{
		service:    svc,
		metadata:   metadata,
		Properties: serialize.NewJSONProperties("clusters"),
		TaskedLock: concurrency.NewTaskedLock(),
	}
}

func (c *Controller) replace(task concurrency.Task, src *Controller) {
	c.Lock(task)
	defer c.Unlock(task)

	//	(&c.Identity).Replace(&src.Identity)
	c.Properties = src.Properties
}

// Restore restores full ability of a Cluster controller by binding with appropriate Foreman
func (c *Controller) Restore(task concurrency.Task, foreman *foreman) {
	if c == nil {
		panic("Calling lib.server.cluster.control.Controller::Restore() from nil pointer!")
	}

	c.Lock(task)
	defer c.Unlock(task)
	c.foreman = foreman
}

// Create creates the necessary infrastructure of the Cluster
func (c *Controller) Create(task concurrency.Task, req Request, foreman *foreman) (err error) {
	if foreman == nil {
		panic("Calling lib.server.cluster.control.Controller::Create() from nil pointer!")
	}
	if task == nil {
		task = concurrency.RootTask()
	}

	c.Lock(task)

	// VPL: For now, always disable addition of feature proxycache-client
	err = c.Properties.LockForWrite(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		v.(*clusterpropsv1.Features).Disabled["proxycache"] = struct{}{}
		return nil
	})
	if err != nil {
		log.Errorf("failed to disable feature 'proxycache': %v", err)
		return err
	}
	// ENDVPL

	c.foreman = foreman
	c.Unlock(task)
	return c.foreman.construct(task, req)
}

// GetService returns the service from the provider
func (c *Controller) GetService(task concurrency.Task) iaas.Service {
	if c == nil {
		panic("Calling Controller::GetService() from nil pointer!")
	}
	c.RLock(task)
	defer c.RUnlock(task)
	return c.service
}

// GetIdentity returns the core data of a cluster
func (c *Controller) GetIdentity(task concurrency.Task) identity.Identity {
	if c == nil {
		panic("Calling lib.server.cluster.control.Controller::GetIdentity() from nil pointer!")
	}
	c.RLock(task)
	defer c.RUnlock(task)
	return c.Identity
}

// GetProperties returns the properties of the cluster
func (c *Controller) GetProperties(task concurrency.Task) *serialize.JSONProperties {
	if c == nil {
		panic("Calling lib.server.cluster.control.Controller::GetProperties() from nil pointer!")
	}
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)
	return c.Properties
}

// GetNetworkConfig returns the network configuration of the cluster
func (c *Controller) GetNetworkConfig(task concurrency.Task) (config clusterpropsv2.Network) {
	if c == nil {
		panic("Calling lib.server.cluster.control.Controller::GetNetworkConfig() from nil pointer!")
	}
	if task == nil {
		task = concurrency.RootTask()
	}

	c.RLock(task)
	if c.Properties.Lookup(Property.NetworkV2) {
		_ = c.Properties.LockForRead(Property.NetworkV2).ThenUse(func(v interface{}) error {
			config = *(v.(*clusterpropsv2.Network))
			return nil
		})
	} else {
		_ = c.Properties.LockForRead(Property.NetworkV1).ThenUse(func(v interface{}) error {
			networkV1 := v.(*clusterpropsv1.Network)
			config = clusterpropsv2.Network{
				NetworkID:      networkV1.NetworkID,
				CIDR:           networkV1.CIDR,
				GatewayID:      networkV1.GatewayID,
				GatewayIP:      networkV1.GatewayIP,
				DefaultRouteIP: networkV1.GatewayIP,
				EndpointIP:     networkV1.PublicIP,
			}
			return nil
		})
	}
	c.RUnlock(task)
	return config
}

// CountNodes returns the number of nodes in the cluster
func (c *Controller) CountNodes(task concurrency.Task) uint {
	if task == nil {
		task = concurrency.RootTask()
	}

	var count uint

	c.RLock(task)
	err := c.GetProperties(task).LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		count = uint(len(v.(*clusterpropsv1.Nodes).PrivateNodes))
		return nil
	})
	c.RUnlock(task)
	if err != nil {
		log.Debugf("failed to count nodes: %v", err)
	}
	return count
}

// ListMasters lists the names of the master nodes in the Cluster
func (c *Controller) ListMasters(task concurrency.Task) []*clusterpropsv1.Node {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	var list []*clusterpropsv1.Node
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		list = v.(*clusterpropsv1.Nodes).Masters
		return nil
	})
	if err != nil {
		log.Errorf("failed to get list of master names: %v", err)
	}
	return list
}

// ListMasterNames lists the names of the master nodes in the Cluster
func (c *Controller) ListMasterNames(task concurrency.Task) []string {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	var list []string
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes).Masters
		for _, v := range nodesV1 {
			list = append(list, v.Name)
		}
		return nil
	})
	if err != nil {
		log.Errorf("failed to get list of master names: %v", err)
	}
	return list
}

// ListMasterIDs lists the IDs of the master nodes in the Cluster
func (c *Controller) ListMasterIDs(task concurrency.Task) []string {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	var list []string
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes).Masters
		for _, v := range nodesV1 {
			list = append(list, v.ID)
		}
		return nil
	})
	if err != nil {
		log.Errorf("failed to get list of master IDs: %v", err)
	}
	return list
}

// ListMasterIPs lists the IP addresses of the master nodes in the Cluster
func (c *Controller) ListMasterIPs(task concurrency.Task) []string {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	var list []string
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes).Masters
		for _, v := range nodesV1 {
			list = append(list, v.PrivateIP)
		}
		return nil
	})
	if err != nil {
		log.Errorf("failed to get list of master IPs: %v", err)
	}
	return list
}

// ListNodes lists the nodes in the Cluster
func (c *Controller) ListNodes(task concurrency.Task) []*clusterpropsv1.Node {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	var list []*clusterpropsv1.Node
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		list = v.(*clusterpropsv1.Nodes).PrivateNodes
		return nil
	})
	if err != nil {
		log.Errorf("failed to get list of node IDs: %v", err)
	}
	return list
}

// ListNodeNames lists the names of the nodes in the Cluster
func (c *Controller) ListNodeNames(task concurrency.Task) []string {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	var list []string
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		var nodesV1 []*clusterpropsv1.Node
		nodesV1 = v.(*clusterpropsv1.Nodes).PrivateNodes
		for _, v := range nodesV1 {
			list = append(list, v.Name)
		}
		return nil
	})
	if err != nil {
		log.Errorf("failed to get list of node IDs: %v", err)
	}
	return list
}

// ListNodeIDs lists the IDs of the nodes in the Cluster
func (c *Controller) ListNodeIDs(task concurrency.Task) []string {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	var list []string
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		var nodesV1 []*clusterpropsv1.Node
		nodesV1 = v.(*clusterpropsv1.Nodes).PrivateNodes
		for _, v := range nodesV1 {
			list = append(list, v.ID)
		}
		return nil
	})
	if err != nil {
		log.Errorf("failed to get list of node IDs: %v", err)
	}
	return list
}

// ListNodeIPs lists the IP addresses of the nodes in the Cluster
func (c *Controller) ListNodeIPs(task concurrency.Task) []string {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	var list []string
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		var nodesV1 []*clusterpropsv1.Node
		nodesV1 = v.(*clusterpropsv1.Nodes).PrivateNodes
		for _, v := range nodesV1 {
			list = append(list, v.PrivateIP)
		}
		return nil
	})
	if err != nil {
		log.Errorf("failed to get list of node IP addresses: %v", err)
	}
	return list
}

// GetNode returns a node based on its ID
func (c *Controller) GetNode(task concurrency.Task, hostID string) (*pb.Host, error) {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	found := false
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		// found, _ := contains(nodesV1.PublicNodes, hostID)
		// if !found {
		found, _ = contains(nodesV1.PrivateNodes, hostID)
		// }
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("failed to find node '%s' in Cluster '%s'", hostID, c.Name)
	}
	return client.New().Host.Inspect(hostID, utils.GetExecutionTimeout())
}

// SearchNode tells if an host ID corresponds to a node of the Cluster
func (c *Controller) SearchNode(task concurrency.Task, hostID string) bool {
	if task == nil {
		task = concurrency.RootTask()
	}
	c.RLock(task)
	defer c.RUnlock(task)

	found := false
	_ = c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		found, _ = contains(v.(*clusterpropsv1.Nodes).PrivateNodes, hostID)
		return nil
	})
	return found
}

// FindAvailableMaster returns the ID of the first master available for execution
func (c *Controller) FindAvailableMaster(task concurrency.Task) (string, error) {
	if task == nil {
		task = concurrency.RootTask()
	}

	masterID := ""
	found := false
	clientHost := client.New().Host
	masterIDs := c.ListMasterIDs(task)
	for _, masterID = range masterIDs {
		sshCfg, err := clientHost.SSHConfig(masterID)
		if err != nil {
			log.Errorf("failed to get ssh config for master '%s': %s", masterID, err.Error())
			continue
		}
		_, err = sshCfg.WaitServerReady("ready", utils.GetConnectSSHTimeout())
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
			return "", err
		}
		found = true
		break
	}
	if !found {
		return "", fmt.Errorf("failed to find available master")
	}
	return masterID, nil
}

// FindAvailableNode returns the ID of a node available
func (c *Controller) FindAvailableNode(task concurrency.Task) (string, error) {
	if task == nil {
		task = concurrency.RootTask()
	}

	hostID := ""
	found := false
	clientHost := client.New().Host
	list := c.ListNodeIDs(task)
	for _, hostID = range list {
		sshCfg, err := clientHost.SSHConfig(hostID)
		if err != nil {
			log.Errorf("failed to get ssh config of node '%s': %s", hostID, err.Error())
			continue
		}
		_, err = sshCfg.WaitServerReady("ready", utils.GetConnectSSHTimeout())
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
			return "", err
		}
		found = true
		break
	}
	if !found {
		return "", fmt.Errorf("failed to find available node")
	}
	return hostID, nil
}

// UpdateMetadata writes Cluster config in Object Storage
func (c *Controller) UpdateMetadata(task concurrency.Task, updatefn func() error) (err error) {
	if task == nil {
		task = concurrency.RootTask()
	}

	defer utils.TimerErrWithLevel(fmt.Sprintf("{task %s} lib.server.cluster.control.Controller::UpdateMetadata() called", task.GetID()), &err, log.TraceLevel)()

	c.Lock(task)
	defer c.Unlock(task)

	c.metadata.Acquire()
	defer c.metadata.Release()

	err = c.metadata.Reload(task)
	if err != nil {
		return err
	}
	if c.metadata.Written() {
		c.replace(task, c.metadata.Get())
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
	if task == nil {
		task = concurrency.RootTask()
	}
	c.Lock(task)
	defer c.Unlock(task)

	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.cluster.control.Controller::DeleteMetadata() called"), &err, log.TraceLevel)()

	c.metadata.Acquire()
	defer c.metadata.Release()

	return c.metadata.Delete()
}

func contains(list []*clusterpropsv1.Node, hostID string) (bool, int) {
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

// Serialize converts cluster data to JSON
func (c *Controller) Serialize() ([]byte, error) {
	return serialize.ToJSON(c)
}

// Deserialize reads json code and reinstanciates cluster
func (c *Controller) Deserialize(buf []byte) error {
	return serialize.FromJSON(buf, c)
}

// AddNode adds one node
func (c *Controller) AddNode(task concurrency.Task, req *pb.HostDefinition) (string, error) {
	hosts, err := c.AddNodes(task, 1, req)
	if err != nil {
		return "", err
	}
	return hosts[0], nil
}

// AddNodes adds <count> nodes
func (c *Controller) AddNodes(task concurrency.Task, count int, req *pb.HostDefinition) (hosts []string, err error) {
	log.Tracef("lib.server.cluster.control.Controller::AddNodes(%d) called", count)
	defer log.Tracef("<<< lib.server.cluster.control.Controller::AddNodes(%d)", count)

	if task == nil {
		task = concurrency.RootTask()
	}

	c.RLock(task)
	nodeDef := complementHostDefinition(req, pb.HostDefinition{})
	var hostImage string

	properties := c.GetProperties(concurrency.RootTask())
	if !properties.Lookup(Property.DefaultsV2) {
		err := properties.LockForRead(Property.DefaultsV1).ThenUse(func(v interface{}) error {
			defaultsV1 := v.(*clusterpropsv1.Defaults)
			return c.UpdateMetadata(task, func() error {
				return properties.LockForWrite(Property.DefaultsV2).ThenUse(func(v interface{}) error {
					defaultsV2 := v.(*clusterpropsv2.Defaults)
					convertDefaultsV1ToDefaultsV2(defaultsV1, defaultsV2)
					return nil
				})
			})
		})
		if err != nil {
			return nil, err
		}
	}
	err = properties.LockForRead(Property.DefaultsV2).ThenUse(func(v interface{}) error {
		defaultsV2 := v.(*clusterpropsv2.Defaults)
		sizing := srvutils.ToPBHostSizing(defaultsV2.NodeSizing)
		nodeDef.Sizing = &sizing
		hostImage = defaultsV2.Image
		return nil
	})
	c.RUnlock(task)
	if err != nil {
		return nil, err
	}

	if nodeDef.ImageId == "" {
		nodeDef.ImageId = hostImage
	}

	var (
		nodeType    NodeType.Enum
		nodeTypeStr string
	)
	nodeDef.Network = c.GetNetworkConfig(task).NetworkID

	var (
		errors []string
	)
	timeout := utils.GetExecutionTimeout() + time.Duration(count)*time.Minute

	var subtasks []concurrency.Task
	for i := 0; i < count; i++ {
		subtask := task.New().Start(c.foreman.taskCreateNode, data.Map{
			"index":   i + 1,
			"type":    nodeType,
			"nodeDef": nodeDef,
			"timeout": timeout,
		})
		subtasks = append(subtasks, subtask)
	}
	for _, s := range subtasks {
		result, err := s.Wait()
		if err != nil {
			errors = append(errors, err.Error())
		} else {
			hostName := result.(string)
			if hostName != "" {
				hosts = append(hosts, hostName)
			}
		}
	}
	hostClt := client.New().Host

	// Starting from here, delete nodes if exiting with error
	newHosts := hosts
	defer func() {
		if err != nil {
			if len(newHosts) > 0 {
				derr := hostClt.Delete(newHosts, utils.GetExecutionTimeout())
				if derr != nil {
					log.Errorf("failed to delete nodes after failure to expand cluster")
				}
				err = retry.AddConsequence(err, derr)
			}
		}
	}()

	if len(errors) > 0 {
		err = fmt.Errorf("errors occured on %s node%s addition: %s", nodeTypeStr, utils.Plural(len(errors)), strings.Join(errors, "\n"))
		return nil, err
	}

	// Now configure new nodes
	err = c.foreman.configureNodesFromList(task, hosts)
	if err != nil {
		return nil, err
	}

	// At last join nodes to cluster
	err = c.foreman.joinNodesFromList(task, hosts)
	if err != nil {
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
func (c *Controller) GetState(task concurrency.Task) (ClusterState.Enum, error) {
	if task == nil {
		task = concurrency.RootTask()
	}

	now := time.Now()
	var (
		collectInterval time.Duration
		state           ClusterState.Enum
	)
	c.RLock(task)
	err := c.Properties.LockForRead(Property.StateV1).ThenUse(func(v interface{}) error {
		stateV1 := v.(*clusterpropsv1.State)
		collectInterval = stateV1.StateCollectInterval
		state = stateV1.State
		return nil
	})
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
func (c *Controller) ForceGetState(task concurrency.Task) (ClusterState.Enum, error) {
	if c == nil {
		panic("Calling c.ForceGetState with c==nil!")
	}
	if task == nil {
		task = concurrency.RootTask()
	}

	state, err := c.foreman.getState(task)
	if err != nil {
		return ClusterState.Unknown, err
	}

	err = c.UpdateMetadata(task, func() error {
		return c.Properties.LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
			stateV1 := v.(*clusterpropsv1.State)
			stateV1.State = state
			c.lastStateCollection = time.Now()
			return nil
		})
	})
	return state, err
}

// deleteMaster deletes the master specified by its ID
func (c *Controller) deleteMaster(task concurrency.Task, hostID string) (err error) {
	if hostID == "" {
		panic("Invalid parameter 'hostID': can't be empty string!")
	}
	if task == nil {
		task = concurrency.RootTask()
	}

	// Removes master from cluster metadata
	var master *clusterpropsv1.Node
	err = c.UpdateMetadata(task, func() error {
		return c.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			found, idx := contains(nodesV1.Masters, hostID)
			if !found {
				return resources.ResourceNotFoundError("host", hostID)
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

	// Starting from here, restore master in cluster metadata if exiting with error
	defer func() {
		if err != nil {
			derr := c.UpdateMetadata(task, func() error {
				return c.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
					nodesV1 := v.(*clusterpropsv1.Nodes)
					nodesV1.Masters = append(nodesV1.Masters, master)
					return nil
				})
			})
			if derr != nil {
				log.Errorf("failed to restore node ownership in cluster")
			}
			err = retry.AddConsequence(err, derr)
		}
	}()

	// Finally delete host
	err = client.New().Host.Delete([]string{master.ID}, utils.GetLongOperationTimeout())
	if err != nil {
		return err
	}

	return nil
}

// DeleteLastNode deletes the last Agent node added
func (c *Controller) DeleteLastNode(task concurrency.Task, selectedMaster string) (err error) {
	if c == nil {
		panic("Calling c.DeleteLastNode with c==nil!")
	}

	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.cluster.control.Controller::DeleteSpecificNode() called"), &err, log.TraceLevel)()

	if task == nil {
		task = concurrency.RootTask()
	}

	var (
		node *clusterpropsv1.Node
	)

	// Removed reference of the node from cluster metadata
	c.RLock(task)
	err = c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		node = nodesV1.PrivateNodes[len(nodesV1.PrivateNodes)-1]
		return nil
	})
	c.RUnlock(task)
	if err != nil {
		return err
	}

	if selectedMaster == "" {
		selectedMaster, err = c.FindAvailableMaster(task)
		if err != nil {
			// FIXME Try deletion anyway ?
			errDelNode := c.deleteNode(task, node, "")
			err = retry.AddConsequence(err, errDelNode)
			return err
		}
	}

	return c.deleteNode(task, node, selectedMaster)
}

// DeleteSpecificNode deletes the node specified by its ID
func (c *Controller) DeleteSpecificNode(task concurrency.Task, hostID string, selectedMaster string) (err error) {
	if c == nil {
		panic("Calling c.DeleteSpecificNode with c==nil!")
	}
	if hostID == "" {
		panic("hostID is empty!")
	}

	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.cluster.control.Controller::DeleteSpecificNode() called"), &err, log.TraceLevel)()

	if task == nil {
		task = concurrency.RootTask()
	}

	var (
		node *clusterpropsv1.Node
	)

	c.RLock(task)
	err = c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		var (
			idx   int
			found bool
		)
		if found, idx = contains(nodesV1.PrivateNodes, hostID); !found {
			return utils.NotFoundError(fmt.Sprintf("failed to find node '%s'", hostID))
		}
		node = nodesV1.PrivateNodes[idx]
		return nil
	})
	c.RUnlock(task)
	if err != nil {
		return err
	}

	if selectedMaster == "" {
		selectedMaster, err = c.FindAvailableMaster(task)
		if err != nil {
			// FIXME Try deletion anyway ?
			errDelNode := c.deleteNode(task, node, "")
			err = retry.AddConsequence(err, errDelNode)
			return err
		}
	}

	return c.deleteNode(task, node, selectedMaster)
}

// deleteNode deletes the node specified by its ID
func (c *Controller) deleteNode(task concurrency.Task, node *clusterpropsv1.Node, selectedMaster string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.cluster.control.Controller::deleteNode(%s) called", node.Name), &err, log.TraceLevel)()

	if c == nil {
		panic("Calling lib.server.cluster.control.Controller::deleteNode() from nil pointer!")
	}
	if node == nil {
		panic("parameter 'node' is nil!")
	}

	if task == nil {
		task = concurrency.RootTask()
	}

	// Removes node from cluster metadata (done before really deleting node to prevent operations on the node in parallel)
	err = c.UpdateMetadata(task, func() error {
		return c.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			length := len(nodesV1.PrivateNodes)
			_, idx := contains(nodesV1.PrivateNodes, node.ID)
			if idx < length-1 {
				nodesV1.PrivateNodes = append(nodesV1.PrivateNodes[:idx], nodesV1.PrivateNodes[idx+1:]...)
			} else {
				nodesV1.PrivateNodes = nodesV1.PrivateNodes[:idx]
			}
			return nil
		})
	})
	if err != nil {
		return err
	}

	// Starting from here, restore node in cluster metadata if exiting with error
	defer func() {
		if err != nil {
			derr := c.UpdateMetadata(task, func() error {
				return c.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
					nodesV1 := v.(*clusterpropsv1.Nodes)
					nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, node)
					return nil
				})
			})
			if derr != nil {
				log.Errorf("failed to restore node ownership in cluster")
			}
			err = retry.AddConsequence(err, derr)
		}
	}()

	// Leave node from cluster (ie leave Docker swarm), if selectedMaster isn't empty
	if selectedMaster != "" {
		err = c.foreman.leaveNodesFromList(task, []string{node.ID}, selectedMaster)
		if err != nil {
			return err
		}
	}

	// Unconfigure node
	err = c.foreman.unconfigureNode(task, node.ID, selectedMaster)
	if err != nil {
		return err
	}

	// Finally delete host
	err = client.New().Host.Delete([]string{node.ID}, utils.GetLongOperationTimeout())
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			// host seems already deleted, so it's a success (handles the case where )
			err = nil
		}
		return err
	}

	return nil
}

// Delete destroys everything related to the infrastructure built for the Cluster
func (c *Controller) Delete(task concurrency.Task) (err error) {
	if c == nil {
		panic("Calling lib.server.cluster.control.Controller::Delete from nil pointer!")
	}

	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.cluster.control.Controller::Delete() called"), &err, log.TraceLevel)()


	if task == nil {
		task = concurrency.RootTask()
	}

	// FIXME Introduce dirty states in metadata, and wait until the end to mark the operation as a success (Removed)

	// Updates metadata
	err = c.UpdateMetadata(task, func() error {
		return c.Properties.LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.State).State = ClusterState.Removed
			return nil
		})
	})
	if err != nil {
		return err
	}

	deleteNodeFunc := func(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
		funcErr := c.DeleteSpecificNode(t, params.(string), "")
		return nil, funcErr
	}
	deleteMasterFunc := func(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
		funcErr := c.deleteMaster(t, params.(string))
		return nil, funcErr
	}

	// Deletes the nodes
	list := c.ListNodeIDs(task)
	length := len(list)
	if length > 0 {
		var subtasks []concurrency.Task
		for i := 0; i < length; i++ {
			subtask := task.New().Start(deleteNodeFunc, list[i])
			subtasks = append(subtasks, subtask)
		}
		for _, s := range subtasks {
			_, subErr := s.Wait()
			if subErr != nil {
				log.Error(subErr)
			}
		}
	}

	// Delete the Masters
	list = c.ListMasterIDs(task)
	length = len(list)
	if len(list) > 0 {
		var subtasks []concurrency.Task
		for i := 0; i < length; i++ {
			subtask := task.New().Start(deleteMasterFunc, list[i])
			subtasks = append(subtasks, subtask)
		}
		for _, s := range subtasks {
			_, subErr := s.Wait()
			if subErr != nil {
				log.Error(subErr)
			}
		}
	}

	// Deletes the network and gateway
	c.RLock(task)
	networkID := ""
	if c.Properties.Lookup(Property.NetworkV2) {
		err = c.Properties.LockForRead(Property.NetworkV2).ThenUse(func(v interface{}) error {
			networkID = v.(*clusterpropsv2.Network).NetworkID
			return nil
		})
	} else {
		err = c.Properties.LockForRead(Property.NetworkV1).ThenUse(func(v interface{}) error {
			networkID = v.(*clusterpropsv1.Network).NetworkID
			return nil
		})
	}
	c.RUnlock(task)
	if err != nil {
		return err
	}

	clientNetwork := client.New().Network
	err = retry.WhileUnsuccessfulDelay5SecondsTimeout(
		func() error {
			return clientNetwork.Delete([]string{networkID}, utils.GetExecutionTimeout())
		},
		utils.GetHostTimeout(),
	)
	if err != nil {
		return err
	}

	// Deletes the metadata
	err = c.DeleteMetadata(task)
	if err != nil {
		return nil
	}
	c.service = nil
	return nil
}

// Stop stops the Cluster is its current state is compatible
func (c *Controller) Stop(task concurrency.Task) error {
	if c == nil {
		panic("Calling c.Stop with c==nil!")
	}

	if task == nil {
		task = concurrency.RootTask()
	}

	state, _ := c.ForceGetState(task)
	if state == ClusterState.Nominal || state == ClusterState.Degraded {
		return c.Stop(task)
	}
	if state != ClusterState.Stopped {
		return fmt.Errorf("failed to stop Cluster because of it's current state: %s", state.String())
	}
	return nil
}

// Start starts the Cluster
func (c *Controller) Start(task concurrency.Task) error {
	if c == nil {
		panic("Calling c.Start with c==nil!")
	}

	if task == nil {
		task = concurrency.RootTask()
	}

	state, err := c.ForceGetState(task)
	if err != nil {
		return err
	}
	if state == ClusterState.Stopped {
		return c.UpdateMetadata(task, func() error {
			return c.Properties.LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
				v.(*clusterpropsv1.State).State = ClusterState.Nominal
				return nil
			})
		})
	}
	if state != ClusterState.Nominal && state != ClusterState.Degraded {
		return fmt.Errorf("failed to start Cluster because of it's current state: %s", state.String())
	}
	return nil
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
// 		err = gw.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
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
