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

package controller

import (
	"fmt"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/resources"
	pb "github.com/CS-SI/SafeScale/safescale"
	"github.com/CS-SI/SafeScale/safescale/client"
	clusterpropsv1 "github.com/CS-SI/SafeScale/safescale/server/cluster/controller/properties/v1"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/identity"
	pbutils "github.com/CS-SI/SafeScale/safescale/utils"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// Controller contains the information about a cluster
type Controller struct {
	identity.Identity
	Properties *serialize.JSONProperties `json:"properties,omitempty"` // Properties contains additional info about the cluster

	blueprint *Blueprint
	metadata  *Metadata
	service   *iaas.Service

	lastStateCollection time.Time

	*sync.RWMutex
}

// NewController ...
func NewController(svc *iaas.Service) *Controller {
	metadata, err := NewMetadata(svc)
	if err != nil {
		panic("failed to create metadata object")
	}
	return &Controller{
		service:    svc,
		metadata:   metadata,
		Properties: serialize.NewJSONProperties("clusters"),
		RWMutex:    &sync.RWMutex{},
	}
}

func (c *Controller) replace(src *Controller) {
	(&c.Identity).Replace(&src.Identity)
	c.Properties = src.Properties
}

// Restore restores full ability of a Cluster controller by binding with appropriate Blueprint
func (c *Controller) Restore(b *Blueprint) error {
	if c == nil {
		panic("Calling c.Restore with c==nil!")
	}
	if b == nil {
		panic("b is nil!")
	}

	c.Lock()
	defer c.Unlock()

	c.blueprint = b
	return nil
}

// Create creates the necessary infrastructure of the Cluster
func (c *Controller) Create(req Request, b *Blueprint) error {
	if b == nil {
		panic("Calling c.Create with c==nil!")
	}

	//VPL: For now, always disable addition of feature proxycache-client
	c.Lock()
	err := c.Properties.LockForWrite(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		v.(*clusterpropsv1.Features).Disabled["proxycache"] = struct{}{}
		return nil
	})
	if err != nil {
		log.Errorf("failed to disable feature 'proxycache': %v")
		return err
	}
	c.Unlock()
	//ENDVPL

	c.blueprint = b
	return c.blueprint.Construct(req)
}

// GetService returns the service from the provider
func (c *Controller) GetService() *iaas.Service {
	if c == nil {
		panic("Calling Controller::GetService() from nil pointer!")
	}

	c.RLock()
	defer c.RUnlock()

	return c.service
}

// GetIdentity returns the core data of a cluster
func (c *Controller) GetIdentity() identity.Identity {
	if c == nil {
		panic("Calling safescale.server.cluster.controller.Controller::GetIdentity() from nil pointer!")
	}
	return c.Identity
}

// GetProperties returns the properties of the cluster
func (c *Controller) GetProperties() *serialize.JSONProperties {
	if c == nil {
		panic("Calling safescale.server.cluster.controller.Controller::GetProperties() from nil pointer!")
	}
	return c.Properties
}

// GetNetworkConfig returns the network configuration of the cluster
func (c *Controller) GetNetworkConfig() (config clusterpropsv1.Network) {
	if c == nil {
		panic("Calling c.GetNetworkConfig() with c==nil!")
	}

	c.RLock()
	_ = c.Properties.LockForRead(Property.NetworkV1).ThenUse(func(v interface{}) error {
		config = *(v.(*clusterpropsv1.Network))
		return nil
	})
	c.RUnlock()
	return config
}

// CountNodes returns the number of public or private nodes in the cluster
func (c *Controller) CountNodes(public bool) uint {
	var count uint
	c.RLock()
	err := c.GetProperties().LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		if public {
			count = uint(len(v.(*clusterpropsv1.Nodes).PublicNodes))
		} else {
			count = uint(len(v.(*clusterpropsv1.Nodes).PrivateNodes))
		}
		return nil
	})
	c.RUnlock()
	if err != nil {
		log.Debugf("failed to count nodes: %v", err)
	}
	return count
}

// ListMasterIDs lists the IDs of the master nodes in the Cluster
func (c *Controller) ListMasterIDs() []string {
	var list []string
	c.RLock()
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes).Masters
		for _, v := range nodesV1 {
			list = append(list, v.ID)
		}
		return nil
	})
	c.RUnlock()
	if err != nil {
		log.Errorf("failed to get list of master IDs: %v", err)
	}
	return list
}

// ListMasterIPs lists the IP addresses of the master nodes in the Cluster
func (c *Controller) ListMasterIPs() []string {
	c.RLock()
	defer c.RUnlock()

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

// ListNodeIDs lists the IDs of the nodes in the Cluster
func (c *Controller) ListNodeIDs(public bool) []string {
	c.RLock()
	defer c.RUnlock()

	var list []string
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		var nodesV1 []*clusterpropsv1.Node
		if public {
			nodesV1 = v.(*clusterpropsv1.Nodes).PublicNodes
		} else {
			nodesV1 = v.(*clusterpropsv1.Nodes).PrivateNodes
		}
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
func (c *Controller) ListNodeIPs(public bool) []string {
	c.RLock()
	defer c.RUnlock()

	var list []string
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		var nodesV1 []*clusterpropsv1.Node
		if public {
			nodesV1 = v.(*clusterpropsv1.Nodes).PublicNodes
		} else {
			nodesV1 = v.(*clusterpropsv1.Nodes).PrivateNodes
		}
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
func (c *Controller) GetNode(hostID string) (*pb.Host, error) {
	c.RLock()
	defer c.RUnlock()

	found := false
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		found, _ := contains(nodesV1.PublicNodes, hostID)
		if !found {
			found, _ = contains(nodesV1.PrivateNodes, hostID)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("failed to find node '%s' in Cluster '%s'", hostID, c.Name)
	}
	return client.New().Host.Inspect(hostID, client.DefaultExecutionTimeout)
}

// SearchNode tells if an host ID corresponds to a node of the Cluster
func (c *Controller) SearchNode(hostID string, public bool) bool {
	c.RLock()
	defer c.RUnlock()

	found := false
	_ = c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		if public {
			found, _ = contains(nodesV1.PublicNodes, hostID)
		} else {
			found, _ = contains(nodesV1.PrivateNodes, hostID)
		}
		return nil
	})
	return found
}

// FindAvailableMaster returns the ID of the first master available for execution
func (c *Controller) FindAvailableMaster() (string, error) {
	c.RLock()
	defer c.RUnlock()

	masterID := ""
	found := false
	safescaleHost := client.New().Host
	masterIDs := c.ListMasterIDs()
	for _, masterID = range masterIDs {
		sshCfg, err := safescaleHost.SSHConfig(masterID)
		if err != nil {
			log.Errorf("failed to get ssh config for master '%s': %s", masterID, err.Error())
			continue
		}
		err = sshCfg.WaitServerReady(2 * time.Minute)
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
func (c *Controller) FindAvailableNode(public bool) (string, error) {
	hostID := ""
	found := false
	clientHost := client.New().Host
	list := c.ListNodeIDs(public)
	for _, hostID = range list {
		sshCfg, err := clientHost.SSHConfig(hostID)
		if err != nil {
			log.Errorf("failed to get ssh config of node '%s': %s", hostID, err.Error())
			continue
		}
		err = sshCfg.WaitServerReady(2 * time.Minute)
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
func (c *Controller) UpdateMetadata(updatefn func() error) error {
	c.Lock()
	defer c.Unlock()

	c.metadata.Acquire()
	defer c.metadata.Release()

	err := c.metadata.Reload()
	if err != nil {
		return err
	}
	if c.metadata.Written() {
		c.replace(c.metadata.Get())
	} else {
		c.metadata.Carry(c)
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
func (c *Controller) DeleteMetadata() error {
	c.Lock()
	defer c.Unlock()

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
func (c *Controller) AddNode(public bool, req *resources.HostDefinition) (string, error) {
	hosts, err := c.AddNodes(1, public, req)
	if err != nil {
		return "", err
	}
	return hosts[0], nil
}

// AddNodes adds <count> nodes
func (c *Controller) AddNodes(count int, public bool, req *resources.HostDefinition) ([]string, error) {
	log.Debugf(">>> safescale.server.cluster.controller.Controller::AddNodes(%d, %v)", count, public)
	defer log.Debugf("<<< safescale.server.cluster.controller.Controller::AddNodes(%d, %v)", count, public)

	var (
		nodeDef   resources.HostDefinition
		hostImage string
	)

	c.RLock()
	err := c.Properties.LockForRead(Property.DefaultsV1).ThenUse(func(v interface{}) error {
		defaultsV1 := v.(*clusterpropsv1.Defaults)
		nodeDef = defaultsV1.NodeSizing
		hostImage = defaultsV1.Image
		return nil
	})
	c.RUnlock()
	if err != nil {
		return nil, err
	}

	if req != nil {
		nodeDef = complementHostDefinition(req, nodeDef)
	}
	pbNodeDef := pbutils.ToPBHostDefinition(&nodeDef)
	if nodeDef.ImageID == "" {
		pbNodeDef.ImageID = hostImage
	}

	var (
		nodeType    NodeType.Enum
		nodeTypeStr string
	)
	if public {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "private"
	}
	pbNodeDef.Public = public
	pbNodeDef.Network = c.GetNetworkConfig().NetworkID

	var (
		hosts   []string
		errors  []string
		dones   []chan error
		results []chan string
	)
	timeout := client.DefaultExecutionTimeout + time.Duration(count)*time.Minute

	for i := 0; i < count; i++ {
		r := make(chan string)
		results = append(results, r)
		d := make(chan error)
		dones = append(dones, d)
		go c.blueprint.asyncCreateNode(i+1, nodeType, *pbNodeDef, timeout, r, d)
	}
	for i := range dones {
		hostName := <-results[i]
		if hostName != "" {
			hosts = append(hosts, hostName)
		}
		err := <-dones[i]
		if err != nil {
			errors = append(errors, err.Error())
		}
	}
	clientHost := client.New().Host

	// Starting from here, delete nodes if exiting with error
	defer func() {
		if err != nil {
			if len(hosts) > 0 {
				derr := clientHost.Delete(hosts, client.DefaultExecutionTimeout)
				if derr != nil {
					log.Errorf("failed to delete nodes after failure to expand cluster")
				}
			}
		}
	}()

	if len(errors) > 0 {
		err = fmt.Errorf("errors occured on %s node%s addition: %s", nodeTypeStr, utils.Plural(len(errors)), strings.Join(errors, "\n"))
		return nil, err
	}

	// Now configure new nodes
	err = c.blueprint.configureNodesFromList(public, hosts)
	if err != nil {
		return nil, err
	}

	// At last join nodes to cluster
	err = c.blueprint.joinNodesFromList(public, hosts)
	if err != nil {
		return nil, err
	}

	return hosts, nil
}

// GetState returns the current state of the Cluster
func (c *Controller) GetState() (ClusterState.Enum, error) {
	now := time.Now()
	var (
		collectInterval time.Duration
		state           ClusterState.Enum
	)
	c.RLock()
	err := c.Properties.LockForRead(Property.StateV1).ThenUse(func(v interface{}) error {
		stateV1 := v.(*clusterpropsv1.State)
		collectInterval = stateV1.StateCollectInterval
		state = stateV1.State
		return nil
	})
	c.RUnlock()
	if err != nil {
		return 0, err
	}
	if now.After(c.lastStateCollection.Add(collectInterval)) {
		return c.ForceGetState()
	}
	return state, nil
}

// ForceGetState returns the current state of the Cluster
// Uses the "actor" GetState from Blueprint
func (c *Controller) ForceGetState() (ClusterState.Enum, error) {
	if c == nil {
		panic("Calling c.ForceGetState with c==nil!")
	}

	state, err := c.blueprint.GetState()
	if err != nil {
		return ClusterState.Unknown, err
	}

	err = c.UpdateMetadata(func() error {
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
func (c *Controller) deleteMaster(hostID string) error {
	if c == nil {
		panic("Calling c.deleteMaster with c==nil!")
	}
	if hostID == "" {
		panic("hostID is empty!")
	}

	var (
		found  bool
		idx    int
		master *clusterpropsv1.Node
	)

	c.RLock()
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		found, idx = contains(nodesV1.Masters, hostID)
		if !found {
			return resources.ResourceNotFoundError("host", hostID)
		}
		master = nodesV1.Masters[idx]
		return nil
	})
	c.RUnlock()
	if err != nil {
		return err
	}

	// Removes master from cluster metadata
	err = c.UpdateMetadata(func() error {
		return c.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			nodesV1.Masters = append(nodesV1.Masters[:idx], nodesV1.Masters[idx+1:]...)
			return nil
		})
	})
	if err != nil {
		return err
	}

	// Starting from here, restore master in cluster metadata if exiting with error
	defer func() {
		if err != nil {
			derr := c.UpdateMetadata(func() error {
				return c.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
					nodesV1 := v.(*clusterpropsv1.Nodes)
					nodesV1.Masters = append(nodesV1.Masters, master)
					return nil
				})
			})
			if derr != nil {
				log.Errorf("failed to restore node ownership in cluster")
			}
		}
	}()

	// Finally delete host
	err = client.New().Host.Delete([]string{master.ID}, 10*time.Minute)
	if err != nil {
		return err
	}

	return nil
}

// DeleteLastNode deletes the last Agent node added
func (c *Controller) DeleteLastNode(public bool, selectedMaster string) error {
	if c == nil {
		panic("Calling c.DeleteLastNode with c==nil!")
	}
	var (
		node *clusterpropsv1.Node
		err  error
		idx  int
	)

	// Removed reference of the node from cluster metadata
	c.RLock()
	err = c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		if public {
			idx = len(nodesV1.PublicNodes) - 1
			node = nodesV1.PublicNodes[idx]
		} else {
			idx = len(nodesV1.PrivateNodes) - 1
			node = nodesV1.PrivateNodes[idx]
		}
		return nil
	})
	c.RUnlock()
	if err != nil {
		return err
	}

	if selectedMaster == "" {
		selectedMaster, err = c.FindAvailableMaster()
		if err != nil {
			return err
		}
	}

	return c.deleteNode(node, idx, public, selectedMaster)
}

// DeleteSpecificNode deletes the node specified by its ID
func (c *Controller) DeleteSpecificNode(hostID string, selectedMaster string) error {
	if c == nil {
		panic("Calling c.DeleteSpecificNode with c==nil!")
	}
	if hostID == "" {
		panic("hostID is empty!")
	}

	var (
		foundInPublic bool
		idx           int
		node          *clusterpropsv1.Node
	)

	c.RLock()
	err := c.Properties.LockForRead(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		foundInPublic, idx = contains(nodesV1.PublicNodes, hostID)
		if foundInPublic {
			node = nodesV1.PublicNodes[idx]
		} else {
			_, idx = contains(nodesV1.PrivateNodes, hostID)
			node = nodesV1.PrivateNodes[idx]
		}
		return nil
	})
	c.RUnlock()
	if err != nil {
		return err
	}

	if selectedMaster == "" {
		selectedMaster, err = c.FindAvailableMaster()
		if err != nil {
			return err
		}
	}

	return c.deleteNode(node, idx, foundInPublic, selectedMaster)
}

// deleteNode deletes the node specified by its ID
func (c *Controller) deleteNode(node *clusterpropsv1.Node, index int, public bool, selectedMaster string) error {
	if c == nil {
		panic("Calling safescale.server.cluster.controller.Controller::DeleteSpecificNode from nil pointer!")
	}
	if node == nil {
		panic("parameter 'node' is nil!")
	}

	// Removes node from cluster metadata
	err := c.UpdateMetadata(func() error {
		return c.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			if public {
				nodesV1.PublicNodes = append(nodesV1.PublicNodes[:index], nodesV1.PublicNodes[index+1:]...)
			} else {
				nodesV1.PrivateNodes = append(nodesV1.PrivateNodes[:index], nodesV1.PrivateNodes[index+1:]...)
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
			derr := c.UpdateMetadata(func() error {
				return c.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
					nodesV1 := v.(*clusterpropsv1.Nodes)
					if public {
						nodesV1.PublicNodes = append(nodesV1.PublicNodes, node)
					} else {
						nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, node)
					}
					return nil
				})
			})
			if derr != nil {
				log.Errorf("failed to restore node ownership in cluster")
			}
		}
	}()

	// Leave node from cluster (ie leave Docker swarm), if selectedMaster isn't empty
	if selectedMaster != "" {
		err = c.blueprint.leaveNodesFromList([]string{node.ID}, public, selectedMaster)
		if err != nil {
			return err
		}
	}

	// Unconfigure node
	err = c.blueprint.unconfigureNode(node.ID, selectedMaster)
	if err != nil {
		return err
	}

	// Finally delete host
	err = client.New().Host.Delete([]string{node.ID}, 10*time.Minute)
	if err != nil {
		if _, ok := err.(resources.ErrResourceNotFound); ok {
			// host seems already deleted, so it's a success (handles the case where )
			err = nil
		}
		return err
	}

	return nil
}

// Delete destroys everything related to the infrastructure built for the Cluster
func (c *Controller) Delete() error {
	if c == nil {
		panic("Calling safescale.server.cluster.controller.Controller::Delete from nil pointer!")
	}

	// Updates metadata
	err := c.UpdateMetadata(func() error {
		return c.Properties.LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.State).State = ClusterState.Removed
			return nil
		})
	})
	if err != nil {
		return err
	}

	var wg sync.WaitGroup

	// Deletes the public nodes
	list := c.ListNodeIDs(true)
	if len(list) > 0 {
		wg.Add(len(list))
		for _, target := range list {
			go func(h string) {
				defer wg.Done()
				_ = c.DeleteSpecificNode(h, "")
			}(target)
		}
		wg.Wait()
	}

	// Deletes the private nodes
	list = c.ListNodeIDs(false)
	if len(list) > 0 {
		wg.Add(len(list))
		for _, target := range list {
			go func(h string) {
				defer wg.Done()
				_ = c.DeleteSpecificNode(h, "")
			}(target)
		}
		wg.Wait()
	}

	// Delete the Masters
	list = c.ListMasterIDs()
	if len(list) > 0 {
		wg.Add(len(list))
		for _, target := range list {
			go func(h string) {
				defer wg.Done()
				_ = c.deleteMaster(h)
			}(target)
		}
		wg.Wait()
	}

	// Deletes the network and gateway
	c.RLock()
	networkID := ""
	err = c.Properties.LockForRead(Property.NetworkV1).ThenUse(func(v interface{}) error {
		networkID = v.(*clusterpropsv1.Network).NetworkID
		return nil
	})
	c.RUnlock()
	if err != nil {
		return err
	}
	clientNetwork := client.New().Network
	err = retry.WhileUnsuccessfulDelay5SecondsTimeout(
		func() error {
			return clientNetwork.Delete([]string{networkID}, client.DefaultExecutionTimeout)
		},
		3*time.Minute,
	)
	if err != nil {
		return err
	}

	// Deletes the metadata
	err = c.DeleteMetadata()
	if err != nil {
		return nil
	}
	c.service = nil
	return nil
}

// Stop stops the Cluster is its current state is compatible
func (c *Controller) Stop() error {
	if c == nil {
		panic("Calling c.Stop with c==nil!")
	}

	state, _ := c.ForceGetState()
	if state == ClusterState.Nominal || state == ClusterState.Degraded {
		return c.Stop()
	}
	if state != ClusterState.Stopped {
		return fmt.Errorf("failed to stop Cluster because of it's current state: %s", state.String())
	}
	return nil
}

// Start starts the Cluster
func (c *Controller) Start() error {
	if c == nil {
		panic("Calling c.Start with c==nil!")
	}

	state, err := c.ForceGetState()
	if err != nil {
		return err
	}
	if state == ClusterState.Stopped {
		return c.UpdateMetadata(func() error {
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
