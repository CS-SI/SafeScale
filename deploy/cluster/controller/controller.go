/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/deploy/cluster/api"
	clusterpropsv1 "github.com/CS-SI/SafeScale/deploy/cluster/controller/properties/v1"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Extension"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/deploy/cluster/identity"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/utils/retry"
	"github.com/CS-SI/SafeScale/utils/serialize"
)

// Controller contains the information about a cluster
type Controller struct {
	identity.Identity `json:"identity"`
	Extensions        *serialize.JSONProperties `json:"extensions,omitempty"` // Extensions contains additional info about the cluster

	blueprint *Blueprint
	metadata  *Metadata
	service   *providers.Service
}

// NewController ...
func NewController(svc *providers.Service) *Controller {
	return &Controller{
		service:    svc,
		Extensions: serialize.NewJSONProperties("clusters"),
	}
}

// GetService returns the service from the provider
func (c *Controller) GetService() *providers.Service {
	return c.service
}

// GetIdentity returns the core data of a cluster
func (c *Controller) GetIdentity() identity.Identity {
	return c.Identity
}

// GetNetworkConfig returns the network configuration of the cluster
func (c *Controller) GetNetworkConfig() (config clusterpropsv1.Network) {
	c.Extensions.LockForRead(Extension.NetworkV1).ThenUse(func(v interface{}) error {
		config = *(v.(*clusterpropsv1.Network))
		return nil
	})
	return config
}

// GetExtensions returns the extensions of the cluster
func (c *Controller) GetExtensions() *serialize.JSONProperties {
	return c.Extensions
}

// BuildHostname builds a unique hostname in the swarmCluster
func (c *Controller) BuildHostname(core string, nodeType NodeType.Enum) (string, error) {
	var (
		index    int
		coreName string
	)

	switch nodeType {
	case NodeType.PublicNode:
		coreName = "pub" + core
	case NodeType.PrivateNode:
		coreName = core
	case NodeType.Master:
		coreName = core
	default:
		return "", fmt.Errorf("Invalid Node Type '%v'", nodeType)
	}

	// Locks for write the manager extension...
	outerErr := c.Extensions.LockForWrite(Extension.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		return c.UpdateMetadata(func() error {
			switch nodeType {
			case NodeType.PublicNode:
				nodesV1.PublicLastIndex++
				index = nodesV1.PublicLastIndex
			case NodeType.PrivateNode:
				nodesV1.PrivateLastIndex++
				index = nodesV1.PrivateLastIndex
			case NodeType.Master:
				nodesV1.MasterLastIndex++
				index = nodesV1.MasterLastIndex
			}
			return nil
		})
	})
	if outerErr != nil {
		return "", outerErr
	}
	return c.Name + "-" + coreName + "-" + strconv.Itoa(index), nil
}

// CountNodes returns the number of public or private nodes in the cluster
func (c *Controller) CountNodes(public bool) uint {
	var count uint
	err := c.Extensions.LockForRead(Extension.NodesV1).ThenUse(func(v interface{}) error {
		if public {
			count = uint(len(v.(*clusterpropsv1.Nodes).PublicNodes))
		} else {
			count = uint(len(v.(*clusterpropsv1.Nodes).PrivateNodes))
		}
		return nil
	})
	if err != nil {
		log.Debugf("failed to count nodes: %v", err)
	}
	return count
}

// ListMasterIDs lists the IDs of the master nodes in the Cluster
func (c *Controller) ListMasterIDs() []string {
	var list []string
	err := c.Extensions.LockForRead(Extension.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes).Masters
		for k, v := range nodesV1 {
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
func (c *Controller) ListMasterIPs() []string {
	var list []string
	err := c.Extensions.LockForRead(Extension.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes).Masters
		for k, v := range nodesV1 {
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
	var list []string
	err := c.Extensions.LockForRead(Extension.NodesV1).ThenUse(func(v interface{}) error {
		var nodesV1 []*clusterpropsv1.Node
		if public {
			nodesV1 = v.(*clusterpropsv1.Nodes).PublicNodes
		} else {
			nodesV1 = v.(*clusterpropsv1.Nodes).PrivateNodes
		}
		for k, v := range nodesV1 {
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
	var list []string
	err := c.Extensions.LockForRead(Extension.NodesV1).ThenUse(func(v interface{}) error {
		var nodesV1 []*clusterpropsv1.Node
		if public {
			nodesV1 = v.(*clusterpropsv1.Nodes).PublicNodes
		} else {
			nodesV1 = v.(*clusterpropsv1.Nodes).PrivateNodes
		}
		for k, v := range nodesV1 {
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
	found := false
	err := c.Extensions.LockForRead(Extension.NodesV1).ThenUse(func(v interface{}) error {
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
	return brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
}

// SearchNode tells if an host ID corresponds to a node of the Cluster
func (c *Controller) SearchNode(hostID string, public bool) bool {
	found := false
	err := c.Extensions.LockForRead(Extension.NodesV1).ThenUse(func(v interface{}) error {
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
	masterID := ""
	found := false
	brokerHost := brokerclient.New().Host
	masterIDs := c.ListMasterIDs()
	for _, masterID = range masterIDs {
		sshCfg, err := brokerHost.SSHConfig(masterID)
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
	brokerHost := brokerclient.New().Host
	for _, hostID = range c.ListNodeIDs(public) {
		sshCfg, err := brokerHost.SSHConfig(hostID)
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

// UpdateMetadata writes swarmCluster config in Object Storage
func (c *Controller) UpdateMetadata(updatefn func() error) error {
	if c.metadata == nil {
		m, err := NewMetadata(c.GetService())
		if err != nil {
			return err
		}
		m.Carry(c)
		c.metadata = m

		c.metadata.Acquire()
	} else {
		c.metadata.Acquire()
		c.Reload()
	}
	defer c.metadata.Release()

	if updatefn != nil {
		err := updatefn()
		if err != nil {
			return err
		}
	}

	// Write metadata
	return c.metadata.Write()
}

// DeleteMetadata removes Cluster metadata from Object Storage
func (c *Controller) DeleteMetadata() error {
	err := c.metadata.Delete()
	if err != nil {
		return nil
	}
	c.metadata = nil
	return nil
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
	// var parsed map[string]interface{}
	// err := serialize.FromJSON(buf, &parsed)
	// if err != nil {
	// 	return err
	// }
	// if c.Extensions == nil {
	// 	field, found := parsed["flavor"].(float64)
	// 	if !found {
	// 		return fmt.Errorf("invalid JSON content in metadata: missing 'flavor' field")
	// 	}
	// 	c.Extensions = serialize.NewJSONProperties("clusters." + strings.ToLower(Flavor.Enum(int(field)).String()))
	// }
	// err = c.Extensions.LockForWrite(Extension.FlavorV1).ThenUse(func(v interface{}) error {
	// 	return serialize.FromJSON(buf, c)
	// })
	// if err != nil {
	// 	return err
	// }

	// return nil
	return serialize.FromJSON(buf, c)
}

// AddNode adds one node
func (c *Controller) AddNode(public bool, req *pb.HostDefinition) (string, error) {
	hosts, err := c.AddNodes(1, public, req)
	if err != nil {
		return "", err
	}
	return hosts[0], nil
}

// AddNodes adds <count> nodes
func (c *Controller) AddNodes(count int, public bool, req *pb.HostDefinition) ([]string, error) {
	var hostDef model.HostSize
	c.GetExtensions().LockForRead(Extension.DefaultsV1).ThenUse(func(v interface{}) error {
		hostDef = v.(*clusterpropsv1.Defaults).NodeSizing
		return nil
	})
	if req != nil {
		if req.CPUNumber > 0 {
			hostDef.CPUNumber = req.CPUNumber
		}
		if req.RAM > 0.0 {
			hostDef.RAM = req.RAM
		}
		if req.Disk > 0 {
			hostDef.Disk = req.Disk
		}
		if req.ImageID != "" {
			hostDef.ImageID = req.ImageID
		}
	}

	var nodeType NodeType.Enum
	if public {
		nodeType = NodeType.PublicNode
	} else {
		nodeType = NodeType.PrivateNode
	}

	var hosts []string
	var errors []string
	var dones []chan error
	var results []chan string
	timeout := brokerclient.DefaultExecutionTimeout + time.Duration(count)*time.Minute
	for i := 0; i < count; i++ {
		r := make(chan string)
		results = append(results, r)
		d := make(chan error)
		dones = append(dones, d)
		// go c.asyncCreateNode(i+1, nodeType, hostDef, timeout, r, d)
		go asyncCreateNode(c, c.blueprint, i+1, nodeType, hostDef, timeout, r, d)
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
	brokerHost := brokerclient.New().Host
	if len(errors) > 0 {
		if len(hosts) > 0 {
			brokerHost.Delete(hosts, brokerclient.DefaultExecutionTimeout)
		}
		return nil, fmt.Errorf("errors occured on node addition: %s", strings.Join(errors, "\n"))
	}

	// Now configure new nodes
	err := c.blueprint.ConfigureNodesFromList(public, hosts)
	if err != nil {
		brokerHost.Delete(hosts, brokerclient.DefaultExecutionTimeout)
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
	err := c.Extensions.LockForRead(Extension.StateV1).ThenUse(func(v interface{}) error {
		stateV1 := v.(*clusterpropsv1.State)
		collectInterval = stateV1.StateCollectInterval
		state = stateV1.State
		return nil
	})
	if err != nil {
		return 0, err
	}
	if now.After(c.lastStateCollection.Add(collectInterval)) {
		return c.ForceGetState()
	}
	return state, nil
}

// ForceGetState returns the current state of the Cluster
// Does nothing currently...
// !!! FIX IT !!!
func (c *Controller) ForceGetState() (ClusterState.Enum, error) {
	var state ClusterState.Enum
	err := c.UpdateMetadata(func() error {
		return c.GetExtensions().LockForWrite(Extension.StateV1).ThenUse(func(v interface{}) error {
			stateV1 := v.(*clusterpropsv1.State)
			stateV1.State = ClusterState.Nominal
			state = stateV1.State
			c.lastStateCollection = time.Now()
			return nil
		})
	})
	return state, err
}

// DeleteLastNode deletes the last Agent node added
func (c *Controller) DeleteLastNode(public bool, selectedMaster string) error {
	var (
		node *Node
		err  error
	)

	if selectedMaster == "" {
		selectedMaster, err = c.FindAvailableMaster()
		if err != nil {
			return err
		}
	}

	err = c.Cluster.Extensions.LockForWrite(Extension.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		if public {
			node = nodesV1.PublicNodes[len(nodesV1.PublicNodes)-1]
		} else {
			node = nodesV1.PrivateNodes[len(nodesV1.PrivateNodes)-1]
		}
		return nil
	})
	if err != nil {
		return err
	}

	// err = c.deleteSwarmWorker(hostID, selectedMaster)
	err = c.blueprint.UnconfigureNode(c, hostID, selectedMaster)
	if err != nil {
		return err
	}

	return c.UpdateMetadata(func() error {
		return c.GetExtensions().LockForWrite(Extension.NodesV1).ThenUse(func(v interface{}) error {
			if public {
				delete(nodesV1.PublicNodes, node)
			} else {
				delete(nodesV1.PrivateNodes, node)
			}
			return nil
		})
	})
}

// DeleteSpecificNode deletes the node specified by its ID
func (c *Controller) DeleteSpecificNode(hostID string, selectedMaster string) error {
	if hostID == "" {
		panic("hostID is empty!")
	}

	var (
		foundInPublic  bool
		foundInPrivate bool
		err            error
	)

	err = c.Cluster.Extensions.LockForRead(Extension.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		foundInPublic, idx := contains(nodesV1.PublicNodeIDs, hostID)
		if !foundInPublic {
			foundInPrivate, idx = contains(nodesV1.PrivateNodeIDs, hostID)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !foundInPublic && !foundInPrivate {
		return fmt.Errorf("host '%s' isn't a registered Node of the Cluster '%s'", hostID, c.Core.Name)
	}

	if selectedMaster == "" {
		selectedMaster, err = c.FindAvailableMaster()
		if err != nil {
			return err
		}
	}

	err = c.blueprint.UnconfigureNode(c, hostID, selectedMaster)
	if err != nil {
		return err
	}

	return c.UpdateMetadata(func() error {
		return c.GetExtensions().LockForWrite(Extension.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			if !foundInPublic {
				foundInPrivate, idx = contains(nodesV1.PrivateNodeIDs, hostID)
			}
			if foundInPublic {
				_, idx := contains(nodesV1.PublicNodeIDs, hostID)
				delete(nodesV1.PublicNodeIDs, hostID)
				nodesV1.PublicNodeIPs = append(nodesV1.PublicNodeIDs[:idx], nodesV1.PublicNodeIDs[idx+1:]...)
			} else {
				_, idx := contains(nodesV1.PrivateNodeIDs, hostID)
				delete(nodesV1.PrivateNodeIDs, hostID)
				nodesV1.PrivateNodeIPs = append(nodesV1.PrivateNodeIDs[:idx], nodesV1.PrivateNodeIDs[idx+1:]...)
			}
			return nil
		})
		return nil
	})
}

// Delete destroys everything related to the infrastructure built for the swarmCluster
func (c *Controller) Delete() error {
	if c.metadata == nil {
		return fmt.Errorf("no metadata found for this swarmCluster")
	}

	// Updates metadata
	err := c.UpdateMetadata(func() error {
		return c.Cluster.Extensions.LockForWrite(Extension.StateV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.State).State = ClusterState.Removed
			return nil
		})
	})
	if err != nil {
		return err
	}

	broker := brokerclient.New()

	// Deletes the public nodes
	list := c.ListNodeIDs(true)
	if len(list) > 0 {
		broker.Host.Delete(list, brokerclient.DefaultExecutionTimeout)
	}

	// Deletes the private nodes
	list = c.ListNodeIDs(false)
	if len(list) > 0 {
		broker.Host.Delete(list, brokerclient.DefaultExecutionTimeout)
	}

	// Delete the Masters
	list = c.ListMasterIDs()
	if len(list) > 0 {
		broker.Host.Delete(list, brokerclient.DefaultExecutionTimeout)
	}

	// Deletes the network and gateway
	err = c.GetExtensions().LockForRead(Extension.NetworkV1).ThenUse(func(v interface{}) error {
		return broker.Network.Delete([]string{v.(*clusterpropsv1.Network).NetworkID}, brokerclient.DefaultExecutionTimeout)
	})
	if err != nil {
		return err
	}

	// Deletes the metadata
	err = c.DeleteMetadata()
	if err != nil {
		return nil
	}
	c.service = nil
	c.Cluster = nil
	return nil
}

// Stop stops the swarmCluster is its current state is compatible
func (c *Controller) Stop() error {
	state, _ := c.ForceGetState()
	if state == ClusterState.Nominal || state == ClusterState.Degraded {
		return c.Stop()
	}
	if state != ClusterState.Stopped {
		return fmt.Errorf("failed to stop swarmCluster because of it's current state: %s", state.String())
	}
	return nil
}

// Start starts the Cluster
func (c *Controller) Start() error {
	state, err := c.ForceGetState()
	if err != nil {
		return err
	}
	if state == ClusterState.Stopped {
		return c.UpdateMetadata(func() error {
			return c.GetExtensions().LockForWrite(Extension.StateV1).ThenUse(func(v interface{}) error {
				v.(*clusterpropsv1.State).State = ClusterState.Nominal
				return nil
			})
		})
	}
	if state != ClusterState.Nominal && state != ClusterState.Degraded {
		return fmt.Errorf("failed to start swarmCluster because of it's current state: %s", state.String())
	}
	return nil
}

// Create creates the necessary infrastructure of Cluster
func (c *Controller) Create(req Request) (api.Cluster, error) {
	return c.blueprint.Create(req)
}

// Reload reloads metadata of Cluster from ObjectStorage
func (c *Controller) Reload() error {
	err := c.metadata.Reload()
	if err != nil {
		return err
	}
	*c = *(c.metadata.Get())
	return nil
}
