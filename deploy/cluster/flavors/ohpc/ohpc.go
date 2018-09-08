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

package ohpc

/*
 * Implements a cluster of hosts with OpenHPC and slurm (or PBS Torque ?)
 */

import (
	"encoding/gob"
	"fmt"
	"log"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/AdditionalInfo"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Flavor"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/NodeType"
	"github.com/CS-SI/SafeScale/deploy/cluster/flavors/dcos/ErrorCode"
	"github.com/CS-SI/SafeScale/deploy/cluster/metadata"

	"github.com/CS-SI/SafeScale/deploy/install"

	"github.com/CS-SI/SafeScale/providers"
	providerapi "github.com/CS-SI/SafeScale/providers/api"
	providermetadata "github.com/CS-SI/SafeScale/providers/metadata"

	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/provideruse"
	"github.com/CS-SI/SafeScale/utils/retry"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
)

const (
	timeoutCtxHost = 10 * time.Minute

	shortTimeoutSSH = time.Minute
	longTimeoutSSH  = 5 * time.Minute

	tempFolder = "/var/tmp/"
)

var (
	// templateBox is the rice box to use in this package
	templateBoxes = map[string]*rice.Box{}

	//funcMap defines the custome functions to be used in templates
	funcMap = template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
		"errcode": func(msg string) int {
			if code, ok := ErrorCode.ErrorCodes[msg]; ok {
				return int(code)
			}
			return 1023
		},
	}
)

// managerData defines the data used by the manager of cluster we want to keep in Object Storage
type managerData struct {
	// MasterID contains the ID of the host acting as a master
	MasterID string
	// Master IP contains the IP if the host acting as a master
	MasterIP string
	// PublicNodeIPs contains a list of IP of the Public Agent nodes
	PublicNodeIPs []string
	// PrivateAvgentIPs contains a list of IP of the Private Agent Nodes
	PrivateNodeIPs []string
	// StateCollectInterval in seconds
	StateCollectInterval time.Duration
	// PrivateLastIndex
	PrivateLastIndex int
	// PublicLastIndex
	PublicLastIndex int
}

// Cluster is the object describing a cluster created by ClusterManagerAPI.CreateCluster
type Cluster struct {
	// common cluster data
	Common *clusterapi.Cluster

	// manager contains data specific to the cluster management
	manager *managerData

	// LastStateCollect contains the date of the last state collection
	lastStateCollection time.Time

	// metadata of cluster
	metadata *metadata.Cluster

	// provider is a pointer to current provider service instance
	provider *providers.Service
}

// GetNetworkID returns the ID of the network used by the cluster
func (c *Cluster) GetNetworkID() string {
	return c.Common.GetNetworkID()
}

// CountNodes returns the number of public or private nodes in the cluster
func (c *Cluster) CountNodes(public bool) uint {
	return c.Common.CountNodes(public)
}

// GetAdditionalInfo returns additional info of the cluster
func (c *Cluster) GetAdditionalInfo(ctx AdditionalInfo.Enum) interface{} {
	return c.Common.GetAdditionalInfo(ctx)
}

// SetAdditionalInfo returns additional info of the cluster
func (c *Cluster) SetAdditionalInfo(ctx AdditionalInfo.Enum, info interface{}) {
	c.Common.SetAdditionalInfo(ctx, info)
}

// Load loads the internals of an existing cluster from metadata
func Load(data *metadata.Cluster) (clusterapi.Cluster, error) {
	svc, err := provideruse.GetProviderService()
	if err != nil {
		return nil, err
	}

	common := data.Get()
	instance := &Cluster{
		Common:   common,
		metadata: data,
		provider: svc,
	}
	instance.resetAdditionalInfos(common)
	return instance, nil
}

func (c *Cluster) resetAdditionalInfos(common *clusterapi.Cluster) {
	if common == nil {
		return
	}
	anon := common.GetAdditionalInfo(AdditionalInfo.Flavor)
	if anon != nil {
		manager := anon.(managerData)
		c.manager = &manager
		// Note: On Load(), need to replace AdditionalInfos that are structs to pointers to struct
		common.SetAdditionalInfo(AdditionalInfo.Flavor, &manager)
	}
}

// Reload reloads metadata of Cluster from ObjectStorage
func (c *Cluster) Reload() error {
	err := c.metadata.Reload()
	if err != nil {
		return err
	}
	c.resetAdditionalInfos(c.metadata.Get())
	return nil
}

// Create creates the necessary infrastructure of cluster
func Create(req clusterapi.Request) (clusterapi.Cluster, error) {
	var (
		nodesDef         pb.HostDefinition
		instance         Cluster
		manager          *managerData
		privateNodeCount int
		gw               *providerapi.Host
		m                *providermetadata.Gateway
		found            bool
		masterChannel    chan error
		nodesStatus      error
	)

	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password for user cladm: %s", err.Error())
	}

	if req.NodesDef != nil {
		nodesDef = *req.NodesDef
	} else {
		nodesDef = pb.HostDefinition{
			CPUNumber: 4,
			RAM:       15.0,
			Disk:      100,
		}
	}
	if nodesDef.ImageID == "" {
		nodesDef.ImageID = "Ubuntu 18.04"
	}

	// Creates network
	log.Printf("Creating Network 'net-%s'", req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	def := pb.NetworkDefinition{
		Name: networkName,
		CIDR: req.CIDR,
		Gateway: &pb.GatewayDefinition{
			CPU:     nodesDef.CPUNumber,
			RAM:     nodesDef.RAM,
			Disk:    nodesDef.Disk,
			ImageID: nodesDef.ImageID,
		},
	}
	network, err := brokerclient.New().Network.Create(def, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		err = fmt.Errorf("Failed to create Network '%s': %s", networkName, err.Error())
		return nil, err
	}
	req.NetworkID = network.ID

	svc, err := provideruse.GetProviderService()
	if err != nil {
		goto cleanNetwork
	}

	m, err = providermetadata.NewGateway(svc, req.NetworkID)
	if err != nil {
		goto cleanNetwork
	}
	found, err = m.Read()
	if err != nil {
		goto cleanNetwork
	}
	if !found {
		err = fmt.Errorf("failed to load gateway metadata")
		goto cleanNetwork
	}
	gw = m.Get()

	// Saving cluster parameters, with status 'Creating'
	manager = &managerData{}
	instance = Cluster{
		Common: &clusterapi.Cluster{
			Name:          req.Name,
			CIDR:          req.CIDR,
			Flavor:        Flavor.BOH,
			State:         ClusterState.Creating,
			Complexity:    req.Complexity,
			Tenant:        req.Tenant,
			Keypair:       kp,
			AdminPassword: cladmPassword,
			NetworkID:     req.NetworkID,
			GatewayIP:     gw.GetPrivateIP(),
			PublicIP:      gw.GetAccessIP(),
			NodesDef:      &nodesDef,
		},
		manager:  manager,
		provider: svc,
	}
	instance.SetAdditionalInfo(AdditionalInfo.Flavor, manager)
	err = instance.updateMetadata()
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanNetwork
	}

	switch req.Complexity {
	case Complexity.Minimal:
		privateNodeCount = 1
	case Complexity.Normal:
		privateNodeCount = 3
	case Complexity.Volume:
		privateNodeCount = 7
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Step 1: starts master creation and nodes creation
	err = instance.createMaster(&nodesDef)
	if err != nil {
		goto cleanNetwork
	}

	// step 2: configure master asynchronously
	masterChannel = make(chan error)
	go instance.asyncConfigureMaster(masterChannel)

	// Step 3: starts node creation
	nodesStatus = instance.createNodes(privateNodeCount, false, &nodesDef)

	// step 4: waits master configuration end
	err = <-masterChannel

	// step 5: reacts on error(s)
	if err != nil {
		goto cleanNodes
	}
	if nodesStatus != nil {
		err = nodesStatus
		goto cleanNodes
	}

	// Cluster created and configured successfully, saving again to Metadata
	instance.Common.State = ClusterState.Created
	err = instance.updateMetadata()
	if err != nil {
		goto cleanNodes
	}

	// Get the state of the cluster until successful
	err = retry.Action(
		func() error {
			status, err := instance.ForceGetState()
			if err != nil {
				return err
			}
			if status != ClusterState.Nominal {
				return fmt.Errorf("cluster is not ready for duty")
			}
			return nil
		},
		retry.PrevailDone(retry.Unsuccessful(), retry.Timeout(5*time.Minute)),
		retry.Constant(5*time.Second),
		nil, nil, nil,
	)
	if err != nil {
		goto cleanNodes
	}
	return &instance, nil

cleanNodes:
	if !req.KeepOnFailure {
		for _, id := range instance.Common.PrivateNodeIDs {
			brokerclient.New().Host.Delete(id, 0)
		}
		brokerclient.New().Host.Delete(instance.manager.MasterID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
	}
cleanNetwork:
	if !req.KeepOnFailure {
		brokerclient.New().Network.Delete(instance.Common.NetworkID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
		instance.metadata.Delete()
	}
	return nil, err
}

// createMaster creates an host acting as a master in the cluster
func (c *Cluster) createMaster(req *pb.HostDefinition) error {
	log.Println("[Master] starting creation...")

	// Create the host
	var err error
	req.Name = c.Common.Name + "-master-1"
	req.Public = false
	req.Network = c.Common.NetworkID
	host, err := brokerclient.New().Host.Create(*req, 0)
	if err != nil {
		log.Printf("[Master] creation failed: %s\n", err.Error())
		return err
	}

	// Registers the new master in the cluster struct
	c.metadata.Acquire()
	err = c.Reload()
	if err != nil {
		c.metadata.Release()
		return err
	}
	c.manager.MasterID = host.ID
	c.manager.MasterIP = host.PRIVATE_IP

	// Update cluster definition in Object Storage
	err = c.metadata.Write()
	c.metadata.Release()
	if err != nil {
		c.manager.MasterID = ""
		c.manager.MasterIP = ""
		brokerclient.New().Host.Delete(host.ID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
		log.Printf("[Master] creation failed: %s", err.Error())
		return err
	}

	log.Println("[Master] creation successful")
	return nil
}

func (c *Cluster) createNodes(count int, public bool, def *pb.HostDefinition) error {
	var countS string
	if count > 1 {
		countS = "s"
	}
	var nodeType NodeType.Enum
	var nodeTypeStr string
	if public {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "private"
	}
	fmt.Printf("Creating %d %s Node%s...\n", count, nodeTypeStr, countS)

	var dones []chan error
	var results []chan string
	for i := 1; i <= count; i++ {
		d := make(chan error)
		dones = append(dones, d)
		r := make(chan string)
		results = append(results, r)
		go c.asyncCreateNode(i, nodeType, def, r, d)
	}

	var state error
	var errors []string
	for i := range dones {
		<-results[i]
		state = <-dones[i]
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "\n"))
	}

	return nil
}

// asyncCreateNode creates a Node in the cluster
// This function is intended to be call as a goroutine
func (c *Cluster) asyncCreateNode(index int, nodeType NodeType.Enum, req *pb.HostDefinition, result chan string, done chan error) {
	var publicIP bool
	var nodeTypeStr string
	if nodeType == NodeType.PublicNode {
		nodeTypeStr = "public"
		publicIP = true
	} else {
		nodeTypeStr = "private"
		publicIP = false
	}
	log.Printf("[Nodes: %s #%d] starting creation...\n", nodeTypeStr, index)

	// Create the host
	var err error
	req.Name, err = c.buildHostname("node", nodeType)
	if err != nil {
		log.Printf("[Nodes: %s #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}
	req.Public = publicIP
	req.Network = c.Common.NetworkID
	host, err := brokerclient.New().Host.Create(*req, 0)
	if err != nil {
		log.Printf("[Nodes: %s #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}

	// Registers the new Agent in the cluster struct
	c.metadata.Acquire()
	err = c.Reload()
	if err != nil {
		c.metadata.Release()
		result <- ""
		done <- err
	}
	if nodeType == NodeType.PublicNode {
		c.Common.PublicNodeIDs = append(c.Common.PublicNodeIDs, host.ID)
		c.manager.PublicNodeIPs = append(c.manager.PublicNodeIPs, host.PRIVATE_IP)
	} else {
		c.Common.PrivateNodeIDs = append(c.Common.PrivateNodeIDs, host.ID)
		c.manager.PrivateNodeIPs = append(c.manager.PrivateNodeIPs, host.PRIVATE_IP)
	}

	// Update cluster definition in Object Storage
	err = c.metadata.Write()
	c.metadata.Release()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		if nodeType == NodeType.PublicNode {
			c.Common.PublicNodeIDs = c.Common.PublicNodeIDs[:len(c.Common.PublicNodeIDs)-1]
			c.manager.PublicNodeIPs = c.manager.PublicNodeIPs[:len(c.manager.PublicNodeIPs)-1]
		} else {
			c.Common.PrivateNodeIDs = c.Common.PrivateNodeIDs[:len(c.Common.PrivateNodeIDs)-1]
			c.manager.PrivateNodeIPs = c.manager.PrivateNodeIPs[:len(c.manager.PrivateNodeIPs)-1]
		}
		brokerclient.New().Host.Delete(host.ID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
		log.Printf("[Nodes: %s #%d] creation failed: %s", nodeTypeStr, index, err.Error())
		result <- ""
		done <- fmt.Errorf("failed to update Cluster configuration: %s", err.Error())
		return
	}

	log.Printf("[Nodes: %s #%d] creation successful\n", nodeTypeStr, index)
	result <- host.ID
	done <- nil
}

// buildHostname builds a unique hostname in the cluster
func (c *Cluster) buildHostname(core string, nodeType NodeType.Enum) (string, error) {
	var (
		index    int
		coreName string
	)

	switch nodeType {
	case NodeType.PublicNode:
		coreName = "pub" + core
	case NodeType.PrivateNode:
		coreName = "priv" + core
	default:
		return "", fmt.Errorf("Invalid Node Type '%v'", nodeType)
	}

	c.metadata.Acquire()
	err := c.Reload()
	if err != nil {
		c.metadata.Release()
		return "", err
	}
	switch nodeType {
	case NodeType.PublicNode:
		c.manager.PublicLastIndex++
		index = c.manager.PublicLastIndex
	case NodeType.PrivateNode:
		c.manager.PrivateLastIndex++
		index = c.manager.PrivateLastIndex
	}

	// Update cluster definition in Object Storage
	err = c.metadata.Write()
	c.metadata.Release()
	if err != nil {
		return "", err
	}
	return c.Core.Name + "-" + coreName + "-" + strconv.Itoa(index), nil
}

// asyncConfigureMaster configure DCOS on master
func (c *Cluster) asyncConfigureMaster(done chan error) {
	log.Println("[Master] starting configuration...")

	host, err := brokerclient.New().Host.Inspect(c.manager.MasterID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		done <- err
		return
	}
	target := install.NewHostTarget(host)

	// Installing component RemoteDesktop on master host
	component, err := install.NewComponent("remotedesktop")
	if err != nil {
		log.Printf("[Master] failed to remotely install component 'RemoteDesktop': %s\n", err.Error())
		done <- err
		return
	}
	ok, results, err := component.Add(target, installapi.Variables{
		"GatewayIP": c.Core.GatewayIP,
		"Hostname":  host.Name,
		"HostIP":    host.PRIVATE_IP,
		"Username":  "cladm",
		"Password":  c.Core.AdminPassword,
	})
	if err != nil {
		done <- err
		return
	}
	if !ok {
		msg := results.Errors()
		log.Printf("[Master] installation script of component 'RemoteDesktop' failed: %s\n", msg)
		done <- fmt.Errorf(msg)
		return
	}
	log.Println("[Master] configuration successful")
	done <- nil
}

// GetName returns the name of the cluster
func (c *Cluster) GetName() string {
	return c.Common.Name
}

// GetMasters returns a list of master servers
func (c *Cluster) GetMasters() ([]string, error) {
	return nil, fmt.Errorf("cluster of flavor 'BOH' doesn't have a master")
}

// Start starts the cluster named 'name'
// In BOH, cluster state is logical, there is no way to stop a BOH cluster (except by stopping the hosts)
func (c *Cluster) Start() error {
	state, err := c.ForceGetState()
	if err != nil {
		return err
	}
	if state == ClusterState.Stopped {
		c.Common.State = ClusterState.Nominal
		return c.updateMetadata()
	}
	if state != ClusterState.Nominal && state != ClusterState.Degraded {
		return fmt.Errorf("failed to start cluster because of it's current state: %s", state.String())
	}
	return nil
}

// Stop stops the cluster is its current state is compatible
func (c *Cluster) Stop() error {
	state, _ := c.ForceGetState()
	if state == ClusterState.Nominal || state == ClusterState.Degraded {
		return c.Stop()
	}
	if state != ClusterState.Stopped {
		return fmt.Errorf("failed to stop cluster because of it's current state: %s", state.String())
	}
	return nil
}

//GetState returns the current state of the cluster
func (c *Cluster) GetState() (ClusterState.Enum, error) {
	now := time.Now()
	if now.After(c.lastStateCollection.Add(c.manager.StateCollectInterval)) {
		return c.ForceGetState()
	}
	return c.Common.State, nil
}

// ForceGetState returns the current state of the cluster
// Does nothing currently...
func (c *Cluster) ForceGetState() (ClusterState.Enum, error) {
	c.Common.State = ClusterState.Nominal
	c.lastStateCollection = time.Now()
	c.updateMetadata()
	return c.Common.State, nil
}

// AddNode adds one node
func (c *Cluster) AddNode(public bool, req *pb.HostDefinition) (string, error) {
	hosts, err := c.AddNodes(1, public, req)
	if err != nil {
		return "", err
	}
	return hosts[0], nil
}

// AddNodes adds <count> nodes
func (c *Cluster) AddNodes(count int, public bool, req *pb.HostDefinition) ([]string, error) {
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
	for i := 0; i < count; i++ {
		r := make(chan string)
		results = append(results, r)
		d := make(chan error)
		dones = append(dones, d)
		go c.asyncCreateNode(i+1, nodeType, req, r, d)
	}
	for i := range dones {
		hostID := <-results[i]
		if hostID != "" {
			hosts = append(hosts, hostID)
		}
		err := <-dones[i]
		if err != nil {
			errors = append(errors, err.Error())
		}

	}
	if len(errors) > 0 {
		if len(hosts) > 0 {
			for _, hostID := range hosts {
				brokerclient.New().Host.Delete(hostID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
			}
		}
		return nil, fmt.Errorf("errors occured on node addition: %s", strings.Join(errors, "\n"))
	}

	return hosts, nil
}

// DeleteLastNode deletes the last Agent node added
func (c *Cluster) DeleteLastNode(public bool) error {
	var hostID string

	if public {
		hostID = c.Common.PublicNodeIDs[len(c.Common.PublicNodeIDs)-1]
	} else {
		hostID = c.Common.PrivateNodeIDs[len(c.Common.PrivateNodeIDs)-1]
	}
	err := brokerclient.New().Host.Delete(hostID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return nil
	}

	if public {
		c.Common.PublicNodeIDs = c.Common.PublicNodeIDs[:len(c.Common.PublicNodeIDs)-1]
	} else {
		c.Common.PrivateNodeIDs = c.Common.PrivateNodeIDs[:len(c.Common.PrivateNodeIDs)-1]
	}
	c.updateMetadata()
	return nil
}

// DeleteSpecificNode deletes the node specified by its ID
func (c *Cluster) DeleteSpecificNode(hostID string) error {
	var foundInPrivate bool
	foundInPublic, idx := contains(c.Common.PublicNodeIDs, hostID)
	if !foundInPublic {
		foundInPrivate, idx = contains(c.Common.PrivateNodeIDs, hostID)
	}
	if !foundInPublic && !foundInPrivate {
		return fmt.Errorf("host '%s' isn't a registered Node of the Cluster '%s'", hostID, c.Common.Name)
	}

	err := brokerclient.New().Host.Delete(hostID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return err
	}

	if foundInPublic {
		c.Common.PublicNodeIDs = append(c.Common.PublicNodeIDs[:idx], c.Common.PublicNodeIDs[idx+1:]...)
	} else {
		c.Common.PrivateNodeIDs = append(c.Common.PrivateNodeIDs[:idx], c.Common.PrivateNodeIDs[idx+1:]...)
	}
	return nil
}

// ListMasterIDs lists the master nodes in the cluster
// No masters in BOH...
func (c *Cluster) ListMasterIDs() []string {
	return []string{c.manager.MasterID}
}

// ListMasterIPs lists the master nodes in the cluster
// No masters in BOH...
func (c *Cluster) ListMasterIPs() []string {
	return []string{c.manager.MasterIP}
}

// ListNodeIDs lists the IDs of the nodes in the cluster
func (c *Cluster) ListNodeIDs(public bool) []string {
	if public {
		return c.Common.PublicNodeIDs
	}
	return c.Common.PrivateNodeIDs
}

// ListNodeIPs lists the IPs of the nodes in the cluster
func (c *Cluster) ListNodeIPs(public bool) []string {
	if public {
		return c.manager.PublicNodeIPs
	}
	return c.manager.PrivateNodeIPs
}

// GetNode returns a node based on its ID
func (c *Cluster) GetNode(hostID string) (*pb.Host, error) {
	found, _ := contains(c.Common.PublicNodeIDs, hostID)
	if !found {
		found, _ = contains(c.Common.PrivateNodeIDs, hostID)
	}
	if !found {
		return nil, fmt.Errorf("failed to find node '%s' in cluster '%s'", hostID, c.Common.Name)
	}
	return brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
}

func contains(list []string, hostID string) (bool, int) {
	var idx int
	found := false
	for i, v := range list {
		if v == hostID {
			found = true
			idx = i
			break
		}
	}
	return found, idx
}

// SearchNode tells if an host ID corresponds to a node of the cluster
func (c *Cluster) SearchNode(hostID string, public bool) bool {
	found, _ := contains(c.Common.PublicNodeIDs, hostID)
	if !found {
		found, _ = contains(c.Common.PrivateNodeIDs, hostID)
	}
	return found
}

// GetConfig returns the public properties of the cluster
func (c *Cluster) GetConfig() clusterapi.Cluster {
	return *c.Common
}

// FindAvailableMaster returns the ID of the first master available for execution
func (c *Cluster) FindAvailableMaster() (string, error) {
	var masterID string
	for _, masterID = range c.manager.MasterIDs {
		err := provideruse.WaitSSHServerReady(c.provider, masterID, 2*time.Minute)
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
			return "", err
		}
		break
	}
	if masterID == "" {
		return "", fmt.Errorf("failed to find available master")
	}
	return masterID, nil
}

// FindAvailableNode returns the ID of a node available
func (c *Cluster) FindAvailableNode(public bool) (string, error) {
	var hostID string
	for _, hostID = range c.ListNodeIDs(public) {
		err := provideruse.WaitSSHServerReady(c.provider, hostID, 2*time.Minute)
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
		}
		break
	}
	if hostID == "" {
		return "", fmt.Errorf("failed to find available node")
	}
	return hostID, nil
}

// updateMetadata writes cluster config in Object Storage
func (c *Cluster) updateMetadata() error {
	if c.metadata == nil {
		m, err := metadata.NewCluster()
		if err != nil {
			return err
		}
		m.Carry(c.Common)
		c.metadata = m
	}
	return c.metadata.Write()
}

// Delete destroys everything related to the infrastructure built for the cluster
func (c *Cluster) Delete() error {
	if c.metadata == nil {
		return fmt.Errorf("no metadata found for this cluster")
	}

	// Updates metadata
	c.Common.State = ClusterState.Removed
	err := c.metadata.Write()
	if err != nil {
		return err
	}

	broker := brokerclient.New()

	// Deletes the public nodes
	for _, n := range c.Common.PublicNodeIDs {
		err := broker.Host.Delete(n, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return err
		}
	}

	// Deletes the private nodes
	for _, n := range c.Common.PrivateNodeIDs {
		err := broker.Host.Delete(n, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return err
		}
	}

	// Deletes the network and gateway
	err = broker.Network.Delete(c.Common.NetworkID, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return err
	}

	// Deletes the metadata
	err = c.metadata.Delete()
	if err != nil {
		return nil
	}
	c.metadata = nil
	c.Common = nil
	c.manager = nil
	return nil
}

func init() {
	gob.Register(Cluster{})
	gob.Register(managerData{})
}
