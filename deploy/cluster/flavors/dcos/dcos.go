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

package dcos

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/AdditionalInfo"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Flavor"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/NodeType"
	"github.com/CS-SI/SafeScale/deploy/cluster/components"
	"github.com/CS-SI/SafeScale/deploy/cluster/flavors/dcos/ErrorCode"
	"github.com/CS-SI/SafeScale/deploy/cluster/metadata"

	"github.com/CS-SI/SafeScale/providers"
	providerapi "github.com/CS-SI/SafeScale/providers/api"
	providermetadata "github.com/CS-SI/SafeScale/providers/metadata"

	"github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/brokeruse"
	"github.com/CS-SI/SafeScale/utils/provideruse"
	"github.com/CS-SI/SafeScale/utils/retry"

	pb "github.com/CS-SI/SafeScale/broker"
)

//go:generate rice embed-go

const (
	dcosVersion string = "1.11.1"

	timeoutCtxHost = 10 * time.Minute

	shortTimeoutSSH = time.Minute
	longTimeoutSSH  = 5 * time.Minute

	bootstrapHTTPPort = 10080

	tempFolder = "/var/tmp/"

	centos = "CentOS 7.3"
)

var (
	// templateBox is the rice box to use in this package
	templateBoxes = map[string]*rice.Box{}

	// commonToolsContent contains the script containing commons tools
	commonToolsContent *string
	//installCommonRequirementsContent contains the script to install/configure common components
	installCommonRequirementsContent *string

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

// managerData defines the data needed by DCOS we want to keep in Object Storage
type managerData struct {
	// BootstrapID is the identifier of the host acting as bootstrap/upgrade server
	BootstrapID string

	// BootstrapIP contains the IP of the bootstrap server reachable by all master and agents
	BootstrapIP string

	// MasterIDs is a slice of hostIDs of the master
	MasterIDs []string

	// MasterIPs contains a list of IP of the master servers
	MasterIPs []string

	// PublicNodeIPs contains a list of IP of the Public Agent nodes
	PublicNodeIPs []string

	// PrivateAvgentIPs contains a list of IP of the Private Agent Nodes
	PrivateNodeIPs []string

	// StateCollectInterval in seconds
	StateCollectInterval time.Duration

	// PrivateLastIndex
	MasterLastIndex int

	// PrivateLastIndex
	PrivateLastIndex int

	// PublicLastIndex
	PublicLastIndex int
}

// Cluster is the object describing a cluster based on DCOS
type Cluster struct {
	// common cluster data
	Common *clusterapi.Cluster

	// manager is a pointer to AdditionalInfo of type Flavor stored in Common, corresponding to
	// DCOS data wanted in Object Storage
	manager *managerData

	// lastStateCollect contains the date of the last state collection
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

// GetAdditionalInfo returns additional info corresponding to 'ctx'
func (c *Cluster) GetAdditionalInfo(ctx AdditionalInfo.Enum) interface{} {
	return c.GetAdditionalInfo(ctx)
}

// CountNodes returns the number of public or private nodes in the cluster
func (c *Cluster) CountNodes(public bool) uint {
	return c.Common.CountNodes(public)
}

// Load loads the internals of an existing cluster from metadata
func Load(data *metadata.Cluster) (clusterapi.ClusterAPI, error) {
	svc, err := provideruse.GetProviderService()
	if err != nil {
		return nil, err
	}

	common := data.Get()
	var manager managerData
	anon := common.GetAdditionalInfo(AdditionalInfo.Flavor)
	if anon != nil {
		manager = anon.(managerData)
	}
	instance := &Cluster{
		Common:   common,
		manager:  &manager,
		metadata: data,
		provider: svc,
	}
	return instance, nil
}

// Create creates the necessary infrastructure of cluster
func Create(req clusterapi.Request) (clusterapi.ClusterAPI, error) {
	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password for user cladm: %s", err.Error())
	}

	var nodesDef pb.HostDefinition
	if req.NodesDef != nil {
		nodesDef = *req.NodesDef
	} else {
		nodesDef = pb.HostDefinition{
			CPUNumber: 4,
			RAM:       15.0,
			Disk:      100,
			ImageID:   centos,
		}
	}
	if nodesDef.ImageID != centos {
		fmt.Printf("cluster Flavor DCOS enforces the use of %s distribution. OS %s ignored.\n", centos, nodesDef.ImageID)
		nodesDef.ImageID = centos
	}

	// Creates network
	log.Printf("Creating Network 'net-%s'", req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	network, err := brokeruse.CreateNetwork(networkName, req.CIDR, &pb.GatewayDefinition{
		CPU:     4,
		RAM:     32.0,
		Disk:    120,
		ImageID: centos,
	})
	if err != nil {
		err = fmt.Errorf("Failed to create Network '%s': %s", networkName, err.Error())
		return nil, err
	}
	req.NetworkID = network.ID

	// Saving cluster parameters, with status 'Creating'
	var (
		instance                                       Cluster
		manager                                        *managerData
		masterCount, privateNodeCount, retcode         int
		kp                                             *providerapi.KeyPair
		kpName                                         string
		gw                                             *providerapi.Host
		m                                              *providermetadata.Gateway
		found                                          bool
		bootstrapChannel, mastersChannel, nodesChannel chan error
		bootstrapStatus, mastersStatus, nodesStatus    error
	)

	svc, err := provideruse.GetProviderService()
	if err != nil {
		goto cleanNetwork
	}

	// Create a KeyPair for the cluster
	kpName = "cluster_" + req.Name + "_key"
	svc.DeleteKeyPair(kpName)
	kp, err = svc.CreateKeyPair(kpName)
	if err != nil {
		err = fmt.Errorf("failed to create Key Pair: %s", err.Error())
		goto cleanNetwork
	}
	defer svc.DeleteKeyPair(kpName)

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
	manager = &managerData{
		BootstrapID: gw.ID,
		BootstrapIP: gw.PrivateIPsV4[0],
	}
	instance = Cluster{
		Common: &clusterapi.Cluster{
			Name:          req.Name,
			CIDR:          req.CIDR,
			Flavor:        Flavor.DCOS,
			State:         ClusterState.Creating,
			Complexity:    req.Complexity,
			Tenant:        req.Tenant,
			NetworkID:     req.NetworkID,
			Keypair:       kp,
			AdminPassword: cladmPassword,
			PublicIP:      gw.GetAccessIP(),
			NodesDef:      &nodesDef,
			AdditionalInfo: map[AdditionalInfo.Enum]interface{}{
				AdditionalInfo.Flavor: manager,
			},
		},
		manager:  manager,
		provider: svc,
	}
	err = instance.updateMetadata()
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanNetwork
	}

	switch req.Complexity {
	case Complexity.Dev:
		masterCount = 1
		privateNodeCount = 1
	case Complexity.Normal:
		masterCount = 3
		privateNodeCount = 3
	case Complexity.Volume:
		masterCount = 5
		privateNodeCount = 3
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Step 1: starts masters and nodes creations
	bootstrapChannel = make(chan error)
	go instance.asyncPrepareBootstrap(bootstrapChannel)

	mastersChannel = make(chan error)
	go instance.asyncCreateMasters(masterCount, mastersChannel)

	nodesChannel = make(chan error)
	go instance.asyncCreateNodes(privateNodeCount, false, &nodesDef, nodesChannel)

	// Step 2: awaits masters creation and bootstrap configuration coroutines
	bootstrapStatus = <-bootstrapChannel
	mastersStatus = <-mastersChannel

	// Step 3: starts bootstrap configuration, if masters have been created
	//         successfully
	if bootstrapStatus == nil && mastersStatus == nil {
		bootstrapChannel = make(chan error)
		go instance.asyncConfigureBootstrap(bootstrapChannel)
		bootstrapStatus = <-bootstrapChannel
	}

	if bootstrapStatus == nil && mastersStatus == nil {
		mastersChannel = make(chan error)
		go instance.asyncConfigureMasters(mastersChannel)
	}

	// Starts nodes configuration, if all masters and nodes
	// have been created and bootstrap has been configured with success
	nodesStatus = <-nodesChannel
	if bootstrapStatus == nil && mastersStatus == nil && nodesStatus == nil {
		nodesChannel = make(chan error)
		go instance.asyncConfigurePrivateNodes(nodesChannel)
		nodesStatus = <-nodesChannel
	}

	if bootstrapStatus == nil && mastersStatus == nil {
		mastersStatus = <-mastersChannel
	}

	if bootstrapStatus != nil {
		err = bootstrapStatus
		goto cleanNodes
	}
	if mastersStatus != nil {
		err = mastersStatus
		goto cleanNodes
	}
	if nodesStatus != nil {
		err = nodesStatus
		goto cleanNodes
	}

	// Cluster created and configured successfully, saving again to Object Storage
	instance.Common.State = ClusterState.Created
	err = instance.updateMetadata()
	if err != nil {
		goto cleanMasters
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
	// If DCOS is ready, install Kubernetes
	retcode, err = instance.installKubernetes()
	if err != nil {
		goto cleanNodes
	}
	if retcode != 0 {
		err = fmt.Errorf("failed to install Kubernetes: retcode=%d", retcode)
	}
	return &instance, nil

cleanNodes:
	if !req.KeepOnFailure {
		for _, id := range instance.Common.PublicNodeIDs {
			brokeruse.DeleteHost(id)
		}
		for _, id := range instance.Common.PrivateNodeIDs {
			brokeruse.DeleteHost(id)
		}
	}
cleanMasters:
	if !req.KeepOnFailure {
		for _, id := range instance.manager.MasterIDs {
			brokeruse.DeleteHost(id)
		}
	}
cleanNetwork:
	if !req.KeepOnFailure {
		brokeruse.DeleteNetwork(instance.Common.NetworkID)
		instance.metadata.Delete()
	}
	return nil, err
}

func (c *Cluster) asyncCreateNodes(count int, public bool, def *pb.HostDefinition, done chan error) {
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
	fmt.Printf("Creating %d DCOS %s Node%s...\n", count, nodeTypeStr, countS)

	var dones []chan error
	var results []chan string
	for i := 1; i <= count; i++ {
		d := make(chan error)
		dones = append(dones, d)
		r := make(chan string)
		results = append(results, r)
		go c.asyncCreateNode(
			i,
			nodeType,
			&pb.HostDefinition{
				CPUNumber: 4,
				RAM:       16.0,
				Disk:      100,
				ImageID:   centos,
			},
			r,
			d)
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
		done <- fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	done <- nil
}

//asyncConfigurePrivateNodes
func (c *Cluster) asyncConfigurePrivateNodes(done chan error) {
	fmt.Println("Configuring DCOS private Nodes...")

	dones := []chan error{}
	for i, hostID := range c.Common.PrivateNodeIDs {
		d := make(chan error)
		dones = append(dones, d)
		go c.asyncConfigureNode(i+1, hostID, NodeType.PrivateNode, d)
	}

	var state error
	var errors []string
	for i := range dones {
		state = <-dones[i]
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		done <- fmt.Errorf(strings.Join(errors, "\n"))
	} else {
		done <- nil
	}
}

// asyncCreateMasters
// Intended to be used as goroutine
func (c *Cluster) asyncCreateMasters(count int, done chan error) {
	var countS string
	if count > 1 {
		countS = "s"
	}
	fmt.Printf("Creating %d DCOS Master server%s...\n", count, countS)

	var dones []chan error

	for i := 1; i <= count; i++ {
		d := make(chan error)
		dones = append(dones, d)
		go c.asyncCreateMaster(i, d)
	}
	var state error
	var errors []string
	for i := range dones {
		state = <-dones[i]
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		done <- fmt.Errorf(strings.Join(errors, "\n"))
		return
	}
	done <- nil
}

// asyncConfigureMasters configure masters
func (c *Cluster) asyncConfigureMasters(done chan error) {
	fmt.Println("Configuring DCOS masters...")

	dones := []chan error{}
	for i, hostID := range c.manager.MasterIDs {
		d := make(chan error)
		dones = append(dones, d)
		go c.asyncConfigureMaster(i+1, hostID, d)
	}

	var state error
	var errors []string
	for i := range dones {
		state = <-dones[i]
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		done <- fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	done <- nil
}

// createAndConfigureNode creates and configure a Node
func (c *Cluster) createAndConfigureNode(public bool, req *pb.HostDefinition) (string, error) {
	var nodeType NodeType.Enum
	if public {
		nodeType = NodeType.PublicNode
	} else {
		nodeType = NodeType.PrivateNode
	}
	if c.Common.State != ClusterState.Created && c.Common.State != ClusterState.Nominal {
		return "", fmt.Errorf("The DCOS flavor of Cluster needs to be at least in state 'Created' to allow node addition.")
	}

	done := make(chan error)
	result := make(chan string)
	go c.asyncCreateNode(1, nodeType, req, result, done)
	hostID := <-result
	err := <-done
	if err != nil {
		return "", err
	}
	close(done)
	done = make(chan error)
	go c.asyncConfigureNode(1, hostID, nodeType, done)
	err = <-done
	if err != nil {
		return "", err
	}
	return hostID, nil
}

// asyncCreateMaster adds a master node
func (c *Cluster) asyncCreateMaster(index int, done chan error) {
	log.Printf("[Masters: #%d] starting creation...\n", index)

	name, err := c.buildHostname("master", NodeType.Master)
	if err != nil {
		log.Printf("[Masters: #%d] creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to create Master server %d: %s", index, err.Error())
		return
	}

	masterHost, err := brokeruse.CreateHost(&pb.HostDefinition{
		Name:      name,
		CPUNumber: 4,
		RAM:       15.0,
		Disk:      60,
		ImageID:   centos,
		Network:   c.Common.NetworkID,
		Public:    false,
	})
	if err != nil {
		log.Printf("[Masters: #%d] creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to create Master server %d: %s", index, err.Error())
		return
	}

	// Registers the new Master in the cluster struct
	c.metadata.Acquire()
	c.manager.MasterIDs = append(c.manager.MasterIDs, masterHost.ID)
	c.manager.MasterIPs = append(c.manager.MasterIPs, masterHost.PRIVATE_IP)

	// Update cluster definition in Object Storage
	err = c.updateMetadata()
	if err != nil {
		// Object Storage failed, removes the ID we just added to the cluster struct
		c.manager.MasterIDs = c.manager.MasterIDs[:len(c.manager.MasterIDs)-1]
		c.manager.MasterIPs = c.manager.MasterIPs[:len(c.manager.MasterIPs)-1]
		c.metadata.Release()
		brokeruse.DeleteHost(masterHost.ID)

		log.Printf("[Masters: #%d] creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to update Cluster definition: %s", err.Error())
		return
	}
	c.metadata.Release()

	// Installs DCOS requirements...
	ssh, err := c.provider.GetSSHConfig(masterHost.ID)
	if err != nil {
		done <- err
		return
	}
	err = ssh.WaitServerReady(longTimeoutSSH)
	if err != nil {
		done <- err
		return
	}
	retcode, _, err := c.executeScript(ssh, "dcos_install_master.sh", map[string]interface{}{})
	if err != nil {
		log.Printf("[Masters: #%d (%s)] configuration failed: %s\n", index, masterHost.ID, err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[Masters: #%d (%s)] installation failed:\nretcode=%d (%s)", index, masterHost.ID, errcode, errcode.String())
			done <- fmt.Errorf("scripted Master installation failed with error code %d (%s)", errcode, errcode.String())
		} else {
			log.Printf("[Masters: #%d (%s)] installation failed:\nretcode=%d", index, masterHost.ID, retcode)
			done <- fmt.Errorf("scripted Master installation failed with error code %d", retcode)
		}
		return
	}

	log.Printf("[Masters: #%d] creation successful", index)
	done <- nil
}

// asyncConfigureMaster configure DCOS on master
func (c *Cluster) asyncConfigureMaster(index int, masterID string, done chan error) {
	log.Printf("[Masters: #%d (%s)] starting configuration...\n", index, masterID)

	ssh, err := c.provider.GetSSHConfig(masterID)
	if err != nil {
		done <- err
		return
	}
	err = ssh.WaitServerReady(longTimeoutSSH)
	if err != nil {
		done <- err
		return
	}
	retcode, _, err := c.executeScript(ssh, "dcos_configure_master.sh", map[string]interface{}{
		"BootstrapIP":   c.manager.BootstrapIP,
		"BootstrapPort": bootstrapHTTPPort,
		"ClusterName":   c.Common.Name,
		"MasterIndex":   index,
		"CladmPassword": c.Common.AdminPassword, // TODO: strong auto generated password
		"Host":          ssh.Host,
	})
	if err != nil {
		log.Printf("[Masters: #%d (%s)] configuration failed: %s\n", index, masterID, err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[Masters: #%d (%s)] configuration failed:\nretcode:%d (%s)", index, masterID, errcode, errcode.String())
			done <- fmt.Errorf("scripted Master configuration failed with error code %d (%s)", errcode, errcode.String())
		} else {
			log.Printf("[Masters: #%d (%s)] configuration failed:\nretcode=%d", index, masterID, retcode)
			done <- fmt.Errorf("scripted Master configuration failed with error code %d", retcode)
		}
		return
	}

	log.Printf("[Masters: #%d (%s)] configuration successful\n", index, masterID)
	done <- nil
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
	req.ImageID = centos
	node, err := brokeruse.CreateHost(req)
	if err != nil {
		log.Printf("[Nodes: %s #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}

	// Registers the new Agent in the cluster struct
	c.metadata.Acquire()
	// TODO:reload the metadata content to be sure to update the last revision of it

	if nodeType == NodeType.PublicNode {
		c.Common.PublicNodeIDs = append(c.Common.PublicNodeIDs, node.ID)
		c.manager.PublicNodeIPs = append(c.manager.PublicNodeIPs, node.PRIVATE_IP)
	} else {
		c.Common.PrivateNodeIDs = append(c.Common.PrivateNodeIDs, node.ID)
		c.manager.PrivateNodeIPs = append(c.manager.PrivateNodeIPs, node.PRIVATE_IP)
	}

	// Update cluster definition in Object Storage
	err = c.metadata.Write()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		if nodeType == NodeType.PublicNode {
			c.Common.PublicNodeIDs = c.Common.PublicNodeIDs[:len(c.Common.PublicNodeIDs)-1]
			c.manager.PublicNodeIPs = c.manager.PublicNodeIPs[:len(c.manager.PublicNodeIPs)-1]
		} else {
			c.Common.PrivateNodeIDs = c.Common.PrivateNodeIDs[:len(c.Common.PrivateNodeIDs)-1]
			c.manager.PrivateNodeIPs = c.manager.PrivateNodeIPs[:len(c.manager.PrivateNodeIPs)-1]
		}
		brokeruse.DeleteHost(node.ID)
		c.metadata.Release()
		log.Printf("[Nodes: %s #%d] creation failed: %s", nodeTypeStr, index, err.Error())
		result <- ""
		done <- fmt.Errorf("failed to update Cluster configuration: %s", err.Error())
		return
	}
	c.metadata.Release()

	// Installs DCOS requirements
	ssh, err := c.provider.GetSSHConfig(node.ID)
	if err != nil {
		result <- ""
		done <- err
		return
	}
	err = ssh.WaitServerReady(longTimeoutSSH)
	if err != nil {
		result <- ""
		done <- err
		return
	}
	retcode, _, err := c.executeScript(ssh, "dcos_install_node.sh", map[string]interface{}{
		"BootstrapIP":   c.manager.BootstrapIP,
		"BootstrapPort": bootstrapHTTPPort,
	})
	if err != nil {
		log.Printf("[Nodes: %s #%d (%s)] installation failed: %s\n", nodeTypeStr, index, node.ID, err.Error())
		result <- ""
		done <- err
		return
	}
	if retcode != 0 {
		result <- ""
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[Nodes: %s #%d (%s)] installation failed: retcode: %d (%s)", nodeTypeStr, index, node.ID, errcode, errcode.String())
			done <- fmt.Errorf("scripted Node configuration failed with error code %d (%s)", errcode, errcode.String())
		} else {
			log.Printf("[Nodes: %s #%d (%s)] installation failed: retcode=%d", nodeTypeStr, index, node.ID, retcode)
			done <- fmt.Errorf("scripted Agent configuration failed with error code %d", retcode)
		}
		return
	}

	log.Printf("[Nodes: %s #%d] creation successful\n", nodeTypeStr, index)
	result <- node.ID
	done <- nil
}

// asyncConfigureNode installs and configure DCOS agent on tarGetHost
func (c *Cluster) asyncConfigureNode(index int, nodeID string, nodeType NodeType.Enum, done chan error) {
	var publicStr string
	var nodeTypeStr string
	if nodeType == NodeType.PublicNode {
		nodeTypeStr = "public"
		publicStr = "yes"
	} else {
		nodeTypeStr = "private"
		publicStr = "no"
	}

	log.Printf("[Nodes: %s #%d (%s)] starting configuration...\n", nodeTypeStr, index, nodeID)

	ssh, err := c.provider.GetSSHConfig(nodeID)
	if err != nil {
		done <- err
		return
	}
	err = ssh.WaitServerReady(shortTimeoutSSH)
	if err != nil {
		done <- err
		return
	}
	retcode, _, err := c.executeScript(ssh, "dcos_configure_node.sh", map[string]interface{}{
		"PublicNode":    publicStr,
		"BootstrapIP":   c.manager.BootstrapIP,
		"BootstrapPort": bootstrapHTTPPort,
	})
	if err != nil {
		log.Printf("[Nodes: %s #%d (%s)] configuration failed: %s\n", nodeTypeStr, index, nodeID, err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[Nodes: %s #%d (%s)] configuration failed: retcode: %d (%s)", nodeTypeStr, index, nodeID, errcode, errcode.String())
			done <- fmt.Errorf("scripted Agent configuration failed with error code %d (%s)", errcode, errcode.String())
		} else {
			log.Printf("[Nodes: %s #%d (%s)] configuration failed: retcode=%d", nodeTypeStr, index, nodeID, retcode)
			done <- fmt.Errorf("scripted Agent configuration failed with error code %d", retcode)
		}
		return
	}

	log.Printf("[Nodes: %s #%d (%s)] configuration successful\n", nodeTypeStr, index, nodeID)
	done <- nil
}

// asyncPrepareBootstrap prepares the bootstrap
func (c *Cluster) asyncPrepareBootstrap(done chan error) {
	log.Printf("[Bootstrap] starting preparation...")

	ssh, err := c.provider.GetSSHConfig(c.manager.BootstrapID)
	if err != nil {
		done <- err
		return
	}
	err = ssh.WaitServerReady(longTimeoutSSH)
	if err != nil {
		done <- err
		return
	}
	retcode, _, err := c.executeScript(ssh, "dcos_prepare_bootstrap.sh", map[string]interface{}{
		"DCOSVersion": dcosVersion,
	})
	if err != nil {
		log.Printf("[Bootstrap] preparation failed: %s", err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[Bootstrap] preparation failed: retcode=%d (%s)", errcode, errcode.String())
			done <- fmt.Errorf("scripted Bootstrap preparation failed with error code %d (%s)", errcode, errcode.String())
		} else {
			log.Printf("[Bootstrap] preparation failed: retcode=%d", retcode)
			done <- fmt.Errorf("scripted Bootstrap preparation failed with error code %d", retcode)
		}
		return
	}

	log.Printf("[Bootstrap] preparation successful")
	done <- nil
}

// asyncConfigureBootstrap prepares the bootstrap
func (c *Cluster) asyncConfigureBootstrap(done chan error) {
	log.Printf("[Bootstrap] starting configuration...")

	ssh, err := c.provider.GetSSHConfig(c.manager.BootstrapID)
	if err != nil {
		done <- err
		return
	}
	err = ssh.WaitServerReady(shortTimeoutSSH)
	if err != nil {
		done <- err
		return
	}
	err = c.uploadDockerImageBuildScripts(ssh)
	if err != nil {
		done <- fmt.Errorf("failed to build configuration script: %s", err.Error())
		return
	}

	var dnsServers []string
	cfg, err := c.provider.GetCfgOpts()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	retcode, _, err := c.executeScript(ssh, "dcos_configure_bootstrap.sh", map[string]interface{}{
		"BootstrapIP":   c.manager.BootstrapIP,
		"BootstrapPort": bootstrapHTTPPort,
		"ClusterName":   c.Common.Name,
		"MasterIPs":     c.manager.MasterIPs,
		"DNSServerIPs":  dnsServers,
		"SSHPrivateKey": c.Common.Keypair.PrivateKey,
		"SSHPublicKey":  c.Common.Keypair.PublicKey,
	})
	if err != nil {
		log.Printf("[Bootstrap] configuration failed: %s", err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[Bootstrap] configuration failed:\nretcode=%d (%s)", errcode, errcode.String())
			done <- fmt.Errorf("scripted Bootstrap configuration failed with error code %d (%s)", errcode, errcode.String())
		} else {
			log.Printf("[Bootstrap] configuration failed:\nretcode=%d", retcode)
			done <- fmt.Errorf("scripted Bootstrap configuration failed with error code %d", retcode)
		}
		return
	}

	log.Printf("[Bootstrap] configuration successful")
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
	case NodeType.Master:
		coreName = core
	default:
		return "", fmt.Errorf("Invalid Node Type '%v'", nodeType)
	}

	c.metadata.Acquire()
	// TODO: Reload the metadata content to be sure to update the last revision of it
	c.metadata.Reload()
	switch nodeType {
	case NodeType.PublicNode:
		c.manager.PublicLastIndex++
		index = c.manager.PublicLastIndex
	case NodeType.PrivateNode:
		c.manager.PrivateLastIndex++
		index = c.manager.PrivateLastIndex
	case NodeType.Master:
		c.manager.MasterLastIndex++
		index = c.manager.MasterLastIndex
	}
	// Update cluster definition in Object Storage
	err := c.metadata.Write()
	if err != nil {
		c.metadata.Release()
		return "", err
	}
	c.metadata.Release()
	return c.Common.Name + "-" + coreName + "-" + strconv.Itoa(index), nil
}

// GetName returns the name of the cluster
func (c *Cluster) GetName() string {
	return c.Common.Name
}

// getDCOSTemplateBox
func getDCOSTemplateBox() (*rice.Box, error) {
	var b *rice.Box
	var found bool
	var err error
	if b, found = templateBoxes["../dcos/scripts"]; !found {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../dcos/scripts")
		if err != nil {
			return nil, err
		}
		templateBoxes["../dcos/scripts"] = b
	}
	return b, nil
}

// getSystemTemplateBox
func getSystemTemplateBox() (*rice.Box, error) {
	var b *rice.Box
	var found bool
	var err error
	if b, found = templateBoxes["../../../../system/scripts"]; !found {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../../../../system/scripts")
		if err != nil {
			return nil, err
		}
		templateBoxes["../../../../system/scripts"] = b
	}
	return b, nil
}

// getCommonTools returns the string corresponding to the script common_tools.sh
// which defines variables and functions useable everywhere
func (c *Cluster) getCommonTools() (*string, error) {
	if commonToolsContent == nil {
		// find the rice.Box
		b, err := getSystemTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := b.String("common_tools.sh")
		if err != nil {
			return nil, fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := template.New("common_tools").Funcs(funcMap).Parse(tmplString)
		if err != nil {
			return nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{})
		if err != nil {
			return nil, fmt.Errorf("error realizing script template: %s", err.Error())
		}
		result := dataBuffer.String()
		commonToolsContent = &result
	}
	return commonToolsContent, nil
}

// getInstallCommonRequirements returns the string corresponding to the script dcos_install_node_commons.sh
// which installs common components (docker in particular)
func (c *Cluster) getInstallCommonRequirements() (*string, error) {
	if installCommonRequirementsContent == nil {
		// find the rice.Box
		b, err := getDCOSTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := b.String("dcos_install_requirements.sh")
		if err != nil {
			return nil, fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := template.New("install_requirements").Funcs(funcMap).Parse(tmplString)
		if err != nil {
			return nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{
			"CIDR":          c.Common.CIDR,
			"CladmPassword": c.Common.AdminPassword,
		})
		if err != nil {
			return nil, fmt.Errorf("error realizing script template: %s", err.Error())
		}
		result := dataBuffer.String()
		installCommonRequirementsContent = &result
	}
	return installCommonRequirementsContent, nil
}

// GetMasters returns a list of masters
func (c *Cluster) GetMasters() ([]string, error) {
	return c.manager.MasterIDs, nil
}

// Start starts the cluster named 'name'
// In BOH, cluster state is logical, there is no way to stop a BOH cluster (except by stopping the hosts)
func (c *Cluster) Start() error {
	state, err := c.ForceGetState()
	if err != nil {
		return err
	}
	if state == ClusterState.Stopped {
		// 1st starts the masters
		// 2nd start the private nodes
		// 2rd start the public nodes
		// 4th update metadata
		//return c.updateMetadata()
		return fmt.Errorf("dcos.(c *Cluster).Start() not yet implemented")
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

// GetState returns the current state of the cluster
func (c *Cluster) GetState() (ClusterState.Enum, error) {
	now := time.Now()
	if now.After(c.lastStateCollection.Add(c.manager.StateCollectInterval)) {
		return c.ForceGetState()
	}
	return c.Common.State, nil
}

// ForceGetState returns the current state of the cluster
// This method will trigger a effective state collection at each call
func (c *Cluster) ForceGetState() (ClusterState.Enum, error) {
	var retcode int
	var ran bool // Tells if command has been run on remote host
	var out []byte

	cmd := "/opt/mesosphere/bin/dcos-diagnostics --diag"
	for _, id := range c.manager.MasterIDs {
		ssh, err := c.provider.GetSSHConfig(id)
		if err != nil {
			continue
		}
		err = ssh.WaitServerReady(shortTimeoutSSH)
		if err != nil {
			continue
		}
		cmdResult, err := ssh.SudoCommand(cmd)
		if err != nil {
			continue
		}
		ran = true
		out, err = cmdResult.CombinedOutput()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				if status, ok := ee.Sys().(syscall.WaitStatus); ok {
					retcode = status.ExitStatus()
					break
				}
			} else {
				continue
			}
		}
	}
	c.lastStateCollection = time.Now()
	var err error
	if ran {
		switch retcode {
		case 0:
			c.Common.State = ClusterState.Nominal
		default:
			c.Common.State = ClusterState.Error
			err = fmt.Errorf(string(out))
		}
	}
	c.lastStateCollection = time.Now()
	c.updateMetadata()
	return c.Common.State, err
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
	if c.Common.State != ClusterState.Created && c.Common.State != ClusterState.Nominal {
		return nil, fmt.Errorf("The DCOS flavor of Cluster needs to be at least in state 'Created' to allow node addition.")
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
		go func(result chan string, done chan error) {
			hostID, err := c.createAndConfigureNode(public, req)
			if err != nil {
				result <- ""
				done <- err
				return
			}
			result <- hostID
			done <- nil
		}(r, d)
	}
	for i := range dones {
		host := <-results[i]
		if host != "" {
			hosts = append(hosts, host)
		}
		err := <-dones[i]
		if err != nil {
			errors = append(errors, err.Error())
		}

	}
	if len(errors) > 0 {
		if len(hosts) > 0 {
			for _, hostID := range hosts {
				brokeruse.DeleteHost(hostID)
			}
		}
		return nil, fmt.Errorf("errors occured on node addition: %s", strings.Join(errors, "\n"))
	}

	return hosts, nil
}

// installKubernetes does the needed to have Kubernetes in DCOS
func (c *Cluster) installKubernetes() (int, error) {
	var options string
	switch c.Common.Complexity {
	case Complexity.Dev:
		options = "dcos_kubernetes_options_dev.conf"
	case Complexity.Normal:
		fallthrough
	case Complexity.Volume:
		options = "dcos_kubernetes_options_prod.conf"
	}

	ssh, err := c.findAvailableMaster()
	if err != nil {
		return 0, err
	}

	optionsPath, err := c.uploadTemplateToFile(ssh, options, options, map[string]interface{}{})
	if err != nil {
		return 0, err
	}
	cmd := fmt.Sprintf("sudo -u cladm -i dcos package install --yes kubernetes --options=%s ; rm -f %s", optionsPath, optionsPath)

	cmdResult, err := ssh.Command(cmd)
	if err != nil {
		return 0, fmt.Errorf("failed to execute command to install Kubernetes: %s", err.Error())
	}
	retcode := 0
	out, err := cmdResult.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				retcode = status.ExitStatus()
			}
		} else {
			return 0, fmt.Errorf("failed to fetch output of Kubernetes installation: %s", err.Error())
		}
	}
	if retcode > 0 {
		return retcode, fmt.Errorf(string(out))
	}
	return 0, nil
}

func (c *Cluster) findAvailableMaster() (*system.SSHConfig, error) {
	var ssh *system.SSHConfig
	var err error
	for _, masterID := range c.manager.MasterIDs {
		ssh, err = c.provider.GetSSHConfig(masterID)
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH config: %s", err.Error())
		}
		err = ssh.WaitServerReady(shortTimeoutSSH)
		if err != nil {
			if _, ok := err.(retry.TimeoutError); ok {
				continue
			}
			return nil, err
		}
		break
	}
	if ssh == nil {
		return nil, fmt.Errorf("failed to find available master")
	}
	return ssh, nil
}

func uploadTemplateAsFile(ssh *system.SSHConfig, name string, path string) error {
	b, err := getDCOSTemplateBox()
	if err != nil {
		return err
	}
	tmplString, err := b.String(name)
	if err != nil {
		return fmt.Errorf("failed to load script template: %s", err.Error())
	}
	err = ssh.UploadString(path, tmplString)
	if err != nil {
		return err
	}
	return nil
}

// installSpark does the needed to have Spark installed in DCOS
func (c *Cluster) installSpark() (int, error) {
	ssh, err := c.findAvailableMaster()
	if err != nil {
		return 0, nil
	}

	cmdResult, err := ssh.Command("sudo -u cladm -i dcos package install spark")
	if err != nil {
		return 0, fmt.Errorf("failed to execute spark package installation: %s", err.Error())
	}
	retcode := 0
	out, err := cmdResult.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				retcode = status.ExitStatus()
			}
		} else {
			return 0, fmt.Errorf("failed to fetch output of spark package installation: %s", err.Error())
		}
	}
	if retcode != 0 {
		return retcode, fmt.Errorf("execution of spark package installation failed: %s", string(out))
	}
	return 0, nil
}

// installElastic does the needed to have Spark installed in DCOS
func (c *Cluster) installElastic() (int, error) {
	ssh, err := c.findAvailableMaster()
	if err != nil {
		return 0, nil
	}

	cmdResult, err := ssh.Command("sudo -u cladm -i dcos package install elastic")
	if err != nil {
		return 0, fmt.Errorf("failed to execute elastic package installation: %s", err.Error())
	}
	retcode := 0
	out, err := cmdResult.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				retcode = status.ExitStatus()
			}
		} else {
			return 0, fmt.Errorf("failed to fetch output of elastic package installation: %s", err.Error())
		}
	}
	if retcode != 0 {
		return retcode, fmt.Errorf("execution of elasticsearch pâckage installation failed: %s", string(out))
	}
	return 0, nil
}

// uploadDockerImageBuildScripts creates the string corresponding to script
// used to prepare Docker images on Bootstrap server
func (c *Cluster) uploadDockerImageBuildScripts(ssh *system.SSHConfig) error {
	_, err := components.UploadBuildScript(ssh, "guacamole", map[string]interface{}{})
	if err != nil {
		return err
	}
	_, err = components.UploadBuildScript(ssh, "proxy", map[string]interface{}{
		"ClusterName": c.Common.Name,
		"DNSDomain":   "",
		"MasterIPs":   c.manager.MasterIPs,
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *Cluster) uploadTemplateToFile(ssh *system.SSHConfig, tmplName string, fileName string, data map[string]interface{}) (string, error) {
	b, err := getDCOSTemplateBox()
	if err != nil {
		return "", err
	}
	tmplString, err := b.String(tmplName)
	if err != nil {
		return "", fmt.Errorf("failed to load template: %s", err.Error())
	}
	tmplCmd, err := template.New(fileName).Funcs(funcMap).Parse(tmplString)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %s", err.Error())
	}
	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, data)
	if err != nil {
		return "", fmt.Errorf("failed to realize template: %s", err.Error())
	}
	cmd := dataBuffer.String()
	remotePath := tempFolder + fileName
	err = ssh.UploadString(remotePath, cmd)
	if err != nil {
		return "", err
	}
	return remotePath, nil
}

// executeScript executes the script template with the parameters on tarGetHost
func (c *Cluster) executeScript(ssh *system.SSHConfig, script string, data map[string]interface{}) (int, *string, error) {
	// Configures CommonTools template var
	commonTools, err := c.getCommonTools()
	if err != nil {
		return 0, nil, err
	}
	data["CommonTools"] = *commonTools

	// Configures InstallCommonRequirements template var
	installCommonRequirements, err := c.getInstallCommonRequirements()
	if err != nil {
		return 0, nil, err
	}
	data["InstallCommonRequirements"] = *installCommonRequirements

	path, err := c.uploadTemplateToFile(ssh, script, script, data)
	if err != nil {
		return 0, nil, err
	}
	cmdResult, err := ssh.SudoCommand(fmt.Sprintf("chmod a+rx %s; %s", path, path))
	//	cmdResult, err := ssh.SudoCommand(fmt.Sprintf("chmod a+rx %s; %s; #rm -f %s", path, path, path))

	if err != nil {
		return 0, nil, fmt.Errorf("failed to execute script '%s': %s", script, err.Error())
	}
	retcode := 0
	out, err := cmdResult.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				retcode = status.ExitStatus()
			}
		} else {
			return 0, nil, fmt.Errorf("failed to fetch output of script '%s': %s", script, err.Error())
		}
	}

	strOut := string(out)
	return retcode, &strOut, nil
}

// DeleteLastNode deletes the last Agent node added
func (c *Cluster) DeleteLastNode(public bool) error {
	var hostID string

	if public {
		hostID = c.Common.PublicNodeIDs[len(c.Common.PublicNodeIDs)-1]
	} else {
		hostID = c.Common.PrivateNodeIDs[len(c.Common.PrivateNodeIDs)-1]
	}
	err := brokeruse.DeleteHost(hostID)
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
func (c *Cluster) DeleteSpecificNode(ID string) error {
	var foundInPrivate bool
	foundInPublic, idx := contains(c.Common.PublicNodeIDs, ID)
	if !foundInPublic {
		foundInPrivate, idx = contains(c.Common.PrivateNodeIDs, ID)
	}
	if !foundInPublic && !foundInPrivate {
		return fmt.Errorf("host ID '%s' isn't a registered Node of the Cluster '%s'", ID, c.Common.Name)
	}

	err := brokeruse.DeleteHost(ID)
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

// ListMasters lists the master nodes in the cluster
func (c *Cluster) ListMasters() ([]*pb.Host, error) {
	return nil, fmt.Errorf("ListMasters not yet implemented")
}

// ListNodes lists the nodes in the cluster
func (c *Cluster) ListNodes(public bool) []string {
	if public {
		return c.Common.PublicNodeIDs
	}
	return c.Common.PrivateNodeIDs
}

// GetNode returns a node based on its ID
func (c *Cluster) GetNode(ID string) (*pb.Host, error) {
	found, _ := contains(c.Common.PublicNodeIDs, ID)
	if !found {
		found, _ = contains(c.Common.PrivateNodeIDs, ID)
	}
	if !found {
		return nil, fmt.Errorf("GetNode not yet implemented")
	}
	return brokeruse.GetHost(ID)
}

// contains ...
func contains(list []string, ID string) (bool, int) {
	var idx int
	found := false
	for i, v := range list {
		if v == ID {
			found = true
			idx = i
			break
		}
	}
	return found, idx
}

// SearchNode tells if an host ID corresponds to a node of the cluster
func (c *Cluster) SearchNode(ID string, public bool) bool {
	found, _ := contains(c.Common.PublicNodeIDs, ID)
	if !found {
		found, _ = contains(c.Common.PrivateNodeIDs, ID)
	}
	return found
}

// GetConfig returns the public properties of the cluster
func (c *Cluster) GetConfig() clusterapi.Cluster {
	return *c.Common
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

	// Deletes the public nodes
	for _, n := range c.Common.PublicNodeIDs {
		err := brokeruse.DeleteHost(n)
		if err != nil {
			return err
		}
	}

	// Deletes the private nodes
	for _, n := range c.Common.PrivateNodeIDs {
		err := brokeruse.DeleteHost(n)
		if err != nil {
			return err
		}
	}

	// Deletes the masters
	for _, n := range c.manager.MasterIDs {
		err := brokeruse.DeleteHost(n)
		if err != nil {
			return err
		}
	}

	// Deletes the network and gateway
	err = brokeruse.DeleteNetwork(c.Common.NetworkID)
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
