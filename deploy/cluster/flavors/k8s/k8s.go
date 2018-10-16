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

package k8s

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"runtime"
	"strconv"
	"strings"
	"time"

	txttmpl "text/template"

	rice "github.com/GeertJohan/go.rice"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Extension"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/NodeType"
	flavortools "github.com/CS-SI/SafeScale/deploy/cluster/flavors/utils"
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

//go:generate rice embed-go

const (
	timeoutCtxHost = 10 * time.Minute

	shortTimeoutSSH = time.Minute
	longTimeoutSSH  = 5 * time.Minute

	tempFolder = "/var/tmp/"

	adminCmd = "sudo -u cladm -i"
)

var (
	// templateBox is the rice box to use in this package
	templateBox *rice.Box

	//installCommonRequirementsContent contains the script to install/configure Core features
	installCommonRequirementsContent *string
)

// managerData defines the data needed by DCOS we want to keep in Object Storage
type managerData struct {
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
	// Core cluster data; serialized in ObjectStorage
	Core *clusterapi.ClusterCore

	// manager is a pointer to Extension of type Flavor stored in Core, corresponding to
	// DCOS data wanted in Object Storage
	manager *managerData

	// lastStateCollect contains the date of the last state collection
	lastStateCollection time.Time

	// metadata of cluster
	metadata *metadata.Cluster

	// provider is a pointer to current provider service instance
	provider *providers.Service

	// gateway ...
	gateway *providerapi.Host
}

// GetNetworkID returns the ID of the network used by the cluster
func (c *Cluster) GetNetworkID() string {
	return c.Core.GetNetworkID()
}

// GetExtension returns additional info corresponding to 'ctx'
func (c *Cluster) GetExtension(ctx Extension.Enum) interface{} {
	return c.Core.GetExtension(ctx)
}

// SetExtension returns additional info corresponding to 'ctx'
func (c *Cluster) SetExtension(ctx Extension.Enum, info interface{}) {
	c.Core.SetExtension(ctx, info)
}

// CountNodes returns the number of public or private nodes in the cluster
func (c *Cluster) CountNodes(public bool) uint {
	return c.Core.CountNodes(public)
}

// Load loads the internals of an existing cluster from metadata
func Load(data *metadata.Cluster) (clusterapi.Cluster, error) {
	svc, err := provideruse.GetProviderService()
	if err != nil {
		return nil, err
	}

	core := data.Get()
	instance := &Cluster{
		Core:     core,
		metadata: data,
		provider: svc,
	}
	instance.resetExtensions(core)
	return instance, nil
}

func (c *Cluster) resetExtensions(Core *clusterapi.ClusterCore) {
	if Core == nil {
		return
	}
	anon := Core.GetExtension(Extension.Flavor)
	if anon != nil {
		manager := anon.(managerData)
		c.manager = &manager
		// Note: On Load(), need to replace Extensions that are struct to pointers to struct
		Core.SetExtension(Extension.Flavor, &manager)
	}
}

// Reload reloads metadata of Cluster from ObjectStorage
func (c *Cluster) Reload() error {
	err := c.metadata.Reload()
	if err != nil {
		return err
	}
	c.resetExtensions(c.metadata.Get())
	return nil
}

// Create creates the necessary infrastructure of cluster
func Create(req clusterapi.Request) (clusterapi.Cluster, error) {
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
		}
	}
	if nodesDef.ImageID == "" {
		nodesDef.ImageID = "Ubuntu 17.10"
	}

	// Creates network
	log.Printf("Creating Network 'net-%s'", req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	def := pb.NetworkDefinition{
		Name: networkName,
		CIDR: req.CIDR,
		Gateway: &pb.GatewayDefinition{
			CPU:     2,
			RAM:     8.0,
			Disk:    50,
			ImageID: "Ubuntu 16.04",
		},
	}
	network, err := brokerclient.New().Network.Create(def, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		err = fmt.Errorf("failed to create Network '%s': %s", networkName, err.Error())
		return nil, err
	}
	log.Printf("Network '%s' created successfully\n", network.Name)
	req.NetworkID = network.ID

	// Saving cluster parameters, with status 'Creating'
	var (
		instance                      Cluster
		masterCount, privateNodeCount int
		kp                            *providerapi.KeyPair
		kpName                        string
		gw                            *providerapi.Host
		m                             *providermetadata.Gateway
		ok                            bool
		gatewayChannel                chan error
		gatewayStatus                 error
		mastersChannel                chan error
		mastersStatus                 error
		nodesChannel                  chan error
		nodesStatus                   error
		feature                       *install.Feature
		results                       install.Results
	)
	broker := brokerclient.New()

	svc, err := provideruse.GetProviderService()
	if err != nil {
		goto cleanNetwork
	}

	// Loads gateway metadata
	m, err = providermetadata.NewGateway(svc, req.NetworkID)
	if err != nil {
		goto cleanNetwork
	}
	ok, err = m.Read()
	if err != nil {
		goto cleanNetwork
	}
	if !ok {
		err = fmt.Errorf("failed to load gateway metadata")
		goto cleanNetwork
	}
	gw = m.Get()

	err = brokerclient.New().Ssh.WaitReady(gw.ID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		err = brokerclient.DecorateError(err, "wait for remote ssh service to be ready", false)
		goto cleanNetwork
	}

	// Create a KeyPair for the user cladm
	kpName = "cluster_" + req.Name + "_cladm_key"
	kp, err = svc.CreateKeyPair(kpName)
	if err != nil {
		err = fmt.Errorf("failed to create Key Pair: %s", err.Error())
		goto cleanNetwork
	}

	// Saving cluster metadata, with status 'Creating'
	instance = Cluster{
		Core: &clusterapi.ClusterCore{
			Name:          req.Name,
			CIDR:          req.CIDR,
			Flavor:        Flavor.K8S,
			State:         ClusterState.Creating,
			Complexity:    req.Complexity,
			Tenant:        req.Tenant,
			NetworkID:     req.NetworkID,
			GatewayIP:     gw.GetPrivateIP(),
			PublicIP:      gw.GetAccessIP(),
			Keypair:       kp,
			AdminPassword: cladmPassword,
			NodesDef:      nodesDef,
		},
		provider: svc,
		manager:  &managerData{},
		gateway:  gw,
	}
	instance.SetExtension(Extension.Flavor, instance.manager)
	err = instance.updateMetadata(nil)
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanNetwork
	}

	err = instance.updateMetadata(func() error {
		// Saves gateway information in cluster metadata
		instance.Core.PublicIP = gw.GetAccessIP()
		return nil
	})
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanNetwork
	}

	switch req.Complexity {
	case Complexity.Small:
		masterCount = 1
		privateNodeCount = 1
	case Complexity.Normal:
		masterCount = 3
		privateNodeCount = 3
	case Complexity.Large:
		masterCount = 5
		privateNodeCount = 6
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Configure gateway
	gatewayChannel = make(chan error)
	go instance.asyncConfigureGateway(gatewayChannel)

	// Create masters and nodes
	gatewayStatus = <-gatewayChannel
	if gatewayStatus == nil {
		mastersChannel = make(chan error)
		go instance.asyncCreateMasters(masterCount, mastersChannel)

		nodesChannel = make(chan error)
		go instance.asyncCreateNodes(privateNodeCount, false, nodesDef, nodesChannel)

		mastersStatus = <-mastersChannel
		nodesStatus = <-nodesChannel
	}

	// Installs kubernetes
	if gatewayStatus == nil && mastersStatus == nil && nodesStatus == nil {
		log.Println("Installing kubernetes feature...")
		target := install.NewClusterTarget(&instance)
		feature, err = install.NewFeature("kubernetes")
		if err != nil {
			err = fmt.Errorf("failed to prepare feature 'kubernetes': %s", err.Error())
			goto cleanNodes
		}
		results, err = feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Printf("failed to install kubernetes feature: %s", err.Error())
			goto cleanNodes
		}
		if !results.Successful() {
			err = fmt.Errorf(results.AllErrorMessages())
			log.Printf("failed to install kubernetes feature: %s", err.Error())
			goto cleanNodes
		}
		log.Println("Feature kubernetes installed successfully.")
	}

	// If any previous step fails, clean everything
	if gatewayStatus != nil {
		err = gatewayStatus
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
	err = instance.updateMetadata(func() error {
		instance.Core.State = ClusterState.Created
		return nil
	})
	if err != nil {
		log.Println("failed to update metadata")
		goto cleanMasters
	}

	// Get the state of the cluster until successful
	err = retry.WhileUnsuccessfulDelay5Seconds(
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
		5*time.Minute,
	)
	if err != nil {
		log.Println("failed to wait ready state of the cluster")
		goto cleanNodes
	}
	return &instance, nil

cleanNodes:
	if !req.KeepOnFailure {
		for _, id := range instance.Core.PublicNodeIDs {
			broker.Host.Delete(id, brokerclient.DefaultExecutionTimeout)
		}
		for _, id := range instance.Core.PrivateNodeIDs {
			broker.Host.Delete(id, brokerclient.DefaultExecutionTimeout)
		}
	}
cleanMasters:
	if !req.KeepOnFailure {
		for _, id := range instance.manager.MasterIDs {
			broker.Host.Delete(id, brokerclient.DefaultExecutionTimeout)
		}
	}
cleanNetwork:
	if !req.KeepOnFailure {
		broker.Network.Delete(instance.Core.NetworkID, brokerclient.DefaultExecutionTimeout)
		instance.metadata.Delete()
	}
	if err == nil {
		return nil, fmt.Errorf("cluster creation failed but no error bubbled up")
	}
	return nil, err
}

func (c *Cluster) asyncCreateNodes(count int, public bool, def pb.HostDefinition, done chan error) {
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
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 1; i <= count; i++ {
		d := make(chan error)
		dones = append(dones, d)
		r := make(chan string)
		results = append(results, r)
		go c.asyncCreateNode(i, nodeType, def, timeout, r, d)
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

// // asyncConfigurePrivateNodes ...
// func (c *Cluster) asyncConfigurePrivateNodes(done chan error) {
// 	fmt.Println("Configuring Kubernetes private Nodes...")

// 	var (
// 		host   *pb.Host
// 		err    error
// 		i      int
// 		hostID string
// 		errors []string
// 	)

// 	dones := []chan error{}
// 	for i, hostID = range c.Core.PrivateNodeIDs {
// 		host, err = brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
// 		if err != nil {
// 			break
// 		}
// 		d := make(chan error)
// 		dones = append(dones, d)
// 		go c.asyncConfigureNode(i+1, host, NodeType.PrivateNode, d)
// 	}
// 	// Deals with the metadata read failure
// 	if err != nil {
// 		errors = append(errors, "failed to get metadata of host '%s': %s", hostID, err.Error())
// 	}

// 	for i = range dones {
// 		err = <-dones[i]
// 		if err != nil {
// 			errors = append(errors, err.Error())
// 		}
// 	}
// 	if len(errors) > 0 {
// 		done <- fmt.Errorf(strings.Join(errors, "\n"))
// 	} else {
// 		done <- nil
// 	}
// }

// asyncCreateMasters
func (c *Cluster) asyncCreateMasters(count int, done chan error) {
	var dones []chan error
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 1; i <= count; i++ {
		d := make(chan error)
		dones = append(dones, d)
		go c.asyncCreateMaster(i, timeout, d)
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

// // asyncConfigureMasters configure masters
// func (c *Cluster) asyncConfigureMasters(done chan error) {
// 	fmt.Println("Configuring Kubernetes master hosts...")

// 	broker := brokerclient.New().Host
// 	dones := []chan error{}
// 	for i, hostID := range c.manager.MasterIDs {
// 		host, err := broker.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
// 		if err != nil {
// 			done <- fmt.Errorf("failed to get metadata of host: %s", err.Error())
// 		}
// 		d := make(chan error)
// 		dones = append(dones, d)
// 		go c.asyncConfigureMaster(i+1, host, d)
// 	}

// 	var state error
// 	var errors []string
// 	for i := range dones {
// 		state = <-dones[i]
// 		if state != nil {
// 			errors = append(errors, state.Error())
// 		}
// 	}
// 	if len(errors) > 0 {
// 		done <- fmt.Errorf(strings.Join(errors, "\n"))
// 		return
// 	}

// 	done <- nil
// }

// createAndConfigureNode creates and configure a Node
func (c *Cluster) createAndConfigureNode(index int, req pb.HostDefinition, timeout time.Duration) (string, error) {
	var nodeType NodeType.Enum
	if req.Public {
		nodeType = NodeType.PublicNode
	} else {
		nodeType = NodeType.PrivateNode
	}
	if c.Core.State != ClusterState.Created && c.Core.State != ClusterState.Nominal {
		return "", fmt.Errorf("cluster flavor K8S needs to be at least in state 'Created' to allow node addition")
	}

	done := make(chan error)
	result := make(chan string)
	go c.asyncCreateNode(index, nodeType, req, timeout, result, done)
	hostID := <-result
	err := <-done
	if err != nil {
		return "", err
	}
	close(done)

	return hostID, nil
}

// asyncCreateMaster adds a master node
func (c *Cluster) asyncCreateMaster(index int, timeout time.Duration, done chan error) {
	log.Printf("[master #%d] starting creation...\n", index)

	name, err := c.buildHostname("master", NodeType.Master)
	if err != nil {
		log.Printf("[master #%d] creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to create Master server %d: %s", index, err.Error())
		return
	}

	hostDef := c.Core.NodesDef
	hostDef.Name = name
	hostDef.Network = c.Core.NetworkID
	hostDef.Public = false
	host, err := brokerclient.New().Host.Create(hostDef, timeout)
	if err != nil {
		err = brokerclient.DecorateError(err, "creation of host", false)
		log.Printf("[master #%d] host resource creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to create Master server %d: %s", index, err.Error())
		return
	}

	// Update cluster definition in Object Storage
	err = c.updateMetadata(func() error {
		c.manager.MasterIDs = append(c.manager.MasterIDs, host.ID)
		c.manager.MasterIPs = append(c.manager.MasterIPs, host.PRIVATE_IP)
		return nil
	})
	if err != nil {
		// Object Storage failed, removes the ID we just added to the cluster struct
		c.manager.MasterIDs = c.manager.MasterIDs[:len(c.manager.MasterIDs)-1]
		c.manager.MasterIPs = c.manager.MasterIPs[:len(c.manager.MasterIPs)-1]
		brokerclient.New().Host.Delete(host.ID, brokerclient.DefaultExecutionTimeout)

		log.Printf("[master #%d (%s)] creation failed: %s\n", index, host.Name, err.Error())
		done <- fmt.Errorf("failed to update Cluster metadata: %s", err.Error())
		return
	}

	// Installs K8S requirements
	log.Printf("[master #%d (%s)] installing requirements...\n", index, host.Name)
	commonRequirements, err := c.getCommonRequirements()
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"reserved_CommonRequirements": *commonRequirements,
	}
	box, err := getK8STemplateBox()
	if err != nil {
		done <- err
		return
	}
	retcode, _, _, err := flavortools.ExecuteScript(box, nil, "k8s_install_master.sh", data, host.ID)
	if err != nil {
		log.Printf("[master #%d (%s)] failed to remotely run installation script: %s\n", index, host.Name, err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[master #%d (%s)] installation failed: retcode=%d", index, host.Name, retcode)
		done <- fmt.Errorf("scripted Node configuration failed with error code %d", retcode)
		return
	}
	log.Printf("[master #%d (%s)] requirements installed successfully.\n", index, host.Name)

	// Installs remotedesktop feature on each master
	log.Printf("[master #%d (%s)] adding feature 'remotedesktop'\n", index, host.Name)
	feature, err := install.NewFeature("remotedesktop")
	if err != nil {
		log.Printf("[master #%d (%s)] failed to instanciate feature 'remotedesktop': %s\n", index, host.Name, err.Error())
		done <- err
		return
	}
	target := install.NewHostTarget(host)
	results, err := feature.Add(target, install.Variables{
		"Username": "cladm",
		"Password": c.Core.AdminPassword,
	}, install.Settings{})
	if err != nil {
		log.Printf("[master #%d (%s)] failed to add feature '%s': %s", index, host.Name, feature.DisplayName(), err.Error())
		done <- err
		return
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Printf("[master #%d (%s)] installation script of feature '%s' failed: %s\n", index, host.Name, feature.DisplayName(), msg)
		done <- fmt.Errorf(msg)
	}
	log.Printf("[master #%d (%s)] feature '%s' added successfully\n", index, host.Name, feature.DisplayName())

	// // install proxycache-client feature
	// feature, err := install.NewFeature("proxycache-client")
	// if err != nil {
	// 	log.Printf("[master #%d (%s)] failed to prepare feature 'proxycache-client': %s", 1, host.ID, err.Error())
	// 	done <- fmt.Errorf("failed to install feature 'proxycache-client': %s", err.Error())
	// }
	// target := install.NewHostTarget(host)
	// ok, results, err := feature.Add(target, values)
	// if err != nil {
	// 	log.Printf("[master #%d (%s)] failed to install feature '%s': %s\n", 1, host.Name, feature.DisplayName(), err.Error())
	// 	done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
	// 	return
	// }
	// if !ok {
	// 	msg := results.Errors()
	// 	log.Printf("[master #%d (%s)] failed to install feature '%s': %s", 1, host.Name, feature.DisplayName(), msg)
	// 	done <- fmt.Errorf(msg)
	// 	return
	// }

	log.Printf("[master #%d (%s)] creation successful\n", index, host.Name)
	done <- nil
}

// asyncCreateNode creates a Node in the cluster
// This function is intended to be call as a goroutine
func (c *Cluster) asyncCreateNode(
	index int, nodeType NodeType.Enum, req pb.HostDefinition, timeout time.Duration,
	result chan string, done chan error,
) {
	var publicIP bool
	var nodeTypeStr string
	if nodeType == NodeType.PublicNode {
		nodeTypeStr = "public"
		publicIP = true
	} else {
		nodeTypeStr = "private"
		publicIP = false
	}

	log.Printf("[%s node #%d] starting creation...\n", nodeTypeStr, index)

	// Create the host
	log.Printf("[%s node #%d] starting host resource creation...\n", nodeTypeStr, index)
	var err error
	name, err := c.buildHostname("node", nodeType)
	if err != nil {
		log.Printf("[%s node #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}
	req.Name = name
	req.Public = publicIP
	req.Network = c.Core.NetworkID
	host, err := brokerclient.New().Host.Create(req, timeout)
	if err != nil {
		err = brokerclient.DecorateError(err, "creation of host", true)
		log.Printf("[%s node #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}

	// Update cluster definition in Object Storage
	err = c.updateMetadata(func() error {
		// Registers the new Agent in the cluster struct
		if nodeType == NodeType.PublicNode {
			c.Core.PublicNodeIDs = append(c.Core.PublicNodeIDs, host.ID)
			c.manager.PublicNodeIPs = append(c.manager.PublicNodeIPs, host.PRIVATE_IP)
		} else {
			c.Core.PrivateNodeIDs = append(c.Core.PrivateNodeIDs, host.ID)
			c.manager.PrivateNodeIPs = append(c.manager.PrivateNodeIPs, host.PRIVATE_IP)
		}
		return nil
	})
	if err != nil {
		// Removes the ID we just added to the cluster struct
		if nodeType == NodeType.PublicNode {
			c.Core.PublicNodeIDs = c.Core.PublicNodeIDs[:len(c.Core.PublicNodeIDs)-1]
			c.manager.PublicNodeIPs = c.manager.PublicNodeIPs[:len(c.manager.PublicNodeIPs)-1]
		} else {
			c.Core.PrivateNodeIDs = c.Core.PrivateNodeIDs[:len(c.Core.PrivateNodeIDs)-1]
			c.manager.PrivateNodeIPs = c.manager.PrivateNodeIPs[:len(c.manager.PrivateNodeIPs)-1]
		}
		brokerclient.New().Host.Delete(host.ID, brokerclient.DefaultExecutionTimeout)

		log.Printf("[%s node #%d] creation failed: %s", nodeTypeStr, index, err.Error())
		result <- ""
		done <- fmt.Errorf("failed to update Cluster configuration: %s", err.Error())
		return
	}
	log.Printf("[%s node #%d (%s)] host resource created successfully.\n", nodeTypeStr, index, host.Name)

	// // install proxycache-client feature
	// feature, err := install.NewFeature("proxycache-client")
	// if err != nil {
	// 	log.Printf("[%s node #%d (%s)] failed to prepare feature 'proxycache-client': %s", nodeTypeStr, index, host.ID, err.Error())
	// 	done <- fmt.Errorf("failed to install feature 'proxycache-client': %s", err.Error())
	// 	return
	// }
	//target := install.NewHostTarget(host)
	// ok, results, err := feature.Add(target, install.Variables{})
	// if err != nil {
	// 	log.Printf("[%s node #%d (%s)] failed to install feature '%s': %s\n", nodeTypeStr, index, host.Name, feature.DisplayName(), err.Error())
	// 	done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
	// 	return
	// }
	// if !ok {
	// 	msg := results.Errors()
	// 	log.Printf("[%s node #%d (%s)] failed to install feature '%s': %s", nodeTypeStr, index, host.Name, feature.DisplayName(), msg)
	// 	done <- fmt.Errorf(msg)
	// 	return
	// }

	// Installs K8S requirements
	log.Printf("[%s node #%d (%s)] installing requirements...\n", nodeTypeStr, index, host.Name)
	commonRequirements, err := c.getCommonRequirements()
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"reserved_CommonRequirements": *commonRequirements,
	}
	box, err := getK8STemplateBox()
	if err != nil {
		done <- err
		return
	}
	retcode, _, _, err := flavortools.ExecuteScript(box, nil, "k8s_install_node.sh", data, host.ID)
	if err != nil {
		log.Printf("[%s node #%d (%s)] failed to remotely run installation script: %s\n", nodeTypeStr, index, host.Name, err.Error())
		result <- ""
		done <- err
		return
	}
	if retcode != 0 {
		result <- ""
		log.Printf("[%s node #%d (%s)] installation failed: retcode=%d", nodeTypeStr, index, host.Name, retcode)
		done <- fmt.Errorf("scripted Node configuration failed with error code %d", retcode)
		return
	}
	log.Printf("[%s node #%d (%s)] requirements installed successfully.\n", nodeTypeStr, index, host.Name)

	log.Printf("[%s node #%d (%s)] creation successful.\n", nodeTypeStr, index, host.Name)
	result <- host.ID
	done <- nil
}

// asyncConfigureGateway prepares the gateway by installing reverse proxy
func (c *Cluster) asyncConfigureGateway(done chan error) {
	log.Printf("[gateway] starting configuration...")

	err := provideruse.WaitSSHServerReady(c.provider, c.gateway.ID, 5*time.Minute)
	if err != nil {
		done <- err
		return
	}
	host, err := brokerclient.New().Host.Inspect(c.gateway.ID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		done <- err
		return
	}

	// Installs reverseproxy
	log.Println("[gateway] starting installation of feature 'reverseproxy'...")
	feature, err := install.NewFeature("reverseproxy")
	if err != nil {
		msg := fmt.Sprintf("[gateway] failed to instanciate feature '%s': %s", feature.DisplayName(), err.Error())
		log.Println(msg)
		done <- fmt.Errorf(msg)
		return
	}
	target := install.NewHostTarget(host)
	results, err := feature.Add(target, install.Variables{}, install.Settings{})
	if err != nil {
		msg := fmt.Sprintf("[gateway] failed to install feature '%s': %s", feature.DisplayName(), err.Error())
		log.Println(msg)
		done <- fmt.Errorf(msg)
		return
	}
	if !results.Successful() {
		msg := fmt.Sprintf("[gateway] failed to install feature '%s': %s", feature.DisplayName(), results.AllErrorMessages())
		log.Println(msg)
		done <- fmt.Errorf(msg)
		return
	}
	log.Println("[gateway] Feature 'reverseproxy' successfully installed")

	log.Printf("[gateway] configuration successful")
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
		coreName = core
	case NodeType.Master:
		coreName = core
	default:
		return "", fmt.Errorf("Invalid Node Type '%v'", nodeType)
	}

	err := c.updateMetadata(func() error {
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
		return nil
	})
	if err != nil {
		return "", err
	}
	return c.Core.Name + "-" + coreName + "-" + strconv.Itoa(index), nil
}

// GetName returns the name of the cluster
func (c *Cluster) GetName() string {
	return c.Core.Name
}

// getK8STemplateBox
func getK8STemplateBox() (*rice.Box, error) {
	if templateBox == nil {
		// Note: path MUST be literal for rice to work
		b, err := rice.FindBox("../k8s/scripts")
		if err != nil {
			return nil, err
		}
		templateBox = b
	}
	return templateBox, nil
}

// getCommonRequirements returns the string corresponding to the script k8s_install_requirements.sh
// which installs common features (docker in particular)
func (c *Cluster) getCommonRequirements() (*string, error) {
	if installCommonRequirementsContent == nil {
		// find the rice.Box
		b, err := getK8STemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := b.String("k8s_install_requirements.sh")
		if err != nil {
			return nil, fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := txttmpl.New("install_requirements").Parse(tmplString)
		if err != nil {
			return nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{
			"CIDR":          c.Core.CIDR,
			"Username":      "cladm",
			"CladmPassword": c.Core.AdminPassword,
			"SSHPublicKey":  c.Core.Keypair.PublicKey,
			"SSHPrivateKey": c.Core.Keypair.PrivateKey,
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
	return c.Core.State, nil
}

// ForceGetState returns the current state of the cluster
// This method will trigger a effective state collection at each call
func (c *Cluster) ForceGetState() (ClusterState.Enum, error) {
	var (
		retcode int
		stderr  string
		ran     bool // Tells if command has been run on remote host
	)

	cmd := fmt.Sprintf("%s kubectl get nodes", adminCmd)
	ssh := brokerclient.New().Ssh
	for _, id := range c.manager.MasterIDs {
		err := provideruse.WaitSSHServerReady(c.provider, id, 2*time.Minute)
		if err == nil {
			if err != nil {
				continue
			}
			retcode, _, stderr, err = ssh.Run(id, cmd, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				continue
			}
			ran = true
			break
		}
	}

	err := c.updateMetadata(func() error {
		c.lastStateCollection = time.Now()
		if ran {
			switch retcode {
			case 0:
				c.Core.State = ClusterState.Nominal
			default:
				c.Core.State = ClusterState.Error
				return fmt.Errorf(stderr)
			}
		}
		return nil
	})
	return c.Core.State, err
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
	if c.Core.State != ClusterState.Created && c.Core.State != ClusterState.Nominal {
		return nil, fmt.Errorf("a K8S cluster needs to be at least in state 'Created' to allow node addition")
	}

	hostReq := c.GetConfig().NodesDef
	hostReq.Public = public
	if req != nil {
		if req.CPUNumber > 0 {
			hostReq.CPUNumber = req.CPUNumber
		}
		if req.RAM > 0.0 {
			hostReq.RAM = req.RAM
		}
		if req.Disk > 0 {
			hostReq.Disk = req.Disk
		}
	}

	var hosts []string
	var errors []string
	var dones []chan error
	var results []chan string
	timeout := brokerclient.DefaultExecutionTimeout + time.Duration(2*count)*time.Minute
	for i := 0; i < count; i++ {
		r := make(chan string)
		results = append(results, r)
		d := make(chan error)
		dones = append(dones, d)
		go func(idx int, result chan string, done chan error) {
			hostID, err := c.createAndConfigureNode(idx, hostReq, timeout)
			if err != nil {
				result <- ""
				done <- err
				return
			}
			result <- hostID
			done <- nil
		}(i+1, r, d)
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
			dones = []chan error{}
			broker := brokerclient.New().Host
			for _, hostID := range hosts {
				d := make(chan error)
				dones = append(dones, d)
				go func(id string, done chan error) {
					broker.Delete(id, brokerclient.DefaultExecutionTimeout)
					done <- nil
				}(hostID, d)
			}
			for _, d := range dones {
				_ = <-d
			}
		}
		return nil, fmt.Errorf("errors occured on node addition: %s", strings.Join(errors, "\n"))
	}

	target := install.NewClusterTarget(c)
	feature, err := install.NewFeature("kubernetes")
	if err != nil {
		return nil, err
	}
	log.Println("Adding feature 'kubernetes'...")
	addResults, err := feature.Add(target, install.Variables{}, install.Settings{})
	if err != nil {
		return nil, err
	}
	if !addResults.Successful() {
		return nil, fmt.Errorf(addResults.AllErrorMessages())
	}
	log.Println("Successfully added feature 'kubernetes'")

	return hosts, nil
}

// FindAvailableMaster returns the ID of a master available
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

// DeleteLastNode deletes the last Agent node added
func (c *Cluster) DeleteLastNode(public bool) error {
	var hostID string

	if public {
		hostID = c.Core.PublicNodeIDs[len(c.Core.PublicNodeIDs)-1]
	} else {
		hostID = c.Core.PrivateNodeIDs[len(c.Core.PrivateNodeIDs)-1]
	}
	err := brokerclient.New().Host.Delete(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return nil
	}

	return c.updateMetadata(func() error {
		if public {
			c.Core.PublicNodeIDs = c.Core.PublicNodeIDs[:len(c.Core.PublicNodeIDs)-1]
		} else {
			c.Core.PrivateNodeIDs = c.Core.PrivateNodeIDs[:len(c.Core.PrivateNodeIDs)-1]
		}
		return nil
	})
}

// DeleteSpecificNode deletes the node specified by its ID
func (c *Cluster) DeleteSpecificNode(ID string) error {
	var foundInPrivate bool
	foundInPublic, idx := contains(c.Core.PublicNodeIDs, ID)
	if !foundInPublic {
		foundInPrivate, idx = contains(c.Core.PrivateNodeIDs, ID)
	}
	if !foundInPublic && !foundInPrivate {
		return fmt.Errorf("host ID '%s' isn't a registered Node of the Cluster '%s'", ID, c.Core.Name)
	}

	err := brokerclient.New().Host.Delete(ID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return err
	}

	if foundInPublic {
		c.Core.PublicNodeIDs = append(c.Core.PublicNodeIDs[:idx], c.Core.PublicNodeIDs[idx+1:]...)
	} else {
		c.Core.PrivateNodeIDs = append(c.Core.PrivateNodeIDs[:idx], c.Core.PrivateNodeIDs[idx+1:]...)
	}
	return nil
}

// ListMasterIDs lists the IDs of the masters in the cluster
func (c *Cluster) ListMasterIDs() []string {
	return c.manager.MasterIDs
}

// ListMasterIPs lists the IPs of the masters in the cluster
func (c *Cluster) ListMasterIPs() []string {
	return c.manager.MasterIPs
}

// ListNodeIDs lists the IDs of the nodes in the cluster; if public is set, list IDs of public nodes
// otherwise list IDs of private nodes
func (c *Cluster) ListNodeIDs(public bool) []string {
	if public {
		return c.Core.PublicNodeIDs
	}
	return c.Core.PrivateNodeIDs
}

// ListNodeIPs lists the IPs of the nodes in the cluster; if public is set, list IDs of public nodes
// otherwise list IDs of private nodes
func (c *Cluster) ListNodeIPs(public bool) []string {
	if public {
		return c.manager.PublicNodeIPs
	}
	return c.manager.PrivateNodeIPs
}

// GetNode returns a node based on its ID
func (c *Cluster) GetNode(ID string) (*pb.Host, error) {
	found, _ := contains(c.Core.PublicNodeIDs, ID)
	if !found {
		found, _ = contains(c.Core.PrivateNodeIDs, ID)
	}
	if !found {
		return nil, fmt.Errorf("GetNode not yet implemented")
	}
	return brokerclient.New().Host.Inspect(ID, brokerclient.DefaultExecutionTimeout)
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
	found, _ := contains(c.Core.PublicNodeIDs, ID)
	if !found {
		found, _ = contains(c.Core.PrivateNodeIDs, ID)
	}
	return found
}

// GetConfig returns the public properties of the cluster
func (c *Cluster) GetConfig() clusterapi.ClusterCore {
	return *c.Core
}

// updateMetadata writes cluster config in Object Storage
func (c *Cluster) updateMetadata(updatefn func() error) error {
	if c.metadata == nil {
		m, err := metadata.NewCluster()
		if err != nil {
			return err
		}
		m.Carry(c.Core)
		c.metadata = m
		c.metadata.Acquire()
	} else {
		c.metadata.Acquire()
		c.Reload()
	}
	if updatefn != nil {
		err := updatefn()
		if err != nil {
			c.metadata.Release()
			return err
		}
	}
	err := c.metadata.Write()
	c.metadata.Release()
	return err
}

// Delete destroys everything related to the infrastructure built for the cluster
func (c *Cluster) Delete() error {
	if c.metadata == nil {
		return fmt.Errorf("no metadata found for this cluster")
	}

	// Updates metadata
	err := c.updateMetadata(func() error {
		c.Core.State = ClusterState.Removed
		return nil
	})
	if err != nil {
		return err
	}

	err = c.updateMetadata(func() error {
		broker := brokerclient.New()

		// Deletes the public nodes
		for _, n := range c.Core.PublicNodeIDs {
			broker.Host.Delete(n, brokerclient.DefaultExecutionTimeout)
		}

		// Deletes the private nodes
		for _, n := range c.Core.PrivateNodeIDs {
			broker.Host.Delete(n, brokerclient.DefaultExecutionTimeout)
		}

		// Deletes the masters
		for _, n := range c.manager.MasterIDs {
			broker.Host.Delete(n, brokerclient.DefaultExecutionTimeout)
		}

		// Deletes the network and gateway
		return broker.Network.Delete(c.Core.NetworkID, brokerclient.DefaultExecutionTimeout)
	})
	if err != nil {
		return err
	}

	// Deletes the metadata
	err = c.metadata.Delete()
	if err != nil {
		return nil
	}
	c.metadata = nil
	c.Core = nil
	c.manager = nil
	return nil
}

func init() {
	gob.Register(Cluster{})
	gob.Register(managerData{})
}
