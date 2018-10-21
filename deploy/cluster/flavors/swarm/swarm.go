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

package swarm

/*
 * Implements a cluster of hosts without cluster management environment
 */

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"runtime"
	"strconv"
	"strings"
	txttmpl "text/template"
	"time"

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
	"github.com/CS-SI/SafeScale/utils/template"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
	pbutils "github.com/CS-SI/SafeScale/broker/utils"
)

//go:generate rice embed-go

const (
	timeoutCtxHost = 10 * time.Minute

	shortTimeoutSSH = time.Minute
	longTimeoutSSH  = 5 * time.Minute

	tempFolder = "/var/tmp/"
)

var (
	// swarmTemplateBox is the rice box to use in this package
	swarmTemplateBox *rice.Box

	// funcMap defines the custome functions to be used in templates
	funcMap = txttmpl.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	}

	installCommonRequirementsContent *string
)

// managerData defines the data used by the manager of cluster we want to keep in Object Storage
type managerData struct {
	// MasterIDs contains the ID of the masters
	MasterIDs []string
	// MasterIPs contains the IP of the masters
	MasterIPs []string
	// PublicNodeIPs contains a list of IP of the Public Agent nodes
	PublicNodeIPs []string
	// PrivateAvgentIPs contains a list of IP of the Private Agent Nodes
	PrivateNodeIPs []string
	// StateCollectInterval in seconds
	StateCollectInterval time.Duration
	// MasterLastIndex
	MasterLastIndex int
	// PrivateLastIndex
	PrivateLastIndex int
	// PublicLastIndex
	PublicLastIndex int
}

// Cluster is the object describing a cluster
type Cluster struct {
	// Core cluster data
	Core *clusterapi.ClusterCore

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
	return c.Core.GetNetworkID()
}

// CountNodes returns the number of public or private nodes in the cluster
func (c *Cluster) CountNodes(public bool) uint {
	return c.Core.CountNodes(public)
}

// GetExtension returns additional info of the cluster
func (c *Cluster) GetExtension(ctx Extension.Enum) interface{} {
	return c.Core.GetExtension(ctx)
}

// SetExtension returns additional info of the cluster
func (c *Cluster) SetExtension(ctx Extension.Enum, info interface{}) {
	c.Core.SetExtension(ctx, info)
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

func (c *Cluster) resetExtensions(core *clusterapi.ClusterCore) {
	if core == nil {
		return
	}
	anon := core.GetExtension(Extension.Flavor)
	if anon != nil {
		manager := anon.(managerData)
		c.manager = &manager
		// Note: On Load(), need to replace Extensions that are structs to pointers to struct
		core.SetExtension(Extension.Flavor, &manager)
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

	nodesDef := pb.HostDefinition{
		CPUNumber: 4,
		RAM:       15.0,
		Disk:      100,
		ImageID:   "Ubuntu 17.10",
	}
	if req.NodesDef != nil {
		if req.NodesDef.CPUNumber > nodesDef.CPUNumber {
			nodesDef.CPUNumber = req.NodesDef.CPUNumber
		}
		if req.NodesDef.RAM > nodesDef.RAM {
			nodesDef.RAM = req.NodesDef.RAM
		}
		if req.NodesDef.Disk > nodesDef.Disk {
			nodesDef.Disk = req.NodesDef.Disk
		}
		if req.NodesDef.ImageID != "" {
			nodesDef.ImageID = req.NodesDef.ImageID
		}
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
			RAM:     15.0,
			Disk:    60,
			ImageID: "Ubuntu 17.10",
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
		instance         Cluster
		masterCount      int
		privateNodeCount int
		kp               *providerapi.KeyPair
		kpName           string
		gw               *providerapi.Host
		m                *providermetadata.Gateway
		ok               bool
		gatewayChannel   chan error
		gatewayStatus    error
		mastersChannel   chan error
		mastersStatus    error
		nodesChannel     chan error
		nodesStatus      error
		target           install.Target
		feature          *install.Feature
		results          install.Results
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
			Name:             req.Name,
			CIDR:             req.CIDR,
			Flavor:           Flavor.SWARM,
			State:            ClusterState.Creating,
			Complexity:       req.Complexity,
			Tenant:           req.Tenant,
			NetworkID:        req.NetworkID,
			GatewayIP:        gw.GetPrivateIP(),
			PublicIP:         gw.GetAccessIP(),
			Keypair:          kp,
			AdminPassword:    cladmPassword,
			NodesDef:         nodesDef,
			DisabledFeatures: req.DisabledDefaultFeatures,
		},
		provider: svc,
		manager:  &managerData{},
	}
	instance.SetExtension(Extension.Flavor, instance.manager)
	err = instance.updateMetadata(func() error {
		// Saves gateway information in cluster metadata
		instance.Core.PublicIP = gw.GetAccessIP()
		return nil
	})
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanNetwork
	}

	//VPL: Disabling proxy-cache always for now
	instance.Core.DisabledFeatures["proxycache"] = struct{}{}
	if _, ok := instance.Core.DisabledFeatures["proxycache"]; !ok {
		feature, err = install.NewFeature("proxycache-server")
		if err != nil {
			goto cleanNetwork
		}
		target := install.NewHostTarget(pbutils.ToPBHost(gw))
		results, err = feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			goto cleanNetwork
		}
		if !results.Successful() {
			err = fmt.Errorf(results.AllErrorMessages())
			goto cleanNetwork
		}
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
		privateNodeCount = 3
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Step 1: starts masters and nodes creations
	gatewayChannel = make(chan error)
	go instance.asyncInstallGateway(pbutils.ToPBHost(gw), gatewayChannel)

	mastersChannel = make(chan error)
	go instance.asyncCreateMasters(masterCount, nodesDef, mastersChannel)

	nodesChannel = make(chan error)
	go instance.asyncCreateNodes(privateNodeCount, false, nodesDef, nodesChannel)

	// Step 2: awaits masters creation and bootstrap configuration coroutines
	gatewayStatus = <-gatewayChannel
	mastersStatus = <-mastersChannel

	// // Step 3: starts bootstrap configuration, if masters have been created
	// //         successfully
	// if gatewayStatus == nil && mastersStatus == nil {
	// 	gatewayChannel = make(chan error)
	// 	go instance.asyncConfigureGateway(gw, gatewayChannel)
	// 	gatewayStatus = <-gatewayChannel
	// }

	// Step 4: finish to configure masters
	if gatewayStatus == nil && mastersStatus == nil {
		mastersChannel = make(chan error)
		go instance.asyncConfigureMasters(mastersChannel)
		mastersStatus = <-mastersChannel
	}

	// Step 5: Starts nodes configuration, if all masters and nodes
	// have been created and gateway has been configured with success
	if gatewayStatus == nil && mastersStatus == nil && nodesStatus == nil {
		nodesChannel = make(chan error)
		go instance.asyncConfigurePrivateNodes(nodesChannel)
		nodesStatus = <-nodesChannel
	}

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

	// Cluster configuration: add remotedesktop cluster-wide (ie on all masters)
	// add feature remotedesktop
	target = install.NewClusterTarget(&instance)
	if _, ok = instance.Core.DisabledFeatures["remotedesktop"]; !ok {
		log.Printf("Adding feature 'remotedesktop' on cluster...\n")

		feature, err = install.NewFeature("remotedesktop")
		if err != nil {
			err = fmt.Errorf("failed to prepare feature 'remotedesktop': %s", err.Error())
			goto cleanNodes
		}
		results, err = feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			err = fmt.Errorf("failed to add feature '%s': %s", feature.DisplayName(), err.Error())
			goto cleanNodes
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			err = fmt.Errorf("failed to add feature '%s': %s", feature.DisplayName(), msg)
			goto cleanNodes
		}
		log.Printf("feature '%s' added successfully.\n", feature.DisplayName())
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

// asyncConfigurePrivateNodes ...
func (c *Cluster) asyncConfigurePrivateNodes(done chan error) {
	fmt.Println("Configuring Private Nodes...")
	err := c.configureNodes(c.Core.PrivateNodeIDs)
	if err != nil {
		done <- err
		return
	}
	fmt.Println("Private Nodes configured sucessfully")
	done <- nil
}

// configureNodes ...
func (c *Cluster) configureNodes(hosts []string) error {
	var joinCmd string

	broker := brokerclient.New()

	// Get Swarm token to join as worker
	cmd := "docker swarm join-token worker -q"
	for _, master := range c.ListMasterIDs() {
		retcode, token, stderr, err := broker.Ssh.Run(master, cmd, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
		if err == nil && retcode == 0 {
			host, err := broker.Host.Inspect(master, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				return err
			}
			joinCmd = fmt.Sprintf("docker swarm join --token %s %s", strings.Trim(token, "\n"), host.GetPRIVATE_IP())
			break
		}
		log.Printf("failed to get token from '%s': %s\n", master, stderr)
	}
	if joinCmd == "" {
		return fmt.Errorf("failed to get token to join the swarm as worker")
	}

	for _, hostID := range hosts {
		retcode, _, stderr, err := broker.Ssh.Run(hostID, joinCmd, brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", hostID, err.Error())
		}
		if retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", hostID, stderr)
		}
	}

	return nil
}

// asyncCreateMasters
// Intended to be used as goroutine
func (c *Cluster) asyncCreateMasters(count int, def pb.HostDefinition, done chan error) {
	var dones []chan error
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 1; i <= count; i++ {
		d := make(chan error)
		dones = append(dones, d)
		go c.asyncCreateMaster(i, def, timeout, d)
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
	fmt.Println("Configuring masters...")

	broker := brokerclient.New()
	joinCmd := ""
	for _, hostID := range c.manager.MasterIDs {
		host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			done <- fmt.Errorf("failed to get metadata of host: %s", err.Error())
			return
		}
		if joinCmd == "" {
			retcode, _, _, err := broker.Ssh.Run(hostID, "docker swarm init",
				brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				done <- fmt.Errorf("failed to init docker swarm")
				return
			}
			retcode, token, stderr, err := broker.Ssh.Run(hostID, "docker swarm join-token manager -q",
				brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				done <- fmt.Errorf("failed to generate token to join swarm as manager: %s", stderr)
				return
			}
			joinCmd = fmt.Sprintf("docker swarm join --token %s %s -q", token, hostID)
		} else {
			retcode, _, stderr, err := broker.Ssh.Run(hostID, joinCmd,
				brokerclient.DefaultConnectionTimeout, brokerclient.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				done <- fmt.Errorf("failed to join host '%s' to swarm as manager: %s", host.Name, stderr)
				return
			}
		}
	}
	fmt.Println("Masters configured successfully")
	done <- nil
}

// asyncCreateMaster adds a master node
func (c *Cluster) asyncCreateMaster(index int, def pb.HostDefinition, timeout time.Duration, done chan error) {
	log.Printf("[master #%d] starting creation...\n", index)

	name, err := c.buildHostname("master", NodeType.Master)
	if err != nil {
		log.Printf("[master #%d] creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to create Master server %d: %s", index, err.Error())
		return
	}

	def.Network = c.Core.NetworkID
	def.Public = false
	def.Name = name
	host, err := brokerclient.New().Host.Create(def, timeout)
	if err != nil {
		err = brokerclient.DecorateError(err, "creation of host resource", false)
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

	// Installs Docker Swarm requirements...
	log.Printf("[master #%d (%s)] installing system requirements", index, host.Name)
	installCommonRequirements, err := c.getInstallCommonRequirements()
	if err != nil {
		done <- fmt.Errorf("failed to retrieve installation script for master: %s", err.Error())
		return
	}
	data := map[string]interface{}{
		"InstallCommonRequirements": *installCommonRequirements,
	}
	box, err := getSWARMTemplateBox()
	if err != nil {
		done <- fmt.Errorf("failed to retrieve installation script for master: %s", err.Error())
		return
	}
	retcode, _, _, err := flavortools.ExecuteScript(box, funcMap, "swarm_install_master.sh", data, host.ID)
	if err != nil {
		log.Printf("[master #%d (%s)] failed to remotely run installation script: %s\n", index, host.Name, err.Error())
		done <- fmt.Errorf("failed to remotely run installation script on host '%s': %s", host.Name, err.Error())
		return
	}
	if retcode != 0 {
		log.Printf("[master #%d (%s)] installation failed:\nretcode=%d", index, host.ID, retcode)
		done <- fmt.Errorf("scripted Master installation failed with error code %d", retcode)
		return
	}
	log.Printf("[master #%d (%s)] systemrequirements successfully installed", index, host.Name)

	values := install.Variables{
		"Password": c.Core.AdminPassword,
	}

	target := install.NewHostTarget(host)
	//VPL: For now, always disable addition of feature proxy-cache-client
	c.Core.DisabledFeatures["proxycache"] = struct{}{}
	if _, ok := c.Core.DisabledFeatures["proxycache"]; !ok {
		// install proxycache-client feature
		feature, err := install.NewFeature("proxycache-client")
		if err != nil {
			log.Printf("[master #%d (%s)] failed to prepare feature 'proxycache-client': %s", index, host.Name, err.Error())
			done <- fmt.Errorf("failed to install feature 'proxycache-client': %s", err.Error())
		}
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Printf("[master #%d (%s)] failed to add feature '%s': %s\n", index, host.Name, feature.DisplayName(), err.Error())
			done <- fmt.Errorf("failed to add feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
			return
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Printf("[master #%d (%s)] failed to add feature '%s': %s", 1, host.Name, feature.DisplayName(), msg)
			done <- fmt.Errorf(msg)
			return
		}
	}

	// install docker feature
	log.Printf("[master #%d (%s)] adding feature 'docker'", index, host.Name)
	feature, err := install.NewFeature("docker")
	if err != nil {
		log.Printf("[master #%d (%s)] failed to prepare feature 'docker': %s", index, host.ID, err.Error())
		done <- fmt.Errorf("failed to install feature 'docker': %s", err.Error())
		return
	}
	results, err := feature.Add(target, values, install.Settings{})
	if err != nil {
		log.Printf("[master #%d (%s)] failed to install feature '%s': %s\n", index, host.Name, feature.DisplayName(), err.Error())
		done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
		return
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Printf("[master #%d (%s)] failed to install feature '%s': %s", index, host.Name, feature.DisplayName(), msg)
		done <- fmt.Errorf(msg)
		return
	}
	log.Printf("[master #%d (%s)] feature 'docker' installed successfully\n", index, host.Name)

	log.Printf("[master #%d (%s)] creation successful\n", index, host.Name)
	done <- nil
}

// asyncCreateNode creates a Node in the cluster
// This function is intended to be call as a goroutine
func (c *Cluster) asyncCreateNode(
	index int, nodeType NodeType.Enum, def pb.HostDefinition, timeout time.Duration,
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
	def.Name, err = c.buildHostname("node", nodeType)
	if err != nil {
		log.Printf("[%s node #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}
	def.Public = publicIP
	def.Network = c.Core.NetworkID
	host, err := brokerclient.New().Host.Create(def, 10*time.Minute)
	if err != nil {
		err = brokerclient.DecorateError(err, "creation of host resource", true)
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

	target := install.NewHostTarget(host)
	c.Core.DisabledFeatures["proxycache"] = struct{}{}
	if _, ok := c.Core.DisabledFeatures["proxycache"]; !ok {
		// install proxycache-client feature
		feature, err := install.NewFeature("proxycache-client")
		if err != nil {
			log.Printf("[%s node #%d (%s)] failed to prepare feature 'proxycache-client': %s", nodeTypeStr, index, host.ID, err.Error())
			done <- fmt.Errorf("failed to install feature 'proxycache-client': %s", err.Error())
			return
		}
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Printf("[%s node #%d (%s)] failed to install feature '%s': %s\n", nodeTypeStr, index, host.Name, feature.DisplayName(), err.Error())
			done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
			return
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Printf("[%s node #%d (%s)] failed to install feature '%s': %s", nodeTypeStr, index, host.Name, feature.DisplayName(), msg)
			done <- fmt.Errorf(msg)
			return
		}
	}

	// Installs requirements
	log.Printf("[%s node #%d (%s)] installing requirements...\n", nodeTypeStr, index, host.Name)
	installCommonRequirements, err := c.getInstallCommonRequirements()
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"InstallCommonRequirements": *installCommonRequirements,
	}
	box, err := getSWARMTemplateBox()
	if err != nil {
		done <- err
		return
	}
	retcode, _, _, err := flavortools.ExecuteScript(box, funcMap, "swarm_install_node.sh", data, host.ID)
	if err != nil {
		log.Printf("[%s node #%d (%s)] failed to remotely run installation script: %s\n", nodeTypeStr, index, host.Name, err.Error())
		result <- ""
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[%s node #%d (%s)] installation failed: retcode=%d", nodeTypeStr, index, host.Name, retcode)
		result <- ""
		done <- fmt.Errorf("scripted configuration failed with error code %d", retcode)
		return
	}
	log.Printf("[%s node #%d (%s)] requirements installed successfully.\n", nodeTypeStr, index, host.Name)

	// install docker feature
	log.Printf("[%s node #%d (%s)] adding feature 'docker'...\n", nodeTypeStr, index, host.Name)
	feature, err := install.NewFeature("docker")
	if err != nil {
		log.Printf("[%s node #%d (%s)] failed to prepare feature 'docker': %s", nodeTypeStr, index, host.Name, err.Error())
		done <- fmt.Errorf("failed to add feature 'docker': %s", err.Error())
		return
	}
	results, err := feature.Add(target, install.Variables{}, install.Settings{})
	if err != nil {
		log.Printf("[%s node #%d (%s)] failed to add feature '%s': %s\n", nodeTypeStr, index, host.Name, feature.DisplayName(), err.Error())
		done <- fmt.Errorf("failed to add feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
		return
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Printf("[%s node #%d (%s)] failed to add feature '%s': %s", nodeTypeStr, index, host.Name, feature.DisplayName(), msg)
		done <- fmt.Errorf("failed to add feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, msg)
		return
	}
	log.Printf("[%s node #%d (%s)] feature 'docker' added successfully.\n", nodeTypeStr, index, host.Name)

	log.Printf("[%s node #%d (%s)] creation successful.\n", nodeTypeStr, index, host.Name)
	result <- host.ID
	done <- nil
}

// asyncInstallGateway prepares the gateway
func (c *Cluster) asyncInstallGateway(gw *pb.Host, done chan error) {
	log.Printf("[gateway] starting installation...")

	err := provideruse.WaitSSHServerReady(c.provider, gw.ID, 5*time.Minute)
	if err != nil {
		done <- err
		return
	}

	box, err := getSWARMTemplateBox()
	if err != nil {
		done <- err
		return
	}
	installCommonRequirements, err := c.getInstallCommonRequirements()
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"InstallCommonRequirements": *installCommonRequirements,
	}
	retcode, _, _, err := flavortools.ExecuteScript(box, funcMap, "swarm_install_gateway.sh", data, gw.ID)
	if err != nil {
		log.Printf("[gateway] installation failed: %s", err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[gateway] installation failed: retcode=%d", retcode)
		done <- fmt.Errorf("scripted gateway installation failed with error code %d", retcode)
		return
	}

	// Installs reverseproxy
	if _, ok := c.Core.DisabledFeatures["reverseproxy"]; !ok {
		log.Println("Adding feature 'reverseproxy' on gateway...")
		feature, err := install.NewFeature("reverseproxy")
		if err != nil {
			msg := fmt.Sprintf("failed to prepare feature '%s' for '%s': %s", feature.DisplayName(), gw.Name, err.Error())
			log.Println(msg)
			done <- fmt.Errorf(msg)
			return
		}
		target := install.NewHostTarget(gw)
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("failed to install feature '%s' on '%s': %s", feature.DisplayName(), gw.Name, err.Error())
			log.Println(msg)
			done <- fmt.Errorf(msg)
			return
		}
		if !results.Successful() {
			msg := fmt.Sprintf("failed to install feature '%s' on '%s': %s", feature.DisplayName(), gw.Name, results.AllErrorMessages())
			log.Println(msg)
			done <- fmt.Errorf(msg)
			return
		}
		log.Println("Feature 'reverseproxy' successfully added on gateway")
	}

	log.Printf("[gateway] preparation successful")
	done <- nil
}

// asyncConfigureGateway prepares the gateway
func (c *Cluster) asyncConfigureGateway(gw *pb.Host, done chan error) {
	log.Printf("[gateway] starting configuration...")

	var dnsServers []string
	cfg, err := c.provider.GetCfgOpts()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	installCommonRequirements, err := c.getInstallCommonRequirements()
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"InstallCommonRequirements": *installCommonRequirements,
		"ClusterName":               c.Core.Name,
		"MasterIPs":                 c.manager.MasterIPs,
		"DNSServerIPs":              dnsServers,
	}
	box, err := getSWARMTemplateBox()
	if err != nil {
		done <- err
		return
	}
	retcode, _, _, err := flavortools.ExecuteScript(box, funcMap, "swarm_configure_gateway.sh", data, gw.ID)
	if err != nil {
		log.Printf("[gateway] configuration failed: %s", err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[gateway] configuration failed:\nretcode=%d", retcode)
		done <- fmt.Errorf("scripted gateway configuration failed with error code %d", retcode)
		return
	}

	log.Printf("[gateway] configuration successful")
	done <- nil
}

// getSWARMTemplateBox
func getSWARMTemplateBox() (*rice.Box, error) {
	var b *rice.Box
	var err error
	if swarmTemplateBox == nil {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../swarm/scripts")
		if err != nil {
			return nil, err
		}
		swarmTemplateBox = b
	}
	return swarmTemplateBox, nil
}

// getInstallCommonRequirements returns the string corresponding to the script swarm_install_requirements.sh
// which installs common features (docker in particular)
func (c *Cluster) getInstallCommonRequirements() (*string, error) {
	if installCommonRequirementsContent == nil {
		// find the rice.Box
		b, err := getSWARMTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := b.String("swarm_install_requirements.sh")
		if err != nil {
			return nil, fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := txttmpl.New("install_requirements").Funcs(template.MergeFuncs(funcMap, false)).Parse(tmplString)
		if err != nil {
			return nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{
			"CIDR":          c.Core.CIDR,
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

// Start starts the cluster named 'name'
func (c *Cluster) Start() error {
	state, err := c.ForceGetState()
	if err != nil {
		return err
	}
	if state == ClusterState.Stopped {
		return c.updateMetadata(func() error {
			c.Core.State = ClusterState.Nominal
			return nil
		})
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
// Does nothing currently...
func (c *Cluster) ForceGetState() (ClusterState.Enum, error) {
	c.updateMetadata(func() error {
		c.Core.State = ClusterState.Nominal
		c.lastStateCollection = time.Now()
		return nil
	})
	return c.Core.State, nil
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
	hostDef := c.GetConfig().NodesDef
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
		go c.asyncCreateNode(i+1, nodeType, hostDef, timeout, r, d)
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
			broker := brokerclient.New().Host
			for _, h := range hosts {
				broker.Delete(h, brokerclient.DefaultExecutionTimeout)
			}
		}
		return nil, fmt.Errorf("errors occured on node addition: %s", strings.Join(errors, "\n"))
	}

	// Now configure new nodes
	err := c.configureNodes(hosts)
	if err != nil {
		broker := brokerclient.New().Host
		for _, h := range hosts {
			broker.Delete(h, brokerclient.DefaultExecutionTimeout)
		}
		return nil, err
	}
	return hosts, nil
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
func (c *Cluster) DeleteSpecificNode(hostID string) error {
	var foundInPrivate bool
	foundInPublic, idx := contains(c.Core.PublicNodeIDs, hostID)
	if !foundInPublic {
		foundInPrivate, idx = contains(c.Core.PrivateNodeIDs, hostID)
	}
	if !foundInPublic && !foundInPrivate {
		return fmt.Errorf("host '%s' isn't a registered Node of the Cluster '%s'", hostID, c.Core.Name)
	}

	err := brokerclient.New().Host.Delete(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return err
	}

	return c.updateMetadata(func() error {
		if foundInPublic {
			c.Core.PublicNodeIDs = append(c.Core.PublicNodeIDs[:idx], c.Core.PublicNodeIDs[idx+1:]...)
		} else {
			c.Core.PrivateNodeIDs = append(c.Core.PrivateNodeIDs[:idx], c.Core.PrivateNodeIDs[idx+1:]...)
		}
		return nil
	})
}

// ListMasterIDs lists the master nodes in the cluster
func (c *Cluster) ListMasterIDs() []string {
	return c.manager.MasterIDs
}

// ListMasterIPs lists the master nodes in the cluster
func (c *Cluster) ListMasterIPs() []string {
	return c.manager.MasterIPs
}

// ListNodeIDs lists the IDs of the nodes in the cluster
func (c *Cluster) ListNodeIDs(public bool) []string {
	if public {
		return c.Core.PublicNodeIDs
	}
	return c.Core.PrivateNodeIDs
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
	found, _ := contains(c.Core.PublicNodeIDs, hostID)
	if !found {
		found, _ = contains(c.Core.PrivateNodeIDs, hostID)
	}
	if !found {
		return nil, fmt.Errorf("failed to find node '%s' in cluster '%s'", hostID, c.Core.Name)
	}
	return brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
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
	found, _ := contains(c.Core.PublicNodeIDs, hostID)
	if !found {
		found, _ = contains(c.Core.PrivateNodeIDs, hostID)
	}
	return found
}

// GetConfig returns the public properties of the cluster
func (c *Cluster) GetConfig() clusterapi.ClusterCore {
	return *c.Core
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
		err := provideruse.WaitSSHServerReady(c.provider, hostID, 5*time.Minute)
		if err != nil {
			if _, ok := err.(retry.ErrTimeout); ok {
				continue
			}
			return "", err
		}
		break
	}
	if hostID == "" {
		return "", fmt.Errorf("failed to find available node")
	}
	return hostID, nil
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

	broker := brokerclient.New()

	// Deletes the public nodes
	for _, n := range c.Core.PublicNodeIDs {
		broker.Host.Delete(n, brokerclient.DefaultExecutionTimeout)
	}

	// Deletes the private nodes
	for _, n := range c.Core.PrivateNodeIDs {
		broker.Host.Delete(n, brokerclient.DefaultExecutionTimeout)
	}

	// Delete the Masters
	for _, n := range c.manager.MasterIDs {
		broker.Host.Delete(n, brokerclient.DefaultExecutionTimeout)
	}

	// Deletes the network and gateway
	err = broker.Network.Delete(c.Core.NetworkID, brokerclient.DefaultExecutionTimeout)
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
