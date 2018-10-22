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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Extension"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/deploy/cluster/flavors/ohpc/enums/ErrorCode"
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

	centos = "CentOS 7.4"
)

var (
	// ohpcTemplateBox is the rice box to use in this package
	ohpcTemplateBox *rice.Box

	// funcMap defines the custome functions to be used in templates
	funcMap = txttmpl.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
		"errcode": func(msg string) int {
			if code, ok := ErrorCode.StringMap[msg]; ok {
				return int(code)
			}
			return 1023
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
	var (
		instance         Cluster
		privateNodeCount int
		gw               *providerapi.Host
		m                *providermetadata.Gateway
		// masterChannel    chan error
		// masterStatus     error
		rpChannel   chan error
		rpStatus    error
		nodesStatus error
		ok          bool
		feature     *install.Feature
		target      install.Target
		values      = install.Variables{}
		results     install.Results
		kpName      string
		kp          *providerapi.KeyPair
	)

	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password for user cladm: %s", err.Error())
	}

	nodesDef := pb.HostDefinition{
		CPUNumber: 4,
		RAM:       15.0,
		Disk:      100,
		ImageID:   centos,
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
	}
	if req.NodesDef.ImageID != "" && req.NodesDef.ImageID != centos {
		fmt.Printf("cluster Flavor OHPC enforces the use of %s distribution. OS %s ignored.\n", centos, req.NodesDef.ImageID)
		nodesDef.ImageID = centos
	}

	// Creates network
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	log.Printf("Creating Network 'net-%s'", networkName)
	def := pb.NetworkDefinition{
		Name: networkName,
		CIDR: req.CIDR,
		Gateway: &pb.GatewayDefinition{
			CPU:     2,
			RAM:     15.0,
			Disk:    60,
			ImageID: centos,
		},
	}
	broker := brokerclient.New()
	network, err := broker.Network.Create(def, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		err = brokerclient.DecorateError(err, "creation of network", true)
		log.Printf("Failed to create Network '%s': %s", networkName, err.Error())
		return nil, err
	}
	log.Printf("Network '%s' created successfully.\n", networkName)
	req.NetworkID = network.ID

	svc, err := provideruse.GetProviderService()
	if err != nil {
		goto cleanNetwork
	}

	// Create a KeyPair for the user cladm
	kpName = "cluster_" + req.Name + "_cladm_key"
	kp, err = svc.CreateKeyPair(kpName)
	if err != nil {
		err = fmt.Errorf("failed to create Key Pair: %s", err.Error())
		goto cleanNetwork
	}

	// Saving cluster parameters, with status 'Creating'
	instance = Cluster{
		Core: &clusterapi.ClusterCore{
			Name:          req.Name,
			CIDR:          req.CIDR,
			Flavor:        Flavor.OHPC,
			Keypair:       kp,
			State:         ClusterState.Creating,
			Complexity:    req.Complexity,
			Tenant:        req.Tenant,
			NetworkID:     req.NetworkID,
			AdminPassword: cladmPassword,
			NodesDef:      nodesDef,
		},
		manager:  &managerData{},
		provider: svc,
	}
	err = instance.updateMetadata(nil)
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanNetwork
	}

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

	//VPL: for now, disables unconditionally the proxycache
	req.DisabledDefaultFeatures["proxycache"] = struct{}{}
	if _, ok = req.DisabledDefaultFeatures["proxycache"]; !ok {
		feature, err = install.NewFeature("proxycache-server")
		if err != nil {
			goto cleanNetwork
		}
		target = install.NewHostTarget(pbutils.ToPBHost(gw))
		results, err = feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			goto cleanNetwork
		}
		if !results.Successful() {
			err = fmt.Errorf(results.AllErrorMessages())
			goto cleanNetwork
		}
	}

	err = instance.updateMetadata(func() error {
		instance.Core.GatewayIP = gw.GetPrivateIP()
		instance.Core.PublicIP = gw.GetAccessIP()
		instance.SetExtension(Extension.Flavor, instance.manager)
		return nil
	})
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanNetwork
	}

	switch req.Complexity {
	case Complexity.Small:
		privateNodeCount = 1
	case Complexity.Normal:
		privateNodeCount = 3
	case Complexity.Large:
		privateNodeCount = 7
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	// step 1: Launching reverseproxy installation on gateway, in parallel
	rpChannel = make(chan error)
	go instance.asyncInstallReverseProxy(gw, rpChannel)

	// Step 2: starts master creation and nodes creation
	err = instance.createMaster(&nodesDef)
	if err != nil {
		goto cleanNetwork
	}

	// // step 2: configure master asynchronously
	// masterChannel = make(chan error)
	// go instance.asyncConfigureMasters(masterChannel)

	// Step 3: starts node creation asynchronously
	_, nodesStatus = instance.AddNodes(privateNodeCount, false, &nodesDef)
	if nodesStatus != nil {
		err = nodesStatus
		goto cleanNodes
	}

	// Waits reverseproxy installation ended
	rpStatus = <-rpChannel
	if rpStatus != nil {
		err = rpStatus
		goto cleanNodes
	}

	// // Waits master configuretion ended
	// masterStatus = <-masterChannel
	// if masterStatus != nil {
	// 	err = masterStatus
	// 	goto cleanNodes
	// }

	// Cluster created and configured successfully, saving again to Metadata
	err = instance.updateMetadata(func() error {
		instance.Core.State = ClusterState.Created
		return nil
	})
	if err != nil {
		goto cleanNodes
	}

	// Install feature ohpc-slurm-master on cluster...
	feature, err = install.NewFeature("ohpc-slurm-master")
	if err != nil {
		goto cleanNodes
	}
	target = install.NewClusterTarget(&instance)
	values = install.Variables{
		"PrimaryMasterIP":   instance.manager.MasterIPs[0],
		"SecondaryMasterIP": "",
	}
	if len(instance.manager.MasterIPs) > 1 {
		values["SecondaryMasterIP"] = instance.manager.MasterIPs[1]
	}
	results, err = feature.Add(target, values, install.Settings{})
	if err != nil {
		goto cleanNodes
	}
	if !results.Successful() {
		err = fmt.Errorf(results.AllErrorMessages())
		goto cleanNodes
	}

	// Install feature ohpc-slurm-node on cluster...
	feature, err = install.NewFeature("ohpc-slurm-node")
	if err != nil {
		goto cleanNodes
	}
	results, err = feature.Add(target, values, install.Settings{})
	if err != nil {
		goto cleanNodes
	}
	if !results.Successful() {
		err = fmt.Errorf(results.AllErrorMessages())
		goto cleanNodes
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
		for _, id := range instance.manager.MasterIDs {
			broker.Host.Delete(id, brokerclient.DefaultExecutionTimeout)
		}
	}
cleanNetwork:
	if !req.KeepOnFailure {
		broker.Network.Delete(instance.Core.NetworkID, brokerclient.DefaultExecutionTimeout)
		instance.metadata.Delete()
	}
	return nil, err
}

// createMaster creates an host acting as a master in the cluster
func (c *Cluster) createMaster(req *pb.HostDefinition) error {
	log.Println("[master #1] starting creation...")

	// Create the host
	var err error
	req.Name = c.Core.Name + "-master-1"
	req.Public = false
	req.Network = c.Core.NetworkID
	host, err := brokerclient.New().Host.Create(*req, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		err = brokerclient.DecorateError(err, "creation of host", true)
		log.Printf("[master #1] creation failed: %s\n", err.Error())
		return err
	}

	// Registers the new master in the cluster struct
	err = c.updateMetadata(func() error {
		c.manager.MasterIDs = append(c.manager.MasterIDs, host.ID)
		c.manager.MasterIPs = append(c.manager.MasterIPs, host.PRIVATE_IP)
		return nil
	})
	if err != nil {
		c.manager.MasterIDs = c.manager.MasterIDs[:len(c.manager.MasterIDs)-1]
		c.manager.MasterIPs = c.manager.MasterIPs[:len(c.manager.MasterIPs)-1]
		brokerclient.New().Host.Delete(host.ID, brokerclient.DefaultExecutionTimeout)
		log.Printf("[Master #1] creation failed: %s", err.Error())
		return err
	}

	target := install.NewHostTarget(host)

	//VPL: for now disables unconditionally proxycache
	c.Core.DisabledFeatures["proxycache"] = struct{}{}
	if _, ok := c.Core.DisabledFeatures["proxycache"]; !ok {
		// install proxycache-client feature
		feature, err := install.NewFeature("proxycache-client")
		if err != nil {
			log.Printf("[master #%d (%s)] failed to prepare feature 'proxycache-client': %s", 1, host.ID, err.Error())
			return fmt.Errorf("failed to add feature 'proxycache-client': %s", err.Error())
		}
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Printf("[master #%d (%s)] failed to install feature '%s': %s\n", 1, host.Name, feature.DisplayName(), err.Error())
			return fmt.Errorf("failed to add feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Printf("[master #%d (%s)] failed to add feature '%s': %s", 1, host.Name, feature.DisplayName(), msg)
			return fmt.Errorf(msg)
		}
	}

	// Installs OHPC requirements...
	installCommonRequirements, err := c.getInstallCommonRequirements()
	if err != nil {
		return err
	}
	data := map[string]interface{}{
		"InstallCommonRequirements": *installCommonRequirements,
		"CladmPassword":             c.Core.AdminPassword,
	}
	box, err := getOHPCTemplateBox()
	if err != nil {
		return err
	}
	retcode, _, _, err := flavortools.ExecuteScript(box, funcMap, "ohpc_install_master.sh", data, host.ID)
	if err != nil {
		log.Printf("[master #%d (%s)] failed to remotely run installation script: %s\n", 1, host.Name, err.Error())
		return err
	}
	if retcode != 0 {
		if retcode == 255 {
			log.Printf("[master #%d (%s)] remote connection failed", 1, host.Name)
			return fmt.Errorf("remote connection failed on master '%s'", host.Name)
		}
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[master #%d (%s)] installation failed:\nretcode=%d (%s)", 1, host.Name, errcode, errcode.String())
			return fmt.Errorf("scripted installation failed on master '%s' (retcode=%d=%s)", host.Name, errcode, errcode.String())
		}
		log.Printf("[master #%d (%s)] installation failed (retcode=%d)", 1, host.Name, retcode)
		return fmt.Errorf("scripted installation failed on master '%s' (retcode=%d)", host.Name, retcode)
	}

	// install docker feature
	feature, err := install.NewFeature("docker")
	if err != nil {
		log.Printf("[master #%d (%s)] failed to prepare feature 'docker': %s", 1, host.ID, err.Error())
		return fmt.Errorf("failed to install feature 'docker': %s", err.Error())
	}
	results, err := feature.Add(target, install.Variables{
		"Hostname": host.Name,
		"Username": "cladm",
		"Password": c.Core.AdminPassword,
	}, install.Settings{})
	if err != nil {
		log.Printf("[master #%d (%s)] failed to install feature '%s': %s\n", 1, host.Name, feature.DisplayName(), err.Error())
		return fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Printf("[master #%d (%s)] failed to install feature '%s': %s", 1, host.Name, feature.DisplayName(), msg)
		return fmt.Errorf(msg)
	}

	log.Printf("[master #%d (%s)] creation successful", 1, host.Name)
	return nil
}

// func (c *Cluster) createNodes(count int, public bool, def pb.HostDefinition) error {
// 	var countS string
// 	if count > 1 {
// 		countS = "s"
// 	}
// 	var nodeType NodeType.Enum
// 	var nodeTypeStr string
// 	if public {
// 		nodeType = NodeType.PublicNode
// 		nodeTypeStr = "public"
// 	} else {
// 		nodeType = NodeType.PrivateNode
// 		nodeTypeStr = "private"
// 	}
// 	fmt.Printf("Creating %d %s Node%s...\n", count, nodeTypeStr, countS)

// 	var dones []chan error
// 	var results []chan string
// 	for i := 1; i <= count; i++ {
// 		d := make(chan error)
// 		dones = append(dones, d)
// 		r := make(chan string)
// 		results = append(results, r)
// 		go c.asyncCreateNode(i, nodeType, def, r, d)
// 	}

// 	var state error
// 	var errors []string
// 	for i := range dones {
// 		<-results[i]
// 		state = <-dones[i]
// 		if state != nil {
// 			errors = append(errors, state.Error())
// 		}
// 	}
// 	if len(errors) > 0 {
// 		return fmt.Errorf(strings.Join(errors, "\n"))
// 	}

// 	return nil
// }

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
	var err error
	req.Name, err = c.buildHostname("node", nodeType)
	if err != nil {
		log.Printf("[%s node #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}
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

	// Registers the new Agent in the cluster struct
	err = c.updateMetadata(func() error {
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

	target := install.NewHostTarget(host)

	//VPL: for now, disables unconditionally proxycache
	c.Core.DisabledFeatures["proxycache"] = struct{}{}
	if _, ok := c.Core.DisabledFeatures["proxycache"]; !ok {
		// install proxycache-client feature
		feature, err := install.NewFeature("proxycache-client")
		if err != nil {
			log.Printf("[master #%d (%s)] failed to prepare feature 'proxycache-client': %s", 1, host.ID, err.Error())
			done <- fmt.Errorf("failed to install feature 'proxycache-client': %s", err.Error())
			return
		}
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Printf("[master #%d (%s)] failed to install feature '%s': %s\n", 1, host.Name, feature.DisplayName(), err.Error())
			done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
			return
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Printf("[master #%d (%s)] failed to install feature '%s': %s", 1, host.Name, feature.DisplayName(), msg)
			done <- fmt.Errorf(msg)
			return
		}
	}

	// Installs OHPC requirements
	installCommonRequirements, err := c.getInstallCommonRequirements()
	if err != nil {
		done <- err
		return
	}
	data := map[string]interface{}{
		"InstallCommonRequirements": *installCommonRequirements,
		"CladmPassword":             c.Core.AdminPassword,
	}
	box, err := getOHPCTemplateBox()
	if err != nil {
		done <- err
		return
	}
	retcode, _, _, err := flavortools.ExecuteScript(box, funcMap, "ohpc_install_node.sh", data, host.ID)
	if err != nil {
		log.Printf("[%s node #%d (%s)] failed to remotely run installation script: %s\n", nodeTypeStr, index, host.Name, err.Error())
		result <- ""
		done <- err
		return
	}
	if retcode != 0 {
		result <- ""
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[%s node #%d (%s)] installation failed: retcode: %d (%s)", nodeTypeStr, index, host.Name, errcode, errcode.String())
			done <- fmt.Errorf("scripted Node configuration failed with error code %d (%s)", errcode, errcode.String())
		} else {
			log.Printf("[%s node #%d (%s)] installation failed: retcode=%d", nodeTypeStr, index, host.Name, retcode)
			done <- fmt.Errorf("scripted Agent configuration failed with error code %d", retcode)
		}
		return
	}

	// install docker feature
	feature, err := install.NewFeature("docker")
	if err != nil {
		log.Printf("[master #%d (%s)] failed to prepare feature 'docker': %s", 1, host.ID, err.Error())
		done <- fmt.Errorf("failed to install feature 'docker': %s", err.Error())
		return
	}
	results, err := feature.Add(target, install.Variables{
		"Hostname": host.Name,
		"Username": "cladm",
		"Password": c.Core.AdminPassword,
	}, install.Settings{})
	if err != nil {
		log.Printf("[master #%d (%s)] failed to install feature '%s': %s\n", 1, host.Name, feature.DisplayName(), err.Error())
		done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
		return
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Printf("[master #%d (%s)] failed to install feature '%s': %s", 1, host.Name, feature.DisplayName(), msg)
		done <- fmt.Errorf(msg)
		return
	}

	log.Printf("[%s node #%d (%s)] creation successful\n", nodeTypeStr, index, host.Name)
	result <- host.ID
	done <- nil
}

// getOHPCTemplateBox
func getOHPCTemplateBox() (*rice.Box, error) {
	var b *rice.Box
	var err error
	if ohpcTemplateBox == nil {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../ohpc/scripts")
		if err != nil {
			return nil, err
		}
		ohpcTemplateBox = b
	}
	return ohpcTemplateBox, nil
}

// getInstallCommonRequirements returns the string corresponding to the script ohpc_install_requirements.sh
// which installs common features
func (c *Cluster) getInstallCommonRequirements() (*string, error) {
	if installCommonRequirementsContent == nil {
		// find the rice.Box
		b, err := getOHPCTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := b.String("ohpc_install_requirements.sh")
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
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return c.Core.Name + "-" + coreName + "-" + strconv.Itoa(index), nil
}

// asyncInstallReverseProxy installs the feature reverseproxy on network gateway
func (c *Cluster) asyncInstallReverseProxy(host *providerapi.Host, done chan error) {
	err := provideruse.WaitSSHServerReady(c.provider, host.ID, 5*time.Minute)
	if err != nil {
		done <- err
		return
	}
	target := install.NewHostTarget(pbutils.ToPBHost(host))
	feature, err := install.NewFeature("reverseproxy")
	if err != nil {
		done <- err
		return
	}
	results, err := feature.Add(target, install.Variables{}, install.Settings{})
	if err != nil {
		done <- fmt.Errorf("failed to execute installation of feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, err.Error())
		return
	}
	if !results.Successful() {
		done <- fmt.Errorf("failed to install feature '%s' on host '%s': %s", feature.DisplayName(), host.Name, results.AllErrorMessages())
		return
	}
	done <- nil
}

// // asyncConfigureMasters configure masters
// func (c *Cluster) asyncConfigureMasters(done chan error) {
// 	var (
// 		dones  []chan error
// 		errors []string
// 	)
// 	for i, id := range c.manager.MasterIDs {
// 		d := make(chan error)
// 		dones = append(dones, d)
// 		go c.asyncConfigureMaster(i+1, id, d)
// 	}
// 	for _, d := range dones {
// 		err := <-d
// 		if err != nil {
// 			errors = append(errors, err.Error())
// 		}
// 	}
// 	if len(errors) > 0 {
// 		msg := strings.Join(errors, "\n")
// 		done <- fmt.Errorf("failed to configure masters: %s", msg)
// 		return
// 	}

// 	log.Println("Masters configured successfully")
// 	done <- nil
// }

// // asyncConfigureMaster configure one master
// func (c *Cluster) asyncConfigureMaster(index int, id string, done chan error) {
// 	log.Printf("[master #%d] starting configuration...\n", index)

// 	// remotedekstop is a feature, can be added after master creation; should be automatically install
// 	// in perform, not deploy
// 	// Installs remotedesktop feature on host
// 	feature, err := install.NewFeature("remotedesktop")
// 	if err != nil {
// 		log.Printf("[master #%d] failed to find feature 'remotedesktop': %s\n", index, err.Error())
// 		done <- fmt.Errorf("[master #%d] %s", index, err.Error())
// 		return
// 	}
// 	broker := brokerclient.New().Host
// 	host, err := broker.Inspect(id, brokerclient.DefaultExecutionTimeout)
// 	if err != nil {
// 		err = brokerclient.DecorateError(err, "inspection of host", false)
// 		done <- fmt.Errorf("[master #%d] %s", index, err.Error())
// 		return
// 	}
// 	target := install.NewHostTarget(host)
// 	results, err := feature.Add(target, install.Variables{
// 		"GatewayIP": c.Core.GatewayIP,
// 		"Hostname":  host.Name,
// 		"HostIP":    host.PRIVATE_IP,
// 		"Username":  "cladm",
// 		"Password":  c.Core.AdminPassword,
// 	}, install.Settings{})
// 	if err != nil {
// 		done <- fmt.Errorf("[master #%d (%s)] failed to install feature '%s': %s", index, host.Name, feature.DisplayName(), err.Error())
// 		return
// 	}
// 	if !results.Successful() {
// 		msg := results.AllErrorMessages()
// 		log.Printf("[master #%d (%s)] installation script of feature '%s' failed: %s\n", index, host.Name, feature.DisplayName(), msg)
// 		done <- fmt.Errorf(msg)
// 		return
// 	}

// 	log.Printf("[master #%d (%s)] configuration successful\n", index, host.Name)
// 	done <- nil
// }

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

//GetState returns the current state of the cluster
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
	request := c.GetConfig().NodesDef
	if req != nil {
		if req.CPUNumber > 0 {
			request.CPUNumber = req.CPUNumber
		}
		if req.RAM > 0.0 {
			request.RAM = req.RAM
		}
		if req.Disk > 0 {
			request.Disk = req.Disk
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
		go c.asyncCreateNode(i+1, nodeType, request, timeout, r, d)
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
			dones := []chan uint8{}
			for _, hostID := range hosts {
				d := make(chan uint8)
				dones = append(dones, d)
				go func() {
					broker.Delete(hostID, brokerclient.DefaultExecutionTimeout)
					d <- 0
				}()
				for i := range hosts {
					<-dones[i]
				}
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
		hostID = c.Core.PublicNodeIDs[len(c.Core.PublicNodeIDs)-1]
	} else {
		hostID = c.Core.PrivateNodeIDs[len(c.Core.PrivateNodeIDs)-1]
	}
	err := brokerclient.New().Host.Delete(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		if status.Code(err) == codes.DeadlineExceeded {
			return fmt.Errorf("deletion of host took too long to respond (may eventually succeed)")
		}
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
		return brokerclient.DecorateError(err, "deletion of host", true)
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
	_, err := brokerclient.New().Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		err = brokerclient.DecorateError(err, "inspection of host", false)
	}
	return nil, err
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
	if c.manager != nil {
		for _, n := range c.manager.MasterIDs {
			broker.Host.Delete(n, brokerclient.DefaultExecutionTimeout)
		}
	}

	// Deletes the network and gateway
	err = broker.Network.Delete(c.Core.NetworkID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return brokerclient.DecorateError(err, "deletion of network", true)
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
