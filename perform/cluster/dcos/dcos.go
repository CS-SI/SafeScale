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

	clusterapi "github.com/CS-SI/SafeScale/perform/cluster/api"
	"github.com/CS-SI/SafeScale/perform/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Flavor"
	"github.com/CS-SI/SafeScale/perform/cluster/api/NodeType"
	"github.com/CS-SI/SafeScale/perform/cluster/components"
	"github.com/CS-SI/SafeScale/perform/cluster/metadata"
	"github.com/CS-SI/SafeScale/providers"
	providerapi "github.com/CS-SI/SafeScale/providers/api"
	providermetadata "github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/utils"

	pb "github.com/CS-SI/SafeScale/broker"
)

//go:generate rice embed-go

const (
	dcosVersion string = "1.11.1"

	timeoutCtxVM = 10 * time.Minute

	bootstrapHTTPPort = 10080

	tempFolder = "/var/tmp/"
)

var (
	// templateBox is the rice box to use in this package
	templateBox *rice.Box

	//installCommonsContent contains the script to install/configure common components
	installCommonsContent *string

	//funcMap defines the custome functions to be used in templates
	funcMap = template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	}
)

//Specific defines the values specific to DCOS cluster we want to keep in Object Storage
type Specific struct {

	//BootstrapID is the identifier of the VM acting as bootstrap/upgrade server
	BootstrapID string

	//BootstrapIP contains the IP of the bootstrap server reachable by all master and agents
	BootstrapIP string

	//MasterIDs is a slice of VMIDs of the master
	MasterIDs []string

	//masterIPs contains a list of IP of the master servers
	MasterIPs []string

	//PublicNodeIPs contains a list of IP of the Public Agent nodes
	PublicNodeIPs []string

	//PrivateAvgentIPs contains a list of IP of the Private Agent Nodes
	PrivateNodeIPs []string

	//StateCollectInterval in seconds
	StateCollectInterval time.Duration
}

//Cluster is the object describing a cluster created by ClusterManagerAPI.CreateCluster
type Cluster struct {
	// common cluster data
	Common *clusterapi.Cluster

	//contains data defining the cluster
	*Specific

	//LastStateCollect contains the date of the last state collection
	lastStateCollection time.Time

	//metadata of cluster
	metadata *metadata.Cluster

	//provider is a pointer to current provider service instance
	provider *providers.Service
}

//GetNetworkID returns the ID of the network used by the cluster
func (c *Cluster) GetNetworkID() string {
	return c.Common.GetNetworkID()
}

//CountNodes returns the number of public or private nodes in the cluster
func (c *Cluster) CountNodes(public bool) uint {
	return c.Common.CountNodes(public)
}

//Load loads the internals of an existing cluster from metadata
func Load(data *metadata.Cluster) (clusterapi.ClusterAPI, error) {
	svc, err := utils.GetProviderService()
	if err != nil {
		return nil, err
	}

	common, anon := data.Get()
	specific := anon.(Specific)
	instance := &Cluster{
		Common:   common,
		Specific: &specific,
		metadata: data,
		provider: svc,
	}
	return instance, nil
}

//Create creates the necessary infrastructure of cluster
func Create(req clusterapi.Request) (clusterapi.ClusterAPI, error) {
	// Creates network
	log.Printf("Creating Network 'net-%s'", req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	network, err := utils.CreateNetwork(networkName, req.CIDR, &pb.GatewayDefinition{
		CPU:     4,
		RAM:     32.0,
		Disk:    120,
		ImageID: "CentOS 7.3",
		Name:    req.Name + "-dcosbootstrap",
	})
	if err != nil {
		err = fmt.Errorf("Failed to create Network '%s': %s", networkName, err.Error())
		return nil, err
	}
	req.NetworkID = network.ID

	// Saving cluster parameters, with status 'Creating'
	var instance Cluster
	var masterCount int
	var privateNodeCount int
	var kp *providerapi.KeyPair
	var kpName string
	var gw *providerapi.VM
	var m *providermetadata.Gateway
	var found bool
	var bootstrapChannel chan error
	var mastersChannel chan error
	var nodesChannel chan error
	var bootstrapStatus error
	var mastersStatus error
	var nodesStatus error

	nodesDef := pb.VMDefinition{
		CPUNumber: 4,
		RAM:       16.0,
		Disk:      100,
		ImageID:   "Centos 7.3",
	}

	svc, err := utils.GetProviderService()
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
	instance = Cluster{
		Common: &clusterapi.Cluster{
			Name:       req.Name,
			CIDR:       req.CIDR,
			Flavor:     Flavor.DCOS,
			State:      ClusterState.Creating,
			Complexity: req.Complexity,
			Tenant:     req.Tenant,
			NetworkID:  req.NetworkID,
			Keypair:    kp,
		},
		Specific: &Specific{
			BootstrapID: gw.ID,
			BootstrapIP: gw.PrivateIPsV4[0],
		},
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
	mastersChannel = make(chan error)
	go instance.asyncCreateMasters(masterCount, mastersChannel)

	nodesChannel = make(chan error)
	go instance.asyncCreateNodes(privateNodeCount, false, &nodesDef, nodesChannel)

	// Step 2: awaits masters creation and bootstrap configuration coroutines
	mastersStatus = <-mastersChannel
	//log.Println("Checkpoint: Masters created.")

	// Step 3: starts bootstrap configuration, if masters have been created
	//         successfully
	if mastersStatus == nil {
		bootstrapChannel = make(chan error)
		go instance.asyncConfigureBootstrap(bootstrapChannel)

		bootstrapStatus = <-bootstrapChannel
		//log.Println("Checkpoint: Bootstrap configured.")
	}

	if bootstrapStatus == nil && mastersStatus == nil {
		mastersChannel = make(chan error)
		go instance.asyncConfigureMasters(mastersChannel)
	}

	nodesStatus = <-nodesChannel
	//	log.Println("Checkpoint: Nodes created.")

	// Starts nodes configuration, if all masters and nodes
	// have been created and bootstrap has been configured with success
	if bootstrapStatus == nil && mastersStatus == nil && nodesStatus == nil {
		nodesChannel = make(chan error)
		go instance.asyncConfigurePrivateNodes(nodesChannel)
		nodesStatus = <-nodesChannel
		//log.Println("Checkpoint: Nodes configured.")
	}

	if bootstrapStatus == nil && mastersStatus == nil {
		mastersStatus = <-mastersChannel
		//log.Println("Checkpoint: Masters configured.")
	}
	if bootstrapStatus == nil && mastersStatus == nil && nodesStatus == nil {
		_, err = instance.installKubernetes()
		if err != nil {
			goto cleanNodes
		}
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

	/*
		_, err = instance.ForceGetState()
		if err != nil {
			return nil, err
		}
	*/
	//	log.Printf("Cluster '%s' created and initialized successfully", req.Name)
	return &instance, nil

cleanNodes:
	//for _, id := range instance.Specific.PublicNodeIDs {
	//	utils.DeleteVM(id)
	//}
	//for _, id := range instance.Specific.PrivateNodeIDs {
	//	utils.DeleteVM(id)
	//}
cleanMasters:
	//for _, id := range instance.Specific.MasterIDs {
	//	utils.DeleteVM(id)
	//}
cleanNetwork:
	//utils.DeleteNetwork(instance.Common.NetworkID)
	//instance.RemoveMetadata()
	return nil, err
}

func (c *Cluster) asyncCreateNodes(count int, public bool, def *pb.VMDefinition, done chan error) {
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
			&pb.VMDefinition{
				CPUNumber: 4,
				RAM:       16.0,
				Disk:      100,
				ImageID:   "Centos 7.3",
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
	for i, vmID := range c.Common.PrivateNodeIDs {
		d := make(chan error)
		dones = append(dones, d)
		go c.asyncConfigureNode(i+1, vmID, NodeType.PrivateNode, d)
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

//asyncCreateMasters
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

//asyncConfigureMasters configure masters
func (c *Cluster) asyncConfigureMasters(done chan error) {
	fmt.Println("Configuring DCOS masters...")

	dones := []chan error{}
	for i, vmID := range c.Specific.MasterIDs {
		d := make(chan error)
		dones = append(dones, d)
		go c.asyncConfigureMaster(i+1, vmID, d)
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

//createAndConfigureNode creates and configure a Node
func (c *Cluster) createAndConfigureNode(public bool, req *pb.VMDefinition) (string, error) {
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
	vmID := <-result
	err := <-done
	if err != nil {
		return "", err
	}
	close(done)
	done = make(chan error)
	go c.asyncConfigureNode(1, vmID, nodeType, done)
	err = <-done
	if err != nil {
		return "", err
	}
	return vmID, nil
}

//asyncCreateMaster adds a master node
func (c *Cluster) asyncCreateMaster(index int, done chan error) {
	log.Printf("[Masters: #%d] starting creation...\n", index)

	name := c.Common.Name + "-dcosmaster-" + strconv.Itoa(index)

	masterVM, err := utils.CreateVM(&pb.VMDefinition{
		Name:      name,
		CPUNumber: 4,
		RAM:       16.0,
		Disk:      60,
		ImageID:   "CentOS 7.3",
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
	c.Specific.MasterIDs = append(c.Specific.MasterIDs, masterVM.ID)
	c.Specific.MasterIPs = append(c.Specific.MasterIPs, masterVM.IP)

	// Update cluster definition in Object Storage
	err = c.updateMetadata()
	if err != nil {
		// Object Storage failed, removes the ID we just added to the cluster struct
		c.Specific.MasterIDs = c.Specific.MasterIDs[:len(c.Specific.MasterIDs)-1]
		c.Specific.MasterIPs = c.Specific.MasterIPs[:len(c.Specific.MasterIPs)-1]
		c.metadata.Release()
		utils.DeleteVM(masterVM.ID)

		log.Printf("[Masters: #%d] creation failed: %s\n", index, err.Error())
		done <- fmt.Errorf("failed to update Cluster definition: %s", err.Error())
		return
	}

	log.Printf("[Masters: #%d] creation successful", index)
	c.metadata.Release()
	done <- nil
}

//asyncConfigureMaster configure DCOS on master
func (c *Cluster) asyncConfigureMaster(index int, masterID string, done chan error) {
	log.Printf("[Masters: #%d (%s)] starting configuration...\n", index, masterID)

	ssh, err := c.provider.GetSSHConfig(masterID)
	if err != nil {
		done <- err
		return
	}
	retcode, output, err := c.executeScript(ssh, "dcos_install_master_node.sh", map[string]interface{}{
		"BootstrapIP":   c.Specific.BootstrapIP,
		"BootstrapPort": bootstrapHTTPPort,
		"ClusterName":   c.Common.Name,
		"MasterIndex":   index,
	})
	if err != nil {
		log.Printf("[Masters: #%d (%s)] configuration failed: %s\n", index, masterID, err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[Masters: #%d (%s)] configuration failed:\nretcode=%d\n%s\n", index, masterID, retcode, *output)
		done <- fmt.Errorf("scripted Master configuration failed with error code %d:\n%s", retcode, *output)
		return
	}

	log.Printf("[Masters: #%d (%s)] configuration successful\n", index, masterID)
	done <- nil
}

//asyncCreateNode creates a Node in the cluster
// This function is intended to be call as a goroutine
func (c *Cluster) asyncCreateNode(index int, nodeType NodeType.Enum, req *pb.VMDefinition, result chan string, done chan error) {
	var publicIP bool
	var count int
	var nodeTypeStr string
	coreName := "node"
	if nodeType == NodeType.PublicNode {
		nodeTypeStr = "public"
		publicIP = true
		coreName = "pub" + coreName
		count = len(c.Common.PublicNodeIDs)
	} else {
		nodeTypeStr = "private"
		publicIP = false
		coreName = "priv" + coreName
		count = len(c.Common.PrivateNodeIDs)
	}
	log.Printf("[Nodes: %s #%d] starting creation...\n", nodeTypeStr, index)

	req.Public = publicIP
	req.Network = c.Common.NetworkID
	req.Name = c.Common.Name + "-dcos" + coreName + "-" + strconv.Itoa(count+1)
	req.ImageID = "CentOS 7.3"
	vm, err := utils.CreateVM(req)
	if err != nil {
		log.Printf("[Nodes: %s #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}

	// Registers the new Agent in the cluster struct
	c.metadata.Acquire()
	if nodeType == NodeType.PublicNode {
		c.Common.PublicNodeIDs = append(c.Common.PublicNodeIDs, vm.ID)
		c.Specific.PublicNodeIPs = append(c.Specific.PublicNodeIPs, vm.IP)
	} else {
		c.Common.PrivateNodeIDs = append(c.Common.PrivateNodeIDs, vm.ID)
		c.Specific.PrivateNodeIPs = append(c.Specific.PrivateNodeIPs, vm.IP)
	}

	// Update cluster definition in Object Storage
	err = c.metadata.Write()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		if nodeType == NodeType.PublicNode {
			c.Common.PublicNodeIDs = c.Common.PublicNodeIDs[:len(c.Common.PublicNodeIDs)-1]
			c.Specific.PublicNodeIPs = c.Specific.PublicNodeIPs[:len(c.Specific.PublicNodeIPs)-1]
		} else {
			c.Common.PrivateNodeIDs = c.Common.PrivateNodeIDs[:len(c.Common.PrivateNodeIDs)-1]
			c.Specific.PrivateNodeIPs = c.Specific.PrivateNodeIPs[:len(c.Specific.PrivateNodeIPs)-1]
		}
		utils.DeleteVM(vm.ID)
		c.metadata.Release()
		log.Printf("[Nodes: %s #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- fmt.Errorf("failed to update Cluster definition: %s", err.Error())
		return
	}

	log.Printf("[Nodes: %s #%d] creation successful\n", nodeTypeStr, index)
	c.metadata.Release()
	result <- vm.ID
	done <- nil
}

//asyncConfigureNode installs and configure DCOS agent on targetVM
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
	retcode, output, err := c.executeScript(ssh, "dcos_install_agent_node.sh", map[string]interface{}{
		"PublicNode":    publicStr,
		"BootstrapIP":   c.Specific.BootstrapIP,
		"BootstrapPort": bootstrapHTTPPort,
	})
	if err != nil {
		log.Printf("[Nodes: %s #%d (%s)] configuration failed: %s\n", nodeTypeStr, index, nodeID, err.Error())
		done <- err
		return
	}
	if retcode != 0 {
		log.Printf("[Nodes: %s #%d (%s)] configuration failed: %s\n", nodeTypeStr, index, nodeID, *output)
		done <- fmt.Errorf("scripted Agent configuration failed with error code %d:\n%s", retcode, *output)
		return
	}

	log.Printf("[Nodes: %s #%d (%s)] configuration successful\n", nodeTypeStr, index, nodeID)
	done <- nil
}

//asyncConfigureBootstrap prepares the bootstrap
func (c *Cluster) asyncConfigureBootstrap(done chan error) {
	log.Printf("[Bootstrap] starting configuration...")

	ssh, err := c.provider.GetSSHConfig(c.Specific.BootstrapID)
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
	retcode, output, err := c.executeScript(ssh, "dcos_install_bootstrap_node.sh", map[string]interface{}{
		"DCOSVersion":   dcosVersion,
		"BootstrapIP":   c.Specific.BootstrapIP,
		"BootstrapPort": bootstrapHTTPPort,
		"ClusterName":   c.Common.Name,
		"MasterIPs":     c.Specific.MasterIPs,
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
		log.Printf("[Bootstrap] configuration failed:\nretcode=%d:\n%s", retcode, *output)
		done <- fmt.Errorf("scripted Bootstrap configuration failed with error code %d:\n%s", retcode, *output)
		return
	}

	log.Printf("[Bootstrap] configuration sucessful")
	done <- nil
}

//GetName returns the name of the cluster
func (c *Cluster) GetName() string {
	return c.Common.Name
}

//getTemplateBox
func getTemplateBox() (*rice.Box, error) {
	if templateBox == nil {
		b, err := rice.FindBox("../dcos/scripts")
		if err != nil {
			return nil, err
		}
		templateBox = b
	}
	return templateBox, nil
}

//getInstallCommons returns the string corresponding to the script dcos_install_node_commons.sh
// which installs common components (docker in particular)
func getInstallCommons() (*string, error) {
	if installCommonsContent == nil {
		// find the rice.Box
		b, err := getTemplateBox()
		if err != nil {
			return nil, err
		}

		// get file contents as string
		tmplString, err := b.String("dcos_install_node_commons.sh")
		if err != nil {
			return nil, fmt.Errorf("error loading script template: %s", err.Error())
		}

		// parse then execute the template
		tmplPrepared, err := template.New("install_commons").Funcs(funcMap).Parse(tmplString)
		if err != nil {
			return nil, fmt.Errorf("error parsing script template: %s", err.Error())
		}
		dataBuffer := bytes.NewBufferString("")
		err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{})
		if err != nil {
			return nil, fmt.Errorf("error realizing script template: %s", err.Error())
		}
		result := dataBuffer.String()
		installCommonsContent = &result
	}
	return installCommonsContent, nil
}

//Start starts the cluster named 'name'
func (c *Cluster) Start() error {
	state, _ := c.ForceGetState()
	if state == ClusterState.Stopped {
		// 1st starts the masters
		// 2nd start the private nodes
		// 2rd start the public nodes
		// 4th update metadata
		c.updateMetadata()
	}
	return fmt.Errorf("Can't start an already started cluster")
}

//Stop stops the cluster is its current state is compatible
func (c *Cluster) Stop() error {
	state, _ := c.ForceGetState()
	if state != ClusterState.Stopped && state != ClusterState.Creating {
		return c.Stop()
	}
	return nil
}

//GetState returns the current state of the cluster
func (c *Cluster) GetState() (ClusterState.Enum, error) {
	now := time.Now()
	if now.After(c.lastStateCollection.Add(c.Specific.StateCollectInterval)) {
		return c.ForceGetState()
	}
	return c.Common.State, nil
}

//ForceGetState returns the current state of the cluster
// This method will trigger a effective state collection at each call
func (c *Cluster) ForceGetState() (ClusterState.Enum, error) {
	var retcode int
	var ran bool // Tells if command has been run on remote host
	var out []byte

	cmd := "/opt/mesosphere/bin/dcos-diagnostics --diag || /opt/mesosphere/bin/3dt --diag"
	for _, id := range c.Specific.MasterIDs {
		ssh, err := c.provider.GetSSHConfig(id)
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

//AddNode adds one node
func (c *Cluster) AddNode(public bool, req *pb.VMDefinition) (string, error) {
	vms, err := c.AddNodes(1, public, req)
	if err != nil {
		return "", err
	}
	return vms[0], nil
}

//AddNodes adds <count> nodes
func (c *Cluster) AddNodes(count int, public bool, req *pb.VMDefinition) ([]string, error) {
	if c.Common.State != ClusterState.Created && c.Common.State != ClusterState.Nominal {
		return nil, fmt.Errorf("The DCOS flavor of Cluster needs to be at least in state 'Created' to allow node addition.")
	}

	var vms []string
	var errors []string
	var dones []chan error
	var results []chan string
	for i := 0; i < count; i++ {
		r := make(chan string)
		results = append(results, r)
		d := make(chan error)
		dones = append(dones, d)
		go func(result chan string, done chan error) {
			vmID, err := c.createAndConfigureNode(public, req)
			if err != nil {
				result <- ""
				done <- err
				return
			}
			result <- vmID
			done <- nil
		}(r, d)
	}
	for i := range dones {
		vm := <-results[i]
		if vm != "" {
			vms = append(vms, vm)
		}
		err := <-dones[i]
		if err != nil {
			errors = append(errors, err.Error())
		}

	}
	if len(errors) > 0 {
		if len(vms) > 0 {
			for _, vmID := range vms {
				utils.DeleteVM(vmID)
			}
		}
		return nil, fmt.Errorf("errors occured on node addition: %s", strings.Join(errors, "\n"))
	}

	return vms, nil
}

//installKubernetes does the needed to have Kubernetes in DCOS
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
	for _, masterID := range c.Specific.MasterIDs {
		ssh, err = c.provider.GetSSHConfig(masterID)
		if err != nil {
			return nil, fmt.Errorf("failed to read SSH config: %s", err.Error())
		}
		//ssh.WaitServerReady(60 * time.Second)
		break
	}
	if ssh == nil {
		return nil, fmt.Errorf("failed to find available master")
	}
	return ssh, nil
}

func uploadTemplateAsFile(ssh *system.SSHConfig, name string, path string) error {
	b, err := getTemplateBox()
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

//installSpark does the needed to have Spark installed in DCOS
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

//installElastic does the needed to have Spark installed in DCOS
func (c *Cluster) installElastic() (int, error) {
	var ssh *system.SSHConfig
	var err error
	for _, masterID := range c.Specific.MasterIDs {
		ssh, err = c.provider.GetSSHConfig(masterID)
		if err != nil {
			return 0, fmt.Errorf("failed to read SSH config: %s", err.Error())
		}
		break
	}
	if ssh == nil {
		return 0, fmt.Errorf("failed to find available master")
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

//uploadDockerImageBuildScripts creates the string corresponding to script
// used to prepare Docker images on Bootstrap server
func (c *Cluster) uploadDockerImageBuildScripts(ssh *system.SSHConfig) error {
	_, err := components.UploadBuildScript(ssh, "guacamole", map[string]interface{}{
		"Password": "",
	})
	if err != nil {
		return err
	}
	_, err = components.UploadBuildScript(ssh, "proxy", map[string]interface{}{
		"DNSDomain": "",
		"MasterIPs": c.Specific.MasterIPs,
	})
	if err != nil {
		return err
	}
	return nil
}

func (c *Cluster) uploadTemplateToFile(ssh *system.SSHConfig, tmplName string, fileName string, data map[string]interface{}) (string, error) {
	b, err := getTemplateBox()
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

//executeScript executes the script template with the parameters on targetVM
func (c *Cluster) executeScript(ssh *system.SSHConfig, script string, data map[string]interface{}) (int, *string, error) {
	// Configures IncludeInstallCommons var
	installCommons, err := getInstallCommons()
	if err != nil {
		return 0, nil, err
	}
	data["IncludeInstallCommons"] = *installCommons

	path, err := c.uploadTemplateToFile(ssh, script, script, data)
	if err != nil {
		return 0, nil, nil
	}
	cmdResult, err := ssh.SudoCommand(fmt.Sprintf("chmod a+rx %s; %s; #rm -f %s", path, path, path))
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

//DeleteLastNode deletes the last Agent node added
func (c *Cluster) DeleteLastNode(public bool) error {
	var vmID string

	if public {
		vmID = c.Common.PublicNodeIDs[len(c.Common.PublicNodeIDs)-1]
	} else {
		vmID = c.Common.PrivateNodeIDs[len(c.Common.PrivateNodeIDs)-1]
	}
	err := utils.DeleteVM(vmID)
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

//DeleteSpecificNode deletes the node specified by its ID
func (c *Cluster) DeleteSpecificNode(ID string) error {
	var foundInPrivate bool
	foundInPublic, idx := contains(c.Common.PublicNodeIDs, ID)
	if !foundInPublic {
		foundInPrivate, idx = contains(c.Common.PrivateNodeIDs, ID)
	}
	if !foundInPublic && !foundInPrivate {
		return fmt.Errorf("VM ID '%s' isn't a registered Node of the Cluster '%s'.", ID, c.Common.Name)
	}

	err := utils.DeleteVM(ID)
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

//ListMasters lists the master nodes in the cluster
func (c *Cluster) ListMasters() ([]*pb.VM, error) {
	return nil, fmt.Errorf("ListMasters not yet implemented")
}

//ListNodes lists the nodes in the cluster
func (c *Cluster) ListNodes(public bool) []string {
	if public {
		return c.Common.PublicNodeIDs
	}
	return c.Common.PrivateNodeIDs
}

//GetNode returns a node based on its ID
func (c *Cluster) GetNode(ID string) (*pb.VM, error) {
	found, _ := contains(c.Common.PublicNodeIDs, ID)
	if !found {
		found, _ = contains(c.Common.PrivateNodeIDs, ID)
	}
	if !found {
		return nil, fmt.Errorf("GetNode not yet implemented")
	}
	return utils.GetVM(ID)
}

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

//SearchNode tells if a VM ID corresponds to a node of the cluster
func (c *Cluster) SearchNode(ID string, public bool) bool {
	found, _ := contains(c.Common.PublicNodeIDs, ID)
	if !found {
		found, _ = contains(c.Common.PrivateNodeIDs, ID)
	}
	return found
}

//GetDefinition returns the public properties of the cluster
func (c *Cluster) GetDefinition() clusterapi.Cluster {
	return *c.Common
}

//updateMetadata writes cluster definition in Object Storage
func (c *Cluster) updateMetadata() error {
	if c.metadata == nil {
		m, err := metadata.NewCluster()
		if err != nil {
			return err
		}
		m.Carry(c.Common, c.Specific)
		c.metadata = m
	}
	return c.metadata.Write()
}

//RemoveMetadata removes definition of cluster from Object Storage
func (c *Cluster) RemoveMetadata() error {
	if len(c.Specific.MasterIDs) > 0 ||
		len(c.Common.PublicNodeIDs) > 0 ||
		len(c.Common.PrivateNodeIDs) > 0 ||
		c.Common.NetworkID != "" {
		return fmt.Errorf("can't remove a definition of a cluster with infrastructure still running")
	}

	if c.metadata == nil {
		return nil
	}

	err := c.metadata.Delete()
	if err != nil {
		return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
	}
	c.Common.State = ClusterState.Removed
	return nil
}

//Delete destroys everything related to the infrastructure built for the cluster
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
		err := utils.DeleteVM(n)
		if err != nil {
			return err
		}
	}

	// Deletes the private nodes
	for _, n := range c.Common.PrivateNodeIDs {
		err := utils.DeleteVM(n)
		if err != nil {
			return err
		}
	}

	// Deletes the masters
	for _, n := range c.Specific.MasterIDs {
		err := utils.DeleteVM(n)
		if err != nil {
			return err
		}
	}

	// Deletes the network and gateway
	err = utils.DeleteNetwork(c.Common.NetworkID)
	if err != nil {
		return err
	}

	// Deletes the metadata
	err = c.metadata.Delete()
	if err != nil {
		return nil
	}
	c.metadata = &metadata.Cluster{}
	c.Common = &clusterapi.Cluster{}
	c.Specific = &Specific{}
	return nil
}

func init() {
	gob.Register(Cluster{})
	gob.Register(Specific{})
}
