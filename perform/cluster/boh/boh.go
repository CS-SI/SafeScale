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

package boh

/*
 * Implements a cluster of hosts with MPICH2
 */

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
	"github.com/CS-SI/SafeScale/perform/cluster/dcos/ErrorCode"
	"github.com/CS-SI/SafeScale/perform/cluster/metadata"

	"github.com/CS-SI/SafeScale/providers"
	providerapi "github.com/CS-SI/SafeScale/providers/api"
	providermetadata "github.com/CS-SI/SafeScale/providers/metadata"

	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/brokeruse"
	"github.com/CS-SI/SafeScale/utils/provideruse"
	"github.com/CS-SI/SafeScale/utils/retry"

	"github.com/CS-SI/SafeScale/system"

	pb "github.com/CS-SI/SafeScale/broker"
)

//go:generate rice embed-go

const (
	timeoutCtxVM = 10 * time.Minute

	shortTimeoutSSH = time.Minute
	longTimeoutSSH  = 5 * time.Minute

	tempFolder = "/var/tmp/"
)

var (
	// templateBox is the rice box to use in this package
	templateBoxes = map[string]*rice.Box{}

	// commonToolsContent contains the script containing commons tools
	commonToolsContent *string

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

//Specific defines the values specific to DCOS cluster we want to keep in Object Storage
type Specific struct {
	//PublicNodeIPs contains a list of IP of the Public Agent nodes
	PublicNodeIPs []string

	//PrivateAvgentIPs contains a list of IP of the Private Agent Nodes
	PrivateNodeIPs []string

	//StateCollectInterval in seconds
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

	// contains data defining the cluster
	*Specific

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

// Load loads the internals of an existing cluster from metadata
func Load(data *metadata.Cluster) (clusterapi.ClusterAPI, error) {
	svc, err := provideruse.GetProviderService()
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

// Create creates the necessary infrastructure of cluster
func Create(req clusterapi.Request) (clusterapi.ClusterAPI, error) {
	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return nil, fmt.Errorf("failed to generate password for user cladm: %s", err.Error())
	}

	// Creates network
	log.Printf("Creating Network 'net-%s'", req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	network, err := brokeruse.CreateNetwork(networkName, req.CIDR, &pb.GatewayDefinition{
		ImageID: "Ubuntu 18.04",
	})
	if err != nil {
		err = fmt.Errorf("Failed to create Network '%s': %s", networkName, err.Error())
		return nil, err
	}
	req.NetworkID = network.ID

	// Saving cluster parameters, with status 'Creating'
	var (
		instance         Cluster
		privateNodeCount int
		kp               *providerapi.KeyPair
		kpName           string
		gw               *providerapi.VM
		m                *providermetadata.Gateway
		found            bool
		nodesChannel     chan error
		nodesStatus      error
	)

	if req.ImageID == "" {
		req.ImageID = "Ubuntu 18.04"
	}
	nodesDef := pb.VMDefinition{
		CPUNumber: 4,
		RAM:       15.0,
		Disk:      100,
		ImageID:   req.ImageID,
	}

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
	instance = Cluster{
		Common: &clusterapi.Cluster{
			Name:          req.Name,
			CIDR:          req.CIDR,
			Flavor:        Flavor.BOH,
			State:         ClusterState.Creating,
			Complexity:    req.Complexity,
			Tenant:        req.Tenant,
			NetworkID:     req.NetworkID,
			Keypair:       kp,
			AdminPassword: cladmPassword,
			PublicIP:      gw.GetAccessIP(),
		},
		Specific: &Specific{},
		provider: svc,
	}
	err = instance.updateMetadata()
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanNetwork
	}

	switch req.Complexity {
	case Complexity.Dev:
		privateNodeCount = 1
	case Complexity.Normal:
		privateNodeCount = 4
	case Complexity.Volume:
		privateNodeCount = 8
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Step 1: starts nodes creation
	nodesChannel = make(chan error)
	go instance.asyncCreateNodes(privateNodeCount, false, &nodesDef, nodesChannel)
	nodesStatus = <-nodesChannel
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
			brokeruse.DeleteVM(id)
		}
	}
cleanNetwork:
	if !req.KeepOnFailure {
		brokeruse.DeleteNetwork(instance.Common.NetworkID)
		instance.metadata.Delete()
	}
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
		done <- fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	done <- nil
}

// createAndConfigureNode creates and configure a Node
func (c *Cluster) createAndConfigureNode(public bool, req *pb.VMDefinition) (string, error) {
	var nodeType NodeType.Enum
	if public {
		nodeType = NodeType.PublicNode
	} else {
		nodeType = NodeType.PrivateNode
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

	return hostID, nil
}

// asyncCreateNode creates a Node in the cluster
// This function is intended to be call as a goroutine
func (c *Cluster) asyncCreateNode(index int, nodeType NodeType.Enum, req *pb.VMDefinition, result chan string, done chan error) {
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
	host, err := brokeruse.CreateVM(req)
	if err != nil {
		log.Printf("[Nodes: %s #%d] creation failed: %s\n", nodeTypeStr, index, err.Error())
		result <- ""
		done <- err
		return
	}

	// Registers the new Agent in the cluster struct
	c.metadata.Acquire()
	if nodeType == NodeType.PublicNode {
		c.Common.PublicNodeIDs = append(c.Common.PublicNodeIDs, host.ID)
		c.Specific.PublicNodeIPs = append(c.Specific.PublicNodeIPs, host.PRIVATE_IP)
	} else {
		c.Common.PrivateNodeIDs = append(c.Common.PrivateNodeIDs, host.ID)
		c.Specific.PrivateNodeIPs = append(c.Specific.PrivateNodeIPs, host.PRIVATE_IP)
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
		brokeruse.DeleteVM(host.ID)
		c.metadata.Release()
		log.Printf("[Nodes: %s #%d] creation failed: %s", nodeTypeStr, index, err.Error())
		result <- ""
		done <- fmt.Errorf("failed to update Cluster configuration: %s", err.Error())
		return
	}
	c.metadata.Release()

	// Installs BOH requirements
	ssh, err := c.provider.GetSSHConfig(host.ID)
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
	retcode, _, err := c.executeScript(ssh, "boh_node_install.sh", map[string]interface{}{})
	if err != nil {
		log.Printf("[Nodes: %s #%d (%s)] installation failed: %s\n", nodeTypeStr, index, host.ID, err.Error())
		result <- ""
		done <- err
		return
	}
	if retcode != 0 {
		result <- ""
		if retcode < int(ErrorCode.NextErrorCode) {
			errcode := ErrorCode.Enum(retcode)
			log.Printf("[Nodes: %s #%d (%s)] installation failed: retcode: %d (%s)", nodeTypeStr, index, host.ID, errcode, errcode.String())
			done <- fmt.Errorf("scripted Node configuration failed with error code %d (%s)", errcode, errcode.String())
		} else {
			log.Printf("[Nodes: %s #%d (%s)] installation failed: retcode=%d", nodeTypeStr, index, host.ID, retcode)
			done <- fmt.Errorf("scripted Agent configuration failed with error code %d", retcode)
		}
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
	switch nodeType {
	case NodeType.PublicNode:
		c.Specific.PublicLastIndex++
		index = c.Specific.PublicLastIndex
	case NodeType.PrivateNode:
		c.Specific.PrivateLastIndex++
		index = c.Specific.PrivateLastIndex
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

// getBOHTemplateBox
func getBOHTemplateBox() (*rice.Box, error) {
	var b *rice.Box
	var found bool
	var err error
	if b, found = templateBoxes["../boh/scripts"]; !found {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../boh/scripts")
		if err != nil {
			return nil, err
		}
		templateBoxes["../boh/scripts"] = b
	}
	return b, nil
}

// getSystemTemplateBox
func getSystemTemplateBox() (*rice.Box, error) {
	var b *rice.Box
	var found bool
	var err error
	if b, found = templateBoxes["../../../system/scripts"]; !found {
		// Note: path MUST be literal for rice to work
		b, err = rice.FindBox("../../../system/scripts")
		if err != nil {
			return nil, err
		}
		templateBoxes["../../../system/scripts"] = b
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

// Start starts the cluster named 'name'
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

// Stop stops the cluster is its current state is compatible
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

// ForceGetState returns the current state of the cluster
// Does nothing currently...
func (c *Cluster) ForceGetState() (ClusterState.Enum, error) {
	c.Common.State = ClusterState.Nominal
	c.lastStateCollection = time.Now()
	c.updateMetadata()
	return c.Common.State, nil
}

// AddNode adds one node
func (c *Cluster) AddNode(public bool, req *pb.VMDefinition) (string, error) {
	vms, err := c.AddNodes(1, public, req)
	if err != nil {
		return "", err
	}
	return vms[0], nil
}

// AddNodes adds <count> nodes
func (c *Cluster) AddNodes(count int, public bool, req *pb.VMDefinition) ([]string, error) {
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
				brokeruse.DeleteVM(hostID)
			}
		}
		return nil, fmt.Errorf("errors occured on node addition: %s", strings.Join(errors, "\n"))
	}

	return hosts, nil
}

func uploadTemplateAsFile(ssh *system.SSHConfig, name string, path string) error {
	b, err := getBOHTemplateBox()
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

func (c *Cluster) uploadTemplateToFile(ssh *system.SSHConfig, tmplName string, fileName string, data map[string]interface{}) (string, error) {
	b, err := getBOHTemplateBox()
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

// executeScript executes the script template with the parameters on targetVM
func (c *Cluster) executeScript(ssh *system.SSHConfig, script string, data map[string]interface{}) (int, *string, error) {
	// Configures CommonTools template var
	commonTools, err := c.getCommonTools()
	if err != nil {
		return 0, nil, err
	}
	data["CommonTools"] = *commonTools

	path, err := c.uploadTemplateToFile(ssh, script, script, data)
	if err != nil {
		return 0, nil, err
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

// DeleteLastNode deletes the last Agent node added
func (c *Cluster) DeleteLastNode(public bool) error {
	var hostID string

	if public {
		hostID = c.Common.PublicNodeIDs[len(c.Common.PublicNodeIDs)-1]
	} else {
		hostID = c.Common.PrivateNodeIDs[len(c.Common.PrivateNodeIDs)-1]
	}
	err := brokeruse.DeleteVM(hostID)
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

	err := brokeruse.DeleteVM(hostID)
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
// No masters in BOH...
func (c *Cluster) ListMasters() ([]*pb.VM, error) {
	return []*pb.VM{}, nil
}

// ListNodes lists the nodes in the cluster
func (c *Cluster) ListNodes(public bool) []string {
	if public {
		return c.Common.PublicNodeIDs
	}
	return c.Common.PrivateNodeIDs
}

// GetNode returns a node based on its ID
func (c *Cluster) GetNode(hostID string) (*pb.VM, error) {
	found, _ := contains(c.Common.PublicNodeIDs, hostID)
	if !found {
		found, _ = contains(c.Common.PrivateNodeIDs, hostID)
	}
	if !found {
		return nil, fmt.Errorf("GetNode not yet implemented")
	}
	return brokeruse.GetVM(hostID)
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

// SearchNode tells if a host ID corresponds to a node of the cluster
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

// updateMetadata writes cluster config in Object Storage
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
		err := brokeruse.DeleteVM(n)
		if err != nil {
			return err
		}
	}

	// Deletes the private nodes
	for _, n := range c.Common.PrivateNodeIDs {
		err := brokeruse.DeleteVM(n)
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
	c.metadata = &metadata.Cluster{}
	c.Common = &clusterapi.Cluster{}
	c.Specific = &Specific{}
	return nil
}

func init() {
	gob.Register(Cluster{})
	gob.Register(Specific{})
}
