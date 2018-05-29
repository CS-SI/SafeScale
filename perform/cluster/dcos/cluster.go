package dcos

/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"syscall"
	"text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"

	clusterapi "github.com/CS-SI/SafeScale/perform/cluster/api"
	"github.com/CS-SI/SafeScale/perform/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/perform/cluster/api/NodeType"
	"github.com/CS-SI/SafeScale/perform/cluster/components"
	"github.com/CS-SI/SafeScale/perform/utils"

	pb "github.com/CS-SI/SafeScale/broker"
)

//go:generate rice embed-go

const (
	dcosVersion string = "1.11.1"

	timeoutCtxVM = 10 * time.Minute
)

var (
	// templateBox is the rice box to use in this package
	templateBox *rice.Box

	//installCommonsContent contains the script to install/configure common components
	installCommonsContent *string
)

//Definition defines the values we want to keep in Object Storage
type Definition struct {
	// common cluster data
	clusterapi.Cluster

	//BootstrapID is the identifier of the VM acting as bootstrap/upgrade server
	BootstrapID string

	//BootstrapIP contains the IP of the bootstrap server reachable by all master and agents
	BootstrapIP string

	//MasterIDs is a slice of VMIDs of the master
	MasterIDs []string

	//masterIPs contains a list of IP of the master servers
	MasterIPs []string

	//PublicAgentIDs is a slice of VMIDs of the public agents
	PublicAgentIDs []string

	//PublicAgentIPs contains a list of IP of the Public Agent nodes
	PublicAgentIPs []string

	//PrivateAgentIDs is a slice of VMIDs of the private agents
	PrivateAgentIDs []string

	//PrivateAvgentIPs contains a list of IP of the Private Agent Nodes
	PrivateAgentIPs []string

	//StateCollectInterval in seconds
	StateCollectInterval time.Duration
}

//Cluster is the object describing a cluster created by ClusterManagerAPI.CreateCluster
type Cluster struct {
	//Definition contains data defining the cluster
	*Definition

	//LastStateCollect contains the date of the last state collection
	lastStateCollection time.Time
}

//GetNetworkID returns the ID of the network used by the cluster
func (c *Cluster) GetNetworkID() string {
	return c.Definition.Cluster.GetNetworkID()
}

//NewCluster creates the necessary infrastructure of cluster
func NewCluster(req clusterapi.Request) (clusterapi.ClusterAPI, error) {
	// Create a KeyPair for the cluster
	svc, err := utils.GetProviderService()
	if err != nil {
		return nil, err
	}
	kpName := "cluster_" + req.Name + "_key"
	svc.DeleteKeyPair(kpName)
	kp, err := svc.CreateKeyPair(kpName)
	if err != nil {
		return nil, fmt.Errorf("failed to create Key Pair: %s", err.Error())
	}
	defer svc.DeleteKeyPair(kpName)

	var masterCount int
	//	var keypair *providerapi.KeyPair

	// Saving cluster parameters, with status 'Creating'
	instance := Cluster{
		Definition: &Definition{
			Cluster: clusterapi.Cluster{
				Name:       req.Name,
				State:      ClusterState.Creating,
				Complexity: req.Complexity,
				Tenant:     req.Tenant,
				NetworkID:  req.NetworkID,
				Keypair:    kp,
			},
		},
	}

	// Creates bootstrap/upgrade server
	log.Printf("Creating DCOS Bootstrap server")
	_, err = instance.addBootstrap()
	if err != nil {
		err = fmt.Errorf("failed to create DCOS bootstrap server: %s", err.Error())
		goto cleanNetwork
	}

	err = instance.WriteDefinition()
	if err != nil {
		err = fmt.Errorf("failed to create cluster '%s': %s", req.Name, err.Error())
		goto cleanBootstrap
	}

	switch req.Complexity {
	case Complexity.Dev:
		masterCount = 1
	case Complexity.Normal:
		masterCount = 3
	case Complexity.Volume:
		masterCount = 5
	}

	log.Printf("Creating DCOS Master servers (%d)", masterCount)
	for i := 1; i <= masterCount; i++ {
		// Creates Master Node
		_, err = instance.addMaster()
		if err != nil {
			err = fmt.Errorf("failed to add DCOS Master %d: %s", i, err.Error())
			goto cleanMasters
		}
	}

	log.Printf("Configuring cluster")
	err = instance.configure()
	if err != nil {
		err = fmt.Errorf("failed to configure DCOS cluster: %s", err.Error())
		goto cleanMasters
	}

	// Cluster created and configured successfully, saving again to Object Storage
	instance.Definition.Cluster.State = ClusterState.Created
	err = instance.WriteDefinition()
	if err != nil {
		goto cleanMasters
	}

	log.Printf("Cluster '%s' created and initialized successfully", req.Name)
	return &instance, nil

cleanMasters:
	//for _, id := range instance.definition.MasterIDs {
	//	utils.DeleteVM(id)
	//}
cleanBootstrap:
	//utils.DeleteVM(instance.definition.BootstrapID)
cleanNetwork:
	//utils.DeleteNetwork(instance.definition.Common.NetworkID)
	//instance.RemoveDefinition()
	return nil, err
}

//GetName returns the name of the cluster
func (c *Cluster) GetName() string {
	return c.Definition.Cluster.Name
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
		tmplPrepared, err := template.New("install_commons").Parse(tmplString)
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
		// 2nd start the agents
		// 3nd start the nodes
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
	if now.After(c.lastStateCollection.Add(c.Definition.StateCollectInterval)) {
		return c.ForceGetState()
	}
	return c.Definition.Cluster.State, nil
}

//ForceGetState returns the current state of the cluster
// This method will trigger a effective state collection at each call
func (c *Cluster) ForceGetState() (ClusterState.Enum, error) {
	// Do effective state collection
	return ClusterState.Error, nil
}

//AddNode adds a node
func (c *Cluster) AddNode(nodeType NodeType.Enum, req *pb.VMDefinition) (*pb.VM, error) {
	switch nodeType {
	case NodeType.PublicAgent:
		fallthrough
	case NodeType.PrivateAgent:
		if c.Definition.Cluster.State == ClusterState.Creating {
			return nil, fmt.Errorf("The DCOS flavor of Cluster needs to be in state 'Created' at least to allow agent node addition.")
		}
		return c.addAgentNode(nodeType, req)
	}
	return nil, fmt.Errorf("unmanaged node type '%s (%d)'", nodeType.String(), nodeType)
}

//addBootstrap
func (c *Cluster) addBootstrap() (*pb.VM, error) {
	name := c.Definition.Cluster.Name + "-dcosbootstrap"
	bootstrapVM, err := utils.CreateVM(&pb.VMDefinition{
		Name:      name,
		CPUNumber: 4,
		RAM:       32.0,
		Disk:      120,
		ImageID:   "CentOS 7.3",
		Network:   c.Definition.Cluster.NetworkID,
		Public:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Bootstrap server: %v", err)
	}

	c.Definition.BootstrapID = bootstrapVM.ID
	c.Definition.BootstrapIP = bootstrapVM.IP

	// Update cluster definition in Object Storage
	err = c.WriteDefinition()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		c.Definition.BootstrapID = ""
		c.Definition.BootstrapIP = ""
		utils.DeleteVM(bootstrapVM.ID)
		return nil, fmt.Errorf("failed to update Cluster definition: %s", err.Error())
	}

	return bootstrapVM, nil
}

//addMasterNode adds a master node
func (c *Cluster) addMaster() (*pb.VM, error) {
	i := len(c.Definition.MasterIDs) + 1
	name := c.Definition.Cluster.Name + "-dcosmaster-" + strconv.Itoa(i)

	masterVM, err := utils.CreateVM(&pb.VMDefinition{
		Name:      name,
		CPUNumber: 4,
		RAM:       16.0,
		Disk:      60,
		ImageID:   "CentOS 7.3",
		Network:   c.Definition.Cluster.NetworkID,
		Public:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Master server %d: %s", i, err.Error())
	}

	// Registers the new Master in the cluster struct
	c.Definition.MasterIDs = append(c.Definition.MasterIDs, masterVM.ID)
	c.Definition.MasterIPs = append(c.Definition.MasterIPs, masterVM.IP)

	// Update cluster definition in Object Storage
	err = c.WriteDefinition()
	if err != nil {
		// Object Storage failed, removes the ID we just added to the cluster struct
		c.Definition.MasterIDs = c.Definition.MasterIDs[:len(c.Definition.MasterIDs)-1]
		c.Definition.MasterIPs = c.Definition.MasterIPs[:len(c.Definition.MasterIPs)-1]
		utils.DeleteVM(masterVM.ID)
		return nil, fmt.Errorf("failed to update Cluster definition: %s", err.Error())
	}

	return masterVM, nil
}

//addAgentNode adds a Public Agent Node to the cluster
func (c *Cluster) addAgentNode(nodeType NodeType.Enum, req *pb.VMDefinition) (*pb.VM, error) {
	var publicIP bool
	coreName := "node"
	if nodeType == NodeType.PublicAgent {
		publicIP = true
		coreName = "pub" + coreName
	} else {
		publicIP = false
		coreName = "priv" + coreName
	}

	i := len(c.Definition.PublicAgentIDs) + 1
	req.Public = publicIP
	req.Network = c.Definition.Cluster.NetworkID
	req.Name = c.Definition.Cluster.Name + "-dcos" + coreName + "-" + strconv.Itoa(i)
	req.ImageID = "CentOS 7.3"
	agentVM, err := utils.CreateVM(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create Master server %d: %s", i, err.Error())
	}

	// Installs DCOS on agent node
	err = c.configureAgent(agentVM, nodeType)
	if err != nil {
		utils.DeleteVM(agentVM.ID)
		return nil, fmt.Errorf("failed to install DCOS on Agent Node: %s", err.Error())
	}

	// Registers the new Agent in the cluster struct
	if nodeType == NodeType.PublicAgent {
		c.Definition.PublicAgentIDs = append(c.Definition.PublicAgentIDs, agentVM.ID)
		c.Definition.PublicAgentIPs = append(c.Definition.PublicAgentIPs, agentVM.IP)
	} else {
		c.Definition.PrivateAgentIDs = append(c.Definition.PrivateAgentIDs, agentVM.ID)
		c.Definition.PrivateAgentIPs = append(c.Definition.PrivateAgentIPs, agentVM.IP)
	}

	// Update cluster definition in Object Storage
	err = c.WriteDefinition()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		if nodeType == NodeType.PublicAgent {
			c.Definition.PublicAgentIDs = c.Definition.PublicAgentIDs[:len(c.Definition.PublicAgentIDs)-1]
			c.Definition.PublicAgentIPs = c.Definition.PublicAgentIPs[:len(c.Definition.PublicAgentIPs)-1]
		} else {
			c.Definition.PrivateAgentIDs = c.Definition.PrivateAgentIDs[:len(c.Definition.PrivateAgentIDs)-1]
			c.Definition.PrivateAgentIPs = c.Definition.PrivateAgentIPs[:len(c.Definition.PrivateAgentIPs)-1]
		}
		utils.DeleteVM(agentVM.ID)
		return nil, fmt.Errorf("failed to update Cluster definition: %s", err.Error())
	}

	return agentVM, nil
}

//configure prepares the bootstrap and masters for duty
func (c *Cluster) configure() error {
	log.Printf("Configuring Bootstrap server")

	prepareDockerImages, err := realizePrepareDockerImages()
	if err != nil {
		return fmt.Errorf("failed to build configuration script: %s", err.Error())
	}

	svc, err := utils.GetProviderService()
	if err != nil {
		return err
	}

	var dnsServers []string
	cfg, err := svc.GetCfgOpts()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	retcode, output, err := c.executeScript(c.Definition.BootstrapID, "dcos_install_bootstrap_node.sh", map[string]interface{}{
		"DCOSVersion":         dcosVersion,
		"BootstrapIP":         c.Definition.BootstrapIP,
		"BootstrapPort":       "80",
		"ClusterName":         c.Definition.Cluster.Name,
		"MasterIPs":           c.Definition.MasterIPs,
		"DNSServerIPs":        dnsServers,
		"SSHPrivateKey":       c.Definition.Cluster.Keypair.PrivateKey,
		"SSHPublicKey":        c.Definition.Cluster.Keypair.PublicKey,
		"PrepareDockerImages": prepareDockerImages,
	})
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("scripted Bootstrap configuration failed with error code %d:\n%s", retcode, *output)
	}

	log.Printf("Configuring Master servers")
	for _, m := range c.Definition.MasterIDs {
		retcode, output, err := c.executeScript(m, "dcos_install_master_node.sh", map[string]interface{}{
			"BootstrapIP":   c.Definition.BootstrapIP,
			"BootstrapPort": "80",
		})
		if err != nil {
			return err
		}
		if retcode != 0 {
			return fmt.Errorf("scripted Master configuration failed with error code %d:\n%s", retcode, *output)
		}
	}

	return nil
}

//realizePrepareDockerImages creates the string corresponding to script
// used to prepare Docker images on Bootstrap server
func realizePrepareDockerImages() (string, error) {
	// Get code to build and export needed docker images
	realizedPrepareImageGuacamole, err := components.RealizeBuildScript("guacamole", map[string]interface{}{})
	if err != nil {
		return "", nil
	}
	realizedPrepareImageProxy, err := components.RealizeBuildScript("proxy", map[string]interface{}{})
	if err != nil {
		return "", nil
	}

	// find the rice.Box
	b, err := getTemplateBox()
	if err != nil {
		return "", err
	}
	// get file contents as string
	tmplString, err := b.String("dcos_docker_prepare_images.sh")
	if err != nil {
		return "", fmt.Errorf("error loading script template: %s", err.Error())
	}
	// Parse the template
	tmplPrepared, err := template.New("prepare_docker_images").Parse(tmplString)
	if err != nil {
		return "", fmt.Errorf("error parsing script template: %s", err.Error())
	}
	// realize the template
	dataBuffer := bytes.NewBufferString("")
	err = tmplPrepared.Execute(dataBuffer, map[string]interface{}{
		"PrepareImageGuacamole": realizedPrepareImageGuacamole,
		"PrepareImageProxy":     realizedPrepareImageProxy,
	})
	if err != nil {
		return "", fmt.Errorf("error realizing script template: %s", err.Error())
	}
	return dataBuffer.String(), nil
}

//configureAgent installs and configure DCOS agent on targetVM
func (c *Cluster) configureAgent(targetVM *pb.VM, nodeType NodeType.Enum) error {
	var typeStr string
	if nodeType == NodeType.PublicAgent {
		typeStr = "yes"
	} else {
		typeStr = "no"
	}

	retcode, output, err := c.executeScript(targetVM.ID, "dcos_install_agent_node.sh", map[string]interface{}{
		"PublicNode":    typeStr,
		"BootstrapIP":   c.Definition.BootstrapIP,
		"BootstrapPort": "80",
	})
	if err != nil {
		return err
	}
	fmt.Println(output)

	if retcode != 0 {
		return fmt.Errorf("scripted Agent configuration failed with error code %d:\n%s", retcode, *output)
	}
	return nil
}

//executeScript executes the script template with the parameters on targetVM
func (c *Cluster) executeScript(targetID string, script string, data map[string]interface{}) (int, *string, error) {
	svc, err := utils.GetProviderService()
	if err != nil {
		return 0, nil, err
	}
	ssh, err := svc.GetSSHConfig(targetID)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to read SSH config: %s", err.Error())
	}
	ssh.WaitServerReady(60 * time.Second)

	// Configures IncludeInstallCommons var
	installCommons, err := getInstallCommons()
	if err != nil {
		return 0, nil, err
	}
	data["IncludeInstallCommons"] = *installCommons

	b, err := getTemplateBox()
	if err != nil {
		return 0, nil, err
	}

	// get file contents as string
	tmplString, err := b.String(script)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to load script template: %s", err.Error())
	}
	// parse and execute the template
	tmplCmd, err := template.New("cmd").Parse(tmplString)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to parse script template: %s", err.Error())
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, data)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to realize script template: %s", err.Error())
	}
	cmd := dataBuffer.String()

	cmdResult, err := ssh.SudoCommand(cmd)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to execute script '%s': %s", script, err.Error())
	}
	retcode := 0
	out, err := cmdResult.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				retcode = int(status)
			}
		} else {
			return 0, nil, fmt.Errorf("failed to fetch output of script '%s': %s", script, err.Error())
		}
	}

	strOut := string(out)
	return retcode, &strOut, nil
}

//DeleteNode deletes an Agent node
func (c *Cluster) DeleteNode(ID string) error {
	return fmt.Errorf("DeleteNode not yet implemented")
}

//ListMasters lists the master nodes in the cluster
func (c *Cluster) ListMasters() ([]*pb.VM, error) {
	return nil, fmt.Errorf("ListMasters not yet implemented")
}

//ListNodes lists the nodes in the cluster
func (c *Cluster) ListNodes() ([]*pb.VM, error) {
	return nil, fmt.Errorf("ListNodes not yet implemented")
}

//GetNode returns a node based on its ID
func (*Cluster) GetNode(ID string) (*pb.VM, error) {
	return nil, fmt.Errorf("ListNodes not yet implemented")
}

//GetDefinition returns the public properties of the cluster
func (c *Cluster) GetDefinition() clusterapi.Cluster {
	return c.Definition.Cluster
}

//WriteDefinition writes cluster definition in Object Storage
func (c *Cluster) WriteDefinition() error {
	//var buffer bytes.Buffer
	//enc := gob.NewEncoder(&buffer)
	//err := enc.Encode(c.definition)
	//if err != nil {
	//	return err
	//}
	//content := bytes.NewReader(buffer.Bytes()

	utils.CreateMetadataContainer()

	// writes  the data in Object Storage
	return utils.WriteMetadata(clusterapi.ClusterMetadataPrefix, c.Definition.Cluster.Name, c.Definition)
}

//ReadDefinition reads definition of cluster named 'name' from Metadata
// Returns (true, nil) if found and loaded, (false, nil) if not found, and (false, error) in case of error
func (c *Cluster) ReadDefinition() (bool, error) {
	utils.CreateMetadataContainer()

	ok, err := utils.FindMetadata(clusterapi.ClusterMetadataPrefix, c.Definition.Cluster.Name)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	// reads the data in Object Storage
	var d Definition
	err = utils.ReadMetadata(clusterapi.ClusterMetadataPrefix, c.Definition.Cluster.Name, func(buf *bytes.Buffer) error {
		return gob.NewDecoder(buf).Decode(&d)
	})
	if err != nil {
		return false, err
	}
	c.Definition = &d
	return true, nil
}

//RemoveDefinition removes definition of cluster from Object Storage
func (c *Cluster) RemoveDefinition() error {
	if len(c.Definition.MasterIDs) > 0 ||
		len(c.Definition.PublicAgentIDs) > 0 ||
		len(c.Definition.PrivateAgentIDs) > 0 ||
		c.Definition.Cluster.NetworkID != "" {
		return fmt.Errorf("can't remove a definition of a cluster with infrastructure still running")
	}

	err := utils.DeleteMetadata(clusterapi.ClusterMetadataPrefix, c.Definition.Cluster.Name)
	if err != nil {
		return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
	}
	c.Definition.Cluster.State = ClusterState.Removed
	return nil
}

//Delete destroys everything related to the infrastructure built for the cluster
func (c *Cluster) Delete() error {
	return fmt.Errorf("dcos.Cluster.Delete not yet implemented")
}
