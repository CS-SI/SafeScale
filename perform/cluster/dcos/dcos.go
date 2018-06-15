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
	"strconv"
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
	"github.com/CS-SI/SafeScale/system"

	"github.com/CS-SI/SafeScale/utils"

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
	common, anon := data.Get()
	specific := anon.(Specific)
	instance := &Cluster{
		Common:   common,
		Specific: &specific,
	}
	return instance, nil
}

//Create creates the necessary infrastructure of cluster
func Create(req clusterapi.Request) (clusterapi.ClusterAPI, error) {
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
		Specific: &Specific{},
	}

	// Creates bootstrap/upgrade server
	log.Printf("Creating DCOS Bootstrap server")
	_, err = instance.addBootstrap()
	if err != nil {
		err = fmt.Errorf("failed to create DCOS bootstrap server: %s", err.Error())
		goto cleanNetwork
	}

	err = instance.updateMetadata()
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
	log.Printf("Cluster '%s' created and initialized successfully", req.Name)
	return &instance, nil

cleanMasters:
	//for _, id := range instance.Specific.MasterIDs {
	//	utils.DeleteVM(id)
	//}
cleanBootstrap:
	//utils.DeleteVM(instance.Specific.BootstrapID)
cleanNetwork:
	//utils.DeleteNetwork(instance.Common.NetworkID)
	//instance.RemoveMetadata()
	return nil, err
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
	svc, err := utils.GetProviderService()
	if err == nil {
		cmd := "/opt/mesosphere/bin/dcos-diagnostics --diag || /opt/mesosphere/bin/3dt --diag"
		for _, id := range c.Specific.MasterIDs {
			ssh, err := svc.GetSSHConfig(id)
			if err != nil {
				continue
			}
			cmdResult, err := ssh.SudoCommand(cmd)
			if err != nil {
				continue
			}
			var retcode int
			out, err := cmdResult.CombinedOutput()
			if err != nil {
				if ee, ok := err.(*exec.ExitError); ok {
					if status, ok := ee.Sys().(syscall.WaitStatus); ok {
						retcode = status.ExitStatus()
					}
				} else {
					continue
				}
			}
			switch retcode {
			case 0:
				c.Common.State = ClusterState.Nominal
				err = nil
			default:
				c.Common.State = ClusterState.Error
				err = fmt.Errorf(string(out))
			}
			c.lastStateCollection = time.Now()
			c.updateMetadata()
			return c.Common.State, err
		}
	}
	c.Common.State = ClusterState.Error
	c.lastStateCollection = time.Now()
	c.updateMetadata()
	return ClusterState.Error, err
}

//AddNode adds a node
func (c *Cluster) AddNode(public bool, req *pb.VMDefinition) (*pb.VM, error) {
	var nodeType NodeType.Enum
	if public {
		nodeType = NodeType.PublicNode
	} else {
		nodeType = NodeType.PrivateNode
	}
	if c.Common.State != ClusterState.Created && c.Common.State != ClusterState.Nominal {
		return nil, fmt.Errorf("The DCOS flavor of Cluster needs to be in state 'Created' at least to allow agent node addition.")
	}
	return c.addAgentNode(nodeType, req)
}

//addBootstrap
func (c *Cluster) addBootstrap() (*pb.VM, error) {
	name := c.Common.Name + "-dcosbootstrap"
	bootstrapVM, err := utils.CreateVM(&pb.VMDefinition{
		Name:      name,
		CPUNumber: 4,
		RAM:       32.0,
		Disk:      120,
		ImageID:   "CentOS 7.3",
		Network:   c.Common.NetworkID,
		Public:    true,
	})
	if err != nil {
		return nil, err
	}

	c.Specific.BootstrapID = bootstrapVM.ID
	c.Specific.BootstrapIP = bootstrapVM.IP

	// Update cluster definition in Object Storage
	err = c.updateMetadata()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		c.Specific.BootstrapID = ""
		c.Specific.BootstrapIP = ""
		utils.DeleteVM(bootstrapVM.ID)
		return nil, fmt.Errorf("failed to update Cluster definition: %s", err.Error())
	}

	return bootstrapVM, nil
}

//addMasterNode adds a master node
func (c *Cluster) addMaster() (*pb.VM, error) {
	i := len(c.Specific.MasterIDs) + 1
	name := c.Common.Name + "-dcosmaster-" + strconv.Itoa(i)

	masterVM, err := utils.CreateVM(&pb.VMDefinition{
		Name:      name,
		CPUNumber: 4,
		RAM:       16.0,
		Disk:      60,
		ImageID:   "CentOS 7.3",
		Network:   c.Common.NetworkID,
		Public:    true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create Master server %d: %s", i, err.Error())
	}

	// Registers the new Master in the cluster struct
	c.Specific.MasterIDs = append(c.Specific.MasterIDs, masterVM.ID)
	c.Specific.MasterIPs = append(c.Specific.MasterIPs, masterVM.IP)

	// Update cluster definition in Object Storage
	err = c.updateMetadata()
	if err != nil {
		// Object Storage failed, removes the ID we just added to the cluster struct
		c.Specific.MasterIDs = c.Specific.MasterIDs[:len(c.Specific.MasterIDs)-1]
		c.Specific.MasterIPs = c.Specific.MasterIPs[:len(c.Specific.MasterIPs)-1]
		utils.DeleteVM(masterVM.ID)
		return nil, fmt.Errorf("failed to update Cluster definition: %s", err.Error())
	}

	return masterVM, nil
}

//addAgentNode adds a Public Agent Node to the cluster
func (c *Cluster) addAgentNode(nodeType NodeType.Enum, req *pb.VMDefinition) (*pb.VM, error) {
	var publicIP bool
	var index int
	coreName := "node"
	if nodeType == NodeType.PublicNode {
		publicIP = true
		coreName = "pub" + coreName
		index = len(c.Common.PublicNodeIDs) + 1
	} else {
		publicIP = false
		coreName = "priv" + coreName
		index = len(c.Common.PrivateNodeIDs) + 1
	}

	req.Public = publicIP
	req.Network = c.Common.NetworkID
	req.Name = c.Common.Name + "-dcos" + coreName + "-" + strconv.Itoa(index)
	req.ImageID = "CentOS 7.3"
	agentVM, err := utils.CreateVM(req)
	if err != nil {
		return nil, err
	}

	// Installs DCOS on agent node
	err = c.configureAgent(agentVM, nodeType)
	if err != nil {
		utils.DeleteVM(agentVM.ID)
		return nil, fmt.Errorf("failed to install DCOS on Agent Node: %s", err.Error())
	}

	// Registers the new Agent in the cluster struct
	if nodeType == NodeType.PublicNode {
		c.Common.PublicNodeIDs = append(c.Common.PublicNodeIDs, agentVM.ID)
		c.Specific.PublicNodeIPs = append(c.Specific.PublicNodeIPs, agentVM.IP)
	} else {
		c.Common.PrivateNodeIDs = append(c.Common.PrivateNodeIDs, agentVM.ID)
		c.Specific.PrivateNodeIPs = append(c.Specific.PrivateNodeIPs, agentVM.IP)
	}

	// Update cluster definition in Object Storage
	err = c.updateMetadata()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		if nodeType == NodeType.PublicNode {
			c.Common.PublicNodeIDs = c.Common.PublicNodeIDs[:len(c.Common.PublicNodeIDs)-1]
			c.Specific.PublicNodeIPs = c.Specific.PublicNodeIPs[:len(c.Specific.PublicNodeIPs)-1]
		} else {
			c.Common.PrivateNodeIDs = c.Common.PrivateNodeIDs[:len(c.Common.PrivateNodeIDs)-1]
			c.Specific.PrivateNodeIPs = c.Specific.PrivateNodeIPs[:len(c.Specific.PrivateNodeIPs)-1]
		}
		utils.DeleteVM(agentVM.ID)
		return nil, fmt.Errorf("failed to update Cluster definition: %s", err.Error())
	}

	return agentVM, nil
}

//configure prepares the bootstrap and masters for duty
func (c *Cluster) configure() error {
	log.Printf("Configuring Bootstrap server")

	prepareDockerImages, err := c.realizePrepareDockerImages()
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
	retcode, output, err := c.executeScript(c.Specific.BootstrapID, "dcos_install_bootstrap_node.sh", map[string]interface{}{
		"DCOSVersion":         dcosVersion,
		"BootstrapIP":         c.Specific.BootstrapIP,
		"BootstrapPort":       "80",
		"ClusterName":         c.Common.Name,
		"MasterIPs":           c.Specific.MasterIPs,
		"DNSServerIPs":        dnsServers,
		"SSHPrivateKey":       c.Common.Keypair.PrivateKey,
		"SSHPublicKey":        c.Common.Keypair.PublicKey,
		"PrepareDockerImages": prepareDockerImages,
	})
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("scripted Bootstrap configuration failed with error code %d:\n%s", retcode, *output)
	}

	log.Printf("Configuring Master servers")
	for _, m := range c.Specific.MasterIDs {
		retcode, output, err := c.executeScript(m, "dcos_install_master_node.sh", map[string]interface{}{
			"BootstrapIP":   c.Specific.BootstrapIP,
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

//installKubernetes does the needed to have Kubernetes in DCOS
func (c *Cluster) installKubernetes() (int, error) {
	var count uint
	var options string
	switch c.Common.Complexity {
	case Complexity.Dev:
		count = 1
		options = "dcos_kubernetes_options_dev.conf"
	case Complexity.Normal:
		fallthrough
	case Complexity.Volume:
		count = 3
		options = "dcos_kubernetes_options_prod.conf"
	}

	// TODO: copy dcos options for kubernetes deployment in /var/tmp/kubernetes.json on remote master
	svc, err := utils.GetProviderService()
	if err != nil {
		return 0, err
	}
	var ssh *system.SSHConfig
	for _, masterID := range c.Specific.MasterIDs {
		ssh, err = svc.GetSSHConfig(masterID)
		if err != nil {
			return 0, fmt.Errorf("failed to read SSH config: %s", err.Error())
		}
		ssh.WaitServerReady(60 * time.Second)
		break
	}
	if ssh == nil {
		return 0, fmt.Errorf("failed to find available master")
	}

	err = uploadTemplateAsFile(ssh, options, "/var/tmp/"+options)
	if err != nil {
		return 0, err
	}
	cmd := "sudo -u cladm -i dcos package install kubernetes --config=/var/tmp/" + options
	fmt.Printf("count=%d, cmd=%s\n", count, cmd)

	return 0, fmt.Errorf("installKubernetes() not yet implemented")
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
	svc, err := utils.GetProviderService()
	if err != nil {
		return 0, err
	}
	var ssh *system.SSHConfig
	for _, masterID := range c.Specific.MasterIDs {
		ssh, err = svc.GetSSHConfig(masterID)
		if err != nil {
			return 0, fmt.Errorf("failed to read SSH config: %s", err.Error())
		}
		ssh.WaitServerReady(60 * time.Second)
		break
	}
	if ssh == nil {
		return 0, fmt.Errorf("failed to find available master")
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
	svc, err := utils.GetProviderService()
	if err != nil {
		return 0, err
	}
	var ssh *system.SSHConfig
	for _, masterID := range c.Specific.MasterIDs {
		ssh, err = svc.GetSSHConfig(masterID)
		if err != nil {
			return 0, fmt.Errorf("failed to read SSH config: %s", err.Error())
		}
		ssh.WaitServerReady(60 * time.Second)
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

//realizePrepareDockerImages creates the string corresponding to script
// used to prepare Docker images on Bootstrap server
func (c *Cluster) realizePrepareDockerImages() (string, error) {
	// Get code to build and export needed docker images
	realizedPrepareImageGuacamole, err := components.RealizeBuildScript("guacamole", map[string]interface{}{})
	if err != nil {
		return "", err
	}
	realizedPrepareImageProxy, err := components.RealizeBuildScript("proxy", map[string]interface{}{
		"MasterIPs": c.Specific.MasterIPs,
		"DNSDomain": "",
	})
	if err != nil {
		return "", err
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
	if nodeType == NodeType.PublicNode {
		typeStr = "yes"
	} else {
		typeStr = "no"
	}

	retcode, output, err := c.executeScript(targetVM.ID, "dcos_install_agent_node.sh", map[string]interface{}{
		"PublicNode":    typeStr,
		"BootstrapIP":   c.Specific.BootstrapIP,
		"BootstrapPort": "80",
	})
	if err != nil {
		return err
	}
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

	remotePath := "/var/tmp/" + script
	err = ssh.UploadString(remotePath, cmd)
	if err != nil {
		return 0, nil, nil
	}
	cmdResult, err := ssh.SudoCommand(fmt.Sprintf("chmod a+rx %s; %s; #rm -f %s", remotePath, remotePath, remotePath))
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
	// writes the data in Object Storage
	m, err := metadata.NewCluster()
	if err != nil {
		return err
	}
	return m.Carry(c.Common, c.Specific).Write()
}

//RemoveMetadata removes definition of cluster from Object Storage
func (c *Cluster) RemoveMetadata() error {
	if len(c.Specific.MasterIDs) > 0 ||
		len(c.Common.PublicNodeIDs) > 0 ||
		len(c.Common.PrivateNodeIDs) > 0 ||
		c.Common.NetworkID != "" {
		return fmt.Errorf("can't remove a definition of a cluster with infrastructure still running")
	}

	m, err := metadata.NewCluster()
	if err != nil {
		return err
	}
	err = m.Carry(c.Common, c.Specific).Delete()
	if err != nil {
		return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
	}
	c.Common.State = ClusterState.Removed
	return nil
}

//Delete destroys everything related to the infrastructure built for the cluster
func (c *Cluster) Delete() error {
	m, err := metadata.NewCluster()
	if err != nil {
		return err
	}
	m.Carry(c.Common, c.Specific)

	// Updates metadata
	c.Common.State = ClusterState.Removed
	err = m.Write()
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

	// Deletes the bootstrap server
	err = utils.DeleteVM(c.Specific.BootstrapID)
	if err != nil {
		return err
	}

	// Deletes the metadata
	return m.Delete()
}

func init() {
	gob.Register(Cluster{})
	gob.Register(Specific{})
}
