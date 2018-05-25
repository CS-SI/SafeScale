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
	clusterapi "github.com/SafeScale/perform/cluster/api"
	"github.com/SafeScale/perform/cluster/api/ClusterState"
	"github.com/SafeScale/perform/cluster/api/NodeType"
	"github.com/SafeScale/perform/cluster/components"

	"github.com/SafeScale/providers"

	providerapi "github.com/SafeScale/providers/api"
)

//go:generate rice embed-go

const (
	dcosVersion string = "1.11.1"
)

var (
	// templateBox is the rice box to use in this package
	templateBox *rice.Box

	//installCommonsContent contains the script to install/configure common components
	installCommonsContent *string
)

//ClusterDefinition defines the values we want to keep in Object Storage
type ClusterDefinition struct {
	//Common cluster data
	Common clusterapi.Cluster

	//NetworkID is the network identifier where the cluster is created
	NetworkID string

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
	//Manager is the cluster manager used to create the cluster
	Manager *Manager

	//Definition contains data defining the cluster
	definition *ClusterDefinition

	//LastStateCollect contains the date of the last state collection
	lastStateCollection time.Time
}

//getService returns a pointer to the infrastructure service of the cluster
func (c *Cluster) getService() *providers.Service {
	return c.Manager.GetService()
}

//GetName returns the name of the cluster
func (c *Cluster) GetName() string {
	return c.definition.Common.Name
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
	if now.After(c.lastStateCollection.Add(c.definition.StateCollectInterval)) {
		return c.ForceGetState()
	}
	return c.definition.Common.State, nil
}

//ForceGetState returns the current state of the cluster
// This method will trigger a effective state collection at each call
func (c *Cluster) ForceGetState() (ClusterState.Enum, error) {
	// Do effective state collection
	return ClusterState.Error, nil
}

//AddNode adds a node
func (c *Cluster) AddNode(nodeType NodeType.Enum, req providerapi.VMRequest) (*clusterapi.Node, error) {
	switch nodeType {
	case NodeType.Bootstrap:
		if c.definition.Common.State != ClusterState.Creating {
			return nil, fmt.Errorf("The DCOS flavor of Cluster doesn't allow to add bootstrap node after initial setup")
		}
		return c.addBootstrapNode(req)
	case NodeType.Master:
		if c.definition.Common.State != ClusterState.Creating {
			return nil, fmt.Errorf("The DCOS flavor of Cluster doesn't allow to add master node after initial setup")
		}
		return c.addMasterNode(req)
	case NodeType.PublicAgent:
		fallthrough
	case NodeType.PrivateAgent:
		if c.definition.Common.State == ClusterState.Creating {
			return nil, fmt.Errorf("The DCOS flavor of Cluster needs to be in state 'Created' at least to allow agent node addition.")
		}
		return c.addAgentNode(req, nodeType)
	}
	return nil, fmt.Errorf("unknown node type '%s'", nodeType)
}

//addBootstrapNode
func (c *Cluster) addBootstrapNode(req providerapi.VMRequest) (*clusterapi.Node, error) {
	svc := c.getService()

	req.Name = c.definition.Common.Name + "-dcosbootstrap"
	req.NetworkIDs = []string{c.definition.NetworkID}
	req.PublicIP = true
	req.KeyPair = c.definition.Common.Keypair

	bootstrapVM, err := svc.CreateVM(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create Bootstrap server: %s", err.Error())
	}

	c.definition.BootstrapID = bootstrapVM.ID
	c.definition.BootstrapIP = bootstrapVM.PrivateIPsV4[0]

	// Update cluster definition in Object Storage
	err = c.SaveDefinition()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		c.definition.BootstrapID = ""
		c.definition.BootstrapIP = ""
		svc.DeleteVM(bootstrapVM.ID)
		return nil, fmt.Errorf("failed to update cluster definition: %s", err.Error())
	}

	return c.toNode(NodeType.Master, req.TemplateID, bootstrapVM), nil
}

//addMasterNode adds a master node
func (c *Cluster) addMasterNode(req providerapi.VMRequest) (*clusterapi.Node, error) {
	svc := c.getService()

	i := len(c.definition.MasterIDs) + 1
	req.Name = c.definition.Common.Name + "-dcosmaster-" + strconv.Itoa(i)
	req.NetworkIDs = []string{c.definition.NetworkID}
	req.PublicIP = true
	req.KeyPair = c.definition.Common.Keypair
	masterVM, err := svc.CreateVM(req)
	if err != nil {
		return nil, fmt.Errorf("failed to create master server %d: %s", i, err.Error())
	}

	// Registers the new Master in the cluster struct
	c.definition.MasterIDs = append(c.definition.MasterIDs, masterVM.ID)
	c.definition.MasterIPs = append(c.definition.MasterIPs, masterVM.PrivateIPsV4[0])

	// Update cluster definition in Object Storage
	err = c.SaveDefinition()
	if err != nil {
		// Object Storage failed, removes the ID we just added to the cluster struct
		c.definition.MasterIDs = c.definition.MasterIDs[:len(c.definition.MasterIDs)-1]
		c.definition.MasterIPs = c.definition.MasterIPs[:len(c.definition.MasterIPs)-1]
		svc.DeleteVM(masterVM.ID)
		return nil, fmt.Errorf("failed to update cluster definition: %s", err.Error())
	}

	return c.toNode(NodeType.Master, req.TemplateID, masterVM), nil
}

//toNode converts a VM struct to a Node struct
func (c *Cluster) toNode(nodeType NodeType.Enum, tmplID string, vm *providerapi.VM) *clusterapi.Node {
	return &clusterapi.Node{
		ID:         vm.ID,
		TemplateID: tmplID,
		State:      vm.State,
		Type:       nodeType,
	}
}

//addAgentNode adds a Public Agent Node to the cluster
func (c *Cluster) addAgentNode(req providerapi.VMRequest, nodeType NodeType.Enum) (*clusterapi.Node, error) {
	svc := c.getService()

	var publicIP bool
	coreName := "node"
	if nodeType == NodeType.PublicAgent {
		publicIP = true
		coreName = "pub" + coreName
	} else {
		publicIP = false
		coreName = "priv" + coreName
	}

	i := len(c.definition.PublicAgentIDs) + 1
	req.PublicIP = publicIP
	req.NetworkIDs = []string{c.definition.NetworkID}
	req.Name = c.definition.Common.Name + "-dcos" + coreName + "-" + strconv.Itoa(i)
	req.KeyPair = c.definition.Common.Keypair
	agentVM, err := svc.CreateVM(req)
	if err != nil {
		return nil, fmt.Errorf("Failed to create Public Agent node '%s': %s", req.Name, err.Error())
	}

	// Installs DCOS on agent node
	err = c.configureAgent(agentVM, nodeType)
	if err != nil {
		svc.DeleteVM(agentVM.ID)
		return nil, fmt.Errorf("Failed to install DCOS on Agent Node: %s", err.Error())

	}

	// Registers the new Agent in the cluster struct
	if nodeType == NodeType.PublicAgent {
		c.definition.PublicAgentIDs = append(c.definition.PublicAgentIDs, agentVM.ID)
		c.definition.PublicAgentIPs = append(c.definition.PublicAgentIPs, agentVM.PrivateIPsV4[0])

	} else {
		c.definition.PrivateAgentIDs = append(c.definition.PrivateAgentIDs, agentVM.ID)
		c.definition.PrivateAgentIPs = append(c.definition.PrivateAgentIPs, agentVM.PrivateIPsV4[0])
	}

	// Update cluster definition in Object Storage
	err = c.SaveDefinition()
	if err != nil {
		// Removes the ID we just added to the cluster struct
		if nodeType == NodeType.PublicAgent {
			c.definition.PublicAgentIDs = c.definition.PublicAgentIDs[:len(c.definition.PublicAgentIDs)-1]
		} else {
			c.definition.PrivateAgentIDs = c.definition.PrivateAgentIDs[:len(c.definition.PrivateAgentIDs)-1]
		}
		svc.DeleteVM(agentVM.ID)
		return nil, fmt.Errorf("failed to update cluster definition: %s", err.Error())
	}

	return c.toNode(nodeType, req.TemplateID, agentVM), nil
}

//configure prepares the bootstrap and masters for duty
func (c *Cluster) configure() error {
	svc := c.getService()

	bootstrapVM, err := svc.GetVM(c.definition.BootstrapID)
	if err != nil {
		return err
	}

	log.Printf("Configuring Bootstrap server")

	prepareDockerImages, err := realizePrepareDockerImages()
	if err != nil {
		return fmt.Errorf("failed to build configuration script: %s", err.Error())
	}
	var dnsServers []string
	cfg, err := svc.GetCfgOpts()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	retcode, output, err := c.executeScript(bootstrapVM, "dcos_install_bootstrap_node.sh", map[string]interface{}{
		"DCOSVersion":         dcosVersion,
		"BootstrapIP":         c.definition.BootstrapIP,
		"BootstrapPort":       "80",
		"ClusterName":         c.definition.Common.Name,
		"MasterIPs":           c.definition.MasterIPs,
		"DNSServerIPs":        dnsServers,
		"SSHPrivateKey":       c.definition.Common.Keypair.PrivateKey,
		"SSHPublicKey":        c.definition.Common.Keypair.PublicKey,
		"PrepareDockerImages": prepareDockerImages,
	})
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("scripted Bootstrap configuration failed with error code %d:\n%s", retcode, *output)
	}

	for _, m := range c.definition.MasterIDs {
		vm, err := svc.GetVM(m)
		if err != nil {
			continue
		}
		log.Printf("Configuring Master server '%s'", vm.Name)
		retcode, output, err := c.executeScript(vm, "dcos_install_master_node.sh", map[string]interface{}{
			"BootstrapIP":   bootstrapVM.AccessIPv4,
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
func (c *Cluster) configureAgent(targetVM *providerapi.VM, nodeType NodeType.Enum) error {
	svc := c.getService()
	bootstrapVM, err := svc.GetVM(c.definition.BootstrapID)
	if err != nil {
		return fmt.Errorf("failed to load data of bootstrap server: %s", err.Error())
	}

	var typeStr string
	if nodeType == NodeType.PublicAgent {
		typeStr = "yes"
	} else {
		typeStr = "no"
	}

	retcode, output, err := c.executeScript(targetVM, "dcos_install_agent_node.sh", map[string]interface{}{
		"PublicNode":    typeStr,
		"BootstrapIP":   bootstrapVM.AccessIPv4,
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
func (c *Cluster) executeScript(targetVM *providerapi.VM, script string, data map[string]interface{}) (int, *string, error) {
	svc := c.getService()

	ssh, err := svc.GetSSHConfig(targetVM.ID)
	if err != nil {
		return 0, nil, fmt.Errorf("[%s] error reading SSHConfig: %s", targetVM.Name, err.Error())
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
		return 0, nil, fmt.Errorf("[%s] error loading script template: %s", targetVM.Name, err.Error())
	}
	// parse and execute the template
	tmplCmd, err := template.New("cmd").Parse(tmplString)
	if err != nil {
		return 0, nil, fmt.Errorf("[%s] error parsing script template: %s", targetVM.Name, err.Error())
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, data)
	if err != nil {
		return 0, nil, fmt.Errorf("[%s] error realizing script template: %s", targetVM.Name, err.Error())
	}
	cmd := dataBuffer.String()

	cmdResult, err := ssh.SudoCommand(cmd)
	if err != nil {
		return 0, nil, fmt.Errorf("[%s] error executing script '%s': %s", targetVM.Name, script, err.Error())
	}
	retcode := 0
	out, err := cmdResult.CombinedOutput()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok {
				retcode = int(status)
			}
		} else {
			return 0, nil, fmt.Errorf("[%s] error fetching output of script '%s': %s", targetVM.Name, script, err.Error())
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
func (c *Cluster) ListMasters() (*[]clusterapi.Node, error) {
	return nil, fmt.Errorf("ListMasters not yet implemented")
}

//ListNodes lists the nodes in the cluster
func (c *Cluster) ListNodes() (*[]clusterapi.Node, error) {
	return nil, fmt.Errorf("ListNodes not yet implemented")
}

//GetNode returns a node based on its ID
func (*Cluster) GetNode(ID string) (*clusterapi.Node, error) {
	return nil, fmt.Errorf("ListNodes not yet implemented")
}

//GetDefinition returns the public properties of the cluster
func (c *Cluster) GetDefinition() clusterapi.Cluster {
	return c.definition.Common
}

//SaveDefinition writes cluster definition in Object Storage
func (c *Cluster) SaveDefinition() error {
	var buffer bytes.Buffer
	enc := gob.NewEncoder(&buffer)
	err := enc.Encode(c.definition)
	if err != nil {
		return err
	}
	return c.getService().PutObject(clusterapi.DeployContainerName, providerapi.Object{
		Name:    clusterapi.ClusterContainerNamePrefix + c.definition.Common.Name,
		Content: bytes.NewReader(buffer.Bytes()),
	})
}

//ReadDefinition reads definition of cluster named 'name' in Object Storage
// Returns (true, nil) if found and loaded, (false, nil) if not found, and (false, error) in case of error
func (c *Cluster) ReadDefinition() (bool, error) {
	svc := c.getService()

	path := clusterapi.ClusterContainerNamePrefix + c.definition.Common.Name
	list, err := svc.ListObjects(clusterapi.DeployContainerName, providerapi.ObjectFilter{
		Path: path,
	})
	if err != nil {
		return false, err
	}
	found := false
	for _, i := range list {
		if i == path {
			found = true
			break
		}
	}
	if found {
		o, err := svc.GetObject(clusterapi.DeployContainerName, clusterapi.ClusterContainerNamePrefix+c.definition.Common.Name, nil)
		if err != nil {
			return false, err
		}
		var buffer bytes.Buffer
		buffer.ReadFrom(o.Content)
		enc := gob.NewDecoder(&buffer)
		var d ClusterDefinition
		err = enc.Decode(&d)
		if err != nil {
			return false, err
		}
		c.definition = &d
		return true, nil
	}
	return false, nil
}

//RemoveDefinition removes definition of cluster from Object Storage
func (c *Cluster) RemoveDefinition() error {
	if len(c.definition.MasterIDs) > 0 ||
		len(c.definition.PublicAgentIDs) > 0 ||
		len(c.definition.PrivateAgentIDs) > 0 ||
		c.definition.NetworkID != "" {
		return fmt.Errorf("can't remove a definition of a cluster with infrastructure still existing")
	}

	svc := c.getService()

	path := clusterapi.ClusterContainerNamePrefix + c.definition.Common.Name
	list, err := svc.ListObjects(clusterapi.DeployContainerName, providerapi.ObjectFilter{
		Path: path,
	})
	if err != nil {
		return err
	}
	found := false
	for _, i := range list {
		if i == path {
			found = true
			break
		}
	}
	if found {
		err := c.getService().DeleteObject(clusterapi.DeployContainerName, clusterapi.ClusterContainerNamePrefix+c.definition.Common.Name)
		if err != nil {
			return fmt.Errorf("failed to remove cluster definition in Object Storage: %s", err.Error())
		}
		c.definition.Common.State = ClusterState.Removed
	}
	return nil
}
