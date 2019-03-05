/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package control

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	txttmpl "text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"
	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/resources"
	pb "github.com/CS-SI/SafeScale/safescale"
	"github.com/CS-SI/SafeScale/safescale/client"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/api"
	clusterpropsv1 "github.com/CS-SI/SafeScale/safescale/server/cluster/control/properties/v1"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/safescale/server/install"
	providermetadata "github.com/CS-SI/SafeScale/safescale/server/metadata"
	pbutils "github.com/CS-SI/SafeScale/safescale/utils"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/concurrency"
	"github.com/CS-SI/SafeScale/utils/template"
)

var (
	timeoutCtxHost = 10 * time.Minute

	// funcMap defines the custome functions to be used in templates
	funcMap = txttmpl.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	}
	tempFolder = "/var/tmp/"

	// // systemTemplateBox ...
	// systemTemplateBox *rice.Box

	// bashLibraryContent contains the script containing bash library
	bashLibraryContent *string
)

// Makers ...
type Makers struct {
	MinimumRequiredServers      func(task concurrency.Task, b Foreman) (int, int, int)          // returns masterCount, pruvateNodeCount, publicNodeCount
	DefaultGatewaySizing        func(task concurrency.Task, b Foreman) resources.HostDefinition // sizing of Gateway(s)
	DefaultMasterSizing         func(task concurrency.Task, b Foreman) resources.HostDefinition // default sizing of master(s)
	DefaultNodeSizing           func(task concurrency.Task, b Foreman) resources.HostDefinition // defailt sizing of node(s)
	DefaultImage                func(task concurrency.Task, b Foreman) string                   // default image of server(s)
	GetNodeInstallationScript   func(task concurrency.Task, b Foreman, nodeType NodeType.Enum) (string, map[string]interface{})
	GetGlobalSystemRequirements func(task concurrency.Task, b Foreman) (*string, error)
	GetTemplateBox              func() (*rice.Box, error)
	InstallGateway              func(task concurrency.Task, b Foreman) error
	ConfigureGateway            func(task concurrency.Task, b Foreman) error
	CreateMaster                func(task concurrency.Task, b Foreman, index int) error
	ConfigureMaster             func(task concurrency.Task, b Foreman, index int, pbHost *pb.Host) error
	UnconfigureMaster           func(task concurrency.Task, b Foreman, pbHost *pb.Host) error
	CreateNode                  func(task concurrency.Task, b Foreman, index int, pbHost *pb.Host) error
	ConfigureNode               func(task concurrency.Task, b Foreman, index int, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr string) error
	UnconfigureNode             func(task concurrency.Task, b Foreman, pbHost *pb.Host, selectedMasterID string) error
	ConfigureCluster            func(task concurrency.Task, b Foreman) error
	UnconfigureCluster          func(task concurrency.Task, b Foreman) error
	JoinMasterToCluster         func(task concurrency.Task, b Foreman, pbost *pb.Host) error
	JoinNodeToCluster           func(task concurrency.Task, b Foreman, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr string) error
	LeaveMasterFromCluster      func(task concurrency.Task, b Foreman, pbHost *pb.Host) error
	LeaveNodeFromCluster        func(task concurrency.Task, b Foreman, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr, selectedMaster string) error
	GetState                    func(task concurrency.Task, b Foreman) (ClusterState.Enum, error)
}

// Foreman interface, exposes public method
type Foreman interface {
	Cluster() api.Cluster
	ExecuteScript(*rice.Box, map[string]interface{}, string, map[string]interface{}, string) (int, string, string, error)
}

// foreman is the private side of Foreman...
type foreman struct {
	cluster *Controller
	makers  Makers
}

// NewForeman creates a new Foreman
func NewForeman(c *Controller, makers Makers) *foreman {
	return &foreman{
		cluster: c,
		makers:  makers,
	}
}

// Cluster ...
func (b *foreman) Cluster() api.Cluster {
	return b.cluster
}

// ExecuteScript executes the script template with the parameters on tarGetHost
func (b *foreman) ExecuteScript(
	box *rice.Box, funcMap map[string]interface{}, tmplName string, data map[string]interface{},
	hostID string,
) (int, string, string, error) {

	// Configures reserved_BashLibrary template var
	bashLibrary, err := system.GetBashLibrary()
	if err != nil {
		return 0, "", "", err
	}
	data["reserved_BashLibrary"] = bashLibrary

	path, err := uploadTemplateToFile(box, funcMap, tmplName, data, hostID, tmplName)
	if err != nil {
		return 0, "", "", err
	}
	var cmd string
	//if debug
	if true {
		cmd = fmt.Sprintf("sudo bash %s", path)
	} else {
		cmd = fmt.Sprintf("sudo bash %s; rc=$?; rm %s; exit $rc", path, path)
	}
	return client.New().Ssh.Run(hostID, cmd, client.DefaultConnectionTimeout, time.Duration(20)*time.Minute)
}

// construct ...
func (b *foreman) construct(task concurrency.Task, req Request) error {
	var err error
	log.Infof("Constructing cluster '%s'...", req.Name)
	defer func() {
		if err == nil {
			log.Infof("Cluster '%s' construction successful.", req.Name)
		}
	}()

	if task == nil {
		task = concurrency.RootTask()
	}

	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		msg := fmt.Sprintf("failed to generate password for user cladm: %s", err.Error())
		log.Errorf("[cluster %s] %s", req.Name, msg)
		return fmt.Errorf(msg)
	}

	// Determine default image
	imageID := "Ubuntu 18.04"
	if b.makers.DefaultImage != nil {
		imageID = b.makers.DefaultImage(task, b)
	}

	// Determine Gateway sizing
	gatewayDef := resources.HostDefinition{
		Cores:    2,
		RAMSize:  7.0,
		DiskSize: 60,
		ImageID:  imageID,
	}
	if b.makers.DefaultGatewaySizing != nil {
		gatewayDef = b.makers.DefaultGatewaySizing(task, b)
		gatewayDef.ImageID = imageID
	}
	//Note: no way yet to define gateway sizing from cli...
	// gatewayDef = complementHostDefinition(req.NodesDef, gatewayDef)
	pbGatewayDef := *pbutils.ToPBGatewayDefinition(&gatewayDef)

	// Determine master sizing
	masterDef := resources.HostDefinition{
		Cores:    4,
		RAMSize:  15.0,
		DiskSize: 100,
		ImageID:  imageID,
	}
	if b.makers.DefaultMasterSizing != nil {
		masterDef = b.makers.DefaultMasterSizing(task, b)
		masterDef.ImageID = imageID
	}
	// Note: no way yet to define master sizing from cli...
	masterDef = complementHostDefinition(req.NodesDef, masterDef)
	pbMasterDef := *pbutils.ToPBHostDefinition(&masterDef)

	// Determine node sizing
	nodeDef := resources.HostDefinition{
		Cores:    4,
		RAMSize:  15.0,
		DiskSize: 100,
		ImageID:  imageID,
	}
	if b.makers.DefaultNodeSizing != nil {
		nodeDef = b.makers.DefaultNodeSizing(task, b)
		nodeDef.ImageID = imageID
	}
	nodeDef = complementHostDefinition(req.NodesDef, nodeDef)
	if nodeDef.ImageID == "" {
		nodeDef.ImageID = imageID
	}
	pbNodeDef := *pbutils.ToPBHostDefinition(&nodeDef)

	// Creates network
	log.Debugf("[cluster %s] creating Network 'net-%s'", req.Name, req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	def := pb.NetworkDefinition{
		Name:    networkName,
		Cidr:    req.CIDR,
		Gateway: &pbGatewayDef,
	}
	clientInstance := client.New()
	clientNetwork := clientInstance.Network
	network, err := clientNetwork.Create(def, client.DefaultExecutionTimeout)
	if err != nil {
		msg := fmt.Sprintf("failed to create network '%s': %s", networkName, err.Error())
		log.Errorf("[cluster %s] %s", req.Name, msg)
		return fmt.Errorf(msg)
	}
	log.Debugf("[cluster %s] network '%s' creation successful.", req.Name, networkName)
	req.NetworkID = network.Id

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := clientNetwork.Delete([]string{network.Id}, client.DefaultExecutionTimeout)
			if derr != nil {
				log.Errorf("after failure, failed to delete network '%s'", networkName)
			}
		}
	}()

	// Saving Cluster parameters, with status 'Creating'
	var (
		kp     *resources.KeyPair
		kpName string
		gw     *resources.Host
		m      *providermetadata.Gateway
	)

	tenant, err := clientInstance.Tenant.Get(client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return err
	}

	// Loads gateway metadata
	m, err = providermetadata.NewGateway(svc, req.NetworkID)
	if err != nil {
		return err
	}
	err = m.Read()
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			if !ok {
				msg := fmt.Sprintf("failed to load gateway metadata of network '%s'", networkName)
				log.Errorf("[cluster %s] %s", req.Name, msg)
				return fmt.Errorf(msg)
			}
		}
		return err
	}
	gw = m.Get()

	err = clientInstance.Ssh.WaitReady(gw.ID, client.DefaultExecutionTimeout)
	if err != nil {
		return client.DecorateError(err, "wait for remote ssh service to be ready", false)
	}

	// Create a KeyPair for the user cladm
	kpName = "cluster_" + req.Name + "_cladm_key"
	kp, err = svc.CreateKeyPair(kpName)
	if err != nil {
		msg := fmt.Sprintf("failed to create Key Pair: %s", err.Error())
		log.Errorf("[cluster %s] %s", req.Name, msg)
		return fmt.Errorf(msg)
	}

	// Saving Cluster metadata, with status 'Creating'

	b.cluster.Identity.Name = req.Name
	b.cluster.Identity.Flavor = req.Flavor
	b.cluster.Identity.Complexity = req.Complexity
	b.cluster.Identity.Keypair = kp
	b.cluster.Identity.AdminPassword = cladmPassword

	// Saves Cluster metadata
	err = b.cluster.UpdateMetadata(task, func() error {
		err := b.cluster.GetProperties(task).LockForWrite(Property.DefaultsV1).ThenUse(func(v interface{}) error {
			defaultsV1 := v.(*clusterpropsv1.Defaults)
			defaultsV1.GatewaySizing = gatewayDef
			defaultsV1.MasterSizing = masterDef
			defaultsV1.NodeSizing = nodeDef
			defaultsV1.Image = imageID
			return nil
		})
		if err != nil {
			return err
		}

		err = b.cluster.GetProperties(task).LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.State).State = ClusterState.Creating
			return nil
		})
		if err != nil {
			return err
		}

		err = b.cluster.GetProperties(task).LockForWrite(Property.CompositeV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.Composite).Tenants = []string{req.Tenant}
			return nil
		})
		if err != nil {
			return err
		}

		return b.cluster.GetProperties(task).LockForWrite(Property.NetworkV1).ThenUse(func(v interface{}) error {
			networkV1 := v.(*clusterpropsv1.Network)
			networkV1.NetworkID = req.NetworkID
			networkV1.GatewayID = gw.ID
			networkV1.GatewayIP = gw.GetPrivateIP()
			networkV1.PublicIP = gw.GetPublicIP()
			networkV1.CIDR = req.CIDR
			return nil
		})
	})
	if err != nil {
		msg := fmt.Sprintf("creation failed: %s", err.Error())
		log.Errorf("[cluster %s] %s", req.Name, msg)
		return fmt.Errorf(msg)
	}

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := b.cluster.DeleteMetadata(task)
			if derr != nil {
				log.Debugf("after failure, failed to delete metadata of cluster")
			}
		}
	}()

	masterCount, privateNodeCount, publicNodeCount := b.determineRequiredNodes(task)
	var (
		// gatewayCh          chan error
		// mastersCh          chan error
		// privateNodesCh     chan error
		// publicNodesCh      chan error
		gatewayStatus      error
		mastersStatus      error
		privateNodesStatus error
		publicNodesStatus  error
	)

	// Step 1: starts gateway installation and masters and nodes creation
	// gatewayCh = make(chan error)
	// go b.taskInstallGateway(pbutils.ToPBHost(gw), gatewayCh)
	gatewayTask := concurrency.NewTask(task, b.taskInstallGateway)
	gatewayTask.Start(pbutils.ToPBHost(gw))

	// mastersCh = make(chan error)
	// go b.taskCreateMasters(masterCount, pbMasterDef, mastersCh)
	mastersTask := concurrency.NewTask(task, b.taskCreateMasters)
	mastersTask.Start(map[string]interface{}{
		"count":     masterCount,
		"masterDef": pbMasterDef,
	})

	// privateNodesCh = make(chan error)
	// go b.taskCreateNodes(privateNodeCount, false, pbNodeDef, privateNodesCh)
	privateNodesTask := concurrency.NewTask(task, b.taskCreateNodes)
	privateNodesTask.Start(map[string]interface{}{
		"count":   privateNodeCount,
		"public":  false,
		"nodeDef": pbNodeDef,
	})

	// publicNodesCh = make(chan error)
	// go b.taskCreateNodes(publicNodeCount, true, pbNodeDef, publicNodesCh)
	publicNodesTask := concurrency.NewTask(task, b.taskCreateNodes)
	publicNodesTask.Start(map[string]interface{}{
		"count":   publicNodeCount,
		"public":  true,
		"nodeDef": pbNodeDef,
	})

	// Step 2: awaits master creations and gateway installation finish
	// gatewayStatus = <-gatewayCh
	gatewayTask.Wait()
	gatewayStatus = gatewayTask.GetError()
	// mastersStatus = <-mastersCh
	mastersTask.Wait()
	mastersStatus = mastersTask.GetError()

	// Starting from here, delete masters if exiting with error and req.KeepOnFailure is not true
	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := client.New().Host.Delete(b.cluster.ListMasterIDs(task), client.DefaultExecutionTimeout)
			if derr != nil {
				log.Errorf("[cluster %s] after failure, failed to delete masters", req.Name)
			}
		}
	}()

	if gatewayStatus == nil && mastersStatus == nil {
		// gatewayCh = make(chan error)
		// go func() { b.taskConfigureGateway(pbutils.ToPBHost(gw), gatewayCh) }()
		// gatewayStatus = <-gatewayCh
		gatewayTask = concurrency.NewTask(task, b.taskConfigureGateway)
		gatewayStatus = gatewayTask.Run(pbutils.ToPBHost(gw))
	}

	// Step 5: configure masters
	if gatewayStatus == nil && mastersStatus == nil {
		// mastersCh = make(chan error)
		// go b.taskConfigureMasters(mastersCh)
		// mastersStatus = <-mastersCh
		mastersTask = concurrency.NewTask(task, b.taskConfigureMasters)
		mastersStatus = mastersTask.Run(nil)
	}

	// privateNodesStatus = <-privateNodesCh
	privateNodesTask.Wait()
	privateNodesStatus = privateNodesTask.GetError()
	// publicNodesStatus = <-publicNodesCh
	publicNodesTask.Wait()
	publicNodesStatus = publicNodesTask.GetError()

	// Starting from here, delete nodes on failure if exits with error and req.KeepOnFailure is false
	defer func() {
		if err != nil && !req.KeepOnFailure {
			clientHost := clientInstance.Host
			derr := clientHost.Delete(b.cluster.ListNodeIDs(task, false), client.DefaultExecutionTimeout)
			if derr != nil {
				log.Debugf("failed to remove private nodes on failure")
			}
			derr = clientHost.Delete(b.cluster.ListNodeIDs(task, true), client.DefaultExecutionTimeout)
			if derr != nil {
				log.Debugf("failed to remove public nodes on failure")
			}
		}
	}()

	// Step 6: Starts nodes configuration, if all masters and nodes
	// have been created and gateway has been configured with success
	if gatewayStatus == nil && mastersStatus == nil {
		if privateNodesStatus == nil {
			// privateNodesCh = make(chan error)
			// go b.taskConfigureNodes(false, privateNodesCh)
			privateNodesTask = concurrency.NewTask(task, b.taskConfigureNodes)
			privateNodesTask.Start(false)
		}
		if publicNodesStatus == nil {
			// publicNodesCh = make(chan error)
			// go b.taskConfigureNodes(true, publicNodesCh)
			publicNodesTask = concurrency.NewTask(task, b.taskConfigureNodes)
			publicNodesTask.Start(true)
		}
		if privateNodesStatus == nil {
			// privateNodesStatus = <-privateNodesCh
			privateNodesTask.Wait()
			privateNodesStatus = privateNodesTask.GetError()
		}
		if publicNodesStatus == nil {
			// publicNodesStatus = <-publicNodesCh
			publicNodesTask.Wait()
			publicNodesStatus = publicNodesTask.GetError()
		}
	}

	if gatewayStatus != nil {
		err = gatewayStatus // value of err may trigger defer calls, don't change anything here
		return err
	}
	if mastersStatus != nil {
		err = mastersStatus // value of err may trigger defer calls, don't change anything here
		return err
	}
	if privateNodesStatus != nil {
		err = privateNodesStatus // value of err may trigger defer calls, don't change anything here
		return err
	}
	if publicNodesStatus != nil {
		err = publicNodesStatus // value of err may trigger defer calls, don't change anything here
		return err
	}

	// At the end, configure cluster as a whole
	err = b.configureCluster(task)
	if err != nil {
		return err
	}

	return b.cluster.UpdateMetadata(task, func() error {
		// Cluster created and configured successfully
		return b.cluster.GetProperties(task).LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.State).State = ClusterState.Created
			return nil
		})
	})
}

// complementHostDefinition complements req with default values if needed
func complementHostDefinition(req *resources.HostDefinition, def resources.HostDefinition) resources.HostDefinition {
	var finalDef resources.HostDefinition
	if req == nil {
		finalDef = def
	} else {
		finalDef = *req
		if finalDef.Cores <= 0 && def.Cores > 0 {
			finalDef.Cores = def.Cores
		}
		if finalDef.RAMSize <= 0.0 && def.RAMSize > 0.0 {
			finalDef.RAMSize = def.RAMSize
		}
		if finalDef.DiskSize <= 0 && def.DiskSize > 0 {
			finalDef.DiskSize = def.DiskSize
		}
		//VPL: no enforcement on GPUNumber and Freq ?
		// if finalDef.GPUNumber == 0 && def.GPUNumber > 0 {
		// 	finalDef.GPUNumber = def.GPUNumber
		// }
		// if finalDef.Freq == 0 && def.Freq >0 {
		// 	finalDef.Freq = def.Freq
		// }
		if finalDef.ImageID == "" {
			finalDef.ImageID = def.ImageID
		}

		if finalDef.Cores <= 0 {
			finalDef.Cores = 4
		}
		if finalDef.RAMSize <= 0.0 {
			finalDef.RAMSize = 15.0
		}
		if finalDef.DiskSize <= 0 {
			finalDef.DiskSize = 100
		}
	}

	return finalDef
}

// GetState returns "actively" the current state of the cluster
func (b *foreman) getState(task concurrency.Task) (ClusterState.Enum, error) {
	if b.makers.GetState != nil {
		return b.makers.GetState(task, b)
	}
	return ClusterState.Unknown, fmt.Errorf("no maker defined for 'GetState'")
}

// configureNode ...
func (b *foreman) configureNode(task concurrency.Task, index int, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr string) error {
	if b.makers.ConfigureNode != nil {
		return b.makers.ConfigureNode(task, b, index, pbHost, nodeType, nodeTypeStr)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// unconfigureNode executes what has to be done to remove node from cluster
func (b *foreman) unconfigureNode(task concurrency.Task, hostID string, selectedMasterID string) error {
	pbHost, err := client.New().Host.Inspect(hostID, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if b.makers.UnconfigureNode != nil {
		return b.makers.UnconfigureNode(task, b, pbHost, selectedMasterID)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// configureMaster ...
func (b *foreman) configureMaster(task concurrency.Task, index int, pbHost *pb.Host) error {
	if b.makers.ConfigureNode != nil {
		return b.makers.ConfigureMaster(task, b, index, pbHost)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// unconfigureMaster executes what has to be done to remove Master from Cluster
func (b *foreman) unconfigureMaster(task concurrency.Task, pbHost *pb.Host) error {
	if b.makers.UnconfigureMaster != nil {
		return b.makers.UnconfigureMaster(task, b, pbHost)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// configureCluster ...
func (b *foreman) configureCluster(task concurrency.Task) error {
	log.Debugf(">>> safescale.cluster.controller.foreman::configureCluster()")
	defer log.Debugf("<<< safescale.cluster.controller.foreman::configureCluster()")

	var err error

	log.Infof("[cluster %s] configuring cluster...", b.cluster.Name)
	defer func() {
		if err == nil {
			log.Infof("[cluster %s] configuration successful.", b.cluster.Name)
		}
	}()

	// Installs remotedesktop feature on all masters
	err = b.installRemoteDesktop(task)
	if err != nil {
		return err
	}

	// configure what has to be done cluster-wide
	if b.makers.ConfigureCluster != nil {
		return b.makers.ConfigureCluster(task, b)
	}

	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

func (b *foreman) determineRequiredNodes(task concurrency.Task) (int, int, int) {
	if b.makers.MinimumRequiredServers != nil {
		return b.makers.MinimumRequiredServers(task, b)
	}
	return 0, 0, 0
}

// uploadTemplateToFile uploads a template named 'tmplName' coming from rice 'box' in a file to a remote host
func uploadTemplateToFile(
	box *rice.Box, funcMap map[string]interface{}, tmplName string, data map[string]interface{},
	hostID string, fileName string,
) (string, error) {

	if box == nil {
		panic("box is nil!")
	}
	host, err := client.New().Host.Inspect(hostID, client.DefaultExecutionTimeout)
	if err != nil {
		return "", fmt.Errorf("failed to get host information: %s", err)
	}

	tmplString, err := box.String(tmplName)
	if err != nil {
		return "", fmt.Errorf("failed to load template: %s", err.Error())
	}
	tmplCmd, err := txttmpl.New(fileName).Funcs(template.MergeFuncs(funcMap, false)).Parse(tmplString)
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

	err = install.UploadStringToRemoteFile(cmd, host, remotePath, "", "", "")
	if err != nil {
		return "", err
	}
	return remotePath, nil
}

// configureNodesFromList ...
func (b *foreman) configureNodesFromList(task concurrency.Task, public bool, hosts []string) error {
	var (
		nodeType    NodeType.Enum
		nodeTypeStr string
	)
	if public {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "private"
	}

	log.Debugf("Configuring %s Nodes...", nodeTypeStr)

	var (
		host   *pb.Host
		err    error
		hostID string
		errors []string
	)

	// dones := []chan error{}
	var subtasks []concurrency.Task
	clientHost := client.New().Host
	length := len(hosts)
	// for i, hostID = range hosts {
	for i := 0; i < length; i++ {
		// host, err = clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		host, err = clientHost.Inspect(hosts[i], client.DefaultExecutionTimeout)
		if err != nil {
			break
		}
		// d := make(chan error)
		// dones = append(dones, d)
		// go b.taskConfigureNode(i+1, host, nodeType, nodeTypeStr, d)
		subtask := concurrency.NewTask(task, b.taskConfigureNode)
		subtasks = append(subtasks, subtask)
		subtask.Start(map[string]interface{}{
			"index":   i + 1,
			"host":    host,
			"type":    nodeType,
			"typeStr": nodeTypeStr,
		})
	}
	// Deals with the metadata read failure
	if err != nil {
		errors = append(errors, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		// err = <-dones[i]
		s.Wait()
		state := s.GetError()
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "\n"))
	}
	return nil
}

// joinNodesFromList ...
func (b *foreman) joinNodesFromList(task concurrency.Task, public bool, hosts []string) error {
	if b.makers.JoinNodeToCluster == nil {
		return nil
	}

	var (
		nodeType    NodeType.Enum
		nodeTypeStr string
	)
	if public {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "private"
	}

	log.Debugf("Joining %s Nodes to cluster...", nodeTypeStr)

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return err
		}
		err = b.makers.JoinNodeToCluster(task, b, pbHost, nodeType, nodeTypeStr)
		if err != nil {
			return err
		}
	}

	return nil
}

// leaveMastersFromList ...
func (b *foreman) leaveMastersFromList(task concurrency.Task, public bool, hosts []string) error {
	if b.makers.LeaveMasterFromCluster == nil {
		return nil
	}

	log.Debugf("Making Masters leaving cluster...")

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return err
		}
		err = b.makers.LeaveMasterFromCluster(task, b, pbHost)
		if err != nil {
			return err
		}
	}

	return nil
}

// leaveNodesFromList ...
func (b *foreman) leaveNodesFromList(task concurrency.Task, hosts []string, public bool, selectedMasterID string) error {
	if b.makers.LeaveNodeFromCluster == nil {
		return nil
	}

	var (
		nodeType    NodeType.Enum
		nodeTypeStr string
	)
	if public {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "private"
	}

	log.Debugf("Making %s Nodes leaving cluster...", nodeTypeStr)

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			// If host seems deleted, consider leaving as a success
			if _, ok := err.(resources.ErrResourceNotFound); ok {
				continue
			}
			return err
		}
		err = b.makers.LeaveNodeFromCluster(task, b, pbHost, nodeType, nodeTypeStr, selectedMasterID)
		if err != nil {
			return err
		}
	}

	return nil
}

// installNodeRequirements ...
func (b *foreman) installNodeRequirements(task concurrency.Task, nodeType NodeType.Enum, pbHost *pb.Host, hostLabel string) error {
	// Get installation script based on node type; if == "", do nothing
	script, params := b.getNodeInstallationScript(task, nodeType)
	if script == "" {
		return nil
	}

	log.Debugf("[%s] installing system requirements...", hostLabel)

	if b.makers.GetTemplateBox == nil {
		err := fmt.Errorf("missing callback GetTemplateBox")
		log.Errorf("[%s] system requirements installation failed: %v", hostLabel, err)
		return err
	}
	box, err := b.makers.GetTemplateBox()
	if err != nil {
		log.Errorf("[%s] system requirements installation failed: %v", hostLabel, err)
		return err
	}

	globalSystemRequirements := ""
	if b.makers.GetGlobalSystemRequirements != nil {
		result, err := b.makers.GetGlobalSystemRequirements(task, b)
		if err != nil {
			log.Errorf("[%s] system requirements installation failed: %v", hostLabel, err)
			return err
		}
		globalSystemRequirements = *result
	}

	var dnsServers []string
	cfg, err := b.cluster.GetService(task).GetCfgOpts()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	identity := b.cluster.GetIdentity(task)
	params["reserved_CommonRequirements"] = globalSystemRequirements
	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	params["MasterIPs"] = b.cluster.ListMasterIPs(task)
	params["CladmPassword"] = identity.AdminPassword

	retcode, _, _, err := b.ExecuteScript(box, funcMap, script, params, pbHost.Id)
	if err != nil {
		log.Errorf("[%s] system requirements installation failed: %s", hostLabel, err.Error())
		return err
	}
	if retcode != 0 {
		log.Errorf("[%s] system requirements installation failed: retcode=%d", hostLabel, retcode)
		return fmt.Errorf("failed to install system requirements on '%s' with error code '%d'", pbHost.Name, retcode)
	}

	log.Debugf("[%s] system requirements installation successful.", hostLabel)
	return nil
}

// getNodeInstallationScript ...
func (b *foreman) getNodeInstallationScript(task concurrency.Task, nodeType NodeType.Enum) (string, map[string]interface{}) {
	if b.makers.GetNodeInstallationScript != nil {
		return b.makers.GetNodeInstallationScript(task, b, nodeType)
	}
	return "", map[string]interface{}{}
}

// installRemoteDesktop installs feature remotedesktop on all masters of the cluster
func (b *foreman) installRemoteDesktop(task concurrency.Task) error {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	disabled := false
	err := b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["remotedesktop"]
		return nil
	})
	if err != nil {
		log.Errorf("[cluster %s] failed to install 'remotedesktop' feature: %v", clusterName, err)
		return err
	}
	if !disabled {
		log.Debugf("[cluster %s] adding feature 'remotedesktop'", clusterName)

		adminPassword := identity.AdminPassword
		target := install.NewClusterTarget(task, b.cluster)

		// Adds remotedesktop feature on master
		feature, err := install.NewFeature(task, "remotedesktop")
		if err != nil {
			log.Debugf("[cluster %s] failed to instanciate feature 'remotedesktop': %s\n", clusterName, err.Error())
			return err
		}
		results, err := feature.Add(target, install.Variables{
			"Username": "cladm",
			"Password": adminPassword,
		}, install.Settings{})
		if err != nil {
			log.Errorf("[cluster %s] failed to add feature '%s': %s", clusterName, feature.DisplayName(), err.Error())
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Errorf("[cluster %s] failed to add '%s' failed: %s\n", clusterName, feature.DisplayName(), msg)
			return fmt.Errorf(msg)
		}
		log.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feature.DisplayName())
	}
	return nil
}

// taskInstallGateway installs necessary components on the gateway
// Designed to work in goroutine
// func (b *Foreman) taskInstallGateway(pbGateway *pb.Host, done chan error) {
func (b *foreman) taskInstallGateway(tr concurrency.TaskRunner, params interface{}) {
	pbGateway := params.(*pb.Host)
	// log.Debugf(">>> safescale.server.cluster.control.foreman::taskInstallGateway(%s)", pbGateway.Name)
	// defer log.Debugf("<<< safescale.server.cluster.control.foreman::taskInstallGateway(%s)", pbGateway.Name)

	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	hostLabel := "gateway"
	log.Debugf("[%s] starting installation...", hostLabel)

	sshCfg, err := client.New().Host.SSHConfig(pbGateway.Id)
	if err != nil {
		// done <- err
		return
	}
	err = sshCfg.WaitServerReady(5 * time.Minute)
	if err != nil {
		// done <- err
		return
	}

	// Installs proxycache server on gateway (if not disabled)
	err = b.installProxyCacheServer(tr.Task(), pbGateway, hostLabel)
	if err != nil {
		// done <- err
		return
	}

	// Installs requirements as defined by cluster Flavor (if it exists)
	err = b.installNodeRequirements(tr.Task(), NodeType.Gateway, pbGateway, "gateway")
	if err != nil {
		// done <- err
		return
	}

	// Installs reverseproxy
	err = b.installReverseProxy(tr.Task(), pbGateway, hostLabel)
	if err != nil {
		// done <- err
		return
	}

	log.Debugf("[%s] preparation successful", hostLabel)
	// done <- nil
}

// taskConfigureGateway prepares the gateway
// Designed to work in goroutine
// func (b *Foreman) taskConfigureGateway(gw *pb.Host, done chan error) {
func (b *foreman) taskConfigureGateway(tr concurrency.TaskRunner, params interface{}) {
	// Convert parameters
	gw := params.(*pb.Host)
	log.Debugf(">>> safescale.server.cluster.control.foreman::taskConfigureGateway(%s)", gw.Name)
	defer log.Debugf("<<< safescale.server.cluster.control.foreman::taskConfigureGateway(%s)", gw.Name)

	log.Debugf("[gateway] starting configuration...")

	// defer task end based on err
	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	// // Docker installation is mandatory on all nodes
	// // Note: normally, docker is already installed in taskInstallGateway through reverseproxy...
	// err := b.installDocker(gw, "gateway")
	// if err != nil {
	// 	done <- err
	// 	return
	// }

	if b.makers.ConfigureGateway != nil {
		err := b.makers.ConfigureGateway(tr.Task(), b)
		if err != nil {
			// done <- err
			return
		}
	}

	log.Debugf("[gateway] configuration successful.")
	// done <- nil
}

// taskCreateMasters ...
// Intended to be used as goroutine
// func (b *Foreman) taskCreateMasters(count int, def pb.HostDefinition, done chan error) {
func (b *foreman) taskCreateMasters(tr concurrency.TaskRunner, params interface{}) {
	// Convert parameters
	p := params.(map[string]interface{})
	count := p["count"].(int)
	def := p["masterDef"].(pb.HostDefinition)

	log.Debugf(">>> safescale.server.cluster.control.foreman::taskCreateMasters(%d)", count)
	defer log.Debugf(">>> safescale.server.cluster.control.foreman::taskCreateMasters(%d)", count)

	// defer task end based on err
	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	clusterName := b.cluster.GetIdentity(tr.Task()).Name

	if count <= 0 {
		log.Debugf("[cluster %s] no masters to create.", clusterName)
		// done <- nil
		return
	}

	log.Debugf("[cluster %s] creating %d master%s...\n", clusterName, count, utils.Plural(count))

	var subtasks []concurrency.Task
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 0; i < count; i++ {
		subtask := concurrency.NewTask(tr.Task(), b.taskCreateMaster).Start(map[string]interface{}{
			"index":     i + 1,
			"masterDef": def,
			"timeout":   timeout,
		})
		subtasks = append(subtasks, subtask)
	}
	var state error
	var errors []string
	for _, s := range subtasks {
		s.Wait()
		state = s.GetError()
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		msg := strings.Join(errors, "\n")
		log.Errorf("[cluster %s] failed to create master(s): %s", clusterName, msg)
		err = fmt.Errorf(msg)
		// done <- fmt.Errorf(msg)
		return
	}

	log.Debugf("[cluster %s] masters creation successful.", clusterName)
	// done <- nil
}

// taskCreateMaster adds a master node
// func (b *Foreman) taskCreateMaster(index int, def pb.HostDefinition, timeout time.Duration, done chan error) {
func (b *foreman) taskCreateMaster(tr concurrency.TaskRunner, params interface{}) {
	// Convert parameters
	p := params.(map[string]interface{})
	index := p["index"].(int)
	def := p["masterDef"].(pb.HostDefinition)
	timeout := p["timeout"].(time.Duration)

	log.Debugf(">>>{task %s} safescale.cluster.controller.foreman::taskCreateMaster(%d)", tr.ID(), index)
	defer log.Debugf("<<<{task %s} safescale.cluster.controller.foreman::taskCreateMaster(%d)", tr.ID(), index)

	// defer task end based on err
	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	hostLabel := fmt.Sprintf("master #%d", index)
	log.Debugf("[%s] starting host resource creation...\n", hostLabel)

	name, err := b.buildHostname(tr.Task(), "master", NodeType.Master)
	if err != nil {
		log.Errorf("[%s] creation failed: %s\n", hostLabel, err.Error())
		// done <- fmt.Errorf("failed to create '%s': %s", hostLabel, err.Error())
		err = fmt.Errorf("failed to create '%s': %s", hostLabel, err.Error())
		return
	}

	def.Network = b.cluster.GetNetworkConfig(tr.Task()).NetworkID
	def.Public = false
	def.Name = name
	clientHost := client.New().Host
	pbHost, err := clientHost.Create(def, timeout)
	if err != nil {
		err = client.DecorateError(err, "creation of host resource", false)
		log.Errorf("[%s] host resource creation failed: %s", hostLabel, err.Error())
		// done <- fmt.Errorf("failed to create '%s': %s", hostLabel, err.Error())
		err = fmt.Errorf("failed to create '%s': %s", hostLabel, err.Error())
		return
	}
	hostLabel = fmt.Sprintf("%s (%s)", hostLabel, pbHost.Name)
	log.Debugf("[%s] host resource creation successful", hostLabel)

	defer func() {
		if err != nil {
			derr := clientHost.Delete([]string{pbHost.Id}, timeout)
			if derr != nil {
				log.Errorf("failed to delete master after failure")
			}
		}
	}()

	err = b.cluster.UpdateMetadata(tr.Task(), func() error {
		// Locks for write the NodesV1 extension...
		return b.cluster.GetProperties(tr.Task()).LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			// Update swarmCluster definition in Object Storage
			node := &clusterpropsv1.Node{
				ID:        pbHost.Id,
				Name:      pbHost.Name,
				PrivateIP: pbHost.PrivateIp,
				PublicIP:  pbHost.PublicIp,
			}
			nodesV1.Masters = append(nodesV1.Masters, node)
			return nil
		})
	})
	if err != nil {
		log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
		// done <- fmt.Errorf("failed to update Cluster metadata: %s", err.Error())
		err = fmt.Errorf("failed to update Cluster metadata: %s", err.Error())
		return
	}

	err = b.installProxyCacheClient(tr.Task(), pbHost, hostLabel)
	if err != nil {
		// done <- err
		return
	}

	// Installs cluster-level system requirements...
	err = b.installNodeRequirements(tr.Task(), NodeType.Master, pbHost, hostLabel)
	if err != nil {
		// done <- err
		return
	}

	log.Debugf("[%s] host rsource creation successful.", hostLabel)
	// done <- nil
}

// taskConfigureMasters configure masters
// func (b *Foreman) taskConfigureMasters(done chan error) {
func (b *foreman) taskConfigureMasters(tr concurrency.TaskRunner, params interface{}) {
	log.Debugf(">>> safescale.server.cluster.control.Foreman::taskConfigureMasters()")
	defer log.Debugf("<<< safescale.server.cluster.control.Foreman::taskConfigureMasters()")

	// defer task end based on err
	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	list := b.cluster.ListMasterIDs(tr.Task())
	if len(list) <= 0 {
		// done <- nil
		return
	}

	log.Debugf("[cluster %s] Configuring masters...", b.cluster.Name)

	clientHost := client.New().Host
	// dones := []chan error{}
	var subtasks []concurrency.Task
	for i, hostID := range b.cluster.ListMasterIDs(tr.Task()) {
		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			// done <- fmt.Errorf("failed to get metadata of host: %s", err.Error())
			err = fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		// d := make(chan error)
		// dones = append(dones, d)
		// go b.taskConfigureMaster(i+1, host, d)
		subtask := concurrency.NewTask(tr.Task(), b.taskConfigureMaster)
		subtasks = append(subtasks, subtask)
		subtask.Start(map[string]interface{}{
			"index": i + 1,
			"host":  host,
		})
	}

	var state error
	var errors []string
	// for i := range dones {
	for _, s := range subtasks {
		// state = <-dones[i]
		s.Wait()
		state = s.GetError()
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		// done <- fmt.Errorf(strings.Join(errors, "\n"))
		err = fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	log.Debugf("[cluster %s] Masters configuration successful.", b.cluster.Name)
	// done <- nil
}

// taskConfigureMaster configures master
// func (b *Foreman) taskConfigureMaster(index int, pbHost *pb.Host, done chan error) {
func (b *foreman) taskConfigureMaster(tr concurrency.TaskRunner, params interface{}) {
	// Convert params
	p := params.(map[string]interface{})
	index := p["index"].(int)
	pbHost := p["host"].(*pb.Host)

	log.Debugf(">>> safescale.server.cluster.control.Foreman::taskConfigureMaster(%d, %s)", index, pbHost.Name)
	defer log.Debugf("<<< safescale.server.cluster.control.Foreman::taskConfigureMaster(%d, %s)", index, pbHost.Name)

	// defer task end based on err
	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	hostLabel := fmt.Sprintf("master #%d (%s)", index, pbHost.Name)
	log.Debugf("[%s] starting configuration...\n", hostLabel)

	// install docker feature
	err = b.installDocker(tr.Task(), pbHost, hostLabel)
	if err != nil {
		// done <- err
		return
	}

	err = b.configureMaster(tr.Task(), index, pbHost)
	if err != nil {
		// done <- err
		return
	}

	log.Debugf("[%s] configuration successful.", hostLabel)
	// done <- nil
}

// func (b *Foreman) taskCreateNodes(count int, public bool, def pb.HostDefinition, done chan error) {
func (b *foreman) taskCreateNodes(tr concurrency.TaskRunner, params interface{}) {
	// Convert params
	p := params.(map[string]interface{})
	count := p["count"].(int)
	public := p["public"].(bool)
	def := p["nodeDef"].(pb.HostDefinition)

	log.Debugf(">>> safescale.server.cluster.control.Foreman::taskCreateNodes(%d, %v)", count, public)
	defer log.Debugf("<<< safescale.server.cluster.control.Foreman::taskCreateNodes(%d, %v)", count, public)

	// defer task end based on err
	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	clusterName := b.cluster.GetIdentity(tr.Task()).Name

	var nodeType NodeType.Enum
	var nodeTypeStr string
	if public {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "private"
	}

	if count <= 0 {
		log.Debugf("[cluster %s] no %s nodes to create.", clusterName, nodeTypeStr)
		// done <- nil
		return
	}
	log.Debugf("[cluster %s] creating %d %s node%s...\n", clusterName, count, nodeTypeStr, utils.Plural(count))

	// var dones []chan error
	// var results []chan string
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	var subtasks []concurrency.Task
	for i := 1; i <= count; i++ {
		// r := make(chan string)
		// results = append(results, r)
		// d := make(chan error)
		// dones = append(dones, d)
		// go b.taskCreateNode(i, nodeType, def, timeout, r, d)
		subtask := concurrency.NewTask(tr.Task(), b.taskCreateNode)
		subtask.Start(map[string]interface{}{
			"index":   i,
			"type":    nodeType,
			"nodeDef": def,
			"timeout": timeout,
		})
		subtasks = append(subtasks, subtask)
	}

	var state error
	var errors []string
	// for i := range dones {
	for _, s := range subtasks {
		// <-results[i]
		// state = <-dones[i]
		s.Wait()
		state = s.GetError()
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		// done <- fmt.Errorf(strings.Join(errors, "\n"))
		err = fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	log.Debugf("[cluster %s] %d %s node%s creation successful.", clusterName, count, nodeTypeStr, utils.Plural(count))
	// done <- nil
}

// taskCreateNode creates a Node in the Cluster
// This function is intended to be call as a goroutine
// func (b *Foreman) taskCreateNode(
// 	index int, nodeType NodeType.Enum, def pb.HostDefinition, timeout time.Duration,
// 	result chan string, done chan error,
func (b *foreman) taskCreateNode(tr concurrency.TaskRunner, params interface{}) {
	// Convert parameters
	p := params.(map[string]interface{})
	index := p["index"].(int)
	nodeType := p["type"].(NodeType.Enum)
	def := p["nodeDef"].(pb.HostDefinition)
	timeout := p["timeout"].(time.Duration)

	log.Debugf(">>> safescale.server.cluster.control.Foreman::taskCreateNode(%d, %s)", index, nodeType.String())
	defer log.Debugf("<<< safescale.server.cluster.control.Foreman::taskCreateNode(%d, %s)", index, nodeType.String())

	if tr == nil {
		panic("Invalid parameter 'tr': can't be ni!")
	}

	// defer task end based on err
	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	var (
		publicIP    bool
		nodeTypeStr string
	)
	if nodeType == NodeType.PublicNode {
		nodeTypeStr = "public"
		publicIP = true
	} else {
		nodeTypeStr = "private"
		publicIP = false
	}
	hostLabel := fmt.Sprintf("%s node #%d", nodeTypeStr, index)
	log.Debugf("[%s] starting host resource creation...", hostLabel)

	// Create the host
	def.Name, err = b.buildHostname(tr.Task(), "node", nodeType)
	if err != nil {
		log.Errorf("[%s] host resource creation failed: %s", hostLabel, err.Error())
		// result <- ""
		// done <- err
		return
	}
	def.Public = publicIP
	def.Network = b.cluster.GetNetworkConfig(tr.Task()).NetworkID
	if timeout < 10*time.Minute {
		timeout = 10 * time.Minute
	}

	clientHost := client.New().Host
	pbHost, err := clientHost.Create(def, timeout)
	if err != nil {
		err = client.DecorateError(err, "creation of host resource", true)
		log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
		// result <- ""
		// done <- err
		return
	}
	hostLabel = fmt.Sprintf("%s node #%d (%s)", nodeTypeStr, index, pbHost.Name)
	log.Debugf("[%s] host resource creation successful.", hostLabel)

	var node *clusterpropsv1.Node
	err = b.cluster.UpdateMetadata(tr.Task(), func() error {
		// Locks for write the NodesV1 extension...
		return b.cluster.GetProperties(tr.Task()).LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			// Registers the new Agent in the swarmCluster struct
			node = &clusterpropsv1.Node{
				ID:        pbHost.Id,
				Name:      pbHost.Name,
				PrivateIP: pbHost.PrivateIp,
				PublicIP:  pbHost.PublicIp,
			}
			if nodeType == NodeType.PublicNode {
				nodesV1.PublicNodes = append(nodesV1.PublicNodes, node)
			} else {
				nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, node)
			}
			return nil
		})
	})
	if err != nil {
		derr := clientHost.Delete([]string{pbHost.Id}, 10*time.Minute)
		if derr != nil {
			log.Errorf("failed to delete node after failure")
		}
		log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
		// result <- ""
		// done <- fmt.Errorf("failed to create node: %s", err.Error())
		err = fmt.Errorf("failed to create node: %s", err.Error())
		return
	}

	// Starting from here, delete node from cluster if exiting with error
	defer func() {
		if err != nil {
			derr := b.cluster.deleteNode(tr.Task(), node, publicIP, "")
			if derr != nil {
				log.Errorf("failed to delete node after failure")
			}
		}
	}()

	err = b.installProxyCacheClient(tr.Task(), pbHost, hostLabel)
	if err != nil {
		// result <- ""
		// done <- err
		return
	}

	err = b.installNodeRequirements(tr.Task(), nodeType, pbHost, hostLabel)
	if err != nil {
		// result <- ""
		// done <- err
		return
	}
	// result <- pbHost.Name
	tr.StoreResult(pbHost.Name)

	log.Debugf("[%s] host resource creation successful.", hostLabel)
	// done <- nil
}

// taskConfigureNodes ...
// func (b *Foreman) taskConfigureNodes(public bool, done chan error) {
func (b *foreman) taskConfigureNodes(tr concurrency.TaskRunner, params interface{}) {
	// Convert parameters
	public := params.(bool)

	log.Debugf(">>> safescale.cluster.controller.Foreman::taskConfigureNodes(%v)", public)
	defer log.Debugf("<<< safescale.cluster.controller.Foreman::taskConfigureNodes(%v)", public)

	var (
		nodeType    NodeType.Enum
		nodeTypeStr string
		err         error
	)

	// defer task end based on err
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	if public {
		nodeType = NodeType.PrivateNode
		nodeTypeStr = "public"
	} else {
		nodeType = NodeType.PublicNode
		nodeTypeStr = "private"
	}
	clusterName := b.cluster.GetIdentity(tr.Task()).Name
	list := b.cluster.ListNodeIDs(tr.Task(), public)
	if len(list) <= 0 {
		log.Debugf("[cluster %s] no %s nodes to configure.", clusterName, nodeTypeStr)
		// done <- nil
		return
	}

	log.Debugf("[cluster %s] configuring %s nodes...", clusterName, nodeTypeStr)

	var (
		pbHost *pb.Host
		i      int
		hostID string
		errors []string
	)

	// dones := []chan error{}
	var subtasks []concurrency.Task
	clientHost := client.New().Host
	for i, hostID = range list {
		pbHost, err = clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			break
		}
		// d := make(chan error)
		// dones = append(dones, d)
		// go b.taskConfigureNode(i+1, pbHost, nodeType, nodeTypeStr, d)
		subtask := concurrency.NewTask(tr.Task(), b.taskConfigureNode).Start(map[string]interface{}{
			"index":   i + 1,
			"host":    pbHost,
			"type":    nodeType,
			"typeStr": nodeTypeStr,
		})
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	if err != nil {
		errors = append(errors, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	// for i = range dones {
	for _, s := range subtasks {
		// 	err = <-dones[i]
		s.Wait()
		err = s.GetError()
		if err != nil {
			errors = append(errors, err.Error())
		}
	}
	if len(errors) > 0 {
		// done <- fmt.Errorf(strings.Join(errors, "\n"))
		err = fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	log.Debugf("[cluster %s] %s nodes configuration successful.", clusterName, nodeTypeStr)
	// done <- nil
}

// taskConfigureNode ...
// func (b *Foreman) taskConfigureNode(
// 	index int, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr string,
// 	done chan error,
// ) {
func (b *foreman) taskConfigureNode(tr concurrency.TaskRunner, params interface{}) {
	// Convert parameters
	p := params.(map[string]interface{})
	index := p["index"].(int)
	pbHost := p["host"].(*pb.Host)
	nodeType := p["type"].(NodeType.Enum)
	nodeTypeStr := p["typeStr"].(string)

	log.Debugf(">>> safescale.cluster.controller.Foreman::taskConfigureNode(%d, %s)", index, pbHost.Name)
	defer log.Debugf("<<< safescale.cluster.controller.Foreman::taskConfigureNode(%d, %s)", index, pbHost.Name)

	// defer task end based on err
	var err error
	defer func() {
		if err != nil {
			tr.Fail(err)
		} else {
			tr.Done()
		}
	}()

	hostLabel := fmt.Sprintf("%s node #%d (%s)", nodeTypeStr, index, pbHost.Name)
	log.Debugf("[%s] starting configuration...", hostLabel)

	// Docker installation is mandatory on all nodes
	err = b.installDocker(tr.Task(), pbHost, hostLabel)
	if err != nil {
		// done <- err
		return
	}

	// Now configures node specifically for cluster flavor
	err = b.configureNode(tr.Task(), index, pbHost, nodeType, nodeTypeStr)
	if err != nil {
		// done <- err
		return
	}

	log.Debugf("[%s] configuration successful.", hostLabel)
	// done <- nil
}

func (b *foreman) installReverseProxy(task concurrency.Task, pbHost *pb.Host, hostLabel string) error {
	// Installs reverseproxy
	disabled := false
	b.cluster.RLock(task)
	err := b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["reverseproxy"]
		return nil
	})
	b.cluster.RUnlock(task)
	if err != nil {
		log.Debugf("[%s] adding feature 'reverseproxy'...", hostLabel)
		log.Errorf("[%s] feature 'reverseproxy' installation failed: %s", hostLabel, err.Error())
		return err
	}
	if !disabled {
		log.Debugf("[%s] adding feature 'reverseproxy'...", hostLabel)
		feature, err := install.NewFeature(task, "reverseproxy")
		if err != nil {
			msg := fmt.Sprintf("[%s] failed to prepare feature 'reverseproxy': %s", hostLabel, err.Error())
			log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		target := install.NewHostTarget(pbHost)
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			msg := fmt.Sprintf("[%s] failed to install feature 'reverseproxy': %s", hostLabel, err.Error())
			log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		if !results.Successful() {
			msg := fmt.Sprintf("[%s] failed to install feature 'reverseproxy': %s", hostLabel, results.AllErrorMessages())
			log.Errorf(msg)
			return fmt.Errorf(msg)
		}
		log.Debugf("[%s] feature 'reverseproxy' addition successful.", hostLabel)
	}
	return nil
}

// install proxycache-client feature if not disabled
func (b *foreman) installProxyCacheClient(task concurrency.Task, pbHost *pb.Host, hostLabel string) error {
	disabled := false
	b.cluster.RLock(task)
	err := b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["proxycache"]
		return nil
	})
	b.cluster.RUnlock(task)
	if err != nil {
		log.Debugf("[%s] adding feature 'proxycache-client'...", hostLabel)
		log.Errorf("[%s] installation failed: %v", hostLabel, err)
		return err
	}
	if !disabled {
		log.Debugf("[%s] adding feature 'proxycache-client'...", hostLabel)

		feature, err := install.NewFeature(task, "proxycache-client")
		if err != nil {
			log.Errorf("[%s] failed to prepare feature 'proxycache-client': %s", hostLabel, err.Error())
			return fmt.Errorf("failed to install feature 'proxycache-client': %s", err.Error())
		}
		target := install.NewHostTarget(pbHost)
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Errorf("[%s] failed to install feature 'proxycache-client': %s", hostLabel, err.Error())
			return fmt.Errorf("failed to install feature 'proxycache-client' on host '%s': %s", pbHost.Name, err.Error())
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Errorf("[%s] failed to install feature 'proxycache-client': %s", hostLabel, msg)
			return fmt.Errorf(msg)
		}
	}
	return nil
}

// install proxycache-server feature if not disabled
func (b *foreman) installProxyCacheServer(task concurrency.Task, pbHost *pb.Host, hostLabel string) error {
	disabled := false
	b.cluster.RLock(task)
	err := b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["proxycache"]
		return nil
	})
	b.cluster.RUnlock(task)
	if err != nil {
		log.Debugf("[%s] adding feature 'proxycache-server'...", hostLabel)
		log.Errorf("[%s] installation failed: %v", hostLabel, err)
		return err
	}
	if !disabled {
		log.Debugf("[%s] adding feature 'proxycache-server'...", hostLabel)

		feature, err := install.NewFeature(task, "proxycache-server")
		if err != nil {
			log.Errorf("[%s] failed to prepare feature 'proxycache-server': %s", hostLabel, err.Error())
			return fmt.Errorf("failed to install feature 'proxycache-server': %s", err.Error())
		}
		target := install.NewHostTarget(pbHost)
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Errorf("[%s] failed to install feature 'proxycache-server': %s", hostLabel, err.Error())
			return fmt.Errorf("failed to install feature 'proxycache-server' on host '%s': %s", pbHost.Name, err.Error())
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Errorf("[%s] failed to install feature 'proxycache-server': %s", hostLabel, msg)
			return fmt.Errorf(msg)
		}
	}
	return nil
}

func (b *foreman) installDocker(task concurrency.Task, pbHost *pb.Host, hostLabel string) error {
	// install docker feature
	log.Debugf("[%s] adding feature 'docker'...\n", hostLabel)
	feature, err := install.NewFeature(task, "docker")
	if err != nil {
		log.Errorf("[%s] failed to prepare feature 'docker': %s", hostLabel, err.Error())
		return fmt.Errorf("failed to add feature 'docker' on host '%s': %s", pbHost.Name, err.Error())
	}
	results, err := feature.Add(install.NewHostTarget(pbHost), install.Variables{}, install.Settings{})
	if err != nil {
		log.Errorf("[%s] failed to add feature 'docker': %s", hostLabel, err.Error())
		return fmt.Errorf("failed to add feature 'docker' on host '%s': %s", pbHost.Name, err.Error())
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Errorf("[%s] failed to add feature 'docker': %s", hostLabel, msg)
		return fmt.Errorf("failed to add feature 'docker' on host '%s': %s", pbHost.Name, msg)
	}
	log.Debugf("[%s] feature 'docker' addition successful.", hostLabel)
	return nil
}

// BuildHostname builds a unique hostname in the Cluster
func (b *foreman) buildHostname(task concurrency.Task, core string, nodeType NodeType.Enum) (string, error) {
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

	// Locks for write the manager extension...
	b.cluster.Lock(task)
	outerErr := b.cluster.GetProperties(task).LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		switch nodeType {
		case NodeType.PublicNode:
			nodesV1.PublicLastIndex++
			index = nodesV1.PublicLastIndex
		case NodeType.PrivateNode:
			nodesV1.PrivateLastIndex++
			index = nodesV1.PrivateLastIndex
		case NodeType.Master:
			nodesV1.MasterLastIndex++
			index = nodesV1.MasterLastIndex
		}
		return nil
	})
	b.cluster.Unlock(task)
	if outerErr != nil {
		return "", outerErr
	}
	return b.cluster.GetIdentity(task).Name + "-" + coreName + "-" + strconv.Itoa(index), nil
}
