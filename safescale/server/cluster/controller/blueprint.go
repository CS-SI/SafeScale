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

package controller

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
	clusterpropsv1 "github.com/CS-SI/SafeScale/safescale/server/cluster/controller/properties/v1"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/safescale/server/install"
	providermetadata "github.com/CS-SI/SafeScale/safescale/server/metadata"
	pbutils "github.com/CS-SI/SafeScale/safescale/utils"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils"
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

// BlueprintActors ...
type BlueprintActors struct {
	MinimumRequiredServers      func(c api.Cluster) (int, int, int)          // returns masterCount, pruvateNodeCount, publicNodeCount
	DefaultGatewaySizing        func(c api.Cluster) resources.HostDefinition // sizing of Gateway(s)
	DefaultMasterSizing         func(c api.Cluster) resources.HostDefinition // default sizing of master(s)
	DefaultNodeSizing           func(c api.Cluster) resources.HostDefinition // defailt sizing of node(s)
	DefaultImage                func(c api.Cluster) string                   // default image of server(s)
	GetNodeInstallationScript   func(c api.Cluster, nodeType NodeType.Enum) (string, map[string]interface{})
	GetGlobalSystemRequirements func(c api.Cluster) (*string, error)
	GetTemplateBox              func() (*rice.Box, error)
	InstallGateway              func(c api.Cluster, b *Blueprint) error
	ConfigureGateway            func(c api.Cluster, b *Blueprint) error
	CreateMaster                func(c api.Cluster, b *Blueprint, index int) error
	ConfigureMaster             func(c api.Cluster, b *Blueprint, index int, pbHost *pb.Host) error
	UnconfigureMaster           func(c api.Cluster, b *Blueprint, pbHost *pb.Host) error
	CreateNode                  func(c api.Cluster, b *Blueprint, index int, pbHost *pb.Host) error
	ConfigureNode               func(c api.Cluster, b *Blueprint, index int, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr string) error
	UnconfigureNode             func(c api.Cluster, b *Blueprint, pbHost *pb.Host, selectedMasterID string) error
	ConfigureCluster            func(c api.Cluster, b *Blueprint) error
	UnconfigureCluster          func(c api.Cluster, b *Blueprint) error
	JoinMasterToCluster         func(c api.Cluster, b *Blueprint, pbost *pb.Host) error
	JoinNodeToCluster           func(c api.Cluster, b *Blueprint, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr string) error
	LeaveMasterFromCluster      func(c api.Cluster, b *Blueprint, pbHost *pb.Host) error
	LeaveNodeFromCluster        func(c api.Cluster, b *Blueprint, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr, selectedMaster string) error
	GetState                    func(c api.Cluster) (ClusterState.Enum, error)
}

// Blueprint ...
type Blueprint struct {
	Cluster *Controller
	Actors  BlueprintActors
}

// NewBlueprint creates a new Blueprint
func NewBlueprint(c *Controller, Actors BlueprintActors) *Blueprint {
	return &Blueprint{
		Cluster: c,
		Actors:  Actors,
	}
}

// Construct ...
func (b *Blueprint) Construct(req Request) error {
	var err error
	log.Infof("Constructing cluster '%s'...", req.Name)
	defer func() {
		if err == nil {
			log.Infof("Cluster '%s' construction successful.", req.Name)
		}
	}()

	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		msg := fmt.Sprintf("failed to generate password for user cladm: %s", err.Error())
		log.Errorf("[cluster %s] %s", req.Name, msg)
		return fmt.Errorf(msg)
	}

	// Determine default image
	imageID := "Ubuntu 18.04"
	if b.Actors.DefaultImage != nil {
		imageID = b.Actors.DefaultImage(b.Cluster)
	}

	// Determine Gateway sizing
	gatewayDef := resources.HostDefinition{
		Cores:    2,
		RAMSize:  7.0,
		DiskSize: 60,
		ImageID:  imageID,
	}
	if b.Actors.DefaultGatewaySizing != nil {
		gatewayDef = b.Actors.DefaultGatewaySizing(b.Cluster)
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
	if b.Actors.DefaultMasterSizing != nil {
		masterDef = b.Actors.DefaultMasterSizing(b.Cluster)
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
	if b.Actors.DefaultNodeSizing != nil {
		nodeDef = b.Actors.DefaultNodeSizing(b.Cluster)
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
		CIDR:    req.CIDR,
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
	req.NetworkID = network.ID

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := clientNetwork.Delete([]string{network.ID}, client.DefaultExecutionTimeout)
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
	b.Cluster.Identity.Name = req.Name
	b.Cluster.Identity.Flavor = req.Flavor
	b.Cluster.Identity.Complexity = req.Complexity
	b.Cluster.Identity.Keypair = kp
	b.Cluster.Identity.AdminPassword = cladmPassword

	// Saves Cluster metadata
	err = b.Cluster.UpdateMetadata(func() error {
		err := b.Cluster.GetProperties().LockForWrite(Property.DefaultsV1).ThenUse(func(v interface{}) error {
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

		err = b.Cluster.GetProperties().LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.State).State = ClusterState.Creating
			return nil
		})
		if err != nil {
			return err
		}

		err = b.Cluster.GetProperties().LockForWrite(Property.CompositeV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.Composite).Tenants = []string{req.Tenant}
			return nil
		})
		if err != nil {
			return err
		}

		return b.Cluster.GetProperties().LockForWrite(Property.NetworkV1).ThenUse(func(v interface{}) error {
			networkV1 := v.(*clusterpropsv1.Network)
			networkV1.NetworkID = req.NetworkID
			networkV1.GatewayID = gw.ID
			networkV1.GatewayIP = gw.GetPrivateIP()
			networkV1.PublicIP = gw.GetAccessIP()
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
			derr := b.Cluster.DeleteMetadata()
			if derr != nil {
				log.Debugf("after failure, failed to delete metadata of cluster")
			}
		}
	}()

	masterCount, privateNodeCount, publicNodeCount := b.determineRequiredNodes()
	var (
		gatewayCh          chan error
		mastersCh          chan error
		privateNodesCh     chan error
		publicNodesCh      chan error
		gatewayStatus      error
		mastersStatus      error
		privateNodesStatus error
		publicNodesStatus  error
	)

	// Step 1: starts gateway installation and masters and nodes creation
	gatewayCh = make(chan error)
	go b.asyncInstallGateway(pbutils.ToPBHost(gw), gatewayCh)

	mastersCh = make(chan error)
	go b.asyncCreateMasters(masterCount, pbMasterDef, mastersCh)

	privateNodesCh = make(chan error)
	go b.asyncCreateNodes(privateNodeCount, false, pbNodeDef, privateNodesCh)

	publicNodesCh = make(chan error)
	go b.asyncCreateNodes(publicNodeCount, true, pbNodeDef, publicNodesCh)

	// Step 2: awaits master creations and gateway installation finish
	gatewayStatus = <-gatewayCh
	mastersStatus = <-mastersCh

	// Starting from here, delete masters if exiting with error and req.KeepOnFailure is not true
	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := client.New().Host.Delete(b.Cluster.ListMasterIDs(), client.DefaultExecutionTimeout)
			if derr != nil {
				log.Errorf("[cluster %s] after failure, failed to delete masters", req.Name)
			}
		}
	}()

	if gatewayStatus == nil && mastersStatus == nil {
		gatewayCh = make(chan error)
		go func() { b.asyncConfigureGateway(pbutils.ToPBHost(gw), gatewayCh) }()
		gatewayStatus = <-gatewayCh
	}

	// Step 5: configure masters
	if gatewayStatus == nil && mastersStatus == nil {
		mastersCh = make(chan error)
		go b.asyncConfigureMasters(mastersCh)
		mastersStatus = <-mastersCh
	}

	privateNodesStatus = <-privateNodesCh
	publicNodesStatus = <-publicNodesCh

	// Starting from here, delete nodes on failure if exits with error and req.KeepOnFailure is false
	defer func() {
		if err != nil && !req.KeepOnFailure {
			clientHost := clientInstance.Host
			derr := clientHost.Delete(b.Cluster.ListNodeIDs(false), client.DefaultExecutionTimeout)
			if derr != nil {
				log.Debugf("failed to remove private nodes on failure")
			}
			derr = clientHost.Delete(b.Cluster.ListNodeIDs(true), client.DefaultExecutionTimeout)
			if derr != nil {
				log.Debugf("failed to remove public nodes on failure")
			}
		}
	}()

	// Step 6: Starts nodes configuration, if all masters and nodes
	// have been created and gateway has been configured with success
	if gatewayStatus == nil && mastersStatus == nil {
		if privateNodesStatus == nil {
			privateNodesCh = make(chan error)
			go b.asyncConfigureNodes(false, privateNodesCh)
		}
		if publicNodesStatus == nil {
			publicNodesCh = make(chan error)
			go b.asyncConfigureNodes(true, publicNodesCh)
		}
		if privateNodesStatus == nil {
			privateNodesStatus = <-privateNodesCh
		}
		if publicNodesStatus == nil {
			publicNodesStatus = <-publicNodesCh
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
	err = b.configureCluster()
	if err != nil {
		return err
	}

	return b.Cluster.UpdateMetadata(func() error {
		// Cluster created and configured successfully
		return b.Cluster.GetProperties().LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
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

// ExecuteScript executes the script template with the parameters on tarGetHost
func (b *Blueprint) ExecuteScript(
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

// GetState returns "actively" the current state of the cluster
func (b *Blueprint) GetState() (ClusterState.Enum, error) {
	if b.Actors.GetState != nil {
		return b.Actors.GetState(b.Cluster)
	}
	return ClusterState.Unknown, fmt.Errorf("no actor defined for 'GetState'")
}

// configureNode ...
func (b *Blueprint) configureNode(index int, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr string) error {
	if b.Actors.ConfigureNode != nil {
		return b.Actors.ConfigureNode(b.Cluster, b, index, pbHost, nodeType, nodeTypeStr)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// unconfigureNode executes what has to be done to remove node from cluster
func (b *Blueprint) unconfigureNode(hostID string, selectedMasterID string) error {
	pbHost, err := client.New().Host.Inspect(hostID, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if b.Actors.UnconfigureNode != nil {
		return b.Actors.UnconfigureNode(b.Cluster, b, pbHost, selectedMasterID)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// configureMaster ...
func (b *Blueprint) configureMaster(index int, pbHost *pb.Host) error {
	if b.Actors.ConfigureNode != nil {
		return b.Actors.ConfigureMaster(b.Cluster, b, index, pbHost)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// unconfigureMaster executes what has to be done to remove Master from Cluster
func (b *Blueprint) unconfigureMaster(pbHost *pb.Host) error {
	if b.Actors.UnconfigureMaster != nil {
		return b.Actors.UnconfigureMaster(b.Cluster, b, pbHost)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// configureCluster ...
func (b *Blueprint) configureCluster() error {
	log.Debugf(">>> safescale.cluster.controller.Blueprint::configureCluster()")
	defer log.Debugf("<<< safescale.cluster.controller.Blueprint::configureCluster()")

	var err error

	log.Infof("[cluster %s] configuring cluster...", b.Cluster.Name)
	defer func() {
		if err == nil {
			log.Infof("[cluster %s] configuration successful.", b.Cluster.Name)
		}
	}()

	// Installs remotedesktop feature on all masters
	err = b.installRemoteDesktop()
	if err != nil {
		return err
	}

	// configure what has to be done cluster-wide
	if b.Actors.ConfigureCluster != nil {
		return b.Actors.ConfigureCluster(b.Cluster, b)
	}

	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

func (b *Blueprint) determineRequiredNodes() (int, int, int) {
	if b.Actors.MinimumRequiredServers != nil {
		return b.Actors.MinimumRequiredServers(b.Cluster)
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
func (b *Blueprint) configureNodesFromList(public bool, hosts []string) error {
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
		i      int
		hostID string
		errors []string
	)

	dones := []chan error{}
	clientHost := client.New().Host
	for i, hostID = range hosts {
		host, err = clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			break
		}
		d := make(chan error)
		dones = append(dones, d)
		go b.asyncConfigureNode(i+1, host, nodeType, nodeTypeStr, d)
	}
	// Deals with the metadata read failure
	if err != nil {
		errors = append(errors, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for i = range dones {
		err = <-dones[i]
		if err != nil {
			errors = append(errors, err.Error())
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "\n"))
	}
	return nil
}

// joinNodesFromList ...
func (b *Blueprint) joinNodesFromList(public bool, hosts []string) error {
	if b.Actors.JoinNodeToCluster == nil {
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
		err = b.Actors.JoinNodeToCluster(b.Cluster, b, pbHost, nodeType, nodeTypeStr)
		if err != nil {
			return err
		}
	}

	return nil
}

// leaveMastersFromList ...
func (b *Blueprint) leaveMastersFromList(public bool, hosts []string) error {
	if b.Actors.LeaveMasterFromCluster == nil {
		return nil
	}

	log.Debugf("Making Mastersleaving cluster...")

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return err
		}
		err = b.Actors.LeaveMasterFromCluster(b.Cluster, b, pbHost)
		if err != nil {
			return err
		}
	}

	return nil
}

// leaveNodesFromList ...
func (b *Blueprint) leaveNodesFromList(hosts []string, public bool, selectedMasterID string) error {
	if b.Actors.LeaveNodeFromCluster == nil {
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
		err = b.Actors.LeaveNodeFromCluster(b.Cluster, b, pbHost, nodeType, nodeTypeStr, selectedMasterID)
		if err != nil {
			return err
		}
	}

	return nil
}

// installNodeRequirements ...
func (b *Blueprint) installNodeRequirements(nodeType NodeType.Enum, pbHost *pb.Host, hostLabel string) error {
	// Get installation script based on node type; if == "", do nothing
	script, params := b.getNodeInstallationScript(nodeType)
	if script == "" {
		return nil
	}

	log.Debugf("[%s] installing system requirements...", hostLabel)

	if b.Actors.GetTemplateBox == nil {
		err := fmt.Errorf("missing callback GetTemplateBox")
		log.Errorf("[%s] system requirements installation failed: %v", hostLabel, err)
		return err
	}
	box, err := b.Actors.GetTemplateBox()
	if err != nil {
		log.Errorf("[%s] system requirements installation failed: %v", hostLabel, err)
		return err
	}

	globalSystemRequirements := ""
	if b.Actors.GetGlobalSystemRequirements != nil {
		result, err := b.Actors.GetGlobalSystemRequirements(b.Cluster)
		if err != nil {
			log.Errorf("[%s] system requirements installation failed: %v", hostLabel, err)
			return err
		}
		globalSystemRequirements = *result
	}

	var dnsServers []string
	cfg, err := b.Cluster.GetService().GetCfgOpts()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	b.Cluster.RLock()
	identity := b.Cluster.GetIdentity()
	b.Cluster.RUnlock()
	params["reserved_CommonRequirements"] = globalSystemRequirements
	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	params["MasterIPs"] = b.Cluster.ListMasterIPs()
	params["CladmPassword"] = identity.AdminPassword

	retcode, _, _, err := b.ExecuteScript(box, funcMap, script, params, pbHost.ID)
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
func (b *Blueprint) getNodeInstallationScript(nodeType NodeType.Enum) (string, map[string]interface{}) {
	if b.Actors.GetNodeInstallationScript != nil {
		return b.Actors.GetNodeInstallationScript(b.Cluster, nodeType)
	}
	return "", map[string]interface{}{}
}

// installRemoteDesktop installs feature remotedesktop on all masters of the cluster
func (b *Blueprint) installRemoteDesktop() error {
	b.Cluster.RLock()
	identity := b.Cluster.GetIdentity()
	clusterName := identity.Name
	b.Cluster.RUnlock()

	disabled := false
	err := b.Cluster.GetProperties().LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
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
		target := install.NewClusterTarget(b.Cluster)

		// Adds remotedesktop feature on master
		feature, err := install.NewFeature("remotedesktop")
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

// asyncInstallGateway installs necessary components on the gateway
// Designed to work in goroutine
func (b *Blueprint) asyncInstallGateway(pbGateway *pb.Host, done chan error) {
	log.Debugf(">>> safescale.server.cluster.controller.Blueprint::asyncInstallGateway(%s)", pbGateway.Name)
	defer log.Debugf("<<< safescale.server.cluster.controller.Blueprint::asyncInstallGateway(%s)", pbGateway.Name)

	hostLabel := "gateway"
	log.Debugf("[%s] starting installation...", hostLabel)

	sshCfg, err := client.New().Host.SSHConfig(pbGateway.ID)
	if err != nil {
		done <- err
		return
	}
	err = sshCfg.WaitServerReady(5 * time.Minute)
	if err != nil {
		done <- err
		return
	}

	// Installs proxycache server on gateway (if not disabled)
	err = b.installProxyCacheServer(pbGateway, hostLabel)
	if err != nil {
		done <- err
		return
	}

	// Installs requirements as defined by cluster Flavor (if it exists)
	err = b.installNodeRequirements(NodeType.Gateway, pbGateway, "gateway")
	if err != nil {
		done <- err
		return
	}

	// Installs reverseproxy
	err = b.installReverseProxy(pbGateway, hostLabel)
	if err != nil {
		done <- err
		return
	}

	log.Debugf("[%s] preparation successful", hostLabel)
	done <- nil
}

// asyncConfigureGateway prepares the gateway
// Designed to work in goroutine
func (b *Blueprint) asyncConfigureGateway(gw *pb.Host, done chan error) {
	log.Debugf(">>> safescale.server.cluster.controller.Blueprint::asyncConfigureGateway(%s)", gw.Name)
	defer log.Debugf("<<< safescale.server.cluster.controller.Blueprint::asyncConfigureGateway(%s)", gw.Name)

	log.Debugf("[gateway] starting configuration...")

	// // Docker installation is mandatory on all nodes
	// // Note: normally, docker is already installed in asyncInstallGateway through reverseproxy...
	// err := b.installDocker(gw, "gateway")
	// if err != nil {
	// 	done <- err
	// 	return
	// }

	if b.Actors.ConfigureGateway != nil {
		err := b.Actors.ConfigureGateway(b.Cluster, b)
		if err != nil {
			done <- err
			return
		}
	}

	log.Debugf("[gateway] configuration successful.")
	done <- nil
}

// asyncCreateMasters ...
// Intended to be used as goroutine
func (b *Blueprint) asyncCreateMasters(count int, def pb.HostDefinition, done chan error) {
	log.Debugf(">>> safescale.server.cluster.controller.Blueprint::asyncCreateMasters(%d)", count)
	defer log.Debugf(">>> safescale.server.cluster.controller.Blueprint::asyncCreateMasters(%d)", count)

	b.Cluster.RLock()
	clusterName := b.Cluster.GetIdentity().Name
	b.Cluster.RUnlock()

	if count <= 0 {
		log.Debugf("[cluster %s] no masters to create.", clusterName)
		done <- nil
		return
	}

	log.Debugf("[cluster %s] creating %d master%s...\n", clusterName, count, utils.Plural(count))

	var dones []chan error
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 1; i <= count; i++ {
		d := make(chan error)
		dones = append(dones, d)
		go b.asyncCreateMaster(i, def, timeout, d)
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
		msg := strings.Join(errors, "\n")
		log.Errorf("[cluster %s] failed to create master(s): %s", clusterName, msg)
		done <- fmt.Errorf(msg)
		return
	}

	log.Debugf("[cluster %s] masters creation successful.", clusterName)
	done <- nil
}

// asyncCreateMaster adds a master node
func (b *Blueprint) asyncCreateMaster(index int, def pb.HostDefinition, timeout time.Duration, done chan error) {
	log.Debugf(">>> safescale.cluster.controller.blueprint.Blueprint::asyncCreateMaster(%d)", index)
	defer log.Debugf("<<< safescale.cluster.controller.blueprint.Blueprint::asyncCreateMaster(%d)", index)

	hostLabel := fmt.Sprintf("master #%d", index)
	log.Debugf("[%s] starting host resource creation...\n", hostLabel)

	name, err := b.buildHostname("master", NodeType.Master)
	if err != nil {
		log.Errorf("[%s] creation failed: %s\n", hostLabel, err.Error())
		done <- fmt.Errorf("failed to create '%s': %s", hostLabel, err.Error())
		return
	}

	def.Network = b.Cluster.GetNetworkConfig().NetworkID
	def.Public = false
	def.Name = name
	clientHost := client.New().Host
	pbHost, err := clientHost.Create(def, timeout)
	if err != nil {
		err = client.DecorateError(err, "creation of host resource", false)
		log.Errorf("[%s] host resource creation failed: %s", hostLabel, err.Error())
		done <- fmt.Errorf("failed to create '%s': %s", hostLabel, err.Error())
		return
	}
	hostLabel = fmt.Sprintf("%s (%s)", hostLabel, pbHost.Name)
	log.Debugf("[%s] host resource creation successful", hostLabel)

	defer func() {
		if err != nil {
			derr := clientHost.Delete([]string{pbHost.ID}, timeout)
			if derr != nil {
				log.Errorf("failed to delete master after failure")
			}
		}
	}()

	err = b.Cluster.UpdateMetadata(func() error {
		// Locks for write the NodesV1 extension...
		return b.Cluster.GetProperties().LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			// Update swarmCluster definition in Object Storage
			node := &clusterpropsv1.Node{
				ID:        pbHost.ID,
				PrivateIP: pbHost.PrivateIP,
				PublicIP:  pbHost.GetPublicIP(),
			}
			nodesV1.Masters = append(nodesV1.Masters, node)
			return nil
		})
	})
	if err != nil {
		log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
		done <- fmt.Errorf("failed to update Cluster metadata: %s", err.Error())
		return
	}

	err = b.installProxyCacheClient(pbHost, hostLabel)
	if err != nil {
		done <- err
		return
	}

	// Installs cluster-level system requirements...
	err = b.installNodeRequirements(NodeType.Master, pbHost, hostLabel)
	if err != nil {
		done <- err
		return
	}

	log.Debugf("[%s] host rsource creation successful.", hostLabel)
	done <- nil
}

// asyncConfigureMasters configure masters
func (b *Blueprint) asyncConfigureMasters(done chan error) {
	log.Debugf(">>> safescale.server.cluster.controller.Blueprint::asyncConfigureMasters()")
	defer log.Debugf("<<< safescale.server.cluster.controller.Blueprint::asyncConfigureMasters()")

	list := b.Cluster.ListMasterIDs()
	if len(list) <= 0 {
		done <- nil
		return
	}

	log.Debugf("[cluster %s] Configuring masters...", b.Cluster.Name)

	clientHost := client.New().Host
	dones := []chan error{}
	for i, hostID := range b.Cluster.ListMasterIDs() {
		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			done <- fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		d := make(chan error)
		dones = append(dones, d)
		go b.asyncConfigureMaster(i+1, host, d)
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

	log.Debugf("[cluster %s] Masters configuration successful.", b.Cluster.Name)
	done <- nil
}

// asyncConfigureMaster configures master
func (b *Blueprint) asyncConfigureMaster(index int, pbHost *pb.Host, done chan error) {
	log.Debugf(">>> safescale.server.cluster.controller.Blueprint::asyncConfigureMaster(%d, %s)", index, pbHost.Name)
	defer log.Debugf("<<< safescale.server.cluster.controller.Blueprint::asyncConfigureMaster(%d, %s)", index, pbHost.Name)

	hostLabel := fmt.Sprintf("master #%d (%s)", index, pbHost.Name)
	log.Debugf("[%s] starting configuration...\n", hostLabel)

	// install docker feature
	err := b.installDocker(pbHost, hostLabel)
	if err != nil {
		done <- err
		return
	}

	err = b.configureMaster(index, pbHost)
	if err != nil {
		done <- err
	}

	log.Debugf("[%s] configuration successful.", hostLabel)
	done <- nil
}

func (b *Blueprint) asyncCreateNodes(count int, public bool, def pb.HostDefinition, done chan error) {
	log.Debugf(">>> safescale.server.cluster.controller.Blueprint::asyncCreateNodes(%d, %v)", count, public)
	defer log.Debugf("<<< safescale.server.cluster.controller.Blueprint::asyncCreateNodes(%d, %v)", count, public)

	b.Cluster.RLock()
	clusterName := b.Cluster.GetIdentity().Name
	b.Cluster.RUnlock()

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
		done <- nil
		return
	}
	log.Debugf("[cluster %s] creating %d %s node%s...\n", clusterName, count, nodeTypeStr, utils.Plural(count))

	var dones []chan error
	var results []chan string
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 1; i <= count; i++ {
		r := make(chan string)
		results = append(results, r)
		d := make(chan error)
		dones = append(dones, d)
		go b.asyncCreateNode(i, nodeType, def, timeout, r, d)
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

	log.Debugf("[cluster %s] %d %s node%s creation successful.", clusterName, count, nodeTypeStr, utils.Plural(count))
	done <- nil
}

// asyncCreateNode creates a Node in the Cluster
// This function is intended to be call as a goroutine
func (b *Blueprint) asyncCreateNode(
	index int, nodeType NodeType.Enum, def pb.HostDefinition, timeout time.Duration,
	result chan string, done chan error,
) {

	log.Debugf(">>> safescale.server.cluster.controller.Blueprint::asyncCreateNode(%d, %s)", index, nodeType.String())
	defer log.Debugf("<<< safescale.server.cluster.controller.Blueprint::asyncCreateNode(%d, %s)", index, nodeType.String())

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
	var err error
	def.Name, err = b.buildHostname("node", nodeType)
	if err != nil {
		log.Errorf("[%s] host resource creation failed: %s", hostLabel, err.Error())
		result <- ""
		done <- err
		return
	}
	def.Public = publicIP
	def.Network = b.Cluster.GetNetworkConfig().NetworkID
	clientHost := client.New().Host
	pbHost, err := clientHost.Create(def, 10*time.Minute)
	if err != nil {
		err = client.DecorateError(err, "creation of host resource", true)
		log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
		result <- ""
		done <- err
		return
	}
	hostLabel = fmt.Sprintf("%s node #%d (%s)", nodeTypeStr, index, pbHost.Name)
	log.Debugf("[%s] host resource creation successful.", hostLabel)

	var node *clusterpropsv1.Node
	err = b.Cluster.UpdateMetadata(func() error {
		// Locks for write the NodesV1 extension...
		return b.Cluster.GetProperties().LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
			nodesV1 := v.(*clusterpropsv1.Nodes)
			// Registers the new Agent in the swarmCluster struct
			node = &clusterpropsv1.Node{
				ID:        pbHost.ID,
				PrivateIP: pbHost.PrivateIP,
				PublicIP:  pbHost.GetPublicIP(),
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
		derr := clientHost.Delete([]string{pbHost.ID}, 10*time.Minute)
		if derr != nil {
			log.Errorf("failed to delete node after failure")
		}
		log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
		result <- ""
		done <- fmt.Errorf("failed to create node: %s", err.Error())
		return
	}

	// Starting from here, delete node from cluster if exiting with error
	defer func() {
		if err != nil {
			derr := b.Cluster.deleteNode(node, 1, publicIP, "")
			if derr != nil {
				log.Errorf("failed to delete node after failure")
			}
		}
	}()

	err = b.installProxyCacheClient(pbHost, hostLabel)
	if err != nil {
		result <- ""
		done <- err
		return
	}

	err = b.installNodeRequirements(nodeType, pbHost, hostLabel)
	if err != nil {
		result <- ""
		done <- err
		return
	}

	log.Debugf("[%s] host resource creation successful.", hostLabel)
	result <- pbHost.Name
	done <- nil
}

// asyncConfigureNodes ...
func (b *Blueprint) asyncConfigureNodes(public bool, done chan error) {
	log.Debugf(">>> safescale.cluster.controller.Blueprint::asyncConfigureNodes(%v)", public)
	defer log.Debugf("<<< safescale.cluster.controller.Blueprint::asyncConfigureNodes(%v)", public)

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

	list := b.Cluster.ListNodeIDs(public)
	if len(list) <= 0 {
		log.Debugf("[cluster %s] no %s nodes to configure.", b.Cluster.Name, nodeTypeStr)
		done <- nil
		return
	}

	log.Debugf("[cluster %s] configuring %s nodes...", b.Cluster.Name, nodeTypeStr)

	var (
		pbHost *pb.Host
		err    error
		i      int
		hostID string
		errors []string
	)

	dones := []chan error{}
	clientHost := client.New().Host
	for i, hostID = range list {
		pbHost, err = clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			break
		}
		d := make(chan error)
		dones = append(dones, d)
		go b.asyncConfigureNode(i+1, pbHost, nodeType, nodeTypeStr, d)
	}
	// Deals with the metadata read failure
	if err != nil {
		errors = append(errors, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for i = range dones {
		err = <-dones[i]
		if err != nil {
			errors = append(errors, err.Error())
		}
	}
	if len(errors) > 0 {
		done <- fmt.Errorf(strings.Join(errors, "\n"))
		return
	}

	log.Debugf("[cluster %s] %s nodes configuration successful.", b.Cluster.Name, nodeTypeStr)
	done <- nil
}

// asyncConfigureNode ...
func (b *Blueprint) asyncConfigureNode(
	index int, pbHost *pb.Host, nodeType NodeType.Enum, nodeTypeStr string,
	done chan error,
) {

	log.Debugf(">>> safescale.cluster.controller.Blueprint::asyncConfigureNode(%d, %s)", index, pbHost.Name)
	defer log.Debugf("<<< safescale.cluster.controller.Blueprint::asyncConfigureNode(%d, %s)", index, pbHost.Name)

	hostLabel := fmt.Sprintf("%s node #%d (%s)", nodeTypeStr, index, pbHost.Name)
	log.Debugf("[%s] starting configuration...", hostLabel)

	// Docker installation is mandatory on all nodes
	err := b.installDocker(pbHost, hostLabel)
	if err != nil {
		done <- err
		return
	}

	// Now configures node specifically for cluster flavor
	err = b.configureNode(index, pbHost, nodeType, nodeTypeStr)
	if err != nil {
		done <- err
		return
	}

	log.Debugf("[%s] configuration successful.", hostLabel)
	done <- nil
}

func (b *Blueprint) installReverseProxy(pbHost *pb.Host, hostLabel string) error {
	// Installs reverseproxy
	disabled := false
	b.Cluster.RLock()
	err := b.Cluster.GetProperties().LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["reverseproxy"]
		return nil
	})
	b.Cluster.RUnlock()
	if err != nil {
		log.Debugf("[%s] adding feature 'reverseproxy'...", hostLabel)
		log.Errorf("[%s] feature 'reverseproxy' installation failed: %s", hostLabel, err.Error())
		return err
	}
	if !disabled {
		log.Debugf("[%s] adding feature 'reverseproxy'...", hostLabel)
		feature, err := install.NewFeature("reverseproxy")
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
func (b *Blueprint) installProxyCacheClient(pbHost *pb.Host, hostLabel string) error {
	disabled := false
	b.Cluster.RLock()
	err := b.Cluster.GetProperties().LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["proxycache"]
		return nil
	})
	b.Cluster.RUnlock()
	if err != nil {
		log.Debugf("[%s] adding feature 'proxycache-client'...", hostLabel)
		log.Errorf("[%s] installation failed: %v", hostLabel, err)
		return err
	}
	if !disabled {
		log.Debugf("[%s] adding feature 'proxycache-client'...", hostLabel)

		feature, err := install.NewFeature("proxycache-client")
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
func (b *Blueprint) installProxyCacheServer(pbHost *pb.Host, hostLabel string) error {
	disabled := false
	b.Cluster.RLock()
	err := b.Cluster.GetProperties().LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["proxycache"]
		return nil
	})
	b.Cluster.RUnlock()
	if err != nil {
		log.Debugf("[%s] adding feature 'proxycache-server'...", hostLabel)
		log.Errorf("[%s] installation failed: %v", hostLabel, err)
		return err
	}
	if !disabled {
		log.Debugf("[%s] adding feature 'proxycache-server'...", hostLabel)

		feature, err := install.NewFeature("proxycache-server")
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

func (b *Blueprint) installDocker(pbHost *pb.Host, hostLabel string) error {
	// install docker feature
	log.Debugf("[%s] adding feature 'docker'...\n", hostLabel)
	feature, err := install.NewFeature("docker")
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
func (b *Blueprint) buildHostname(core string, nodeType NodeType.Enum) (string, error) {
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
	b.Cluster.Lock()
	outerErr := b.Cluster.Properties.LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
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
	b.Cluster.Unlock()
	if outerErr != nil {
		return "", outerErr
	}
	return b.Cluster.Name + "-" + coreName + "-" + strconv.Itoa(index), nil
}
