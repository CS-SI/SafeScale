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

package controller

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	txttmpl "text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"
	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
	pbutils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/deploy/cluster/api"
	clusterpropsv1 "github.com/CS-SI/SafeScale/deploy/cluster/controller/properties/v1"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Extension"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/deploy/install"
	"github.com/CS-SI/SafeScale/providers"
	providermetadata "github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	provpropsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
	"github.com/CS-SI/SafeScale/utils/template"
)

var (
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

// BlueprintCallbacks ...
type BlueprintCallbacks struct {
	DetermineRequiredNodes      func(c api.Cluster) (int, int, int)
	InstallGateway              func(c api.Cluster, b *Blueprint) error
	ConfigureGateway            func(c api.Cluster, b *Blueprint) error
	CreateMaster                func(c api.Cluster, b *Blueprint, index int) error
	CreateNode                  func(c api.Cluster, b *Blueprint, index int, host *pb.Host) error
	ConfigureMaster             func(c api.Cluster, b *Blueprint, index int, host *pb.Host) error
	UnconfigureMaster           func(c api.Cluster, b *Blueprint, host *pb.Host) error
	ConfigureNode               func(c api.Cluster, b *Blueprint, index int, host *pb.Host, nodeType NodeType.Enum, nodeTypeStr string) error
	UnconfigureNode             func(c api.Cluster, b *Blueprint, host *pb.Host) error
	ConfigureCluster            func(c api.Cluster, b *Blueprint) error
	UnconfigureCluster          func(c api.Cluster, b *Blueprint) error
	GetGlobalSystemRequirements func(c api.Cluster, b *Blueprint) (*string, error)
	GetTemplateBox              func() (*rice.Box, error)
}

// Blueprint ...
type Blueprint struct {
	Cluster   *Controller
	Callbacks BlueprintCallbacks
}

// NewBlueprint creates a new Blueprint
func NewBlueprint(c *Controller, callbacks BlueprintCallbacks) *Blueprint {
	return &Blueprint{
		Cluster:   c,
		Callbacks: callbacks,
	}
}

// Construct ...
func (b *Blueprint) Construct(req Request) error {
	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return fmt.Errorf("failed to generate password for user cladm: %s", err.Error())
	}
	nodesDef := model.HostSize{
		HostSize: &provpropsv1.HostSize{
			Cores:    4,
			RAMSize:  15.0,
			DiskSize: 100,
		},
	}
	imageID := "Ubuntu 18.04"
	if req.NodesDef != nil {
		if req.NodesDef.CPUNumber > int32(nodesDef.Cores) {
			nodesDef.Cores = int(req.NodesDef.CPUNumber)
		}
		if req.NodesDef.RAM > nodesDef.RAMSize {
			nodesDef.RAMSize = req.NodesDef.RAM
		}
		if req.NodesDef.Disk > int32(nodesDef.DiskSize) {
			nodesDef.DiskSize = int(req.NodesDef.Disk)
		}
		if req.NodesDef.ImageID != "" {
			imageID = req.NodesDef.ImageID
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
	broker := brokerclient.New()
	network, err := broker.Network.Create(def, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		err = fmt.Errorf("failed to create Network '%s': %s", networkName, err.Error())
		return err
	}
	log.Printf("Network '%s' created successfully\n", network.Name)
	req.NetworkID = network.ID

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := broker.Network.Delete([]string{network.ID}, brokerclient.DefaultExecutionTimeout)
			if derr != nil {
				log.Debugf("failed to delete up network on failure")
			}
		}
	}()

	// Saving Cluster parameters, with status 'Creating'
	var (
		masterCount      int
		privateNodeCount int
		kp               *model.KeyPair
		kpName           string
		gw               *model.Host
		m                *providermetadata.Gateway
		ok               bool
		target           install.Target
		feature          *install.Feature
		results          install.Results
		doInstall        bool
		outerErr         error
	)

	tenant, err := broker.Tenant.Get(brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	svc, err := providers.GetService(tenant.Name)
	if err != nil {
		return err
	}

	// Loads gateway metadata
	m, err = providermetadata.NewGateway(svc, req.NetworkID)
	if err != nil {
		return err
	}
	ok, err = m.Read()
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("failed to load gateway metadata")
	}
	gw = m.Get()

	err = broker.Ssh.WaitReady(gw.ID, brokerclient.DefaultExecutionTimeout)
	if err != nil {
		return brokerclient.DecorateError(err, "wait for remote ssh service to be ready", false)
	}

	// Create a KeyPair for the user cladm
	kpName = "cluster_" + req.Name + "_cladm_key"
	kp, err = svc.CreateKeyPair(kpName)
	if err != nil {
		return fmt.Errorf("failed to create Key Pair: %s", err.Error())
	}

	// Saving Cluster metadata, with status 'Creating'
	b.Cluster.Identity.Name = req.Name
	b.Cluster.Identity.Flavor = Flavor.SWARM
	b.Cluster.Identity.Complexity = req.Complexity
	b.Cluster.Identity.Keypair = kp
	b.Cluster.Identity.AdminPassword = cladmPassword

	// Saves Cluster metadata
	outerErr = b.Cluster.UpdateMetadata(func() error {
		err := b.Cluster.GetExtensions().LockForWrite(Extension.DefaultsV1).ThenUse(func(v interface{}) error {
			defaultsV1 := v.(*clusterpropsv1.Defaults)
			defaultsV1.NodeSizing = nodesDef
			defaultsV1.Image = imageID
			return nil
		})
		if err != nil {
			return err
		}

		err = b.Cluster.GetExtensions().LockForWrite(Extension.StateV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.State).State = ClusterState.Creating
			return nil
		})
		if err != nil {
			return err
		}

		err = b.Cluster.GetExtensions().LockForWrite(Extension.CompositeV1).ThenUse(func(v interface{}) error {
			v.(*clusterpropsv1.Composite).Tenants = []string{req.Tenant}
			return nil
		})
		if err != nil {
			return err
		}

		return b.Cluster.GetExtensions().LockForWrite(Extension.NetworkV1).ThenUse(func(v interface{}) error {
			networkV1 := v.(*clusterpropsv1.Network)
			networkV1.NetworkID = req.NetworkID
			networkV1.GatewayIP = gw.GetPrivateIP()
			networkV1.PublicIP = gw.GetAccessIP()
			networkV1.CIDR = req.CIDR
			return nil
		})
	})
	if err != nil {
		return fmt.Errorf("failed to create Cluster '%s': %s", req.Name, err.Error())
	}

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := b.Cluster.DeleteMetadata()
			if derr != nil {
				log.Debugf("failed to delete metadata on failure")
			}
		}
	}()

	//VPL: Disabling proxycache always for now
	err = b.Cluster.GetExtensions().LockForWrite(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		featuresV1 := v.(*clusterpropsv1.Features)
		featuresV1.Disabled["proxycache"] = struct{}{}
		return nil
	})
	if err != nil {
		return err
	}
	err = b.Cluster.GetExtensions().LockForRead(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		_, doInstall = v.(*clusterpropsv1.Features).Disabled["proxycache"]
		return nil
	})
	if err != nil {
		return err
	}
	if doInstall {
		feature, err = install.NewFeature("proxycache-server")
		if err != nil {
			return err
		}
		target := install.NewHostTarget(pbutils.ToPBHost(gw))
		results, err = feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			err = fmt.Errorf(results.AllErrorMessages())
			return err
		}
	}

	masterCount, privateNodeCount, publicNodeCount := b.determineRequiredNodes()

	runtime.GOMAXPROCS(runtime.NumCPU())

	// Step 1: starts masters and nodes creations
	gatewayChannel := make(chan error)
	go asyncInstallGateway(b.Cluster, b, pbutils.ToPBHost(gw), gatewayChannel)

	mastersChannel := make(chan error)
	go asyncCreateMasters(b.Cluster, b, masterCount, nodesDef, mastersChannel)

	privateNodesChannel := make(chan error)
	go asyncCreateNodes(b.Cluster, b, privateNodeCount, false, nodesDef, privateNodesChannel)

	publicNodesChannel := make(chan error)
	go asyncCreateNodes(b.Cluster, b, publicNodeCount, false, nodesDef, publicNodesChannel)

	// Step 2: awaits masters creation and gateway installation coroutines
	gatewayStatus := <-gatewayChannel
	mastersStatus := <-mastersChannel

	// Starting from here, delete masters if exit with error and req.KeepOnFailure is not true
	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := brokerclient.New().Host.Delete(b.Cluster.ListMasterIDs(), brokerclient.DefaultExecutionTimeout)
			if derr != nil {
				log.Debugf("failed to delete masters on failure")
			}
		}
	}()

	// Step 3: starts gateway configuration, if masters have been created successfully
	if gatewayStatus == nil && mastersStatus == nil {
		gatewayChannel = make(chan error)
		go asyncConfigureGateway(b.Cluster, b, gw, gatewayChannel)
		gatewayStatus = <-gatewayChannel
	}

	// Step 4: configure masters
	if gatewayStatus == nil && mastersStatus == nil {
		mastersChannel = make(chan error)
		go asyncConfigureMasters(b.Cluster, b, mastersChannel)
		mastersStatus = <-mastersChannel
	}

	privateNodesStatus := <-privateNodesChannel
	publicNodesStatus := <-publicNodesChannel

	// Starting from here, delete nodes on failure if exits with error and req.KeepOnFailure is false
	defer func() {
		if err != nil && !req.KeepOnFailure {
			broker := brokerclient.New().Host
			derr := broker.Delete(b.Cluster.ListNodeIDs(false), brokerclient.DefaultExecutionTimeout)
			if derr != nil {
				log.Debugf("failed to remove private nodes on failure")
			}
			derr = broker.Delete(b.Cluster.ListNodeIDs(true), brokerclient.DefaultExecutionTimeout)
			if derr != nil {
				log.Debugf("failed to remove public nodes on failure")
			}
		}
	}()

	// Step 5: Starts nodes configuration, if all masters and nodes
	// have been created and gateway has been configured with success
	if gatewayStatus == nil && mastersStatus == nil {
		if privateNodesStatus == nil {
			privateNodesChannel = make(chan error)
			go asyncConfigureNodes(b.Cluster, b, false, privateNodesChannel)
		}
		if gatewayStatus == nil && mastersStatus == nil && publicNodesStatus == nil {
			publicNodesChannel = make(chan error)
			go asyncConfigureNodes(b.Cluster, b, true, publicNodesChannel)
		}
		privateNodesStatus = <-privateNodesChannel
		publicNodesStatus = <-publicNodesChannel
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
	err = b.ConfigureCluster()
	if err != nil {
		return err
	}

	// Automatic feature installation: add remotedesktop Cluster-wide (ie on all masters), except if explicitely disabled
	doInstall = false
	err = b.Cluster.GetExtensions().LockForRead(Extension.FeaturesV1).ThenUse(func(v interface{}) error {
		_, doInstall = v.(*clusterpropsv1.Features).Disabled["remotedesktop"]
		return nil
	})
	target = install.NewClusterTarget(b.Cluster)
	if doInstall {
		log.Printf("Adding feature 'remotedesktop' on swarmCluster...\n")

		feature, err = install.NewFeature("remotedesktop")
		if err != nil {
			return fmt.Errorf("failed to prepare feature 'remotedesktop': %s", err.Error())
		}
		results, err = feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			return fmt.Errorf("failed to add feature '%s': %s", feature.DisplayName(), err.Error())
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("failed to add feature '%s': %s", feature.DisplayName(), msg)
		}
		log.Printf("feature '%s' added successfully.\n", feature.DisplayName())
	}

	// Cluster created and configured successfully, saving again to Object Storage
	err = b.Cluster.UpdateMetadata(func() error {
		return b.Cluster.GetExtensions().LockForWrite(Extension.StateV1).ThenUse(func(v interface{}) error {
			stateV1 := v.(*clusterpropsv1.State)
			stateV1.State = ClusterState.Created
			return nil
		})
	})
	if err != nil {
		log.Println("failed to update metadata")
		return err
	}

	// Get the state of the swarmCluster until successful
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			status, err := b.Cluster.ForceGetState()
			if err != nil {
				return err
			}
			if status != ClusterState.Nominal {
				return fmt.Errorf("swarmCluster is not ready for duty")
			}
			return nil
		},
		5*time.Minute,
	)
	if err != nil {
		log.Println("failed to wait ready state of the swarmCluster")
		return err
	}
	return nil
}

// ConfigureNode ...
func (b *Blueprint) ConfigureNode(index int, host *pb.Host, nodeType NodeType.Enum, nodeTypeStr string) error {
	if b.Callbacks.ConfigureNode != nil {
		return b.Callbacks.ConfigureNode(b.Cluster, b, index, host, nodeType, nodeTypeStr)
	}
	return fmt.Errorf("failed to execute 'ConfigureNode' callback")
}

// ConfigureMaster ...
func (b *Blueprint) ConfigureMaster(index int, host *pb.Host) error {
	if b.Callbacks.ConfigureNode != nil {
		return b.Callbacks.ConfigureMaster(b.Cluster, b, index, host)
	}
	return fmt.Errorf("failed to execute 'ConfigureNode' callback")
}

// ConfigureCluster ...
func (b *Blueprint) ConfigureCluster() error {
	if b.Callbacks.ConfigureCluster != nil {
		return b.Callbacks.ConfigureCluster(b.Cluster, b)
	}
	return fmt.Errorf("failed to execute 'ConfigureCluster' callback")
}

// GetTemplateBox ...
func (b *Blueprint) GetTemplateBox() (*rice.Box, error) {
	if b.Callbacks.GetTemplateBox != nil {
		return b.Callbacks.GetTemplateBox()
	}
	return nil, fmt.Errorf("failed to execute 'GetTemplateBox' callback")
}

// GetGlobalSystemRequirements ...
func (b *Blueprint) GetGlobalSystemRequirements(c api.Cluster) (*string, error) {
	if b.Callbacks.GetGlobalSystemRequirements != nil {
		return b.Callbacks.GetGlobalSystemRequirements(c, b)
	}
	return nil, fmt.Errorf("failed to execute 'GetGlobalSystemRequirements' callback")
}

func (b *Blueprint) determineRequiredNodes() (int, int, int) {
	if b.Callbacks.DetermineRequiredNodes != nil {
		return b.Callbacks.DetermineRequiredNodes(b.Cluster)
	}
	return 0, 0, 0
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
	return brokerclient.New().Ssh.Run(hostID, cmd, brokerclient.DefaultConnectionTimeout, time.Duration(20)*time.Minute)
}

// uploadTemplateToFile uploads a template named 'tmplName' coming from rice 'box' in a file to a remote host
func uploadTemplateToFile(
	box *rice.Box, funcMap map[string]interface{}, tmplName string, data map[string]interface{},
	hostID string, fileName string,
) (string, error) {

	if box == nil {
		panic("box is nil!")
	}
	broker := brokerclient.New()
	host, err := broker.Host.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
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

// ConfigureNodesFromList ...
func (b *Blueprint) ConfigureNodesFromList(public bool, hosts []string) error {
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
	brokerHost := brokerclient.New().Host
	for i, hostID = range hosts {
		host, err = brokerHost.Inspect(hostID, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			break
		}
		d := make(chan error)
		dones = append(dones, d)
		go asyncConfigureNode(b.Cluster, b, i+1, host, nodeType, nodeTypeStr, d)
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
