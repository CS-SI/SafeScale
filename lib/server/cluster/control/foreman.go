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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	txttmpl "text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"
	log "github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster/api"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	clusterpropsv2 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v2"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/NodeType"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Property"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/install"
	providermetadata "github.com/CS-SI/SafeScale/lib/server/metadata"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/template"
)

var (
	timeoutCtxHost = utils.GetLongOperationTimeout()

	// funcMap defines the custome functions to be used in templates
	funcMap = txttmpl.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
	}

	// // systemTemplateBox ...
	// systemTemplateBox *rice.Box

	// bashLibraryContent contains the script containing bash library
	bashLibraryContent *string
)

// Makers ...
type Makers struct {
	MinimumRequiredServers      func(task concurrency.Task, b Foreman) (int, int, int)   // returns masterCount, pruvateNodeCount, publicNodeCount
	DefaultGatewaySizing        func(task concurrency.Task, b Foreman) pb.HostDefinition // sizing of Gateway(s)
	DefaultMasterSizing         func(task concurrency.Task, b Foreman) pb.HostDefinition // default sizing of master(s)
	DefaultNodeSizing           func(task concurrency.Task, b Foreman) pb.HostDefinition // defailt sizing of node(s)
	DefaultImage                func(task concurrency.Task, b Foreman) string            // default image of server(s)
	GetNodeInstallationScript   func(task concurrency.Task, b Foreman, nodeType NodeType.Enum) (string, map[string]interface{})
	GetGlobalSystemRequirements func(task concurrency.Task, b Foreman) (string, error)
	GetTemplateBox              func() (*rice.Box, error)
	ConfigureGateway            func(task concurrency.Task, b Foreman) error
	CreateMaster                func(task concurrency.Task, b Foreman, index int) error
	ConfigureMaster             func(task concurrency.Task, b Foreman, index int, pbHost *pb.Host) error
	UnconfigureMaster           func(task concurrency.Task, b Foreman, pbHost *pb.Host) error
	CreateNode                  func(task concurrency.Task, b Foreman, index int, pbHost *pb.Host) error
	ConfigureNode               func(task concurrency.Task, b Foreman, index int, pbHost *pb.Host) error
	UnconfigureNode             func(task concurrency.Task, b Foreman, pbHost *pb.Host, selectedMasterID string) error
	ConfigureCluster            func(task concurrency.Task, b Foreman) error
	UnconfigureCluster          func(task concurrency.Task, b Foreman) error
	JoinMasterToCluster         func(task concurrency.Task, b Foreman, pbHost *pb.Host) error
	JoinNodeToCluster           func(task concurrency.Task, b Foreman, pbHost *pb.Host) error
	LeaveMasterFromCluster      func(task concurrency.Task, b Foreman, pbHost *pb.Host) error
	LeaveNodeFromCluster        func(task concurrency.Task, b Foreman, pbHost *pb.Host, selectedMaster string) error
	GetState                    func(task concurrency.Task, b Foreman) (ClusterState.Enum, error)
}

//go:generate mockgen -destination=../mocks/mock_foreman.go -package=mocks github.com/CS-SI/SafeScale/lib/server/cluster/control Foreman

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

	// cmd = fmt.Sprintf("sudo bash %s; rc=$?; if [[ rc -eq 0 ]]; then rm %s; fi; exit $rc", path, path)
	cmd = fmt.Sprintf("sudo bash %s; rc=$?; exit $rc", path)

	return client.New().Ssh.Run(hostID, cmd, utils.GetConnectionTimeout(), 2*utils.GetLongOperationTimeout())
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
	var imageID string
	if req.NodesDef != nil {
		imageID = req.NodesDef.ImageId
	}
	if imageID == "" && b.makers.DefaultImage != nil {
		imageID = b.makers.DefaultImage(task, b)
	}
	if imageID == "" {
		imageID = "Ubuntu 18.04"
	}

	// Determine Gateway sizing
	var gatewaysDefault *pb.HostDefinition
	if b.makers.DefaultGatewaySizing != nil {
		gatewaysDefault = complementHostDefinition(nil, b.makers.DefaultGatewaySizing(task, b))
	} else {
		gatewaysDefault = &pb.HostDefinition{
			Sizing: &pb.HostSizing{
				MinCpuCount: 2,
				MaxCpuCount: 4,
				MinRamSize:  7.0,
				MaxRamSize:  16.0,
				MinDiskSize: 50,
				GpuCount:    -1,
			},
		}
	}
	gatewaysDefault.ImageId = imageID
	gatewaysDef := complementHostDefinition(req.GatewaysDef, *gatewaysDefault)

	// Determine master sizing
	var mastersDefault *pb.HostDefinition
	if b.makers.DefaultMasterSizing != nil {
		mastersDefault = complementHostDefinition(nil, b.makers.DefaultMasterSizing(task, b))
	} else {
		mastersDefault = &pb.HostDefinition{
			Sizing: &pb.HostSizing{
				MinCpuCount: 4,
				MaxCpuCount: 8,
				MinRamSize:  15.0,
				MaxRamSize:  32.0,
				MinDiskSize: 100,
				GpuCount:    -1,
			},
		}
	}
	// Note: no way yet to define master sizing from cli...
	mastersDefault.ImageId = imageID
	mastersDef := complementHostDefinition(req.MastersDef, *mastersDefault)

	// Determine node sizing
	var nodesDefault *pb.HostDefinition
	if b.makers.DefaultNodeSizing != nil {
		nodesDefault = complementHostDefinition(nil, b.makers.DefaultNodeSizing(task, b))
	} else {
		nodesDefault = &pb.HostDefinition{
			Sizing: &pb.HostSizing{
				MinCpuCount: 4,
				MaxCpuCount: 8,
				MinRamSize:  15.0,
				MaxRamSize:  32.0,
				MinDiskSize: 100,
				GpuCount:    -1,
			},
		}
	}
	nodesDefault.ImageId = imageID
	nodesDef := complementHostDefinition(req.NodesDef, *nodesDefault)

	// Creates network
	log.Debugf("[cluster %s] creating network 'net-%s'", req.Name, req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	sizing := srvutils.FromPBHostDefinitionToPBGatewayDefinition(*gatewaysDef)
	gwFailoverDisabled := req.Complexity == Complexity.Small
	for k := range req.DisabledDefaultFeatures {
		if k == "gateway-failover" {
			gwFailoverDisabled = true
			break
		}
	}
	def := pb.NetworkDefinition{
		Name:     networkName,
		Cidr:     req.CIDR,
		Gateway:  &sizing,
		FailOver: !gwFailoverDisabled,
	}
	clientInstance := client.New()
	clientNetwork := clientInstance.Network
	network, err := clientNetwork.Create(def, utils.GetExecutionTimeout())
	if err != nil {
		msg := fmt.Sprintf("failed to create network '%s': %s", networkName, err.Error())
		log.Errorf("[cluster %s] %s", req.Name, msg)
		return fmt.Errorf(msg)
	}
	log.Debugf("[cluster %s] network '%s' creation successful.", req.Name, networkName)
	req.NetworkID = network.Id

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := clientNetwork.Delete([]string{network.Id}, utils.GetExecutionTimeout())
			if derr != nil {
				log.Errorf("after failure, failed to delete network '%s'", networkName)
			}
		}
	}()

	// Saving Cluster parameters, with status 'Creating'
	var (
		kp                               *resources.KeyPair
		kpName                           string
		primaryGateway, secondaryGateway *resources.Host
	)

	tenant, err := clientInstance.Tenant.Get(utils.GetExecutionTimeout())
	if err != nil {
		return err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return err
	}

	// Loads primary gateway metadata
	primaryGatewayMetadata, err := providermetadata.LoadHost(svc, network.GatewayId)
	if err != nil {
		return err
	}
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
	primaryGateway = primaryGatewayMetadata.Get()
	err = clientInstance.Ssh.WaitReady(primaryGateway.ID, utils.GetExecutionTimeout())
	if err != nil {
		return client.DecorateError(err, "wait for remote ssh service to be ready", false)
	}

	// Loads secondary gateway metadata
	if !gwFailoverDisabled {
		secondaryGatewayMetadata, err := providermetadata.LoadHost(svc, network.SecondaryGatewayId)
		if err != nil {
			return err
		}
		if err != nil {
			if _, ok := err.(utils.ErrNotFound); ok {
				if !ok {
					msg := fmt.Sprintf("failed to load secondary gateway metadata of network '%s'", networkName)
					log.Errorf("[cluster %s] %s", req.Name, msg)
					return fmt.Errorf(msg)
				}
			}
			return err
		}
		secondaryGateway = secondaryGatewayMetadata.Get()
		err = clientInstance.Ssh.WaitReady(primaryGateway.ID, utils.GetExecutionTimeout())
		if err != nil {
			return client.DecorateError(err, "wait for remote ssh service to be ready", false)
		}
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
	err = b.cluster.UpdateMetadata(task, func() error {
		err := b.cluster.GetProperties(task).LockForWrite(Property.DefaultsV2).ThenUse(func(v interface{}) error {
			defaultsV2 := v.(*clusterpropsv2.Defaults)
			defaultsV2.GatewaySizing = srvutils.FromPBHostSizing(*gatewaysDef.Sizing)
			defaultsV2.MasterSizing = srvutils.FromPBHostSizing(*mastersDef.Sizing)
			defaultsV2.NodeSizing = srvutils.FromPBHostSizing(*nodesDef.Sizing)
			defaultsV2.Image = imageID
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

		return b.cluster.GetProperties(task).LockForWrite(Property.NetworkV2).ThenUse(func(v interface{}) error {
			networkV2 := v.(*clusterpropsv2.Network)
			networkV2.NetworkID = req.NetworkID
			networkV2.CIDR = req.CIDR
			networkV2.GatewayID = primaryGateway.ID
			networkV2.GatewayIP = primaryGateway.GetPrivateIP()
			if !gwFailoverDisabled {
				networkV2.SecondaryGatewayID = secondaryGateway.ID
				networkV2.SecondaryGatewayIP = secondaryGateway.GetPrivateIP()
				networkV2.DefaultRouteIP = network.VirtualIp.PrivateIp
				//VPL: no public IP on VIP yet...
				// networkV2.EndpointIP = network.VirtualIp.PublicIp
				networkV2.EndpointIP = primaryGateway.GetPublicIP()
			} else {
				networkV2.DefaultRouteIP = primaryGateway.GetPrivateIP()
				networkV2.EndpointIP = primaryGateway.GetPublicIP()
			}
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

	masterCount, privateNodeCount, _ := b.determineRequiredNodes(task)
	var (
		primaryGatewayStatus   error
		secondaryGatewayStatus error
		mastersStatus          error
		privateNodesStatus     error
		secondaryGatewayTask   concurrency.Task
	)

	// Step 1: starts gateway installation plus masters creation plus nodes creation
	primaryGatewayTask := task.New().Start(b.taskInstallGateway, srvutils.ToPBHost(primaryGateway))
	if !gwFailoverDisabled {
		secondaryGatewayTask = task.New().Start(b.taskInstallGateway, srvutils.ToPBHost(secondaryGateway))
	}
	mastersTask := task.New().Start(b.taskCreateMasters, data.Map{
		"count":     masterCount,
		"masterDef": mastersDef,
	})

	privateNodesTask := task.New().Start(b.taskCreateNodes, data.Map{
		"count":   privateNodeCount,
		"public":  false,
		"nodeDef": nodesDef,
	})

	// Step 2: awaits gateway installation end and masters installation end
	_, primaryGatewayStatus = primaryGatewayTask.Wait()
	if !gwFailoverDisabled {
		_, secondaryGatewayStatus = secondaryGatewayTask.Wait()
	}
	_, mastersStatus = mastersTask.Wait()

	// Starting from here, delete masters if exiting with error and req.KeepOnFailure is not true
	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := client.New().Host.Delete(b.cluster.ListMasterIDs(task), utils.GetExecutionTimeout())
			if derr != nil {
				log.Errorf("[cluster %s] after failure, failed to delete masters", req.Name)
			}
		}
	}()

	// Step 3: run (not start so no parallelism here) gateway configuration (needs MasterIPs so masters must be installed first)
	if primaryGatewayStatus == nil && secondaryGatewayStatus == nil && mastersStatus == nil {
		// Configure Gateway(s) and waits for the result
		primaryGatewayTask = task.New().Start(b.taskConfigureGateway, srvutils.ToPBHost(primaryGateway))
		if !gwFailoverDisabled {
			secondaryGatewayTask = task.New().Start(b.taskConfigureGateway, srvutils.ToPBHost(secondaryGateway))
		}
		_, primaryGatewayStatus = primaryGatewayTask.Wait()
		if !gwFailoverDisabled {
			_, secondaryGatewayStatus = secondaryGatewayTask.Wait()
		}
	}

	// Step 4: configure masters (if masters created successfully and gateway configure successfully)
	if primaryGatewayStatus == nil && secondaryGatewayStatus == nil && mastersStatus == nil {
		_, mastersStatus = task.New().Run(b.taskConfigureMasters, nil)
	}

	// Step 5: awaits nodes creation
	_, privateNodesStatus = privateNodesTask.Wait()

	// Starting from here, delete nodes on failure if exits with error and req.KeepOnFailure is false
	defer func() {
		if err != nil && !req.KeepOnFailure {
			clientHost := clientInstance.Host
			derr := clientHost.Delete(b.cluster.ListNodeIDs(task), utils.GetExecutionTimeout())
			if derr != nil {
				log.Debugf("failed to remove private nodes on failure")
			}

		}
	}()

	// Step 6: Starts nodes configuration, if all masters and nodes
	// have been created and gateway has been configured with success
	if primaryGatewayStatus == nil && secondaryGatewayStatus == nil && mastersStatus == nil && privateNodesStatus == nil {
		_, privateNodesStatus = task.New().Run(b.taskConfigureNodes, nil)
	}

	if primaryGatewayStatus != nil {
		err = primaryGatewayStatus // value of err may trigger defer calls, don't change anything here
		return err
	}
	if secondaryGatewayStatus != nil {
		err = secondaryGatewayStatus // value of err may trigger defer calls, don't change anything here
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
func complementHostDefinition(req *pb.HostDefinition, def pb.HostDefinition) *pb.HostDefinition {
	var finalDef pb.HostDefinition
	if req == nil {
		finalDef = def
	} else {
		finalDef = *req
		finalDef.Sizing = &pb.HostSizing{}
		*finalDef.Sizing = *req.Sizing

		if def.Sizing.MinCpuCount > 0 && finalDef.Sizing.MinCpuCount == 0 {
			finalDef.Sizing.MinCpuCount = def.Sizing.MinCpuCount
		}
		if def.Sizing.MaxCpuCount > 0 && finalDef.Sizing.MaxCpuCount == 0 {
			finalDef.Sizing.MaxCpuCount = def.Sizing.MaxCpuCount
		}
		if def.Sizing.MinRamSize > 0.0 && finalDef.Sizing.MinRamSize == 0.0 {
			finalDef.Sizing.MinRamSize = def.Sizing.MinRamSize
		}
		if def.Sizing.MaxRamSize > 0.0 && finalDef.Sizing.MaxRamSize == 0.0 {
			finalDef.Sizing.MaxRamSize = def.Sizing.MaxRamSize
		}
		if def.Sizing.MinDiskSize > 0 && finalDef.Sizing.MinDiskSize == 0 {
			finalDef.Sizing.MinDiskSize = def.Sizing.MinDiskSize
		}
		if finalDef.Sizing.GpuCount <= 0 && def.Sizing.GpuCount > 0 {
			finalDef.Sizing.GpuCount = def.Sizing.GpuCount
		}
		if finalDef.Sizing.MinCpuFreq == 0 && def.Sizing.MinCpuFreq > 0 {
			finalDef.Sizing.MinCpuFreq = def.Sizing.MinCpuFreq
		}
		if finalDef.ImageId == "" {
			finalDef.ImageId = def.ImageId
		}

		if finalDef.Sizing.MinCpuCount <= 0 {
			finalDef.Sizing.MinCpuCount = 2
		}
		if finalDef.Sizing.MaxCpuCount <= 0 {
			finalDef.Sizing.MaxCpuCount = 4
		}
		if finalDef.Sizing.MinRamSize <= 0.0 {
			finalDef.Sizing.MinRamSize = 7.0
		}
		if finalDef.Sizing.MaxRamSize <= 0.0 {
			finalDef.Sizing.MaxRamSize = 16.0
		}
		if finalDef.Sizing.MinDiskSize <= 0 {
			finalDef.Sizing.MinDiskSize = 50
		}
	}

	return &finalDef
}

// GetState returns "actively" the current state of the cluster
func (b *foreman) getState(task concurrency.Task) (ClusterState.Enum, error) {
	if b.makers.GetState != nil {
		return b.makers.GetState(task, b)
	}
	return ClusterState.Unknown, fmt.Errorf("no maker defined for 'GetState'")
}

// configureNode ...
func (b *foreman) configureNode(task concurrency.Task, index int, pbHost *pb.Host) error {
	if b.makers.ConfigureNode != nil {
		return b.makers.ConfigureNode(task, b, index, pbHost)
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
}

// unconfigureNode executes what has to be done to remove node from cluster
func (b *foreman) unconfigureNode(task concurrency.Task, hostID string, selectedMasterID string) error {
	pbHost, err := client.New().Host.Inspect(hostID, utils.GetExecutionTimeout())
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

	// Installs reverseproxy feature on cluster (gateways)
	err = b.installReverseProxy(task)
	if err != nil {
		return err
	}

	// Installs remotedesktop feature on cluster (all masters)
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
	host, err := client.New().Host.Inspect(hostID, utils.GetExecutionTimeout())
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
	remotePath := srvutils.TempFolder + "/" + fileName

	err = install.UploadStringToRemoteFile(cmd, host, remotePath, "", "", "")
	if err != nil {
		return "", err
	}
	return remotePath, nil
}

// configureNodesFromList configures nodes from a list
func (b *foreman) configureNodesFromList(task concurrency.Task, hosts []string) error {
	log.Debugf("Configuring nodes...")

	var (
		host   *pb.Host
		err    error
		hostID string
		errors []string
	)

	var subtasks []concurrency.Task
	clientHost := client.New().Host
	length := len(hosts)
	for i := 0; i < length; i++ {
		host, err = clientHost.Inspect(hosts[i], utils.GetExecutionTimeout())
		if err != nil {
			break
		}
		subtask := task.New().Start(b.taskConfigureNode, map[string]interface{}{
			"index": i + 1,
			"host":  host,
		})
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	if err != nil {
		errors = append(errors, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		return fmt.Errorf(strings.Join(errors, "\n"))
	}
	return nil
}

// joinNodesFromList makes nodes from a list join the cluster
func (b *foreman) joinNodesFromList(task concurrency.Task, hosts []string) error {
	if b.makers.JoinNodeToCluster == nil {
		// configure what has to be done cluster-wide
		if b.makers.ConfigureCluster != nil {
			return b.makers.ConfigureCluster(task, b)
		}
	}

	log.Debugf("Joining nodes to cluster...")

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, utils.GetExecutionTimeout())
		if err != nil {
			return err
		}

		if b.makers.JoinMasterToCluster != nil {
			err = b.makers.JoinNodeToCluster(task, b, pbHost)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// leaveMastersFromList makes masters from a list leave the cluster
func (b *foreman) leaveMastersFromList(task concurrency.Task, public bool, hosts []string) error {
	if b.makers.LeaveMasterFromCluster == nil {
		return nil
	}

	log.Debugf("Making Masters leaving cluster...")

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, utils.GetExecutionTimeout())
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

// leaveNodesFromList makes nodes from a list leave the cluster
func (b *foreman) leaveNodesFromList(task concurrency.Task, hosts []string, selectedMasterID string) error {
	if b.makers.LeaveNodeFromCluster == nil {
		return nil
	}

	log.Debugf("Ordering nodes to leave cluster...")

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, utils.GetExecutionTimeout())
		if err != nil {
			// If host seems deleted, consider leaving as a success
			if _, ok := err.(resources.ErrResourceNotFound); ok {
				continue
			}
			return err
		}
		err = b.makers.LeaveNodeFromCluster(task, b, pbHost, selectedMasterID)
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
		globalSystemRequirements = result
	}
	params["reserved_CommonRequirements"] = globalSystemRequirements

	if nodeType == NodeType.Master {
		tp := b.cluster.GetService(task).GetTenantParameters()
		content := map[string]interface{}{
			"tenants": []map[string]interface{}{
				tp,
			},
		}
		jsoned, err := json.MarshalIndent(content, "", "    ")
		if err != nil {
			log.Errorf("[%s] tenant parameters convert to JSON failed: %v", hostLabel, err)
			return err
		}
		params["reserved_TenantJSON"] = string(jsoned)
	}

	var dnsServers []string
	cfg, err := b.cluster.GetService(task).GetConfigurationOptions()
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	identity := b.cluster.GetIdentity(task)
	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	params["MasterIPs"] = b.cluster.ListMasterIPs(task)
	params["CladmPassword"] = identity.AdminPassword
	netCfg := b.cluster.GetNetworkConfig(task)
	params["DefaultRouteIP"] = netCfg.DefaultRouteIP
	params["EndpointIP"] = netCfg.EndpointIP

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

// taskInstallGateway installs necessary components on one gateway
// This function is intended to be call as a goroutine
func (b *foreman) taskInstallGateway(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	pbGateway := params.(*pb.Host)
	// log.Debugf(">>> lib.server.cluster.control.foreman::taskInstallGateway(%s)", pbGateway.Name)
	// defer log.Debugf("<<< lib.server.cluster.control.foreman::taskInstallGateway(%s)", pbGateway.Name)

	hostLabel := "gateway"
	log.Debugf("[%s] starting installation...", hostLabel)

	sshCfg, err := client.New().Host.SSHConfig(pbGateway.Id)
	if err != nil {
		return nil, err
	}
	_, err = sshCfg.WaitServerReady("ready", utils.GetHostTimeout())
	if err != nil {
		return nil, err
	}

	// Installs docker and docker-compose on gateway
	err = b.installDockerCompose(t, pbGateway, hostLabel)
	if err != nil {
		return nil, err
	}

	// Configure docker in Swarm mode
	//	err = b.configureDockerSwarm(tr.Task(), pbGateway, hostLabel)
	//	if err != nil {
	//		return nil, err
	//	}

	// Installs proxycache server on gateway (if not disabled)
	err = b.installProxyCacheServer(t, pbGateway, hostLabel)
	if err != nil {
		return nil, err
	}

	// Installs requirements as defined by cluster Flavor (if it exists)
	err = b.installNodeRequirements(t, NodeType.Gateway, pbGateway, hostLabel)
	if err != nil {
		return nil, err
	}

	log.Debugf("[%s] preparation successful", hostLabel)
	return nil, nil
}

// configureDockerSwarm
//func (b *foreman) configureDockerSwarm(task concurrency.Task, gw *pb.Host, hostLabel string) error {
//	cmd := fmt.Sprintf("docker swarm init --advertise-addr %s", gw.GetPrivateIp())
//	retcode, _, _, err := client.New().Ssh.Run(gw.Id, cmd, utils.GetConnectionTimeout(), 2*utils.GetLongOperationTimeout())
//	if err != nil {
//		return err
//	}
//	if retcode != 0 {
//		return fmt.Errorf("failed to initialize docker swarm on '%s'", hostLabel)
//	}
//	return nil
//}

// taskConfigureGateway prepares one gateway
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureGateway(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	// Convert parameters
	gw := params.(*pb.Host)

	log.Debugf(">>> lib.server.cluster.control.foreman::taskConfigureGateway(%s)", gw.Name)
	defer log.Debugf("<<< lib.server.cluster.control.foreman::taskConfigureGateway(%s)", gw.Name)

	log.Debugf("[%s] starting configuration...", gw.Name)

	if b.makers.ConfigureGateway != nil {
		err := b.makers.ConfigureGateway(t, b)
		if err != nil {
			return nil, err
		}
	}

	log.Debugf("[%s] configuration successful.", gw.Name)
	return nil, nil
}

// taskCreateMasters creates masters
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateMasters(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	// Convert parameters
	p := params.(data.Map)
	count := p["count"].(int)
	def := p["masterDef"].(*pb.HostDefinition)

	log.Debugf(">>> lib.server.cluster.control.foreman::taskCreateMasters(%d)", count)
	defer log.Debugf(">>> lib.server.cluster.control.foreman::taskCreateMasters(%d)", count)

	clusterName := b.cluster.GetIdentity(t).Name

	defer timer(fmt.Sprintf("[cluster %s] 'taskCreateMasters' called", clusterName))()

	if count <= 0 {
		log.Debugf("[cluster %s] no masters to create.", clusterName)
		return nil, nil
	}

	log.Debugf("[cluster %s] creating %d master%s...\n", clusterName, count, utils.Plural(count))

	var subtasks []concurrency.Task
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 0; i < count; i++ {
		subtask := t.New().Start(b.taskCreateMaster, data.Map{
			"index":     i + 1,
			"masterDef": def,
			"timeout":   timeout,
		})
		subtasks = append(subtasks, subtask)
	}
	var errors []string
	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		msg := strings.Join(errors, "\n")
		log.Errorf("[cluster %s] failed to create master(s): %s", clusterName, msg)
		return nil, fmt.Errorf(msg)
	}

	log.Debugf("[cluster %s] masters creation successful.", clusterName)
	return nil, nil
}

// taskCreateMaster creates one master
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateMaster(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	// Convert parameters
	p := params.(data.Map)
	index := p["index"].(int)
	def := p["masterDef"].(*pb.HostDefinition)
	timeout := p["timeout"].(time.Duration)

	log.Debugf(">>>{task %s} safescale.cluster.controller.foreman::taskCreateMaster(%d)", t.GetID(), index)
	defer log.Debugf("<<<{task %s} safescale.cluster.controller.foreman::taskCreateMaster(%d)", t.GetID(), index)

	hostLabel := fmt.Sprintf("master #%d", index)
	log.Debugf("[%s] starting host resource creation...", hostLabel)

	var err error
	hostDef := *def
	hostDef.Name, err = b.buildHostname(t, "master", NodeType.Master)
	if err != nil {
		log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
		return nil, fmt.Errorf("failed to create '%s': %s", hostLabel, err.Error())
	}

	hostDef.Network = b.cluster.GetNetworkConfig(t).NetworkID
	hostDef.Public = false
	clientHost := client.New().Host
	pbHost, err := clientHost.Create(hostDef, timeout)
	if pbHost != nil {
		// Updates cluster metadata to keep track of created host, before testing if an error occured during the creation
		mErr := b.cluster.UpdateMetadata(t, func() error {
			// Locks for write the NodesV1 extension...
			return b.cluster.GetProperties(t).LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
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
		if mErr != nil {
			log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
			return nil, fmt.Errorf("failed to update Cluster metadata: %s", err.Error())
		}
	}
	if err != nil {
		err = client.DecorateError(err, "creation of host resource", false)
		log.Errorf("[%s] host resource creation failed: %s", hostLabel, err.Error())
		return nil, err
	}
	hostLabel = fmt.Sprintf("%s (%s)", hostLabel, pbHost.Name)
	log.Debugf("[%s] host resource creation successful", hostLabel)

	// err = b.cluster.UpdateMetadata(tr.Task(), func() error {
	// 	// Locks for write the NodesV1 extension...
	// 	return b.cluster.GetProperties(tr.Task()).LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
	// 		nodesV1 := v.(*clusterpropsv1.Nodes)
	// 		// Update swarmCluster definition in Object Storage
	// 		node := &clusterpropsv1.Node{
	// 			ID:        pbHost.Id,
	// 			Name:      pbHost.Name,
	// 			PrivateIP: pbHost.PrivateIp,
	// 			PublicIP:  pbHost.PublicIp,
	// 		}
	// 		nodesV1.Masters = append(nodesV1.Masters, node)
	// 		return nil
	// 	})
	// })
	// if err != nil {
	// 	log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
	// 	err = fmt.Errorf("failed to update Cluster metadata: %s", err.Error())
	// 	return
	// }

	err = b.installProxyCacheClient(t, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	// Installs cluster-level system requirements...
	err = b.installNodeRequirements(t, NodeType.Master, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	log.Debugf("[%s] host resource creation successful.", hostLabel)
	return nil, nil
}

// taskConfigureMasters configure masters
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureMasters(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	log.Debugf(">>> lib.server.cluster.control.Foreman::taskConfigureMasters()")
	defer log.Debugf("<<< lib.server.cluster.control.Foreman::taskConfigureMasters()")

	list := b.cluster.ListMasterIDs(t)
	if len(list) <= 0 {
		return nil, nil
	}

	log.Debugf("[cluster %s] Configuring masters...", b.cluster.Name)

	clientHost := client.New().Host
	var subtasks []concurrency.Task
	for i, hostID := range b.cluster.ListMasterIDs(t) {
		host, err := clientHost.Inspect(hostID, utils.GetExecutionTimeout())
		if err != nil {
			err = fmt.Errorf("failed to get metadata of host: %s", err.Error())
			continue
		}
		subtask := t.New().Start(b.taskConfigureMaster, data.Map{
			"index": i + 1,
			"host":  host,
		})
		subtasks = append(subtasks, subtask)
	}

	var errors []string
	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		return nil, fmt.Errorf(strings.Join(errors, "\n"))
	}

	log.Debugf("[cluster %s] Masters configuration successful.", b.cluster.Name)
	return nil, nil
}

// taskConfigureMaster configures one master
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureMaster(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	// Convert params
	p := params.(data.Map)
	index := p["index"].(int)
	pbHost := p["host"].(*pb.Host)

	log.Debugf(">>> lib.server.cluster.control.Foreman::taskConfigureMaster(%d, %s)", index, pbHost.Name)
	defer log.Debugf("<<< lib.server.cluster.control.Foreman::taskConfigureMaster(%d, %s)", index, pbHost.Name)

	hostLabel := fmt.Sprintf("master #%d (%s)", index, pbHost.Name)
	log.Debugf("[%s] starting configuration...\n", hostLabel)

	// install docker and docker-compose feature
	err := b.installDockerCompose(t, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	err = b.configureMaster(t, index, pbHost)
	if err != nil {
		return nil, err
	}

	log.Debugf("[%s] configuration successful.", hostLabel)
	return nil, nil
}

// taskCreateNodes creates nodes
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateNodes(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	// Convert params
	p := params.(data.Map)
	count := p["count"].(int)
	public := p["public"].(bool)
	def := p["nodeDef"].(*pb.HostDefinition)

	log.Debugf(">>> lib.server.cluster.control.Foreman::taskCreateNodes(%d, %v)", count, public)
	defer log.Debugf("<<< lib.server.cluster.control.Foreman::taskCreateNodes(%d, %v)", count, public)

	clusterName := b.cluster.GetIdentity(t).Name

	defer timer(fmt.Sprintf("[cluster %s] 'taskCreateNodes' called", clusterName))()

	if count <= 0 {
		log.Debugf("[cluster %s] no nodes to create.", clusterName)
		return nil, nil
	}
	log.Debugf("[cluster %s] creating %d node%s...", clusterName, count, utils.Plural(count))

	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	var subtasks []concurrency.Task
	for i := 1; i <= count; i++ {
		subtask := t.New().Start(b.taskCreateNode, data.Map{
			"index":   i,
			"type":    NodeType.Node,
			"nodeDef": def,
			"timeout": timeout,
		})
		subtasks = append(subtasks, subtask)
	}

	var errors []string
	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errors = append(errors, state.Error())
		}
	}
	if len(errors) > 0 {
		return nil, fmt.Errorf(strings.Join(errors, "\n"))
	}

	log.Debugf("[cluster %s] %d node%s creation successful.", clusterName, count, utils.Plural(count))
	return nil, nil
}

// taskCreateNode creates a Node in the Cluster
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateNode(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	// Convert parameters
	p := params.(data.Map)
	index := p["index"].(int)
	def := p["nodeDef"].(*pb.HostDefinition)
	timeout := p["timeout"].(time.Duration)

	log.Debugf(">>> lib.server.cluster.control.Foreman::taskCreateNode(%d)", index)
	defer log.Debugf("<<< lib.server.cluster.control.Foreman::taskCreateNode(%d)", index)

	hostLabel := fmt.Sprintf("node #%d", index)
	log.Debugf("[%s] starting host resource creation...", hostLabel)

	// Create the host
	var err error
	hostDef := *def
	hostDef.Name, err = b.buildHostname(t, "node", NodeType.Node)
	if err != nil {
		log.Errorf("[%s] host resource creation failed: %s", hostLabel, err.Error())
		return nil, err
	}
	hostDef.Network = b.cluster.GetNetworkConfig(t).NetworkID
	if timeout < utils.GetLongOperationTimeout() {
		timeout = utils.GetLongOperationTimeout()
	}

	clientHost := client.New().Host
	var node *clusterpropsv1.Node
	pbHost, err := clientHost.Create(hostDef, timeout)
	if pbHost != nil {
		mErr := b.cluster.UpdateMetadata(t, func() error {
			// Locks for write the NodesV1 extension...
			return b.cluster.GetProperties(t).LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
				nodesV1 := v.(*clusterpropsv1.Nodes)
				// Registers the new Agent in the swarmCluster struct
				node = &clusterpropsv1.Node{
					ID:        pbHost.Id,
					Name:      pbHost.Name,
					PrivateIP: pbHost.PrivateIp,
					PublicIP:  pbHost.PublicIp,
				}
				nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, node)
				return nil
			})
		})
		if mErr != nil {
			derr := clientHost.Delete([]string{pbHost.Id}, utils.GetLongOperationTimeout())
			if derr != nil {
				log.Errorf("failed to delete node after failure")
			}
			log.Errorf("[%s] creation failed: %s", hostLabel, mErr.Error())
			return nil, fmt.Errorf("failed to create node: %s", mErr.Error())
		}
	}
	if err != nil {
		err = client.DecorateError(err, "creation of host resource", true)
		log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
		return nil, err
	}
	hostLabel = fmt.Sprintf("node #%d (%s)", index, pbHost.Name)
	log.Debugf("[%s] host resource creation successful.", hostLabel)

	// err = b.cluster.UpdateMetadata(tr.Task(), func() error {
	// 	// Locks for write the NodesV1 extension...
	// 	return b.cluster.GetProperties(tr.Task()).LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
	// 		nodesV1 := v.(*clusterpropsv1.Nodes)
	// 		// Registers the new Agent in the swarmCluster struct
	// 		node = &clusterpropsv1.Node{
	// 			ID:        pbHost.Id,
	// 			Name:      pbHost.Name,
	// 			PrivateIP: pbHost.PrivateIp,
	// 			PublicIP:  pbHost.PublicIp,
	// 		}
	// 		nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, node)
	// 		return nil
	// 	})
	// })
	// if err != nil {
	// 	derr := clientHost.Delete([]string{pbHost.Id}, utils.GetLongOperationTimeout())
	// 	if derr != nil {
	// 		log.Errorf("failed to delete node after failure")
	// 	}
	// 	log.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
	// 	err = fmt.Errorf("failed to create node: %s", err.Error())
	// 	return
	// }

	err = b.installProxyCacheClient(t, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	err = b.installNodeRequirements(t, NodeType.Node, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	log.Debugf("[%s] host resource creation successful.", hostLabel)
	return pbHost.Name, nil
}

// taskConfigureNodes configures nodes
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureNodes(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	log.Debugf(">>> safescale.cluster.controller.Foreman::taskConfigureNodes()")
	defer log.Debugf("<<< safescale.cluster.controller.Foreman::taskConfigureNodes()")

	clusterName := b.cluster.GetIdentity(t).Name

	defer timer(fmt.Sprintf("[cluster %s] 'taskConfigureNodes' called", clusterName))()

	list := b.cluster.ListNodeIDs(t)
	if len(list) <= 0 {
		log.Debugf("[cluster %s] no nodes to configure.", clusterName)
		return nil, nil
	}

	log.Debugf("[cluster %s] configuring nodes...", clusterName)

	var (
		pbHost *pb.Host
		i      int
		hostID string
		errors []string
		err    error
	)

	var subtasks []concurrency.Task
	clientHost := client.New().Host
	for i, hostID = range list {
		pbHost, err = clientHost.Inspect(hostID, utils.GetExecutionTimeout())
		if err != nil {
			break
		}
		subtask := t.New().Start(b.taskConfigureNode, data.Map{
			"index": i + 1,
			"host":  pbHost,
		})
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	if err != nil {
		errors = append(errors, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		_, err := s.Wait()
		if err != nil {
			errors = append(errors, err.Error())
		}
	}
	if len(errors) > 0 {
		return nil, fmt.Errorf(strings.Join(errors, "\n"))
	}

	log.Debugf("[cluster %s] nodes configuration successful.", clusterName)
	return nil, nil
}

// taskConfigureNode configure one node
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureNode(t concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	// Convert parameters
	p := params.(data.Map)
	index := p["index"].(int)
	pbHost := p["host"].(*pb.Host)

	log.Debugf(">>> safescale.cluster.controller.Foreman::taskConfigureNode(%d, %s)", index, pbHost.Name)
	defer log.Debugf("<<< safescale.cluster.controller.Foreman::taskConfigureNode(%d, %s)", index, pbHost.Name)

	hostLabel := fmt.Sprintf("node #%d (%s)", index, pbHost.Name)
	log.Debugf("[%s] starting configuration...", hostLabel)

	// Docker and docker-compose installation is mandatory on all nodes
	err := b.installDockerCompose(t, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	// Now configures node specifically for cluster flavor
	err = b.configureNode(t, index, pbHost)
	if err != nil {
		return nil, err
	}

	log.Debugf("[%s] configuration successful.", hostLabel)
	return nil, nil
}

// Installs reverseproxy
func (b *foreman) installReverseProxy(task concurrency.Task) error {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	defer timer(fmt.Sprintf("[cluster %s] installing 'reverseproxy' called", clusterName))()

	disabled := false
	err := b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["remotedesktop"]
		if !disabled {
			_, disabled = v.(*clusterpropsv1.Features).Disabled["reverseproxy"]
		}
		return nil
	})
	if err != nil {
		log.Errorf("[cluster %s] failed to install  embedded feature 'kong4gateway': %v", clusterName, err)
		return err
	}
	if !disabled {
		log.Debugf("[cluster %s] adding feature 'kong4gateway'", clusterName)
		feat, err := install.NewEmbeddedFeature(task, "kong4gateway")
		if err != nil {
			log.Errorf("[cluster %s] failed to instanciate embedded feature '%s': %s\n", clusterName, feat.DisplayName(), err.Error())
			return err
		}
		target := install.NewClusterTarget(task, b.cluster)
		results, err := feat.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			log.Errorf("[cluster %s] failed to add embedded feature '%s': %s", clusterName, feat.DisplayName(), err.Error())
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Errorf("[cluster %s] failed to add '%s' failed: %s\n", clusterName, feat.DisplayName(), msg)
			return fmt.Errorf(msg)
		}
		log.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	}
	return nil
}

func timer(in string) func() {
	log.Info(in)
	start := time.Now()
	return func() { log.Info(in, "... finished in (ms):", time.Since(start).Nanoseconds() * 1000000) }
}

// installRemoteDesktop installs feature remotedesktop on all masters of the cluster
func (b *foreman) installRemoteDesktop(task concurrency.Task) error {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name
	defer timer(fmt.Sprintf("[cluster %s] installing 'remotedesktop' called", clusterName))()

	disabled := false
	err := b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["remotedesktop"]
		if !disabled {
			_, disabled = v.(*clusterpropsv1.Features).Disabled["reverseproxy"]
		}
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
		feat, err := install.NewEmbeddedFeature(task, "remotedesktop")
		if err != nil {
			log.Errorf("[cluster %s] failed to instantiate feature 'remotedesktop': %s\n", clusterName, err.Error())
			return err
		}
		results, err := feat.Add(target, install.Variables{
			"Username": "cladm",
			"Password": adminPassword,
		}, install.Settings{})
		if err != nil {
			log.Errorf("[cluster %s] failed to add feature '%s': %s", clusterName, feat.DisplayName(), err.Error())
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			log.Errorf("[cluster %s] failed to add '%s' failed: %s\n", clusterName, feat.DisplayName(), msg)
			return fmt.Errorf(msg)
		}
		log.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
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

		feat, err := install.NewEmbeddedFeature(task, "proxycache-server")
		if err != nil {
			log.Errorf("[%s] failed to prepare feature 'proxycache-server': %s", hostLabel, err.Error())
			return fmt.Errorf("failed to install feature 'proxycache-server': %s", err.Error())
		}
		target := install.NewHostTarget(pbHost)
		results, err := feat.Add(target, install.Variables{}, install.Settings{})
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

func (b *foreman) installDockerCompose(task concurrency.Task, pbHost *pb.Host, hostLabel string) error {
	// install docker-compose (and docker) feature
	log.Debugf("[%s] adding feature 'docker-compose'...\n", hostLabel)
	feat, err := install.NewEmbeddedFeature(task, "docker-compose")
	if err != nil {
		log.Errorf("[%s] failed to prepare feature 'docker-compose': %s", hostLabel, err.Error())
		return fmt.Errorf("failed to add feature 'docker-compose' on host '%s': %s", pbHost.Name, err.Error())
	}
	results, err := feat.Add(install.NewHostTarget(pbHost), install.Variables{}, install.Settings{})
	if err != nil {
		log.Errorf("[%s] failed to add feature 'docker-compose': %s", hostLabel, err.Error())
		return fmt.Errorf("failed to add feature 'docker-compose' on host '%s': %s", pbHost.Name, err.Error())
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		log.Errorf("[%s] failed to add feature 'docker-compose': %s", hostLabel, msg)
		return fmt.Errorf("failed to add feature 'docker-compose' on host '%s': %s", pbHost.Name, msg)
	}
	log.Debugf("[%s] feature 'docker-compose' addition successful.", hostLabel)
	return nil
}

// BuildHostname builds a unique hostname in the Cluster
func (b *foreman) buildHostname(task concurrency.Task, core string, nodeType NodeType.Enum) (string, error) {
	var (
		index int
	)

	// Locks for write the manager extension...
	b.cluster.Lock(task)
	outerErr := b.cluster.GetProperties(task).LockForWrite(Property.NodesV1).ThenUse(func(v interface{}) error {
		nodesV1 := v.(*clusterpropsv1.Nodes)
		switch nodeType {
		case NodeType.Node:
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
	return b.cluster.GetIdentity(task).Name + "-" + core + "-" + strconv.Itoa(index), nil
}
