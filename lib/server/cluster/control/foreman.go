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
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	txttmpl "text/template"
	"time"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

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
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/template"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

var (
	timeoutCtxHost = temporal.GetLongOperationTimeout()

	// funcMap defines the custom functions to be used in templates
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
	DefaultNodeSizing           func(task concurrency.Task, b Foreman) pb.HostDefinition // default sizing of node(s)
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

// NewForeman creates a new *foreman to build a cluster
func NewForeman(c *Controller, makers Makers) Foreman {
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
) (errCode int, stdOut string, stdErr string, err error) {

	tracer := concurrency.NewTracer(nil, "("+hostID+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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

	// cmd = fmt.Sprintf("sudo bash %s; rc=$?; if [[ rc -eq 0 ]]; then rm %s; fi; exit $rc", path, path)
	cmd := fmt.Sprintf("sudo bash %s; rc=$?; exit $rc", path)

	return client.New().SSH.Run(hostID, cmd, temporal.GetConnectionTimeout(), 2*temporal.GetLongOperationTimeout())
}

// construct ...
func (b *foreman) construct(task concurrency.Task, req Request) (err error) {
	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Wants to inform about the duration of the operation
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting construction of cluster '%s'...", req.Name),
		fmt.Sprintf("Ending construction of cluster '%s'", req.Name),
	)()

	state := ClusterState.Unknown

	defer func() {
		if err != nil {
			state = ClusterState.Error
		} else {
			state = ClusterState.Created
		}

		metaErr := b.cluster.UpdateMetadata(task, func() error {
			// Cluster created and configured successfully
			return b.cluster.GetProperties(task).LockForWrite(Property.StateV1).ThenUse(func(v interface{}) error {
				v.(*clusterpropsv1.State).State = state
				return nil
			})
		})

		if metaErr != nil {
			err = scerr.AddConsequence(err, metaErr)
		}
	}()

	if task == nil {
		task = concurrency.RootTask()
	}

	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	if err != nil {
		return err
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

	// Initialize service to use
	clientInstance := client.New()
	tenant, err := clientInstance.Tenant.Get(temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return err
	}

	// Determine if Gateway Failover must be set
	caps := svc.GetCapabilities()
	gwFailoverDisabled := req.Complexity == Complexity.Small || !caps.PrivateVirtualIP
	for k := range req.DisabledDefaultFeatures {
		if k == "gateway-failover" {
			gwFailoverDisabled = true
			break
		}
	}

	// Creates network
	logrus.Debugf("[cluster %s] creating network 'net-%s'", req.Name, req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	sizing := srvutils.FromPBHostDefinitionToPBGatewayDefinition(*gatewaysDef)
	def := pb.NetworkDefinition{
		Name:     networkName,
		Cidr:     req.CIDR,
		Gateway:  &sizing,
		FailOver: !gwFailoverDisabled,
	}
	clientNetwork := clientInstance.Network
	network, err := clientNetwork.Create(def, temporal.GetExecutionTimeout())
	if err != nil {
		return err
	}
	logrus.Debugf("[cluster %s] network '%s' creation successful.", req.Name, networkName)
	req.NetworkID = network.Id

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := clientNetwork.Delete([]string{network.Id}, temporal.GetExecutionTimeout())
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Saving Cluster parameters, with status 'Creating'
	var (
		kp                               *resources.KeyPair
		kpName                           string
		primaryGateway, secondaryGateway *resources.Host
	)

	// Loads primary gateway metadata
	primaryGatewayMetadata, err := providermetadata.LoadHost(svc, network.GatewayId)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			if !ok {
				return err
			}
		}
		return err
	}
	primaryGateway, err = primaryGatewayMetadata.Get()
	if err != nil {
		return err
	}
	err = clientInstance.SSH.WaitReady(primaryGateway.ID, temporal.GetExecutionTimeout())
	if err != nil {
		return client.DecorateError(err, "wait for remote ssh service to be ready", false)
	}

	// Loads secondary gateway metadata
	if !gwFailoverDisabled {
		secondaryGatewayMetadata, err := providermetadata.LoadHost(svc, network.SecondaryGatewayId)
		if err != nil {
			if _, ok := err.(scerr.ErrNotFound); ok {
				if !ok {
					return err
				}
			}
			return err
		}
		secondaryGateway, err = secondaryGatewayMetadata.Get()
		if err != nil {
			return err
		}
		err = clientInstance.SSH.WaitReady(primaryGateway.ID, temporal.GetExecutionTimeout())
		if err != nil {
			return client.DecorateError(err, "wait for remote ssh service to be ready", false)
		}
	}

	// Create a KeyPair for the user cladm
	kpName = "cluster_" + req.Name + "_cladm_key"
	kp, err = svc.CreateKeyPair(kpName)
	if err != nil {
		return err
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
				// VPL: no public IP on VIP yet...
				// networkV2.EndpointIP = network.VirtualIp.PublicIp
				networkV2.EndpointIP = primaryGateway.GetPublicIP()
				networkV2.PrimaryPublicIP = primaryGateway.GetPublicIP()
				networkV2.SecondaryPublicIP = secondaryGateway.GetPublicIP()
			} else {
				networkV2.DefaultRouteIP = primaryGateway.GetPrivateIP()
				networkV2.EndpointIP = primaryGateway.GetPublicIP()
				networkV2.PrimaryPublicIP = networkV2.EndpointIP
			}
			return nil
		})
	})
	if err != nil {
		return err
	}

	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := b.cluster.DeleteMetadata(task)
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
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
	primaryGatewayTask, err := task.New()
	if err != nil {
		return err
	}
	primaryGatewayTask, err = primaryGatewayTask.Start(b.taskInstallGateway, srvutils.ToPBHost(primaryGateway))
	if err != nil {
		return err
	}
	if !gwFailoverDisabled {
		secondaryGatewayTask, err = task.New()
		if err != nil {
			return err
		}
		secondaryGatewayTask, err = secondaryGatewayTask.Start(b.taskInstallGateway, srvutils.ToPBHost(secondaryGateway))
		if err != nil {
			return err
		}
	}
	mastersTask, err := task.New()
	if err != nil {
		return err
	}
	mastersTask, err = mastersTask.Start(b.taskCreateMasters, data.Map{
		"count":     masterCount,
		"masterDef": mastersDef,
		"nokeep":    !req.KeepOnFailure,
	})
	if err != nil {
		return err
	}

	privateNodesTask, err := task.New()
	if err != nil {
		return err
	}
	privateNodesTask, err = privateNodesTask.Start(b.taskCreateNodes, data.Map{
		"count":   privateNodeCount,
		"public":  false,
		"nodeDef": nodesDef,
		"nokeep":  !req.KeepOnFailure,
	})
	if err != nil {
		return err
	}

	// FIXME What about cleanup ?, unit test Task class

	// Step 2: awaits gateway installation end and masters installation end
	_, primaryGatewayStatus = primaryGatewayTask.Wait()
	if primaryGatewayStatus != nil {
		mastersTask.Abort()
		privateNodesTask.Abort()
		return primaryGatewayStatus
	}
	if !gwFailoverDisabled {
		if secondaryGatewayTask != nil {
			_, secondaryGatewayStatus = secondaryGatewayTask.Wait()
			if secondaryGatewayStatus != nil {
				mastersTask.Abort()
				privateNodesTask.Abort()
				return secondaryGatewayStatus
			}
		}
	}

	// Starting from here, delete masters if exiting with error and req.KeepOnFailure is not true
	defer func() {
		if err != nil && !req.KeepOnFailure {
			derr := client.New().Host.Delete(b.cluster.ListMasterIDs(task), temporal.GetExecutionTimeout())
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()
	_, mastersStatus = mastersTask.Wait()
	if mastersStatus != nil {
		privateNodesTask.Abort()
		return mastersStatus
	}

	// Step 3: run (not start so no parallelism here) gateway configuration (needs MasterIPs so masters must be installed first)
	// Configure Gateway(s) and waits for the result
	primaryGatewayTask, err = task.New()
	if err != nil {
		return err
	}
	primaryGatewayTask, err = primaryGatewayTask.Start(b.taskConfigureGateway, srvutils.ToPBHost(primaryGateway))
	if err != nil {
		return err
	}
	if !gwFailoverDisabled {
		secondaryGatewayTask, err = task.New()
		if err != nil {
			return err
		}
		secondaryGatewayTask, err = secondaryGatewayTask.Start(b.taskConfigureGateway, srvutils.ToPBHost(secondaryGateway))
		if err != nil {
			return err
		}
	}
	_, primaryGatewayStatus = primaryGatewayTask.Wait()
	if primaryGatewayStatus != nil {
		if !gwFailoverDisabled {
			if secondaryGatewayTask != nil {
				secondaryGatewayTask.Abort()
			}
		}
		return primaryGatewayStatus
	}

	if !gwFailoverDisabled {
		if secondaryGatewayTask != nil {
			_, secondaryGatewayStatus = secondaryGatewayTask.Wait()
			if secondaryGatewayStatus != nil {
				return secondaryGatewayStatus
			}
		}
	}

	// Step 4: configure masters (if masters created successfully and gateway configure successfully)
	mt, err := task.New()
	if err != nil {
		return err
	}
	_, mastersStatus = mt.Run(b.taskConfigureMasters, nil)
	if mastersStatus != nil {
		return mastersStatus
	}

	// Starting from here, delete nodes on failure if exits with error and req.KeepOnFailure is false
	defer func() {
		if err != nil && !req.KeepOnFailure {
			clientHost := clientInstance.Host
			derr := clientHost.Delete(b.cluster.ListNodeIDs(task), temporal.GetExecutionTimeout())
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Step 5: awaits nodes creation
	_, privateNodesStatus = privateNodesTask.Wait()
	if privateNodesStatus != nil {
		return privateNodesStatus
	}

	// Step 6: Starts nodes configuration, if all masters and nodes
	// have been created and gateway has been configured with success
	pnt, privateNodesStatus := task.New()
	if privateNodesStatus != nil {
		return privateNodesStatus
	}
	_, privateNodesStatus = pnt.Run(b.taskConfigureNodes, nil)
	if privateNodesStatus != nil {
		return privateNodesStatus
	}

	// At the end, configure cluster as a whole
	err = b.configureCluster(task, data.Map{
		"PrimaryGateway":   primaryGateway,
		"SecondaryGateway": secondaryGateway,
	})
	if err != nil {
		return err
	}

	return nil
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
	pbHost, err := client.New().Host.Inspect(hostID, temporal.GetExecutionTimeout())
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
// params contains a data.Map with primary and secondary Gateway hosts
func (b *foreman) configureCluster(task concurrency.Task, params concurrency.TaskParameters) (err error) {
	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Infof("[cluster %s] configuring cluster...", b.cluster.Name)
	defer func() {
		if err == nil {
			logrus.Infof("[cluster %s] configuration successful.", b.cluster.Name)
		} else {
			logrus.Errorf("[cluster %s] configuration failed: %s", b.cluster.Name, err.Error())
		}
	}()

	err = b.createSwarm(task, params)
	if err != nil {
		return err
	}

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

// configureCluster configures cluster
func (b *foreman) createSwarm(task concurrency.Task, params concurrency.TaskParameters) (err error) {
	if params == nil {
		return scerr.InvalidParameterError("params", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		p                                = data.Map{}
		ok                               bool
		primaryGateway, secondaryGateway *resources.Host
	)
	if p, ok = params.(data.Map); !ok {
		return scerr.InvalidParameterError("params", "must be a data.Map")
	}
	if primaryGateway, ok = p["PrimaryGateway"].(*resources.Host); !ok || primaryGateway == nil {
		return scerr.InvalidParameterError("params", "key 'PrimaryGateway' must be defined and cannot be nil")
	}
	secondaryGateway, ok = p["SecondaryGateway"].(*resources.Host)
	if !ok {
		logrus.Debugf("secondary gateway not configured")
	}

	clientInstance := client.New()
	clientHost := clientInstance.Host
	clientSSH := clientInstance.SSH

	cluster := b.cluster

	// Join masters in Docker Swarm as managers
	joinCmd := ""
	for _, hostID := range cluster.ListMasterIDs(task) {
		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		if joinCmd == "" {
			retcode, _, _, err := clientSSH.Run(hostID, "docker swarm init && docker node update "+host.Name+" --label-add safescale.host.role=master",
				client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to init docker swarm")
			}
			retcode, token, stderr, err := clientSSH.Run(hostID, "docker swarm join-token manager -q", client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to generate token to join swarm as manager: %s", stderr)
			}
			token = strings.Trim(token, "\n")
			joinCmd = fmt.Sprintf("docker swarm join --token %s %s", token, host.PrivateIp)
		} else {
			masterJoinCmd := joinCmd + " && docker node update " + host.Name + " --label-add safescale.host.role=master"
			retcode, _, stderr, err := clientSSH.Run(hostID, masterJoinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil || retcode != 0 {
				return fmt.Errorf("failed to join host '%s' to swarm as manager: %s", host.Name, stderr)
			}
		}
	}

	selectedMasterID, err := b.Cluster().FindAvailableMaster(task)
	if err != nil {
		return fmt.Errorf("failed to find an available docker manager: %v", err)
	}
	selectedMaster, err := clientHost.Inspect(selectedMasterID, client.DefaultExecutionTimeout)
	if err != nil {
		return fmt.Errorf("failed to get metadata of docker manager: %s", err.Error())
	}

	// build command to join Docker Swarm as workers
	joinCmd, err = b.getSwarmJoinCommand(task, selectedMaster, true)
	if err != nil {
		return err
	}

	// Join private node in Docker Swarm as workers
	for _, hostID := range cluster.ListNodeIDs(task) {
		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		if err != nil {
			return fmt.Errorf("failed to get metadata of host: %s", err.Error())
		}
		retcode, _, stderr, err := clientSSH.Run(hostID, joinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", host.Name, stderr)
		}
		labelCmd := "docker node update " + host.Name + " --label-add safescale.host.role=node"
		retcode, _, stderr, err = clientSSH.Run(selectedMaster.Id, labelCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to label swarm worker '%s' as node: %s", host.Name, stderr)
		}
	}

	// Join gateways in Docker Swarm as workers
	retcode, _, stderr, err := clientSSH.Run(primaryGateway.ID, joinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", primaryGateway.Name, stderr)
	}
	labelCmd := "docker node update " + primaryGateway.Name + " --label-add safescale.host.role=gateway"
	retcode, _, stderr, err = clientSSH.Run(selectedMaster.Id, labelCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return fmt.Errorf("failed to label docker Swarm worker '%s' as gateway: %s", primaryGateway.Name, stderr)
	}

	if secondaryGateway != nil {
		retcode, _, stderr, err := clientSSH.Run(secondaryGateway.ID, joinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", primaryGateway.Name, stderr)
		}
		labelCmd := "docker node update " + secondaryGateway.Name + " --label-add safescale.host.role=gateway"
		retcode, _, stderr, err = clientSSH.Run(selectedMaster.Id, labelCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to label docker swarm worker '%s' as gateway: %s", secondaryGateway.Name, stderr)
		}
	}

	return nil
}

// getSwarmJoinCommand builds the command to obtain swarm token
func (b *foreman) getSwarmJoinCommand(task concurrency.Task, selectedMaster *pb.Host, worker bool) (string, error) {
	clientInstance := client.New()
	var memberType string
	if worker {
		memberType = "worker"
	} else {
		memberType = "manager"
	}
	tokenCmd := fmt.Sprintf("docker swarm join-token %s -q", memberType)
	retcode, token, stderr, err := clientInstance.SSH.Run(selectedMaster.Id, tokenCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil || retcode != 0 {
		return "", fmt.Errorf("failed to generate token to join swarm as worker: %s", stderr)
	}
	token = strings.Trim(token, "\n")
	return fmt.Sprintf("docker swarm join --token %s %s", token, selectedMaster.PrivateIp), nil
}

// uploadTemplateToFile uploads a template named 'tmplName' coming from rice 'box' in a file to a remote host
func uploadTemplateToFile(
	box *rice.Box, funcMap map[string]interface{}, tmplName string, data map[string]interface{},
	hostID string, fileName string,
) (string, error) {

	if box == nil {
		return "", scerr.InvalidParameterError("box", "cannot be nil!")
	}
	host, err := client.New().Host.Inspect(hostID, temporal.GetExecutionTimeout())
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
func (b *foreman) configureNodesFromList(task concurrency.Task, hosts []string) (err error) {
	tracer := concurrency.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		host   *pb.Host
		hostID string
		errs   []string
	)

	var subtasks []concurrency.Task
	clientHost := client.New().Host
	length := len(hosts)
	for i := 0; i < length; i++ {
		host, err = clientHost.Inspect(hosts[i], temporal.GetExecutionTimeout())
		if err != nil {
			break
		}
		subtask, err := task.New()
		if err != nil {
			break
		}
		subtask, err = subtask.Start(b.taskConfigureNode, data.Map{
			"index": i + 1,
			"host":  host,
		})
		if err != nil {
			break
		}
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	if err != nil {
		errs = append(errs, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf(strings.Join(errs, "\n"))
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

	logrus.Debugf("Joining nodes to cluster...")

	clientInstance := client.New()
	clientHost := clientInstance.Host
	clientSSH := clientInstance.SSH

	selectedMasterID, err := b.Cluster().FindAvailableMaster(task)
	if err != nil {
		return fmt.Errorf("failed to join workers to Docker Swarm: %v", err)
	}
	selectedMaster, err := clientHost.Inspect(selectedMasterID, client.DefaultExecutionTimeout)
	if err != nil {
		return fmt.Errorf("failed to get metadata of host: %s", err.Error())
	}
	joinCmd, err := b.getSwarmJoinCommand(task, selectedMaster, true)
	if err != nil {
		return err
	}

	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			return err
		}

		retcode, _, stderr, err := clientSSH.Run(pbHost.Id, joinCmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to join host '%s' to swarm as worker: %s", pbHost.Name, stderr)
		}
		nodeLabel := "docker node update " + pbHost.Name + " --label-add safescale.host.role=node"
		retcode, _, stderr, err = clientSSH.Run(selectedMaster.Id, nodeLabel, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
		if err != nil || retcode != 0 {
			return fmt.Errorf("failed to add label to docker Swarm worker '%s': %s", pbHost.Name, stderr)
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

	logrus.Debugf("Making Masters leaving cluster...")

	clientHost := client.New().Host
	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
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
	logrus.Debugf("Instructing nodes to leave cluster...")

	selectedMaster, err := b.Cluster().FindAvailableMaster(task)
	if err != nil {
		return err
	}

	clientHost := client.New().Host

	// Unjoins from cluster are done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			// If host seems deleted, consider leaving as a success
			if _, ok := err.(scerr.ErrNotFound); ok {
				continue
			}
			return err
		}

		if b.makers.LeaveNodeFromCluster != nil {
			err = b.makers.LeaveNodeFromCluster(task, b, pbHost, selectedMasterID)
			if err != nil {
				return err
			}
		}

		err = b.leaveNodeFromSwarm(task, pbHost, selectedMaster)
		if err != nil {
			return err
		}
	}

	return nil
}

func (b *foreman) leaveNodeFromSwarm(task concurrency.Task, pbHost *pb.Host, selectedMaster string) error {
	if selectedMaster == "" {
		var err error
		selectedMaster, err = b.Cluster().FindAvailableMaster(task)
		if err != nil {
			return err
		}
	}

	clientSSH := client.New().SSH

	// Check worker is member of the Swarm
	cmd := fmt.Sprintf("docker node ls --format \"{{.Hostname}}\" --filter \"name=%s\" | grep -i %s", pbHost.Name, pbHost.Name)
	retcode, _, _, err := clientSSH.Run(selectedMaster, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		// node is already expelled from Docker Swarm
		return nil
	}
	// node is a worker in the Swarm: 1st ask worker to leave Swarm
	cmd = "docker swarm leave"
	retcode, _, stderr, err := clientSSH.Run(pbHost.Id, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to make node '%s' leave swarm: %s", pbHost.Name, stderr)
	}

	// 2nd: wait the Swarm worker to appear as down from Swarm master
	cmd = fmt.Sprintf("docker node ls --format \"{{.Status}}\" --filter \"name=%s\" | grep -i down", pbHost.Name)
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			retcode, _, _, err := clientSSH.Run(selectedMaster, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fmt.Errorf("'%s' not in Down state", pbHost.Name)
			}
			return nil
		},
		temporal.GetHostTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fmt.Errorf("Swarm worker '%s' didn't reach 'Down' state after %v", pbHost.Name, temporal.GetHostTimeout())
		default:
			return fmt.Errorf("Swarm worker '%s' didn't reach 'Down' state: %v", pbHost.Name, retryErr)
		}
	}

	// 3rd, ask master to remove node from Swarm
	cmd = fmt.Sprintf("docker node rm %s", pbHost.Name)
	retcode, _, stderr, err = clientSSH.Run(selectedMaster, cmd, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("failed to remove worker '%s' from Swarm on master '%s': %s", pbHost.Name, selectedMaster, stderr)
	}
	return nil
}

// installNodeRequirements ...
func (b *foreman) installNodeRequirements(task concurrency.Task, nodeType NodeType.Enum, pbHost *pb.Host, hostLabel string) (err error) {
	if b.makers.GetTemplateBox == nil {
		return scerr.InvalidParameterError("b.makers.GetTemplateBox", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	netCfg, err := b.cluster.GetNetworkConfig(task)
	if err != nil {
		return err
	}

	// Get installation script based on node type; if == "", do nothing
	script, params := b.getNodeInstallationScript(task, nodeType)
	if script == "" {
		return nil
	}

	box, err := b.makers.GetTemplateBox()
	if err != nil {
		return err
	}

	globalSystemRequirements := ""
	if b.makers.GetGlobalSystemRequirements != nil {
		result, err := b.makers.GetGlobalSystemRequirements(task, b)
		if err != nil {
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
			return err
		}
		params["reserved_TenantJSON"] = string(jsoned)

		// Finds the folder where the current binary resides
		var (
			exe       string
			binaryDir string
			path      string
		)
		exe, _ = os.Executable()
		if exe != "" {
			binaryDir = filepath.Dir(exe)
		}

		// Uploads safescale binary
		if binaryDir != "" {
			path = binaryDir + "/safescale"
		}
		if path == "" {
			path, err = exec.LookPath("safescale")
			if err != nil {
				msg := "failed to find local binary 'safescale', make sure its path is in environment variable PATH"
				logrus.Errorf(utils.Capitalize(msg))
				return fmt.Errorf(msg)
			}
		}
		err = install.UploadFile(path, pbHost, "/opt/safescale/bin/safescale", "root", "root", "0755")
		if err != nil {
			logrus.Errorf("failed to upload 'safescale' binary")
			return fmt.Errorf("failed to upload 'safescale' binary': %s", err.Error())
		}

		// Uploads safescaled binary
		path = ""
		if binaryDir != "" {
			path = binaryDir + "/safescaled"
		}
		if path == "" {
			path, err = exec.LookPath("safescaled")
			if err != nil {
				msg := "failed to find local binary 'safescaled', make sure its path is in environment variable PATH"
				logrus.Errorf(utils.Capitalize(msg))
				return fmt.Errorf(msg)
			}
		}
		err = install.UploadFile(path, pbHost, "/opt/safescale/bin/safescaled", "root", "root", "0755")
		if err != nil {
			logrus.Errorf("failed to upload 'safescaled' binary")
			return fmt.Errorf("failed to upload 'safescaled' binary': %s", err.Error())
		}

		// Optionally propagate SAFESCALE_METADATA_SUFFIX env vars to master
		suffix := os.Getenv("SAFESCALE_METADATA_SUFFIX")
		if suffix != "" {
			cmdTmpl := "sudo sed -i '/^SAFESCALE_METADATA_SUFFIX=/{h;s/=.*/=%s/};${x;/^$/{s//SAFESCALE_METADATA_SUFFIX=%s/;H};x}' /etc/environment"
			cmd := fmt.Sprintf(cmdTmpl, suffix, suffix)
			retcode, stdout, stderr, err := client.New().SSH.Run(pbHost.Id, cmd, client.DefaultConnectionTimeout, 2*temporal.GetLongOperationTimeout())
			if err != nil {
				msg := fmt.Sprintf("failed to submit content of SAFESCALE_METADATA_SUFFIX to host '%s': %s", pbHost.Name, err.Error())
				logrus.Errorf(utils.Capitalize(msg))
				return fmt.Errorf(msg)
			}
			if retcode != 0 {
				output := stdout
				if output != "" && stderr != "" {
					output += "\n" + stderr
				} else if stderr != "" {
					output = stderr
				}
				msg := fmt.Sprintf("failed to copy content of SAFESCALE_METADATA_SUFFIX to host '%s': %s", pbHost.Name, output)
				logrus.Errorf(utils.Capitalize(msg))
				return fmt.Errorf(msg)
			}
		}
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
	params["DefaultRouteIP"] = netCfg.DefaultRouteIP
	params["EndpointIP"] = netCfg.EndpointIP

	retcode, _, _, err := b.ExecuteScript(box, funcMap, script, params, pbHost.Id)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fmt.Errorf("[%s] system requirements installation failed: retcode=%d", hostLabel, retcode)
	}

	logrus.Debugf("[%s] system requirements installation successful.", hostLabel)
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
func (b *foreman) taskInstallGateway(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	if t == nil {
		t, err = concurrency.VoidTask()
		if err != nil {
			return nil, err
		}
	}
	pbGateway, ok := params.(*pb.Host)
	if !ok {
		return result, scerr.InvalidParameterError("params", "must contain a *pb.Host")
	}
	if pbGateway == nil {
		return result, scerr.InvalidParameterError("params", "cannot be nil")
	}

	tracer := concurrency.NewTracer(t, "("+pbGateway.Name+")", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := pbGateway.Name
	logrus.Debugf("[%s] starting installation...", hostLabel)

	sshCfg, err := client.New().Host.SSHConfig(pbGateway.Id)
	if err != nil {
		return nil, err
	}
	_, err = sshCfg.WaitServerReady("ready", temporal.GetHostTimeout())
	if err != nil {
		return nil, err
	}

	// Installs docker and docker-compose on gateway
	err = b.installDocker(t, pbGateway, hostLabel)
	if err != nil {
		return nil, err
	}

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

	logrus.Debugf("[%s] preparation successful", hostLabel)
	return nil, nil
}

// taskConfigureGateway prepares one gateway
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureGateway(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// Convert parameters
	gw, ok := params.(*pb.Host)
	if !ok {
		return result, scerr.InvalidParameterError("params", "must contain a *pb.Host")
	}
	if gw == nil {
		return result, scerr.InvalidParameterError("params", "cannot be nil")
	}

	tracer := concurrency.NewTracer(t, "("+gw.Name+")", false).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Debugf("[%s] starting configuration...", gw.Name)

	if b.makers.ConfigureGateway != nil {
		err := b.makers.ConfigureGateway(t, b)
		if err != nil {
			return nil, err
		}
	}

	logrus.Debugf("[%s] configuration successful in [%s].", gw.Name, tracer.Stopwatch().String())
	return nil, nil
}

// taskCreateMasters creates masters
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateMasters(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// Convert parameters
	p := params.(data.Map)
	count := p["count"].(int)
	def := p["masterDef"].(*pb.HostDefinition)
	nokeep := p["nokeep"].(bool)

	tracer := concurrency.NewTracer(t, fmt.Sprintf("(%d, <*pb.HostDefinition>, %v)", count, nokeep), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	clusterName := b.cluster.GetIdentity(t).Name

	if count <= 0 {
		logrus.Debugf("[cluster %s] no masters to create.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] creating %d master%s...\n", clusterName, count, utils.Plural(count))

	var subtasks []concurrency.Task
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 0; i < count; i++ {
		subtask, err := t.New()
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(b.taskCreateMaster, data.Map{
			"index":     i + 1,
			"masterDef": def,
			"timeout":   timeout,
			"nokeep":    nokeep,
		})
		if err != nil {
			return nil, err
		}
		subtasks = append(subtasks, subtask)
	}
	var errs []string
	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "\n")
		return nil, fmt.Errorf("[cluster %s] failed to create master(s): %s", clusterName, msg)
	}

	logrus.Debugf("[cluster %s] masters creation successful.", clusterName)
	return nil, nil
}

// taskCreateMaster creates one master
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateMaster(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// Convert parameters
	p := params.(data.Map)
	index := p["index"].(int)
	def := p["masterDef"].(*pb.HostDefinition)
	timeout := p["timeout"].(time.Duration)
	nokeep := p["nokeep"].(bool)

	tracer := concurrency.NewTracer(t, fmt.Sprintf("(%d, <*pb.HostDefinition>, %s, %v)", index, temporal.FormatDuration(timeout), nokeep), true).GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := fmt.Sprintf("master #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, err := b.cluster.GetNetworkConfig(t)
	if err != nil {
		return nil, err
	}

	hostDef := *def
	hostDef.Name, err = b.buildHostname(t, "master", NodeType.Master)
	if err != nil {
		return nil, err
	}

	hostDef.Network = netCfg.NetworkID
	hostDef.Public = false
	clientHost := client.New().Host
	pbHost, err := clientHost.Create(hostDef, timeout)
	if pbHost != nil {
		// Updates cluster metadata to keep track of created host, before testing if an error occurred during the creation
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
		if mErr != nil && nokeep {
			derr := clientHost.Delete([]string{pbHost.Id}, temporal.GetLongOperationTimeout())
			if derr != nil {
				mErr = scerr.AddConsequence(mErr, derr)
			}
			return nil, mErr
		}
	}
	if err != nil {
		return nil, client.DecorateError(err, fmt.Sprintf("[%s] host resource creation failed: %s", hostLabel, err.Error()), false)
	}
	hostLabel = fmt.Sprintf("%s (%s)", hostLabel, pbHost.Name)
	logrus.Debugf("[%s] host resource creation successful", hostLabel)

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
	// 	logrus.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
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

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return nil, nil
}

// taskConfigureMasters configure masters
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureMasters(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(t, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	list := b.cluster.ListMasterIDs(t)
	if len(list) == 0 {
		return nil, nil
	}

	logrus.Debugf("[cluster %s] Configuring masters...", b.cluster.Name)
	started := time.Now()

	clientHost := client.New().Host
	var subtasks []concurrency.Task
	for i, hostID := range b.cluster.ListMasterIDs(t) {
		host, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			logrus.Warnf("failed to get metadata of host: %s", err.Error())
			continue
		}
		subtask, err := t.New()
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(b.taskConfigureMaster, data.Map{
			"index": i + 1,
			"host":  host,
		})
		if err != nil {
			return nil, err
		}
		subtasks = append(subtasks, subtask)
	}

	var errs []string
	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "\n"))
	}

	logrus.Debugf("[cluster %s] Masters configuration successful in [%s].", b.cluster.Name, temporal.FormatDuration(time.Since(started)))
	return nil, nil
}

// taskConfigureMaster configures one master
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureMaster(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// Convert params
	p := params.(data.Map)
	index := p["index"].(int)
	pbHost := p["host"].(*pb.Host)
	// FIXME: validate parameters

	tracer := concurrency.NewTracer(t, fmt.Sprintf("(%d, '%s')", index, pbHost.Name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	started := time.Now()

	hostLabel := fmt.Sprintf("master #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] starting configuration...\n", hostLabel)

	// install docker and docker-compose feature
	err = b.installDocker(t, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	err = b.configureMaster(t, index, pbHost)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
	return nil, nil
}

// taskCreateNodes creates nodes
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateNodes(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// Convert params
	p := params.(data.Map)
	count := p["count"].(int)
	public := p["public"].(bool)
	def := p["nodeDef"].(*pb.HostDefinition)
	nokeep := p["nokeep"].(bool)

	tracer := concurrency.NewTracer(t, fmt.Sprintf("(%d, %v)", count, public), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	clusterName := b.cluster.GetIdentity(t).Name

	if count <= 0 {
		logrus.Debugf("[cluster %s] no nodes to create.", clusterName)
		return nil, nil
	}
	logrus.Debugf("[cluster %s] creating %d node%s...", clusterName, count, utils.Plural(count))

	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	var subtasks []concurrency.Task
	for i := 1; i <= count; i++ {
		subtask, err := t.New()
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(b.taskCreateNode, data.Map{
			"index":   i,
			"type":    NodeType.Node,
			"nodeDef": def,
			"timeout": timeout,
			"nokeep":  nokeep,
		})
		if err != nil {
			return nil, err
		}
		subtasks = append(subtasks, subtask)
	}

	var errs []string
	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "\n"))
	}

	logrus.Debugf("[cluster %s] %d node%s creation successful.", clusterName, count, utils.Plural(count))
	return nil, nil
}

// taskCreateNode creates a Node in the Cluster
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateNode(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// Convert parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}
	if p == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}
	// FIME: validate parameters
	index := p["index"].(int)
	def := p["nodeDef"].(*pb.HostDefinition)
	timeout := p["timeout"].(time.Duration)
	nokeep := p["nokeep"].(bool)

	tracer := concurrency.NewTracer(t, fmt.Sprintf("(%d)", index), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := fmt.Sprintf("node #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, err := b.cluster.GetNetworkConfig(t)
	if err != nil {
		return nil, err
	}

	// Create the host
	hostDef := *def
	hostDef.Name, err = b.buildHostname(t, "node", NodeType.Node)
	if err != nil {
		return nil, err
	}
	hostDef.Network = netCfg.NetworkID
	if timeout < temporal.GetLongOperationTimeout() {
		timeout = temporal.GetLongOperationTimeout()
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
		if mErr != nil && nokeep {
			derr := clientHost.Delete([]string{pbHost.Id}, temporal.GetLongOperationTimeout())
			if derr != nil {
				mErr = scerr.AddConsequence(mErr, derr)
			}
			return nil, mErr
		}
	}
	if err != nil {
		return nil, client.DecorateError(err, fmt.Sprintf("[%s] creation failed: %s", hostLabel, err.Error()), true)
	}
	hostLabel = fmt.Sprintf("node #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] host resource creation successful.", hostLabel)

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
	// 	derr := clientHost.Delete([]string{pbHost.Id}, temporal.GetLongOperationTimeout())
	// 	if derr != nil {
	// 		logrus.Errorf("failed to delete node after failure")
	// 	}
	// 	logrus.Errorf("[%s] creation failed: %s", hostLabel, err.Error())
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

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return pbHost.Name, nil
}

// taskConfigureNodes configures nodes
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureNodes(t concurrency.Task, params concurrency.TaskParameters) (task concurrency.TaskResult, err error) {
	clusterName := b.cluster.GetIdentity(t).Name

	tracer := concurrency.NewTracer(t, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	list := b.cluster.ListNodeIDs(t)
	if len(list) == 0 {
		logrus.Debugf("[cluster %s] no nodes to configure.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] configuring nodes...", clusterName)

	var (
		pbHost *pb.Host
		i      int
		hostID string
		errs   []string
	)

	var subtasks []concurrency.Task
	clientHost := client.New().Host
	for i, hostID = range list {
		pbHost, err = clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			break
		}
		subtask, err := t.New()
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(b.taskConfigureNode, data.Map{
			"index": i + 1,
			"host":  pbHost,
		})
		if err != nil {
			return nil, err
		}
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	if err != nil {
		errs = append(errs, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		_, err := s.Wait()
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "\n"))
	}

	logrus.Debugf("[cluster %s] nodes configuration successful.", clusterName)
	return nil, nil
}

// taskConfigureNode configure one node
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureNode(t concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// Convert parameters
	p := params.(data.Map)
	index := p["index"].(int)
	pbHost := p["host"].(*pb.Host)

	tracer := concurrency.NewTracer(t, fmt.Sprintf("(%d, %s)", index, pbHost.Name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := fmt.Sprintf("node #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// Docker and docker-compose installation is mandatory on all nodes
	err = b.installDocker(t, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	// Now configures node specifically for cluster flavor
	err = b.configureNode(t, index, pbHost)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[%s] configuration successful.", hostLabel)
	return nil, nil
}

// Installs reverseproxy
func (b *foreman) installReverseProxy(task concurrency.Task) (err error) {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	disabled := false
	err = b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["remotedesktop"]
		if !disabled {
			_, disabled = v.(*clusterpropsv1.Features).Disabled["reverseproxy"]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !disabled {
		logrus.Debugf("[cluster %s] adding feature 'edgeproxy4network'", clusterName)
		feat, err := install.NewEmbeddedFeature(task, "edgeproxy4network")
		if err != nil {
			return err
		}
		target, err := install.NewClusterTarget(task, b.cluster)
		if err != nil {
			return err
		}
		results, err := feat.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
		}
		logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	}
	return nil
}

// installRemoteDesktop installs feature remotedesktop on all masters of the cluster
func (b *foreman) installRemoteDesktop(task concurrency.Task) (err error) {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	disabled := false
	err = b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["remotedesktop"]
		if !disabled {
			_, disabled = v.(*clusterpropsv1.Features).Disabled["reverseproxy"]
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !disabled {
		logrus.Debugf("[cluster %s] adding feature 'remotedesktop'", clusterName)

		adminPassword := identity.AdminPassword
		target, err := install.NewClusterTarget(task, b.cluster)
		if err != nil {
			return err
		}

		// Adds remotedesktop feature on master
		feat, err := install.NewEmbeddedFeature(task, "remotedesktop")
		if err != nil {
			return err
		}
		results, err := feat.Add(target, install.Variables{
			"Username": "cladm",
			"Password": adminPassword,
		}, install.Settings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
		}
		logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	}
	return nil
}

// install proxycache-client feature if not disabled
func (b *foreman) installProxyCacheClient(task concurrency.Task, pbHost *pb.Host, hostLabel string) (err error) {
	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	disabled := false
	b.cluster.RLock(task)
	err = b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["proxycache"]
		return nil
	})
	b.cluster.RUnlock(task)
	if err != nil {
		return err
	}
	if !disabled {
		feature, err := install.NewFeature(task, "proxycache-client")
		if err != nil {
			return err
		}
		target, err := install.NewHostTarget(pbHost)
		if err != nil {
			return err
		}
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[%s] failed to install feature 'proxycache-client': %s", hostLabel, msg)
		}
	}
	return nil
}

// install proxycache-server feature if not disabled
func (b *foreman) installProxyCacheServer(task concurrency.Task, pbHost *pb.Host, hostLabel string) (err error) {
	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	disabled := false
	b.cluster.RLock(task)
	err = b.cluster.GetProperties(task).LockForRead(Property.FeaturesV1).ThenUse(func(v interface{}) error {
		_, disabled = v.(*clusterpropsv1.Features).Disabled["proxycache"]
		return nil
	})
	b.cluster.RUnlock(task)
	if err != nil {
		return err
	}
	if !disabled {
		feat, err := install.NewEmbeddedFeature(task, "proxycache-server")
		if err != nil {
			return err
		}
		target, err := install.NewHostTarget(pbHost)
		if err != nil {
			return err
		}
		results, err := feat.Add(target, install.Variables{}, install.Settings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[%s] failed to install feature 'proxycache-server': %s", hostLabel, msg)
		}
	}
	return nil
}

// intallDocker installs docker and docker-compose
func (b *foreman) installDocker(task concurrency.Task, pbHost *pb.Host, hostLabel string) (err error) {
	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	feat, err := install.NewEmbeddedFeature(task, "docker")
	if err != nil {
		return err
	}
	target, err := install.NewHostTarget(pbHost)
	if err != nil {
		return err
	}
	results, err := feat.Add(target, install.Variables{}, install.Settings{})
	if err != nil {
		return err
	}
	if !results.Successful() {
		msg := results.AllErrorMessages()
		logrus.Errorf("[%s] failed to add feature 'docker': %s", hostLabel, msg)
		return fmt.Errorf("failed to add feature 'docker' on host '%s': %s", pbHost.Name, msg)
	}
	logrus.Debugf("[%s] feature 'docker' addition successful.", hostLabel)
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
