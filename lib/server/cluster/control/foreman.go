/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	txttmpl "text/template"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/errcontrol"

	rice "github.com/GeertJohan/go.rice"
	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster/api"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	clusterpropsv2 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v2"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/clusterstate"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/flavor"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/nodetype"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hostproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/abstract/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/install"
	providermetadata "github.com/CS-SI/SafeScale/lib/server/metadata"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
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
)

// Makers ...
type Makers struct {
	MinimumRequiredServers func(task concurrency.Task, b Foreman) (
		int, int, int,
	) // returns masterCount, privateNodeCount, publicNodeCount
	DefaultGatewaySizing      func(task concurrency.Task, b Foreman) *pb.HostDefinition // sizing of Gateway(s)
	DefaultMasterSizing       func(task concurrency.Task, b Foreman) *pb.HostDefinition // default sizing of master(s)
	DefaultNodeSizing         func(task concurrency.Task, b Foreman) *pb.HostDefinition // default sizing of node(s)
	DefaultImage              func(task concurrency.Task, b Foreman) string             // default image of server(s)
	GetNodeInstallationScript func(task concurrency.Task, b Foreman, nodeType nodetype.Enum) (
		string, map[string]interface{},
	)
	GetGlobalSystemRequirements func(task concurrency.Task, f Foreman) (string, error)
	GetTemplateBox              func() (*rice.Box, error)
	ConfigureGateway            func(task concurrency.Task, f Foreman) error
	CreateMaster                func(task concurrency.Task, f Foreman, index int) error
	ConfigureMaster             func(task concurrency.Task, f Foreman, index int, pbHost *pb.Host) error
	UnconfigureMaster           func(task concurrency.Task, f Foreman, pbHost *pb.Host) error
	CreateNode                  func(task concurrency.Task, f Foreman, index int, pbHost *pb.Host) error
	ConfigureNode               func(task concurrency.Task, f Foreman, index int, pbHost *pb.Host) error
	UnconfigureNode             func(task concurrency.Task, f Foreman, pbHost *pb.Host, selectedMasterID string) error
	ConfigureCluster            func(task concurrency.Task, f Foreman, req Request) error
	UnconfigureCluster          func(task concurrency.Task, f Foreman) error
	JoinMasterToCluster         func(task concurrency.Task, f Foreman, pbHost *pb.Host) error
	JoinNodeToCluster           func(task concurrency.Task, f Foreman, pbHost *pb.Host) error
	LeaveMasterFromCluster      func(task concurrency.Task, f Foreman, pbHost *pb.Host) error
	LeaveNodeFromCluster        func(task concurrency.Task, f Foreman, pbHost *pb.Host, selectedMaster string) error
	GetState                    func(task concurrency.Task, f Foreman) (clusterstate.Enum, error)
}

//go:generate mockgen -destination=../mocks/mock_foreman.go -package=mocks github.com/CS-SI/SafeScale/lib/server/cluster/control Foreman

// Foreman interface, exposes public method
type Foreman interface {
	Cluster() api.Cluster
	ExecuteScript(*rice.Box, map[string]interface{}, string, map[string]interface{}, string) (
		int, string, string, error,
	)
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

	tracer := debug.NewTracer(nil, "("+hostID+")", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Configures reserved_BashLibrary template var
	bashLibrary, err := system.GetBashLibrary()
	err = errcontrol.Crasher(err)
	if err != nil {
		return 0, "", "", err
	}

	data["reserved_BashLibrary"] = bashLibrary
	data["TemplateOperationDelay"] = uint(math.Ceil(2 * temporal.GetDefaultDelay().Seconds()))
	data["TemplateOperationTimeout"] = strings.Replace(
		(temporal.GetHostTimeout() / 2).Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["TemplateLongOperationTimeout"] = strings.Replace(
		temporal.GetHostTimeout().Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["TemplatePullImagesTimeout"] = strings.Replace(
		(2 * temporal.GetHostTimeout()).Truncate(time.Minute).String(), "0s", "", -1,
	)

	path, err := uploadTemplateToFile(box, funcMap, tmplName, data, hostID, tmplName)
	err = errcontrol.Crasher(err)
	if err != nil {
		return 0, "", "", err
	}

	var rc int
	var stout string
	var sterr string

	rounds := 3
	err = retry.WhileUnsuccessful(func() error {
		rounds = rounds -1
		if rounds < 0 {
			return fail.AbortedError("foreman failed 3 times", nil)
		}
		// cmd = fmt.Sprintf("sudo bash %s; rc=$?; if [[ rc -eq 0 ]]; then rm %s; fi; exit $rc", path, path)
		cmd := fmt.Sprintf("sudo bash %s", path)
		logrus.Debugf("foreman about to run '%s', iteration %d", cmd, rounds)

		// FIXME: ExecuteScript sometimes blocks 4 ever..., add a retry here and a pertinent timeout
		rc, stout, sterr, err = client.New().SSH.Run(
			hostID, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), 3*time.Minute,
		)
		if rc != 0 || err != nil {
			logrus.Warnf("Execute script: %s, rc=%d, err=%v, stdout='%s', stderr='%s'", cmd, rc, err, stout, sterr)
			return fmt.Errorf("failure")
		}

		return nil
	},temporal.GetDefaultDelay(), temporal.GetLongOperationTimeout())

	return rc, stout, sterr, err
}

// construct ...
func (b *foreman) construct(task concurrency.Task, req Request) (err error) {
	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Wants to inform about the duration of the operation
	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting construction of cluster '%s'", req.Name),
		fmt.Sprintf("Ending construction of cluster '%s'", req.Name),
	)()

	begin := time.Now()

	crashPlan := ""
	if crashPlanCandidate := os.Getenv("SAFESCALE_PLANNED_CRASHES"); crashPlanCandidate != "" {
		if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
			logrus.Warnf("Reloading crashplan: %s", crashPlanCandidate)
		}
		crashPlan = crashPlanCandidate
	}
	_ = errcontrol.CrashSetup(crashPlan)

	defer func() {
		_ = task.Abort()
	}()

	state := clusterstate.Unknown

	taskTrack := []*concurrency.Task{}
	cleanTrackedTasks := func() {
		if err != nil {
			for _, tp := range taskTrack {
				if tp != nil {
					theTask := *tp
					if !theTask.Aborted() {
						abortError := theTask.Abort()
						taskId, _ := theTask.GetID()
						if abortError != nil {
							logrus.Warnf("error aborting task '%s': %s", taskId, abortError)
						}
					}
				}
			}
		}
	}

	defer func() {
		if err != nil {
			state = clusterstate.Error
		} else {
			state = clusterstate.Nominal
		}

		if err == nil || req.KeepOnFailure {
			metaErr := b.cluster.UpdateMetadata(
				task, func() error {
					// Cluster created and configured successfully
					return b.cluster.GetProperties(task).LockForWrite(property.StateV1).ThenUse(
						func(clonable data.Clonable) error {
							clonable.(*clusterpropsv1.State).State = state
							return nil
						},
					)
				},
			)

			if metaErr != nil {
				err = fail.AddConsequence(err, metaErr)
			}
		}
	}()

	// Generate needed password for account cladm
	cladmPassword, err := utils.GeneratePassword(16)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error generating password: %w", err)
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
		imageID = "Ubuntu 18.04" // FIXME: Remove hardcoded default
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

	gatewaysDef := complementHostDefinition(
		req.GatewaysDef, gatewaysDefault,
	)

	if lower, err := gatewaysDef.LowerThan(gatewaysDefault); err == nil && lower {
		if !req.Force {
			return fail.Errorf(
				fmt.Sprintf(
					"requested gateway sizing %s less than recommended %s", spew.Sdump(gatewaysDef),
					spew.Sdump(gatewaysDefault),
				), nil,
			)
		}
	}

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
	mastersDef := complementHostDefinition(req.MastersDef, mastersDefault)

	if lower, err := mastersDef.LowerThan(mastersDefault); err == nil && lower {
		if !req.Force {
			return fail.Errorf("requested master sizing less than recommended", nil)
		}
	}

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
	nodesDef := complementHostDefinition(req.NodesDef, nodesDefault)

	if lower, err := nodesDef.LowerThan(nodesDefault); err == nil && lower {
		if !req.Force {
			return fail.Errorf("requested node sizing less than recommended", nil)
		}
	}

	// Initialize service to use
	clientInstance := client.New()
	tenant, err := clientInstance.Tenant.Get(temporal.GetExecutionTimeout())
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error getting tenant: %w", err)
	}
	svc, err := iaas.UseService(tenant.Name)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error using service: %w", err)
	}

	// Determine if Gateway Failover must be set
	caps := svc.GetCapabilities()
	gwFailoverDisabled := req.Complexity == complexity.Small || !caps.PrivateVirtualIP
	for k := range req.DisabledDefaultFeatures {
		if k == "gateway-failover" {
			gwFailoverDisabled = true
			break
		}
	}

	defer func() {
		niter := 0
		if err != nil && !req.KeepOnFailure {
			logrus.Debugf("Deleting network because of: %v", err)
			logrus.Debugf("Waiting %s for pending tasks...", temporal.GetHostCleanupTimeout())

			if time.Since(begin) > 60*time.Second {
				// if there are machines running we have a race condition...
				time.Sleep(temporal.GetHostCleanupTimeout()) // FIXME: Replace this by a WaitForAllSubtasksDone...
			} else {
				time.Sleep(60 * time.Second)
			}

			for {
				if niter == 2 {
					break
				}
				derr := b.wipe(task)
				derr = errcontrol.Crasher(derr)
				if derr != nil {
					err = fail.AddConsequence(err, derr)
				}
				pc, derr := b.cluster.service.GetConfigurationOptions()
				if derr != nil {
					err = fail.AddConsequence(err, derr)
				} else {
					if mbn, ok := pc.Get("MetadataBucketName"); ok {
						if mbns, ok := mbn.(string); ok {
							_ = client.New().Bucket.Prune([]string{mbns}, 2*time.Minute)
						}
					}
				}
				niter++
			}
		}
	}()

	// Creates network
	logrus.Debugf("[cluster %s] creating network 'net-%s'", req.Name, req.Name)
	req.Name = strings.ToLower(req.Name)
	networkName := "net-" + req.Name
	sizing := srvutils.FromPBHostDefinitionToPBGatewayDefinition(gatewaysDef)
	def := pb.NetworkDefinition{
		Name:          networkName,
		Cidr:          req.CIDR,
		Gateway:       sizing,
		FailOver:      !gwFailoverDisabled,
		Domain:        req.Domain,
		KeepOnFailure: req.KeepOnFailure,
	}
	clientNetwork := clientInstance.Network

	cancellableCtx := task.GetContext()
	network, err := clientNetwork.CreateWithCancel(cancellableCtx, &def, temporal.GetExecutionTimeout())
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error getting the network client: %w", err)
	}
	logrus.Debugf("[cluster %s] network '%s' creation successful.", req.Name, networkName)
	req.NetworkID = network.Id

	// Saving Cluster parameters, with status 'Creating'
	var (
		kp                               *abstract.KeyPair
		kpName                           string
		primaryGateway, secondaryGateway *abstract.Host
	)

	// Loads primary gateway metadata
	logrus.Debugf("[cluster %s] loading gateway metadata", req.Name)
	primaryGatewayMetadata, err := providermetadata.LoadHost(svc, network.GatewayId)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error loading primary gateway metadata: %w", err)
	}
	primaryGateway, err = primaryGatewayMetadata.Get()
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error getting primary gateway metadata: %w", err)
	}
	logrus.Debugf("[cluster %s] waiting for primary gateway ready through SSH", req.Name)
	err = clientInstance.SSH.WaitReady(primaryGateway.ID, temporal.GetExecutionTimeout())
	err = errcontrol.Crasher(err)
	if err != nil {
		return client.DecorateError(err, "wait for remote ssh service to be ready", false)
	}

	// Loads secondary gateway metadata
	if !gwFailoverDisabled {
		secondaryGatewayMetadata, err := providermetadata.LoadHost(svc, network.SecondaryGatewayId)
		err = errcontrol.Crasher(err)
		if err != nil {
			return fail.Wrapf("error loading secondary gateway metadata: %w", err)
		}
		secondaryGateway, err = secondaryGatewayMetadata.Get()
		err = errcontrol.Crasher(err)
		if err != nil {
			return fail.Wrapf("error getting secondary gateway metadata: %w", err)
		}
		err = clientInstance.SSH.WaitReady(primaryGateway.ID, temporal.GetExecutionTimeout())
		err = errcontrol.Crasher(err)
		if err != nil {
			return client.DecorateError(err, "wait for remote ssh service to be ready", false)
		}
	}

	// Create a KeyPair for the user cladm
	kpName = "cluster_" + req.Name + "_cladm_key"
	kp, err = abstract.NewKeyPair(kpName)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error creating keypair: %w", err)
	}

	defer func() {
		if err != nil && !req.KeepOnFailure {
			logrus.Debug("deleting keypair")
			derr := svc.DeleteKeyPair(kpName)
			derr = errcontrol.Crasher(derr)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
		}
	}()

	// Adding disabled features to cluster identity
	var disabledFeatures []string
	for k, _ := range req.DisabledDefaultFeatures {
		disabledFeatures = append(disabledFeatures, k)
	}

	// Saving Cluster metadata, with status 'Creating'
	b.cluster.Identity.Name = req.Name
	b.cluster.Identity.Flavor = req.Flavor
	b.cluster.Identity.Complexity = req.Complexity
	b.cluster.Identity.Keypair = kp
	b.cluster.Identity.AdminPassword = cladmPassword
	b.cluster.Identity.DisabledProperties = disabledFeatures

	defer func() {
		if err != nil {
			logrus.Warnf("Cleaning cluster metadata because of: %v", err)
		}
		if err != nil && !req.KeepOnFailure {
			derr := b.cluster.DeleteMetadata(task)
			derr = errcontrol.Crasher(derr)
			if derr != nil {
				err = fail.AddConsequence(err, derr)
			}
			if err != nil {
				logrus.Error(err)
			}
		}
	}()

	logrus.Debugf("[cluster %s] Updating cluster metadata", req.Name)
	err = b.cluster.UpdateMetadata(
		task, func() error {
			err := b.cluster.GetProperties(task).LockForWrite(property.DefaultsV2).ThenUse(
				func(clonable data.Clonable) error {
					defaultsV2 := clonable.(*clusterpropsv2.Defaults)
					var merr error
					defaultsV2.GatewaySizing, merr = srvutils.FromPBHostSizing(gatewaysDef.Sizing)
					if merr != nil {
						return merr
					}
					defaultsV2.MasterSizing, merr = srvutils.FromPBHostSizing(mastersDef.Sizing)
					if merr != nil {
						return merr
					}
					defaultsV2.NodeSizing, merr = srvutils.FromPBHostSizing(nodesDef.Sizing)
					if merr != nil {
						return merr
					}
					defaultsV2.Image = imageID
					return nil
				},
			)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}

			err = b.cluster.GetProperties(task).LockForWrite(property.StateV1).ThenUse(
				func(clonable data.Clonable) error {
					clonable.(*clusterpropsv1.State).State = clusterstate.Creating
					return nil
				},
			)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}

			err = b.cluster.GetProperties(task).LockForWrite(property.CompositeV1).ThenUse(
				func(clonable data.Clonable) error {
					clonable.(*clusterpropsv1.Composite).Tenants = []string{req.Tenant}
					return nil
				},
			)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}

			return b.cluster.GetProperties(task).LockForWrite(property.NetworkV2).ThenUse(
				func(clonable data.Clonable) error {
					networkV2 := clonable.(*clusterpropsv2.Network)
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
				},
			)
		},
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error updating cluster metadata: %w", err)
	}
	masterCount, privateNodeCount, _ := b.determineRequiredNodes(task)
	var (
		primaryGatewayErr       error
		secondaryGatewayCfgErr  error
		mastersErr              error
		privateNodesCreationErr error
		secondaryGatewayCfgTask concurrency.Task
	)

	// From now on, if there is an error, clean tasks we are about to create
	defer cleanTrackedTasks()

	// Step 1: starts gateway installation plus masters creation plus nodes creation
	primaryGatewayTask, err := task.NewWithContext(cancellableCtx)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error creating primary gateway task: %w", err)
	}
	pbPrimaryGateway, err := srvutils.ToPBHost(primaryGateway)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("protobuf error: %w", err)
	}

	logrus.Debugf("[cluster %s] Installing in primary gateway", req.Name)
	primaryGatewayTask, err = primaryGatewayTask.Start(b.taskInstallGateway, pbPrimaryGateway)
	taskTrack = append(taskTrack, &primaryGatewayTask)
	err = errcontrol.Crasher(err) // verified
	if err != nil {
		return fail.Wrapf("error creating primary gateway task: %w", err)
	}
	if !gwFailoverDisabled {
		secondaryGatewayCfgTask, err = task.NewWithContext(cancellableCtx)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		pbSecondaryGateway, err := srvutils.ToPBHost(secondaryGateway)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		secondaryGatewayCfgTask, err = secondaryGatewayCfgTask.Start(b.taskInstallGateway, pbSecondaryGateway)
		err = errcontrol.Crasher(err)
		if err != nil {
			defer func() {
				if pbSecondaryGateway != nil {
					derr := clientInstance.Host.Delete([]string{pbSecondaryGateway.Id}, temporal.GetLongOperationTimeout())
					derr = errcontrol.Crasher(derr)
					if derr != nil {
						err = fail.AddConsequence(err, derr)
					}
				}
			}()
			return err
		}
	}

	logrus.Debugf("[cluster %s] creating masters", req.Name)
	mastersTask, err := task.NewWithContext(cancellableCtx)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}
	mastersTask, err = mastersTask.Start(
		b.taskCreateMasters, data.Map{
			"count":     masterCount,
			"masterDef": mastersDef,
			"nokeep":    !req.KeepOnFailure,
		},
	)
	taskTrack = append(taskTrack, &mastersTask)
	err = errcontrol.Crasher(err) // validated
	if err != nil {
		return fail.Wrapf("error starting master creation task: %w", err)
	}

	logrus.Debugf("[cluster %s] creating nodes", req.Name)
	privateNodesCreationTask, err := task.NewWithContext(cancellableCtx)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error creating private nodes task: %w", err)
	}
	privateNodesCreationTask, err = privateNodesCreationTask.Start(
		b.taskCreateNodes, data.Map{
			"count":   privateNodeCount,
			"public":  false,
			"nodeDef": nodesDef,
			"nokeep":  !req.KeepOnFailure,
		},
	)
	taskTrack = append(taskTrack, &privateNodesCreationTask)
	err = errcontrol.Crasher(err) // validated
	if err != nil {
		return fail.Wrapf("error starting private nodes task: %w", err)
	}

	// Step 2: waits for gateway installation end and masters installation end
	logrus.Debugf("[cluster %s] waiting for primary gateway finishes its install", req.Name)
	_, primaryGatewayErr = primaryGatewayTask.Wait()
	primaryGatewayErr = errcontrol.Crasher(primaryGatewayErr) // validated
	if primaryGatewayErr != nil {
		return fail.Wrapf("error waiting for primary gateway task: %w", primaryGatewayErr)
	}
	logrus.Debugf("Primary gateway created")
	if !gwFailoverDisabled {
		if secondaryGatewayCfgTask != nil {
			_, secondaryGatewayCfgErr = secondaryGatewayCfgTask.Wait()
			secondaryGatewayCfgErr = errcontrol.Crasher(secondaryGatewayCfgErr) // FIXME: Test for wait error
			if secondaryGatewayCfgErr != nil {
				defer func() {
					if secondaryGateway != nil {
						derr := clientInstance.Host.Delete([]string{secondaryGateway.ID}, temporal.GetLongOperationTimeout())
						derr = errcontrol.Crasher(derr)
						if derr != nil {
							secondaryGatewayCfgErr = fail.AddConsequence(secondaryGatewayCfgErr, derr)
						}
					}
				}()
				return fail.Wrapf("error waiting for secondary gateway task: %w", secondaryGatewayCfgErr)
			}
		}
		logrus.Debugf("Secondary gateway created")
	}

	// waits the masters creation
	logrus.Debugf("Waiting for masters to be created...")
	_, mastersErr = mastersTask.Wait()
	mastersErr = errcontrol.Crasher(mastersErr) // FIXME: Test for wait error
	if mastersErr != nil {
		return fail.Wrapf("error waiting for masters task: %w", mastersErr)
	}
	logrus.Debugf("Masters created")

	// Step 3: start gateway(s) configuration (needs ClusterMasterIPs so masters must be installed first)
	// Configure Gateway(s) and waits for the result
	primaryGatewayTask, err = task.NewWithContext(cancellableCtx)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error creating new task: %w", err)
	}
	pbPrimaryGateway, err = srvutils.ToPBHost(primaryGateway)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error dealing with protobuf: %w", err)
	}

	logrus.Debugf("[cluster %s] configuring gateway", req.Name)
	primaryGatewayTask, err = primaryGatewayTask.Start(b.taskConfigureGateway, pbPrimaryGateway)
	taskTrack = append(taskTrack, &primaryGatewayTask)
	err = errcontrol.Crasher(err) // validated
	if err != nil {
		return fail.Wrapf("error starting primary gateway configuration task: %w", err)
	}
	if !gwFailoverDisabled {
		secondaryGatewayCfgTask, err = task.NewWithContext(cancellableCtx)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		pbSecondaryGateway, err := srvutils.ToPBHost(secondaryGateway)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		secondaryGatewayCfgTask, err = secondaryGatewayCfgTask.Start(b.taskConfigureGateway, pbSecondaryGateway)
		taskTrack = append(taskTrack, &secondaryGatewayCfgTask)
		err = errcontrol.Crasher(err)
		if err != nil {
			defer func() {
				if pbSecondaryGateway != nil {
					derr := clientInstance.Host.Delete([]string{pbSecondaryGateway.Id}, temporal.GetLongOperationTimeout())
					derr = errcontrol.Crasher(derr)
					if derr != nil {
						err = fail.AddConsequence(err, derr)
					}
				}
			}()
			return fail.Wrapf("error configuring secondary gateway: %w", err)
		}
	}

	logrus.Debugf("[cluster %s] waiting until gateway configuration is finished", req.Name)
	_, primaryGatewayErr = primaryGatewayTask.Wait()
	primaryGatewayErr = errcontrol.Crasher(primaryGatewayErr) // validated
	if primaryGatewayErr != nil {
		return fail.Wrapf("error creating primary gateway: %w", primaryGatewayErr)
	}
	logrus.Debugf("Primary gateway configured")
	if !gwFailoverDisabled {
		if secondaryGatewayCfgTask != nil {
			_, secondaryGatewayCfgErr = secondaryGatewayCfgTask.Wait()
			secondaryGatewayCfgErr = errcontrol.Crasher(secondaryGatewayCfgErr) // validated...
			if secondaryGatewayCfgErr != nil {
				defer func() {
					if secondaryGateway != nil {
						derr := clientInstance.Host.Delete([]string{secondaryGateway.ID}, temporal.GetLongOperationTimeout())
						derr = errcontrol.Crasher(derr)
						if derr != nil {
							secondaryGatewayCfgErr = fail.AddConsequence(secondaryGatewayCfgErr, derr)
						}
					}
				}()
				return fail.Wrapf("error creating secondary gateway: %w", secondaryGatewayCfgErr)
			}
		}
		logrus.Debugf("Secondary gateway configured")
	}

	// Step 4: configure masters
	logrus.Debugf("Configuring Masters...")
	mt, err := task.NewWithContext(cancellableCtx)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error creating master configuration task: %w", err)
	}
	_, mastersErr = mt.Run(b.taskConfigureMasters, nil)
	mastersErr = errcontrol.Crasher(mastersErr) // validated
	if mastersErr != nil {
		return fail.Wrapf("error configurating masters: %w", mastersErr)
	}
	logrus.Debugf("Masters configured")

	// Step 5: awaits nodes creation
	logrus.Debugf("[cluster %s] waiting until nodes are created", req.Name)
	_, privateNodesCreationErr = privateNodesCreationTask.Wait()
	privateNodesCreationErr = errcontrol.Crasher(privateNodesCreationErr) // validated
	if privateNodesCreationErr != nil {
		return fail.Wrapf("error creating private nodes: %w", privateNodesCreationErr)
	}

	// Step 6: Starts nodes configuration, if all masters and nodes
	// have been created and gateway has been configured with success
	logrus.Debugf("[cluster %s] configuring nodes", req.Name)
	pnt, privateNodesCfgErr := task.NewWithContext(cancellableCtx)
	privateNodesCfgErr = errcontrol.Crasher(privateNodesCfgErr)
	if privateNodesCfgErr != nil {
		return fail.Wrapf("error creating private nodes configuration task: %w", privateNodesCfgErr)
	}
	_, privateNodesCfgErr = pnt.Run(b.taskConfigureNodes, nil)
	privateNodesCfgErr = errcontrol.Crasher(privateNodesCfgErr) // metadata cleanup, +1 min
	if privateNodesCfgErr != nil {
		return fail.Wrapf("error in task configuring private nodes: %w", privateNodesCfgErr)
	}
	logrus.Debugf("Nodes configured")

	// At the end, configure cluster as a whole
	logrus.Debugf("Starting cluster configuration...")
	err = b.configureCluster(
		task, data.Map{
			"Request":          req,
			"PrimaryGateway":   primaryGateway,
			"SecondaryGateway": secondaryGateway,
		},
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("error configuring cluster: %w", err)
	}
	logrus.Debugf("Cluster configured")
	return nil
}

func (b *foreman) wipe(task concurrency.Task) (err error) {
	cluster := b.cluster

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	theCtx := task.GetContext()

	logrus.Debugf("wipe: updating metadata")

	// Updates metadata
	err = cluster.UpdateMetadata(
		task, func() error {
			return cluster.Properties.LockForWrite(property.StateV1).ThenUse(
				func(clonable data.Clonable) error {
					clonable.(*clusterpropsv1.State).State = clusterstate.Removed
					return nil
				},
			)
		},
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrap(err, "")
	}

	deleteMasterFunc := func(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
		funcErr := cluster.wipeMaster(task, params.(string))
		if funcErr != nil {
			return nil, fail.Wrap(funcErr, "")
		}
		return nil, nil
	}

	var cleaningErrors []error

	logrus.Debugf("wipe: listing node ids")

	// check if nodes and/or masters have volumes attached (which would forbid the deletion)
	nodeList := cluster.ListNodeIDs(task)
	nodeLength := len(nodeList)
	if nodeLength > 0 {
		logrus.Warnf("wipe: looking for attached volumes")
		if err := checkForAttachedVolumes(task, cluster, nodeList, "node"); err != nil {
			return err
		}
	}

	logrus.Debugf("[cluster %s] detected %d nodes ...", b.cluster.Name, nodeLength)

	masterList := cluster.ListMasterIDs(task)
	masterLength := len(masterList)
	if masterLength > 0 {
		if err := checkForAttachedVolumes(task, cluster, masterList, "master"); err != nil {
			return err
		}
	}

	logrus.Debugf("[cluster %s] detected %d masters ...", b.cluster.Name, masterLength)

	logrus.Debugf("[cluster %s] deleting nodes ...", b.cluster.Name)

	expectedMasters, expectedNodes, _ := b.determineRequiredNodes(task)

	// If no nodes, generate the names, look for its id, add it to nodeList
	if nodeLength != expectedNodes {
		num := expectedNodes
		for i := 1; i <= num; i++ {
			nodeList = append(nodeList, fmt.Sprintf("%s-node-%d", b.cluster.Name, i))
		}
		nodeLength = len(nodeList)
	}

	// No volumes attached, delete nodes
	if nodeLength > 0 {
		var subtasks []concurrency.Task
		for i := 0; i < nodeLength; i++ {
			subtask, err := task.NewWithContext(theCtx)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
			subtask, err = subtask.Start(b.taskWipeNode, nodeList[i])
			subtasks = append(subtasks, subtask)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
		}
		for _, s := range subtasks {
			_, _, subErr := s.WaitFor(3*time.Minute)
			subErr = errcontrol.Crasher(subErr) // FIXME: Test for wait error
			if subErr != nil {
				cleaningErrors = append(cleaningErrors, subErr)
			}
		}
	}

	logrus.Debugf("[cluster %s] deleting masters ...", b.cluster.Name)

	if masterLength != expectedMasters {
		num := expectedMasters
		for i := 1; i <= num; i++ {
			masterList = append(masterList, fmt.Sprintf("%s-master-%d", b.cluster.Name, i))
		}
		masterLength = len(masterList)
	}

	// delete the Masters
	if masterLength > 0 {
		var subtasks []concurrency.Task
		for i := 0; i < masterLength; i++ {
			subtask, err := task.NewWithContext(theCtx)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}

			subtask, err = subtask.Start(deleteMasterFunc, masterList[i])
			subtasks = append(subtasks, subtask)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
		}
		for _, s := range subtasks {
			_, _, subErr := s.WaitFor(3*time.Minute)
			subErr = errcontrol.Crasher(subErr) // FIXME: Test for wait error
			if subErr != nil {
				cleaningErrors = append(cleaningErrors, subErr)
			}
		}
	}

	// get access to metadata
	cluster.RLock(task)
	networkID := ""
	if cluster.Properties.Lookup(property.NetworkV2) {
		err = cluster.Properties.LockForRead(property.NetworkV2).ThenUse(
			func(clonable data.Clonable) error {
				networkID = clonable.(*clusterpropsv2.Network).NetworkID
				return nil
			},
		)
		err = errcontrol.Crasher(err)
	} else {
		err = cluster.Properties.LockForRead(property.NetworkV1).ThenUse(
			func(clonable data.Clonable) error {
				networkID = clonable.(*clusterpropsv1.Network).NetworkID
				return nil
			},
		)
		err = errcontrol.Crasher(err)
	}
	cluster.RUnlock(task)
	if err != nil {
		cleaningErrors = append(cleaningErrors, err)
		return fail.ErrListError(cleaningErrors)
	}

	logrus.Debugf("[cluster %s] deleting network ...", b.cluster.Name)

	// Deletes the network
	if networkID != "" {
		clientNetwork := client.New().Network
		retryErr := retry.WhileUnsuccessfulDelay5SecondsTimeout(
			func() error {
				netCleanErr := clientNetwork.Destroy([]string{networkID}, temporal.GetExecutionTimeout())
				if netCleanErr != nil {
					if nceArr, ok := netCleanErr.(fail.ErrList); ok {
						theErr := nceArr.Errors()
						if len(theErr) > 0 {
							if _, ok := theErr[0].(fail.ErrNotFound); ok {
								return fail.AbortedError("not found", netCleanErr)
							}
						}
					}
				}
				return netCleanErr
			},
			temporal.GetHostTimeout(),
		)
		if retryErr != nil {
			cleaningErrors = append(cleaningErrors, retryErr)
			return fail.ErrListError(cleaningErrors)
		}
	}

	logrus.Debugf("[cluster %s] deleting metadata ...", b.cluster.Name)

	// Deletes the metadata
	err = cluster.DeleteMetadata(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		cleaningErrors = append(cleaningErrors, err)
		return fail.ErrListError(cleaningErrors)
	}

	cluster.service = nil

	return fail.ErrListError(cleaningErrors)
}

// destruct destroys a cluster meticulously
func (b *foreman) destruct(task concurrency.Task) (err error) {
	cluster := b.cluster

	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	theCtx := task.GetContext()

	// Updates metadata
	err = cluster.UpdateMetadata(
		task, func() error {
			return cluster.Properties.LockForWrite(property.StateV1).ThenUse(
				func(clonable data.Clonable) error {
					clonable.(*clusterpropsv1.State).State = clusterstate.Removed
					return nil
				},
			)
		},
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrap(err, "")
	}

	// Unconfigure cluster
	if b.makers.UnconfigureCluster != nil {
		err = b.makers.UnconfigureCluster(task, b)
		err = errcontrol.Crasher(err)
		if err != nil {
			return fail.Wrap(err, "")
		}
	}

	deleteMasterFunc := func(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
		funcErr := cluster.deleteMaster(task, params.(string))
		if funcErr != nil {
			return nil, fail.Wrap(funcErr, "")
		}
		return nil, nil
	}

	var cleaningErrors []error

	// check if nodes and/or masters have volumes attached (which would forbid the deletion)
	nodeList := cluster.ListNodeIDs(task)
	nodeLength := len(nodeList)
	if nodeLength > 0 {
		if err := checkForAttachedVolumes(task, cluster, nodeList, "node"); err != nil {
			return err
		}
	}

	logrus.Debugf("[cluster %s] detected %d nodes ...", b.cluster.Name, nodeLength)

	masterList := cluster.ListMasterIDs(task)
	masterLength := len(masterList)
	if masterLength > 0 {
		if err := checkForAttachedVolumes(task, cluster, masterList, "master"); err != nil {
			return err
		}
	}

	logrus.Debugf("[cluster %s] detected %d masters ...", b.cluster.Name, masterLength)

	logrus.Debugf("[cluster %s] deleting nodes ...", b.cluster.Name)

	// No volumes attached, delete nodes
	if nodeLength > 0 {
		var subtasks []concurrency.Task
		for i := 0; i < nodeLength; i++ {
			subtask, err := task.NewWithContext(theCtx)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
			subtask, err = subtask.Start(b.taskDeleteNode, nodeList[i])
			subtasks = append(subtasks, subtask)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
		}
		for _, s := range subtasks {
			_, _, subErr := s.WaitFor(3*time.Minute)
			subErr = errcontrol.Crasher(subErr) // FIXME: Test for wait error
			if subErr != nil {
				cleaningErrors = append(cleaningErrors, subErr)
			}
		}
	}

	logrus.Debugf("[cluster %s] deleting masters ...", b.cluster.Name)

	// delete the Masters
	if masterLength > 0 {
		var subtasks []concurrency.Task
		for i := 0; i < masterLength; i++ {
			subtask, err := task.NewWithContext(theCtx)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}

			subtask, err = subtask.Start(deleteMasterFunc, masterList[i])
			subtasks = append(subtasks, subtask)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
		}
		for _, s := range subtasks {
			_, _, subErr := s.WaitFor(3*time.Minute)
			subErr = errcontrol.Crasher(subErr) // FIXME: Test for wait error
			if subErr != nil {
				cleaningErrors = append(cleaningErrors, subErr)
			}
		}
	}

	// get access to metadata
	cluster.RLock(task)
	networkID := ""
	if cluster.Properties.Lookup(property.NetworkV2) {
		err = cluster.Properties.LockForRead(property.NetworkV2).ThenUse(
			func(clonable data.Clonable) error {
				networkID = clonable.(*clusterpropsv2.Network).NetworkID
				return nil
			},
		)
		err = errcontrol.Crasher(err)
	} else {
		err = cluster.Properties.LockForRead(property.NetworkV1).ThenUse(
			func(clonable data.Clonable) error {
				networkID = clonable.(*clusterpropsv1.Network).NetworkID
				return nil
			},
		)
		err = errcontrol.Crasher(err)
	}
	cluster.RUnlock(task)
	if err != nil {
		cleaningErrors = append(cleaningErrors, err)
		return fail.ErrListError(cleaningErrors)
	}

	logrus.Debugf("[cluster %s] deleting network ...", b.cluster.Name)

	// Deletes the network
	clientNetwork := client.New().Network
	retryErr := retry.WhileUnsuccessfulDelay5SecondsTimeout(
		func() error {
			netCleanErr := clientNetwork.Destroy([]string{networkID}, temporal.GetExecutionTimeout())
			if netCleanErr != nil {
				if nceArr, ok := netCleanErr.(fail.ErrList); ok {
					theErr := nceArr.Errors()
					if len(theErr) > 0 {
						if _, ok := theErr[0].(fail.ErrNotFound); ok {
							return fail.AbortedError("not found", netCleanErr)
						}
					}
				}
			}
			return netCleanErr
		},
		temporal.GetHostTimeout(),
	)
	if retryErr != nil {
		cleaningErrors = append(cleaningErrors, retryErr)
		return fail.ErrListError(cleaningErrors)
	}

	logrus.Debugf("[cluster %s] deleting metadata ...", b.cluster.Name)

	// Deletes the metadata
	err = cluster.DeleteMetadata(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		cleaningErrors = append(cleaningErrors, err)
		return fail.ErrListError(cleaningErrors)
	}

	cluster.service = nil

	return fail.ErrListError(cleaningErrors)
}

func checkForAttachedVolumes(task concurrency.Task, cluster *Controller, list []string, what string) error {
	// Check first if there are volumes attached to nodes
	length := len(list)
	svc := cluster.GetService(task)

	for i := 0; i < length; i++ {
		// list may contains empty string ID, in case a node creation failed
		if list[i] == "" {
			continue
		}
		mh, err := providermetadata.LoadHost(svc, list[i])
		err = errcontrol.Crasher(err)
		if err != nil {
			switch err.(type) {
			case fail.ErrNotFound:
				continue
			default:
				return err
			}
		}
		host, err := mh.Get()
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		err = host.Properties.LockForRead(hostproperty.VolumesV1).ThenUse(
			func(clonable data.Clonable) error {
				nAttached := len(clonable.(*propsv1.HostVolumes).VolumesByID)
				if nAttached > 0 {
					return fail.Wrapf("host has %d volume%s attached", nAttached, utils.Plural(nAttached))
				}
				return nil
			},
		)
		err = errcontrol.Crasher(err)
		if err != nil {
			return fail.InvalidRequestError(
				fmt.Sprintf(
					"cannot delete %s '%s' because of attached volumes: %v", what, host.Name, err,
				),
			)
		}
	}
	return nil
}

func (b *foreman) taskDeleteNode(task concurrency.Task, params concurrency.TaskParameters) (
	concurrency.TaskResult, error,
) {
	funcErr := b.cluster.DeleteSpecificNode(task, params.(string), "")
	return nil, funcErr
}

func (b *foreman) taskWipeNode(task concurrency.Task, params concurrency.TaskParameters) (
	concurrency.TaskResult, error,
) {
	funcErr := b.cluster.WipeSpecificNode(task, params.(string), "")
	return nil, funcErr
}

// complementHostDefinition complements req with default values if needed
func complementHostDefinition(req *pb.HostDefinition, def *pb.HostDefinition) *pb.HostDefinition {
	if req == nil {
		return def
	}

	// finalDef := srvutils.ClonePBHostDefinition(req)
	finalDef := req.Clone()
	if finalDef.Sizing == nil {
		finalDef.Sizing = srvutils.ClonePBHostSizing(def.Sizing)
		return finalDef
	}

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
	return finalDef
}

// GetState returns "actively" (if active state is proposed by maker) the current state of the cluster
func (b *foreman) getState(task concurrency.Task) (clusterstate.Enum, error) {
	if b.makers.GetState != nil {
		return b.makers.GetState(task, b)
	}

	var stateV1 clusterstate.Enum
	err := b.cluster.GetProperties(task).LockForRead(property.StateV1).ThenUse(
		func(clonable data.Clonable) error {
			stateV1 = clonable.(*clusterpropsv1.State).State
			return nil
		},
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return clusterstate.Unknown, err
	}
	return stateV1, nil
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
	err = errcontrol.Crasher(err)
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
	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Debugf("[cluster %s] configuring cluster...", b.cluster.Name)
	defer func() {
		if err == nil {
			logrus.Debugf("[cluster %s] configuration successful.", b.cluster.Name)
		} else {
			logrus.Debugf("[cluster %s] configuration failed: %s", b.cluster.Name, err.Error())
		}
	}()

	var (
		p   data.Map
		ok  bool
		req Request
	)

	p, ok = params.(data.Map)
	if !ok {
		return fail.InvalidParameterError("params", "must be of type 'data.Map'")
	}
	req, ok = p["Request"].(Request)
	if !ok {
		return fail.InvalidParameterError("params[Request]", "missing or not of type 'Request'")
	}

	// Configure docker Swarm except if flavor is K8S (Kubernetes)
	if req.Flavor != flavor.K8S {
		err = b.createSwarm(task, params)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
	}

	// Installs ntp server feature on cluster (masters)
	err = b.installTimeServer(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	// Installs ntp client feature on cluster (anything but masters)
	err = b.installTimeClient(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	// Installs reverseproxy feature on cluster (gateways)
	if _, ok := req.DisabledDefaultFeatures["reverseproxy"]; !ok {
		err = b.installReverseProxy(task)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
	}

	// configure what has to be done cluster-wide
	if b.makers.ConfigureCluster != nil {
		err = b.makers.ConfigureCluster(task, b, req)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
	}

	// Installs ansible feature on cluster (all masters)
	if _, ok := req.DisabledDefaultFeatures["ansible"]; !ok {
		err = b.installAnsible(task)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
	}

	// Installs remotedesktop feature on cluster (all masters)
	if _, ok := req.DisabledDefaultFeatures["remotedesktop"]; !ok {
		err = b.installRemoteDesktop(task)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
	}
	return nil

}

func (b *foreman) determineRequiredNodes(task concurrency.Task) (int, int, int) {
	if b.makers.MinimumRequiredServers != nil {
		return b.makers.MinimumRequiredServers(task, b)
	}
	return 0, 0, 0
}

// createSwarm configures Swarm
func (b *foreman) createSwarm(task concurrency.Task, params concurrency.TaskParameters) (err error) {
	if params == nil {
		return fail.InvalidParameterError("params", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		p                                data.Map
		ok                               bool
		primaryGateway, secondaryGateway *abstract.Host
	)
	if p, ok = params.(data.Map); !ok {
		return fail.InvalidParameterError("params", "must be a data.Map")
	}
	if primaryGateway, ok = p["PrimaryGateway"].(*abstract.Host); !ok || primaryGateway == nil {
		return fail.InvalidParameterError("params[primaryGateway]", "must be a not-nil '*abstract.Host'")
	}
	secondaryGateway, ok = p["SecondaryGateway"].(*abstract.Host)
	if !ok || secondaryGateway == nil {
		logrus.Debugf("secondary gateway not configured")
	}

	clientInstance := client.New()
	clientHost := clientInstance.Host
	clientSSH := clientInstance.SSH

	cluster := b.cluster

	// Join masters in Docker Swarm as managers
	joinCmd := ""
	for _, hostID := range cluster.ListMasterIDs(task) {
		if task != nil && task.Aborted() {
			return fail.AbortedError("aborted by parent task", nil)
		}

		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		err = errcontrol.Crasher(err)
		if err != nil {
			return fail.Wrapf("failed to get metadata of host: %s", err.Error())
		}
		if joinCmd == "" {
			retcode, _, _, err := clientSSH.Run(
				hostID, "docker swarm init && docker node update "+host.Name+" --label-add safescale.host.role=master",
				outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
			)
			err = errcontrol.Crasher(err)
			if err != nil || retcode != 0 {
				return fail.Wrapf("failed to init docker swarm")
			}
			retcode, token, stderr, err := clientSSH.Run(
				hostID, "docker swarm join-token manager -q", outputs.COLLECT, client.DefaultConnectionTimeout,
				client.DefaultExecutionTimeout,
			)
			err = errcontrol.Crasher(err)
			if err != nil || retcode != 0 {
				return fail.Wrapf("failed to generate token to join swarm as manager: %s", stderr)
			}
			token = strings.Trim(token, "\n")
			joinCmd = fmt.Sprintf("docker swarm join --token %s %s", token, host.PrivateIp)
		} else {
			masterJoinCmd := joinCmd + " && docker node update " + host.Name + " --label-add safescale.host.role=master"
			retcode, _, stderr, err := clientSSH.Run(
				hostID, masterJoinCmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
			)
			err = errcontrol.Crasher(err)
			if err != nil || retcode != 0 {
				return fail.Wrapf("failed to join host '%s' to swarm as manager: %s", host.Name, stderr)
			}
		}
	}

	selectedMasterID, err := b.Cluster().FindAvailableMaster(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("failed to find an available docker manager: %v", err)
	}
	selectedMaster, err := clientHost.Inspect(selectedMasterID, client.DefaultExecutionTimeout)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("failed to get metadata of docker manager: %s", err.Error())
	}

	// build command to join Docker Swarm as workers
	joinCmd, err = b.getSwarmJoinCommand(task, selectedMaster, true)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	// Join private node in Docker Swarm as workers
	for _, hostID := range cluster.ListNodeIDs(task) {
		if task != nil && task.Aborted() {
			return fail.AbortedError("aborted by parent task", nil)
		}

		host, err := clientHost.Inspect(hostID, client.DefaultExecutionTimeout)
		err = errcontrol.Crasher(err)
		if err != nil {
			return fail.Wrapf("failed to get metadata of host: %s", err.Error())
		}
		retcode, _, stderr, err := clientSSH.Run(
			hostID, joinCmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
		)
		err = errcontrol.Crasher(err)
		if err != nil || retcode != 0 {
			return fail.Wrapf("failed to join host '%s' to swarm as worker: %s", host.Name, stderr)
		}
		labelCmd := "docker node update " + host.Name + " --label-add safescale.host.role=node"
		retcode, _, stderr, err = clientSSH.Run(
			selectedMaster.Id, labelCmd, outputs.COLLECT, client.DefaultConnectionTimeout,
			client.DefaultExecutionTimeout,
		)
		err = errcontrol.Crasher(err)
		if err != nil || retcode != 0 {
			return fail.Wrapf("failed to label swarm worker '%s' as node: %s", host.Name, stderr)
		}
	}

	// Join gateways in Docker Swarm as workers
	retcode, _, stderr, err := clientSSH.Run(
		primaryGateway.ID, joinCmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
	)
	err = errcontrol.Crasher(err)
	if err != nil || retcode != 0 {
		return fail.Wrapf("failed to join host '%s' to swarm as worker: %s", primaryGateway.Name, stderr)
	}
	labelCmd := "docker node update " + primaryGateway.Name + " --label-add safescale.host.role=gateway"
	retcode, _, stderr, err = clientSSH.Run(
		selectedMaster.Id, labelCmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
	)
	err = errcontrol.Crasher(err)
	if err != nil || retcode != 0 {
		return fail.Wrapf("failed to label docker Swarm worker '%s' as gateway: %s", primaryGateway.Name, stderr)
	}

	if secondaryGateway != nil {
		retcode, _, stderr, err := clientSSH.Run(
			secondaryGateway.ID, joinCmd, outputs.COLLECT, client.DefaultConnectionTimeout,
			client.DefaultExecutionTimeout,
		)
		err = errcontrol.Crasher(err)
		if err != nil || retcode != 0 {
			return fail.Wrapf("failed to join host '%s' to swarm as worker: %s", primaryGateway.Name, stderr)
		}
		labelCmd := "docker node update " + secondaryGateway.Name + " --label-add safescale.host.role=gateway"
		retcode, _, stderr, err = clientSSH.Run(
			selectedMaster.Id, labelCmd, outputs.COLLECT, client.DefaultConnectionTimeout,
			client.DefaultExecutionTimeout,
		)
		err = errcontrol.Crasher(err)
		if err != nil || retcode != 0 {
			return fail.Wrapf("failed to label docker swarm worker '%s' as gateway: %s", secondaryGateway.Name, stderr)
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
	retcode, token, stderr, err := clientInstance.SSH.Run(
		selectedMaster.Id, tokenCmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
	)
	err = errcontrol.Crasher(err)
	if err != nil || retcode != 0 {
		return "", fail.Wrapf("failed to generate token to join swarm as worker: %s", stderr)
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
		return "", fail.InvalidParameterError("box", "cannot be nil!")
	}
	host, err := client.New().Host.Inspect(hostID, temporal.GetExecutionTimeout())
	err = errcontrol.Crasher(err)
	if err != nil {
		return "", fail.Wrapf("failed to get host information: %s", err)
	}

	tmplString, err := box.String(tmplName)
	err = errcontrol.Crasher(err)
	if err != nil {
		return "", fail.Wrapf("failed to load template: %s", err.Error())
	}

	tmplCmd, err := template.Parse(fileName, tmplString, funcMap)
	err = errcontrol.Crasher(err)
	if err != nil {
		return "", fail.Wrapf("failed to parse template: %s", err.Error())
	}

	data["TemplateOperationDelay"] = uint(math.Ceil(2 * temporal.GetDefaultDelay().Seconds()))
	data["TemplateOperationTimeout"] = strings.Replace(
		(temporal.GetHostTimeout() / 2).Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["TemplateLongOperationTimeout"] = strings.Replace(
		temporal.GetHostTimeout().Truncate(time.Minute).String(), "0s", "", -1,
	)
	data["TemplatePullImagesTimeout"] = strings.Replace(
		(2 * temporal.GetHostTimeout()).Truncate(time.Minute).String(), "0s", "", -1,
	)

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Execute(dataBuffer, data)
	err = errcontrol.Crasher(err)
	if err != nil {
		return "", fail.Wrapf("failed to realize template: %s", err.Error())
	}
	cmd := dataBuffer.String()
	remotePath := utils.TempFolder + "/" + fileName

	err = install.UploadStringToRemoteFile(cmd, host, remotePath, "", "", "")
	err = errcontrol.Crasher(err)
	if err != nil {
		return "", err
	}
	return remotePath, nil
}

// configureNodesFromList configures nodes from a list
func (b *foreman) configureNodesFromList(task concurrency.Task, hosts []string) (err error) {
	tracer := debug.NewTracer(task, "", true).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		host   *pb.Host
		hostID string
		errs   []string
	)

	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	theCtx := task.GetContext()

	var subtasks []concurrency.Task
	clientHost := client.New().Host
	length := len(hosts)
	for i := 0; i < length; i++ {
		if task != nil && task.Aborted() {
			return fail.AbortedError("aborted by parent task", nil)
		}

		hostID = hosts[i]
		host, err = clientHost.Inspect(hosts[i], temporal.GetExecutionTimeout())
		err = errcontrol.Crasher(err)
		if err != nil {
			break
		}
		subtask, err := task.NewWithContext(theCtx)
		err = errcontrol.Crasher(err)
		if err != nil {
			break
		}
		subtask, err = subtask.Start(
			b.taskConfigureNode, data.Map{
				"index": i + 1,
				"host":  host,
			},
		)
		subtasks = append(subtasks, subtask)
		err = errcontrol.Crasher(err)
		if err != nil {
			break
		}
	}
	// Deals with the metadata read failure
	if err != nil {
		errs = append(errs, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		_, _, state := s.WaitFor(3*time.Minute)
		state = errcontrol.Crasher(state) // FIXME: Test for wait error
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		return fail.Wrapf(strings.Join(errs, "\n"))
	}
	return nil
}

// joinNodesFromList makes nodes from a list join the cluster
func (b *foreman) joinNodesFromList(task concurrency.Task, hosts []string) error {
	if b.makers.JoinNodeToCluster == nil {
		// configure what has to be done cluster-wide
		if b.makers.ConfigureCluster != nil {
			// FIXME: fill req.DisabledDefaultFeatures with information from (currently non-existent) cluster features metadata
			req := Request{}
			return b.makers.ConfigureCluster(task, b, req)
		}
	}

	logrus.Debugf("Joining nodes to cluster...")

	clientInstance := client.New()
	clientHost := clientInstance.Host
	clientSSH := clientInstance.SSH

	selectedMasterID, err := b.Cluster().FindAvailableMaster(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("failed to join workers to Docker Swarm: %v", err)
	}
	selectedMaster, err := clientHost.Inspect(selectedMasterID, client.DefaultExecutionTimeout)
	err = errcontrol.Crasher(err)
	if err != nil {
		return fail.Wrapf("failed to get metadata of host: %s", err.Error())
	}
	joinCmd, err := b.getSwarmJoinCommand(task, selectedMaster, true)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	// Joins to cluster is done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		if task != nil && task.Aborted() {
			return fail.AbortedError("aborted by parent task", nil)
		}

		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}

		retcode, _, stderr, err := clientSSH.Run(
			pbHost.Id, joinCmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
		)
		err = errcontrol.Crasher(err)
		if err != nil || retcode != 0 {
			return fail.Wrapf("failed to join host '%s' to swarm as worker: %s", pbHost.Name, stderr)
		}
		nodeLabel := "docker node update " + pbHost.Name + " --label-add safescale.host.role=node"
		retcode, _, stderr, err = clientSSH.Run(
			selectedMaster.Id, nodeLabel, outputs.COLLECT, client.DefaultConnectionTimeout,
			client.DefaultExecutionTimeout,
		)
		err = errcontrol.Crasher(err)
		if err != nil || retcode != 0 {
			return fail.Wrapf("failed to add label to docker Swarm worker '%s': %s", pbHost.Name, stderr)
		}

		if b.makers.JoinMasterToCluster != nil {
			err = b.makers.JoinNodeToCluster(task, b, pbHost)
			err = errcontrol.Crasher(err)
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
		if task != nil && task.Aborted() {
			return fail.AbortedError("aborted by parent task", nil)
		}

		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		err = b.makers.LeaveMasterFromCluster(task, b, pbHost)
		err = errcontrol.Crasher(err)
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
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	clientHost := client.New().Host

	// Unjoins from cluster are done sequentially, experience shows too many join at the same time
	// may fail (depending of the cluster Flavor)
	for _, hostID := range hosts {
		if task != nil && task.Aborted() {
			return fail.AbortedError("aborted by parent task", nil)
		}

		pbHost, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		err = errcontrol.Crasher(err)
		if err != nil {
			// If host seems deleted, consider leaving as a success
			if _, ok := err.(fail.ErrNotFound); ok {
				continue
			}
			return err
		}

		if b.makers.LeaveNodeFromCluster != nil {
			err = b.makers.LeaveNodeFromCluster(task, b, pbHost, selectedMasterID)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
		}

		if b.cluster.GetIdentity(task).Flavor != flavor.K8S {
			// Docker Swarm is always installed, even if the cluster type is not SWARM (for now, may evolve in the future)
			// So removing a Node implies removing also from Swarm
			err = b.leaveNodeFromSwarm(task, pbHost, selectedMaster)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (b *foreman) leaveNodeFromSwarm(task concurrency.Task, pbHost *pb.Host, selectedMaster string) error {
	if selectedMaster == "" {
		var err error
		selectedMaster, err = b.Cluster().FindAvailableMaster(task)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
	}

	clientSSH := client.New().SSH

	// Check worker is member of the Swarm
	cmd := fmt.Sprintf(
		"docker node ls --format \"{{.Hostname}}\" --filter \"name=%s\" | grep -i %s", pbHost.Name, pbHost.Name,
	)
	retcode, _, _, err := clientSSH.Run(
		selectedMaster, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}
	if retcode != 0 {
		// node is already expelled from Docker Swarm
		return nil
	}
	// node is a worker in the Swarm: 1st ask worker to leave Swarm
	cmd = "docker swarm leave"
	retcode, _, stderr, err := clientSSH.Run(
		pbHost.Id, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fail.Wrapf("failed to make node '%s' leave swarm: %s", pbHost.Name, stderr)
	}

	// 2nd: wait the Swarm worker to appear as down from Swarm master
	cmd = fmt.Sprintf("docker node ls --format \"{{.Status}}\" --filter \"name=%s\" | grep -i down", pbHost.Name)
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			retcode, _, _, err := clientSSH.Run(
				selectedMaster, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
			)
			err = errcontrol.Crasher(err)
			if err != nil {
				return err
			}
			if retcode != 0 {
				return fail.Wrapf("'%s' not in Down state", pbHost.Name)
			}
			return nil
		},
		temporal.GetHostTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case retry.ErrTimeout:
			return fail.Wrapf("worker '%s' didn't reach 'Down' state after %v", pbHost.Name, temporal.GetHostTimeout())
		default:
			return fail.Wrapf("worker '%s' didn't reach 'Down' state: %v", pbHost.Name, retryErr)
		}
	}

	// 3rd, ask master to remove node from Swarm
	cmd = fmt.Sprintf("docker node rm %s", pbHost.Name)
	retcode, _, stderr, err = clientSSH.Run(
		selectedMaster, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, client.DefaultExecutionTimeout,
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fail.Wrapf(
			"failed to remove worker '%s' from Swarm on master '%s': %s", pbHost.Name, selectedMaster, stderr,
		)
	}
	return nil
}

// installNodeRequirements ...
func (b *foreman) installNodeRequirements(
	task concurrency.Task, nodeType nodetype.Enum, pbHost *pb.Host, hostLabel string,
) (err error) {
	if b.makers.GetTemplateBox == nil {
		return fail.InvalidParameterError("b.makers.GetTemplateBox", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	netCfg, err := b.cluster.GetNetworkConfig(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	// Get installation script based on node type; if == "", do nothing
	script, params := b.getNodeInstallationScript(task, nodeType)
	if script == "" {
		return nil
	}

	box, err := b.makers.GetTemplateBox()
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	globalSystemRequirements := ""
	if b.makers.GetGlobalSystemRequirements != nil {
		result, err := b.makers.GetGlobalSystemRequirements(task, b)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		globalSystemRequirements = result
	}
	params["reserved_CommonRequirements"] = globalSystemRequirements

	if nodeType == nodetype.Master {
		tp := b.cluster.GetService(task).GetTenantParameters()
		content := map[string]interface{}{
			"tenants": []map[string]interface{}{
				tp,
			},
		}
		jsoned, err := json.MarshalIndent(content, "", "    ")
		err = errcontrol.Crasher(err)
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
			_, err := os.Stat(path)
			err = errcontrol.Crasher(err)
			if err != nil {
				path = ""
			}
		}
		if path == "" {
			path, err = exec.LookPath("safescale")
			err = errcontrol.Crasher(err)
			if err != nil {
				msg := "failed to find local binary 'safescale', make sure its path is in environment variable PATH"
				logrus.Errorf(utils.Capitalize(msg))
				return fail.Wrapf(msg)
			}
		}
		err = install.UploadFile(path, pbHost, utils.BinFolder+"/safescale", "root", "root", "0755")
		err = errcontrol.Crasher(err)
		if err != nil {
			logrus.Errorf("failed to upload 'safescale' binary")
			return fail.Wrapf("failed to upload 'safescale' binary': %s", err.Error())
		}

		// Uploads safescaled binary
		path = ""
		if binaryDir != "" {
			path = binaryDir + "/safescaled"
			_, err := os.Stat(path)
			err = errcontrol.Crasher(err)
			if err != nil {
				path = binaryDir + "../safescaled/safescaled"
				_, err := os.Stat(path)
				err = errcontrol.Crasher(err)
				if err != nil {
					path = ""
				}
			}
		}
		if path == "" {
			path, err = exec.LookPath("safescaled")
			err = errcontrol.Crasher(err)
			if err != nil {
				msg := "failed to find local binary 'safescaled', make sure its path is in environment variable PATH"
				logrus.Errorf(utils.Capitalize(msg))
				return fail.Wrapf(msg)
			}
		}
		err = install.UploadFile(path, pbHost, "/opt/safescale/bin/safescaled", "root", "root", "0755")
		err = errcontrol.Crasher(err)
		if err != nil {
			logrus.Errorf("failed to upload 'safescaled' binary")
			return fail.Wrapf("failed to upload 'safescaled' binary': %s", err.Error())
		}

		// Optionally propagate SAFESCALE_METADATA_SUFFIX env vars to master
		suffix := os.Getenv("SAFESCALE_METADATA_SUFFIX")
		if suffix != "" {
			cmdTmpl := "sudo bash -c 'echo SAFESCALE_METADATA_SUFFIX=%s >> /etc/environment'"
			cmd := fmt.Sprintf(cmdTmpl, suffix)
			retcode, stdout, stderr, err := client.New().SSH.Run(
				pbHost.Id, cmd, outputs.COLLECT, client.DefaultConnectionTimeout, 2*time.Minute,
			)
			err = errcontrol.Crasher(err)
			if err != nil {
				msg := fmt.Sprintf(
					"failed to submit content of SAFESCALE_METADATA_SUFFIX to host '%s': %s", pbHost.Name, err.Error(),
				)
				logrus.Errorf(utils.Capitalize(msg))
				return fail.Wrapf(msg)
			}
			if retcode != 0 {
				output := stdout
				if output != "" && stderr != "" {
					output += "\n" + stderr
				} else if stderr != "" {
					output = stderr
				}
				msg := fmt.Sprintf(
					"failed to copy content of SAFESCALE_METADATA_SUFFIX to host '%s': rc='%d', output='%s'", pbHost.Name, retcode, output,
				)
				logrus.Errorf(utils.Capitalize(msg))
				return fail.Wrapf(msg)
			}
		}
	}

	var dnsServers []string
	cfg, err := b.cluster.GetService(task).GetConfigurationOptions()
	err = errcontrol.Crasher(err)
	if err == nil {
		dnsServers = cfg.GetSliceOfStrings("DNSList")
	}
	identity := b.cluster.GetIdentity(task)
	params["ClusterName"] = identity.Name
	params["DNSServerIPs"] = dnsServers
	params["ClusterMasterNames"] = b.cluster.ListMasterNames(task)
	params["ClusterMasterIDs"] = b.cluster.ListMasterIDs(task)
	params["ClusterMasterIPs"] = b.cluster.ListMasterIPs(task)
	params["ClusterNodeNames"] = b.cluster.ListNodeNames(task)
	params["ClusterNodeIDs"] = b.cluster.ListNodeIDs(task)
	params["ClusterNodeIPs"] = b.cluster.ListNodeIPs(task)
	params["CladmPassword"] = identity.AdminPassword
	params["DefaultRouteIP"] = netCfg.DefaultRouteIP
	params["EndpointIP"] = netCfg.EndpointIP
	params["GatewayIP"] = netCfg.GatewayIP // legacy
	params["PrimaryGatewayIP"] = netCfg.GatewayIP
	if netCfg.SecondaryGatewayIP != "" {
		params["SecondaryGatewayIP"] = netCfg.SecondaryGatewayIP
	}
	retcode, outscr, _, err := b.ExecuteScript(box, funcMap, script, params, pbHost.Id)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}
	if retcode != 0 {
		return fail.Wrapf("[%s] system requirements installation failed: retcode=%d, output=%s", hostLabel, retcode, outscr)
	}

	logrus.Debugf("[%s] system requirements installation successful.", hostLabel)
	return nil
}

// getNodeInstallationScript ...
func (b *foreman) getNodeInstallationScript(task concurrency.Task, nodeType nodetype.Enum) (
	string, map[string]interface{},
) {
	if b.makers.GetNodeInstallationScript != nil {
		return b.makers.GetNodeInstallationScript(task, b, nodeType)
	}
	return "", map[string]interface{}{}
}

// taskInstallGateway installs necessary components on one gateway
// This function is intended to be call as a goroutine
func (b *foreman) taskInstallGateway(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	begins := time.Now()
	unfinished := install.StepResult{
		Iscompleted: false,
		Success:     false,
		Err:         fmt.Errorf("unfinished step taskInstallGateway"),
	}

	defer func() {
		logrus.Debugf("Exiting gateway install with: result %v and error %v after %s", result, err, time.Since(begins))
	}()

	if task == nil {
		logrus.Warnf("replacing task")
		task, err = concurrency.VoidTask()
		if err != nil {
			unfinished.Err = err
			return unfinished, err
		}
	}
	pbGateway, ok := params.(*pb.Host)
	if !ok {
		return unfinished, fail.InvalidParameterError("params", "must contain a *pb.Host")
	}
	if pbGateway == nil {
		return unfinished, fail.InvalidParameterError("params", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "("+pbGateway.Name+")", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := pbGateway.Name
	logrus.Debugf("[%s] starting installation...", hostLabel)

	sshCfg, err := client.New().Host.SSHConfig(pbGateway.Id)
	err = errcontrol.Crasher(err)
	if err != nil {
		unfinished.Err = err
		return unfinished, err
	}

	logrus.Debugf("[%s] waiting for SSH...", hostLabel)
	_, err = sshCfg.WaitServerReady(task, "ready", temporal.GetHostTimeout())
	err = errcontrol.Crasher(err)
	if err != nil {
		unfinished.Err = err
		return unfinished, err
	}

	// Installs docker and docker-compose on gateway
	logrus.Debugf("[%s] installing docker...", hostLabel)
	err = b.installDocker(task, pbGateway, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		unfinished.Err = err
		return unfinished, err
	}

	// Installs proxycache server on gateway (if not disabled)
	logrus.Debugf("[%s] installing proxy cache server...", hostLabel)
	err = b.installProxyCacheServer(task, pbGateway, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		unfinished.Err = err
		return unfinished, err
	}

	// Installs requirements as defined by cluster Flavor (if it exists)
	logrus.Debugf("[%s] installing node requirements...", hostLabel)
	err = b.installNodeRequirements(task, nodetype.Gateway, pbGateway, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		unfinished.Err = err
		return unfinished, err
	}

	logrus.Debugf("[%s] preparation successful", hostLabel)
	return install.StepResult{
		Iscompleted: true,
		Success:     true,
		Err:         nil,
	}, nil
}

// taskConfigureGateway prepares one gateway
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureGateway(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	// Convert parameters
	gw, ok := params.(*pb.Host)
	if !ok {
		return result, fail.InvalidParameterError("params", "must contain a *pb.Host")
	}
	if gw == nil {
		return result, fail.InvalidParameterError("params", "cannot be nil")
	}

	tracer := debug.NewTracer(task, "("+gw.Name+")", false).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Debugf("[%s] starting configuration...", gw.Name)

	if b.makers.ConfigureGateway != nil {
		err := b.makers.ConfigureGateway(task, b)
		err = errcontrol.Crasher(err) // validated
		if err != nil {
			return nil, fail.Wrapf("[%s] error configuring the gateway: %w", gw.Name, err)
		}
	}

	logrus.Debugf("[%s] configuration successful in [%s].", gw.Name, tracer.Stopwatch().String())
	return nil, nil
}

// taskCreateMasters creates masters
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateMasters(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	// Convert parameters
	p := params.(data.Map)
	count := p["count"].(int)
	def := p["masterDef"].(*pb.HostDefinition)
	nokeep := p["nokeep"].(bool)

	tracer := debug.NewTracer(
		task, fmt.Sprintf("(%d, <*pb.HostDefinition>, %v)", count, nokeep), true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	def.KeepOnFailure = !nokeep

	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	theCtx := task.GetContext()
	if theCtx == nil {
		return nil, fail.InvalidParameterError("task", "cannot have a nil context")
	}

	clusterName := b.cluster.GetIdentity(task).Name

	if count <= 0 {
		logrus.Debugf("[cluster %s] no masters to create.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] creating %d master%s...\n", clusterName, count, utils.Plural(count))

	if task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	var subtasks []concurrency.Task
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	for i := 0; i < count; i++ {
		subtask, err := task.NewWithContext(theCtx)
		err = errcontrol.Crasher(err)
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(
			b.taskCreateMaster, data.Map{
				"index":     i + 1,
				"masterDef": def,
				"timeout":   timeout,
				"nokeep":    nokeep,
			},
		)
		subtasks = append(subtasks, subtask)
		err = errcontrol.Crasher(err)
		if err != nil {
			return nil, err
		}
	}

	var errs []string

	stch := make(chan bool)

	go func() {
		for _, s := range subtasks {
			_, _, state := s.WaitFor(15*time.Minute)
			state = errcontrol.Crasher(state) // FIXME: Test for wait error
			if state != nil {
				errs = append(errs, state.Error())
			}
		}

		stch <- true
		return
	}()

	select {
	case <-stch:
		if len(errs) > 0 {
			msg := strings.Join(errs, "\n")
			return nil, fail.Wrapf("[cluster %s] failed to create master(s): %s", clusterName, msg)
		}
		logrus.Debugf("[cluster %s] masters creation successful.", clusterName)
		return nil, nil
	case <-task.GetContext().Done():
		return nil, fail.AbortedError("Already aborted by parent", task.GetContext().Err())
	}
}

// taskCreateMaster creates one master
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateMaster(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	// Convert parameters
	p := params.(data.Map)
	index := p["index"].(int)
	def := p["masterDef"].(*pb.HostDefinition)
	timeout := p["timeout"].(time.Duration)
	nokeep := p["nokeep"].(bool)

	tracer := debug.NewTracer(
		task, fmt.Sprintf("(%d, <*pb.HostDefinition>, %s, %v)", index, temporal.FormatDuration(timeout), nokeep), true,
	).GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	def.KeepOnFailure = !nokeep

	hostLabel := fmt.Sprintf("master #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, err := b.cluster.GetNetworkConfig(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	hostDef := def.Clone()
	hostDef.Name, err = b.buildHostname(task, "master", nodetype.Master)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	// Checks if a host named like the one we want to create already exists on provider side
	_, err = b.cluster.service.InspectHost(hostDef.Name)
	err = errcontrol.Crasher(err)
	if err == nil {
		return nil, fail.DuplicateError(fmt.Sprintf("there is already a host named '%s'", hostDef.Name))
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	hostDef.Network = netCfg.NetworkID
	hostDef.Public = false
	clientHost := client.New().Host

	cancellableCtx := task.GetContext()
	pbHost, err := clientHost.CreateWithCancel(cancellableCtx, hostDef, timeout)
	defer func() {
		if err != nil && nokeep {
			if pbHost != nil {
				derr := clientHost.Delete([]string{pbHost.Id}, temporal.GetLongOperationTimeout())
				derr = errcontrol.Crasher(derr)
				if derr != nil {
					err = fail.AddConsequence(err, derr)
				}
			}
		}
	}()

	if pbHost != nil {
		// Updates cluster metadata to keep track of created host, before testing if an error occurred during the creation
		mErr := b.cluster.UpdateMetadata(
			task, func() error {
				// Locks for write the NodesV1 extension...
				return b.cluster.GetProperties(task).LockForWrite(property.NodesV1).ThenUse(
					func(clonable data.Clonable) error {
						nodesV1 := clonable.(*clusterpropsv1.Nodes)
						// Update swarmCluster definition in Object Storage
						node := &clusterpropsv1.Node{
							ID:        pbHost.Id,
							Name:      pbHost.Name,
							PrivateIP: pbHost.PrivateIp,
							PublicIP:  pbHost.PublicIp,
						}
						nodesV1.Masters = append(nodesV1.Masters, node)
						return nil
					},
				)
			},
		)
		if mErr != nil && nokeep {
			return nil, mErr
		}
	}
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, client.DecorateError(
			err, fmt.Sprintf("[%s] host resource creation failed: %s", hostLabel, err.Error()), false,
		)
	}
	hostLabel = fmt.Sprintf("%s (%s)", hostLabel, pbHost.Name)
	logrus.Debugf("[%s] host resource creation successful", hostLabel)

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	err = b.installProxyCacheClient(task, pbHost, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	// Installs cluster-level system requirements...
	err = b.installNodeRequirements(task, nodetype.Master, pbHost, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return nil, nil
}

// taskConfigureMasters configure masters
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureMasters(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	list := b.cluster.ListMasterIDs(task)
	if len(list) == 0 {
		return nil, nil
	}

	logrus.Debugf("[cluster %s] Configuring masters...", b.cluster.Name)
	started := time.Now()

	theCtx := task.GetContext()

	clientHost := client.New().Host
	var subtasks []concurrency.Task
	for i, hostID := range b.cluster.ListMasterIDs(task) {
		if task != nil && task.Aborted() {
			return nil, fail.AbortedError("aborted by parent task", nil)
		}

		host, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		err = errcontrol.Crasher(err)
		if err != nil {
			logrus.Warnf("failed to get metadata of host: %s", err.Error())
			continue
		}
		subtask, err := task.NewWithContext(theCtx)
		err = errcontrol.Crasher(err)
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(
			b.taskConfigureMaster, data.Map{
				"index": i + 1,
				"host":  host,
			},
		)
		subtasks = append(subtasks, subtask)
		err = errcontrol.Crasher(err)
		if err != nil {
			return nil, err
		}
	}

	var errs []string
	for _, s := range subtasks {
		_, state := s.Wait()
		state = errcontrol.Crasher(state) // FIXME: Test for wait error
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		return nil, fail.Wrapf(strings.Join(errs, "\n"))
	}

	logrus.Debugf(
		"[cluster %s] Masters configuration successful in [%s].", b.cluster.Name,
		temporal.FormatDuration(time.Since(started)),
	)
	return nil, nil
}

// taskConfigureMaster configures one master
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureMaster(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	if b == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate params
	p := params.(data.Map)
	index := p["index"].(int)
	pbHost := p["host"].(*pb.Host)
	// FIXME: validate parameters

	tracer := debug.NewTracer(task, fmt.Sprintf("(%d, '%s')", index, pbHost.Name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	started := time.Now()

	hostLabel := fmt.Sprintf("master #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] starting configuration...\n", hostLabel)

	// install docker and docker-compose feature
	err = b.installDocker(task, pbHost, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	err = b.configureMaster(task, index, pbHost)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	logrus.Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
	return nil, nil
}

// taskCreateNodes creates nodes
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateNodes(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	if b == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate params
	p, ok := params.(data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}
	var (
		count  int
		public bool
		def    *pb.HostDefinition
		nokeep bool
	)
	if count, ok = p["count"].(int); !ok {
		return nil, fail.InvalidParameterError("params[count]", "is missing or not an integer")
	}
	if public, ok = p["public"].(bool); !ok {
		return nil, fail.InvalidParameterError("params[public]", "is missing or not a bool")
	}
	if def, ok = p["nodeDef"].(*pb.HostDefinition); !ok {
		return nil, fail.InvalidParameterError("params[nodeDef]", "is missing or not a *pb.HostDefinition")
	}
	if nokeep, ok = p["nokeep"].(bool); !ok {
		return nil, fail.InvalidParameterError("params[nokeep]", "is missing or not a bool")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%d, %v)", count, public), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	def.KeepOnFailure = !nokeep

	clusterName := b.cluster.GetIdentity(task).Name

	theCtx := task.GetContext()

	if count <= 0 {
		logrus.Debugf("[cluster %s] no nodes to create.", clusterName)
		return nil, nil
	}
	logrus.Debugf("[cluster %s] creating %d node%s...", clusterName, count, utils.Plural(count))

	if task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	var subtasks []concurrency.Task
	for i := 1; i <= count; i++ {
		if task.Aborted() {
			return nil, fail.AbortedError("aborted by parent task", nil)
		}

		subtask, err := task.NewWithContext(theCtx)
		err = errcontrol.Crasher(err)
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(
			b.taskCreateNode, data.Map{
				"index": i,
				"nodeDef": def,
				"timeout": timeout,
				"nokeep":  nokeep,
			},
		)
		subtasks = append(subtasks, subtask)
		err = errcontrol.Crasher(err)
		if err != nil {
			return nil, err
		}
	}

	defer func() {
		if err != nil {
			for _, s := range subtasks {
				if !s.Aborted() {
					abortedErr := s.Abort()
					if abortedErr != nil {
						logrus.Warnf("error aborting subtask: %v", abortedErr)
					}
				}
			}
		}
	}()

	if task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	var errs []string
	stch := make(chan bool)
	go func() {
		for _, s := range subtasks {
			_, state := s.Wait() // FIXME: Block risk
			state = errcontrol.Crasher(state) // FIXME: Test for wait error
			if state != nil {
				errs = append(errs, state.Error())
			}
		}
		stch <- true
		return
	}()

	select {
	case <-stch:
		if len(errs) != 0 {
			return nil, fail.Wrapf(strings.Join(errs, "\n"))
		}
		logrus.Debugf("[cluster %s] %d node%s creation successful.", clusterName, count, utils.Plural(count))
		return nil, nil
	case <-task.GetContext().Done():
		return nil, fail.AbortedError("aborted by parent task.", task.GetContext().Err())
	}
}

// taskCreateNode creates a Node in the Cluster
// This function is intended to be call as a goroutine
func (b *foreman) taskCreateNode(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	if b == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate params
	p, ok := params.(data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}
	var (
		index   int
		def     *pb.HostDefinition
		timeout time.Duration
		nokeep  bool
	)
	if index, ok = p["index"].(int); !ok {
		return nil, fail.InvalidParameterError("params[index]", "is missing or not an integer")
	}
	if def, ok = p["nodeDef"].(*pb.HostDefinition); !ok {
		return nil, fail.InvalidParameterError("params[nodeDef]", "is missing or not a *pb.HostDefinition")
	}
	if timeout, ok = p["timeout"].(time.Duration); !ok {
		return nil, fail.InvalidParameterError("params[timeout]", "is missing or not a time.Duration")
	}
	if nokeep, ok = p["nokeep"].(bool); !ok {
		return nil, fail.InvalidParameterError("params[nokeep]", "is missing or not a bool")
	}

	tracer := debug.NewTracer(task, fmt.Sprintf("(%d)", index), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	def.KeepOnFailure = !nokeep

	hostLabel := fmt.Sprintf("node #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, err := b.cluster.GetNetworkConfig(task)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	// Create the host
	// hostDef := srvutils.ClonePBHostDefinition(def)
	hostDef := def.Clone()
	hostDef.Name, err = b.buildHostname(task, "node", nodetype.Node)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}
	hostDef.Network = netCfg.NetworkID
	if timeout < temporal.GetLongOperationTimeout() {
		timeout = temporal.GetLongOperationTimeout()
	}

	// Checks if a host named like the one we want to create already exists on provider side
	_, err = b.cluster.service.InspectHost(hostDef.Name)
	err = errcontrol.Crasher(err)
	if err == nil {
		return nil, fail.DuplicateError(fmt.Sprintf("there is already a host named '%s'", hostDef.Name))
	}

	clientHost := client.New().Host
	var node *clusterpropsv1.Node

	cancellableCtx := task.GetContext()
	pbHost, err := clientHost.CreateWithCancel(cancellableCtx, hostDef, timeout)
	defer func() {
		if err != nil && nokeep {
			if pbHost != nil {
				derr := clientHost.Delete([]string{pbHost.Id}, temporal.GetLongOperationTimeout())
				derr = errcontrol.Crasher(derr)
				if derr != nil {
					err = fail.AddConsequence(err, derr)
				}
			}
		}
	}()
	if pbHost != nil {
		mErr := b.cluster.UpdateMetadata(
			task, func() error {
				// Locks for write the NodesV1 extension...
				return b.cluster.GetProperties(task).LockForWrite(property.NodesV1).ThenUse(
					func(clonable data.Clonable) error {
						nodesV1 := clonable.(*clusterpropsv1.Nodes)
						// Registers the new Agent in the swarmCluster struct
						node = &clusterpropsv1.Node{
							ID:        pbHost.Id,
							Name:      pbHost.Name,
							PrivateIP: pbHost.PrivateIp,
							PublicIP:  pbHost.PublicIp,
						}
						nodesV1.PrivateNodes = append(nodesV1.PrivateNodes, node)
						return nil
					},
				)
			},
		)
		if mErr != nil && nokeep {
			return nil, mErr
		}
		if mErr != nil {
			logrus.Warnf("error writing cluster metadata of '%s'", pbHost.Id)
		}
	}
	if err != nil {
		return nil, client.DecorateError(err, fmt.Sprintf("[%s] creation failed: %s", hostLabel, err.Error()), true)
	}
	hostLabel = fmt.Sprintf("node #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] host resource creation successful.", hostLabel)

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	err = b.installProxyCacheClient(task, pbHost, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		logrus.Debugf("[%s] failure installing proxy cache client", hostLabel)
		return nil, err
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	err = b.installNodeRequirements(task, nodetype.Node, pbHost, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		logrus.Debugf("[%s] failure installing node requirements", hostLabel)
		return nil, err
	}

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return pbHost.Id, nil
}

// taskConfigureNodes configures nodes
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureNodes(
	task concurrency.Task, params concurrency.TaskParameters,
) (_ concurrency.TaskResult, err error) {
	clusterName := b.cluster.GetIdentity(task).Name

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	list := b.cluster.ListNodeIDs(task)
	if len(list) == 0 {
		logrus.Debugf("[cluster %s] no nodes to configure.", clusterName)
		return nil, nil
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	logrus.Debugf("[cluster %s] configuring nodes...", clusterName)

	var (
		pbHost *pb.Host
		hostID string
		errs   []string
	)

	theCtx := task.GetContext()

	var subtasks []concurrency.Task
	clientHost := client.New().Host
	for i, aHost := range list {
		if task != nil && task.Aborted() {
			return nil, fail.AbortedError("aborted by parent task", nil)
		}

		hostID = aHost
		pbHost, err = clientHost.Inspect(aHost, temporal.GetExecutionTimeout())
		err = errcontrol.Crasher(err)
		if err != nil {
			break
		}
		subtask, err := task.NewWithContext(theCtx)
		err = errcontrol.Crasher(err)
		if err != nil {
			return nil, err
		}
		subtask, err = subtask.Start(
			b.taskConfigureNode, data.Map{
				"index": i + 1,
				"host":  pbHost,
			},
		)
		subtasks = append(subtasks, subtask)
		err = errcontrol.Crasher(err)
		if err != nil {
			return nil, err
		}
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	// Deals with the metadata read failure
	if err != nil {
		errs = append(errs, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		if task != nil && task.Aborted() {
			return nil, fail.AbortedError("aborted by parent task", nil)
		}

		_, err := s.Wait()
		err = errcontrol.Crasher(err)
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return nil, fail.Wrapf(strings.Join(errs, "\n"))
	}

	logrus.Debugf("[cluster %s] nodes configuration successful.", clusterName)
	return nil, nil
}

// taskConfigureNode configure one node
// This function is intended to be call as a goroutine
func (b *foreman) taskConfigureNode(
	task concurrency.Task, params concurrency.TaskParameters,
) (result concurrency.TaskResult, err error) {
	// Convert parameters
	p := params.(data.Map)
	index := p["index"].(int)
	pbHost := p["host"].(*pb.Host)

	tracer := debug.NewTracer(task, fmt.Sprintf("(%d, %s)", index, pbHost.Name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := fmt.Sprintf("node #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	// Docker and docker-compose installation is mandatory on all nodes
	err = b.installDocker(task, pbHost, hostLabel)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	// Now configures node specifically for cluster flavor
	err = b.configureNode(task, index, pbHost)
	err = errcontrol.Crasher(err)
	if err != nil {
		return nil, err
	}

	if task != nil && task.Aborted() {
		return nil, fail.AbortedError("aborted by parent task", nil)
	}

	logrus.Debugf("[%s] configuration successful.", hostLabel)
	return nil, nil
}

// Installs Time Server (NTP)
func (b *foreman) installTimeServer(task concurrency.Task) (err error) {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	logrus.Debugf("[cluster %s] adding feature 'ntpserver'", clusterName)
	feat, err := install.NewEmbeddedFeature(task, "ntpserver")
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	target, err := install.NewClusterTarget(task, b.cluster)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	results, err := feat.Add(target, install.Variables{}, install.Settings{})
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	if !results.Successful() {
		msg := results.AllErrorMessages()
		return fail.Wrapf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
	}
	logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	return nil
}

// Installs Time Client (NTP)
func (b *foreman) installTimeClient(task concurrency.Task) (err error) {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	logrus.Debugf("[cluster %s] adding feature 'ntpclient'", clusterName)
	feat, err := install.NewEmbeddedFeature(task, "ntpclient")
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	target, err := install.NewClusterTarget(task, b.cluster)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	var peers []string
	copy(b.Cluster().ListMasterIPs(task), peers)
	results, err := feat.Add(target, install.Variables{"Peers": peers}, install.Settings{})
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	if !results.Successful() {
		msg := results.AllErrorMessages()
		return fail.Wrapf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
	}
	logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	return nil
}

// Installs reverseproxy
func (b *foreman) installReverseProxy(task concurrency.Task) (err error) {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	logrus.Debugf("[cluster %s] adding feature 'edgeproxy4network'", clusterName)
	feat, err := install.NewEmbeddedFeature(task, "edgeproxy4network")
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	target, err := install.NewClusterTarget(task, b.cluster)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	results, err := feat.Add(target, install.Variables{}, install.Settings{})
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	if !results.Successful() {
		msg := results.AllErrorMessages()
		return fail.Wrapf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
	}
	logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	return nil
}

// installRemoteDesktop installs feature remotedesktop on all masters of the cluster
func (b *foreman) installRemoteDesktop(task concurrency.Task) (err error) {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Debugf("[cluster %s] adding feature 'remotedesktop'", clusterName)

	adminPassword := identity.AdminPassword
	target, err := install.NewClusterTarget(task, b.cluster)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	// Adds remotedesktop feature on master
	feat, err := install.NewEmbeddedFeature(task, "remotedesktop")
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	results, err := feat.Add(
		target, install.Variables{
			"Username": "cladm",
			"Password": adminPassword,
		}, install.Settings{},
	)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	if !results.Successful() {
		msg := results.AllErrorMessages()
		return fail.Wrapf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
	}
	logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	return nil
}

// installAnsible installs feature ansible on all masters of the cluster
func (b *foreman) installAnsible(task concurrency.Task) (err error) {
	identity := b.cluster.GetIdentity(task)
	clusterName := identity.Name

	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	logrus.Debugf("[cluster %s] adding feature 'ansible'", clusterName)

	target, err := install.NewClusterTarget(task, b.cluster)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	// Adds ansible
	feat, err := install.NewEmbeddedFeature(task, "ansible")
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	results, err := feat.Add(target, install.Variables{}, install.Settings{})
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	if !results.Successful() {
		msg := results.AllErrorMessages()
		return fail.Wrapf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
	}
	logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	return nil
}

// install proxycache-client feature if not disabled
func (b *foreman) installProxyCacheClient(task concurrency.Task, pbHost *pb.Host, hostLabel string) (err error) {
	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	disabled := false
	b.cluster.RLock(task)
	err = b.cluster.GetProperties(task).LockForRead(property.FeaturesV1).ThenUse(
		func(clonable data.Clonable) error {
			_, disabled = clonable.(*clusterpropsv1.Features).Disabled["proxycache"]
			return nil
		},
	)
	err = errcontrol.Crasher(err)
	b.cluster.RUnlock(task)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	if !disabled {
		feature, err := install.NewFeature(task, "proxycache-client")
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		target, err := install.NewHostTarget(pbHost)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		results, err := feature.Add(target, install.Variables{}, install.Settings{})
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fail.Wrapf("[%s] failed to install feature 'proxycache-client': %s", hostLabel, msg)
		}
	}
	return nil
}

// install proxycache-server feature if not disabled
func (b *foreman) installProxyCacheServer(task concurrency.Task, pbHost *pb.Host, hostLabel string) (err error) {
	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	disabled := false
	b.cluster.RLock(task)
	err = b.cluster.GetProperties(task).LockForRead(property.FeaturesV1).ThenUse(
		func(clonable data.Clonable) error {
			_, disabled = clonable.(*clusterpropsv1.Features).Disabled["proxycache"]
			return nil
		},
	)
	err = errcontrol.Crasher(err)
	b.cluster.RUnlock(task)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	if !disabled {
		feat, err := install.NewEmbeddedFeature(task, "proxycache-server")
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		target, err := install.NewHostTarget(pbHost)
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		results, err := feat.Add(target, install.Variables{}, install.Settings{})
		err = errcontrol.Crasher(err)
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fail.Wrapf("[%s] failed to install feature 'proxycache-server': %s", hostLabel, msg)
		}
	}
	return nil
}

// intallDocker installs docker and docker-compose
func (b *foreman) installDocker(task concurrency.Task, pbHost *pb.Host, hostLabel string) (err error) {
	tracer := debug.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)()

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	feat, err := install.NewFeature(task, "docker")
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	target, err := install.NewHostTarget(pbHost)
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	results, err := feat.Add(target, install.Variables{}, install.Settings{})
	err = errcontrol.Crasher(err)
	if err != nil {
		return err
	}

	if task != nil && task.Aborted() {
		return fail.AbortedError("aborted by parent task", nil)
	}

	if !results.Successful() {
		msg := results.AllErrorMessages()
		logrus.Errorf("[%s] failed to add feature 'docker': %s", hostLabel, msg)
		return fail.Wrapf("failed to add feature 'docker' on host '%s': %s", pbHost.Name, msg)
	}
	logrus.Debugf("[%s] feature 'docker' addition successful.", hostLabel)
	return nil
}

// buildHostname builds a unique hostname in the Cluster
func (b *foreman) buildHostname(task concurrency.Task, core string, nodeType nodetype.Enum) (string, error) {
	var (
		index int
	)

	// Locks for write the manager extension...
	b.cluster.Lock(task)
	outerErr := b.cluster.GetProperties(task).LockForWrite(property.NodesV1).ThenUse(
		func(clonable data.Clonable) error {
			nodesV1 := clonable.(*clusterpropsv1.Nodes)
			switch nodeType {
			case nodetype.Node:
				nodesV1.PrivateLastIndex++
				index = nodesV1.PrivateLastIndex
			case nodetype.Master:
				nodesV1.MasterLastIndex++
				index = nodesV1.MasterLastIndex
			}
			return nil
		},
	)
	b.cluster.Unlock(task)
	if outerErr != nil {
		return "", outerErr
	}
	return b.cluster.GetIdentity(task).Name + "-" + core + "-" + strconv.Itoa(index), nil
}
