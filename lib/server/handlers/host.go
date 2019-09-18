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

package handlers

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostProperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/IPVersion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/NetworkProperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
)

//go:generate mockgen -destination=../mocks/mock_hostapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers HostAPI

// TODO At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// HostAPI defines API to manipulate hosts
type HostAPI interface {
	Create(ctx context.Context, name string, net string, os string, public bool, sizingParam interface{}, force bool) (*resources.Host, error)
	List(ctx context.Context, all bool) ([]*resources.Host, error)
	ForceInspect(ctx context.Context, ref string) (*resources.Host, error)
	Inspect(ctx context.Context, ref string) (*resources.Host, error)
	Delete(ctx context.Context, ref string) error
	SSH(ctx context.Context, ref string) (*system.SSHConfig, error)
	Reboot(ctx context.Context, ref string) error
	Resize(ctx context.Context, name string, cpu int, ram float32, disk int, gpuNumber int, freq float32) (*resources.Host, error)
	Start(ctx context.Context, ref string) error
	Stop(ctx context.Context, ref string) error
}

// HostHandler host service
type HostHandler struct {
	service iaas.Service
}

// NewHostHandler ...
func NewHostHandler(svc iaas.Service) HostAPI {
	return &HostHandler{
		service: svc,
	}
}

// Start starts a host
func (handler *HostHandler) Start(ctx context.Context, ref string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::Start(%s) called", ref), &err, log.TraceLevel)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		return infraErrf(err, "Error getting ssh config of host '%s': loading host metadata", ref)
	}
	if mh == nil {
		return infraErr(fmt.Errorf("host '%s' not found", ref))
	}
	id := mh.Get().ID
	err = handler.service.StartHost(id)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound, resources.ErrTimeout, retry.ErrTimeout:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}

	err = handler.service.WaitHostState(id, HostState.STARTED, utils.GetHostTimeout())
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound, resources.ErrTimeout, retry.ErrTimeout:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}

	return err
}

// Stop stops a host
func (handler *HostHandler) Stop(ctx context.Context, ref string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::Stop(%s) called", ref), &err, log.TraceLevel)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		return infraErrf(err, "Error getting ssh config of host '%s': loading host metadata", ref)
	}
	if mh == nil {
		return infraErr(fmt.Errorf("host '%s' not found", ref))
	}
	id := mh.Get().ID
	err = handler.service.StopHost(id)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound, resources.ErrTimeout, retry.ErrTimeout:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}

	err = handler.service.WaitHostState(id, HostState.STOPPED, utils.GetHostTimeout())
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound, resources.ErrTimeout, retry.ErrTimeout:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}
	return err
}

// Reboot reboots a host
func (handler *HostHandler) Reboot(ctx context.Context, ref string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::Reboot(%s) called", ref), &err, log.TraceLevel)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		return infraErr(fmt.Errorf("failed to load metadata of host '%s': %v", ref, err))
	}
	if mh == nil {
		return infraErr(fmt.Errorf("host '%s' not found", ref))
	}
	id := mh.Get().ID
	err = handler.service.RebootHost(id)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound, resources.ErrTimeout, retry.ErrTimeout:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return handler.service.WaitHostState(id, HostState.STARTED, utils.GetHostTimeout())
		},
		utils.GetHostTimeout(),
	)
	if err != nil {
		switch err.(type) {
		case resources.ErrTimeout, retry.ErrTimeout:
			return infraErrf(err, "timeout waiting host '%s' to be rebooted", ref)
		case resources.ErrResourceNotFound:
			return infraErr(err)
		default:
			return infraErr(err)
		}
	}

	return nil
}

// Resize ...
func (handler *HostHandler) Resize(ctx context.Context, ref string, cpu int, ram float32, disk int, gpuNumber int, freq float32) (newHost *resources.Host, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::Resize(%s) called", ref), &err, log.TraceLevel)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		return nil, infraErrf(err, "failed to load host metadata")
	}
	if mh == nil {
		return nil, throwErrf("host '%s' not found", ref)
	}

	id := mh.Get().ID
	hostSizeRequest := resources.SizingRequirements{
		MinDiskSize: disk,
		MinRAMSize:  ram,
		MinCores:    cpu,
		MinFreq:     freq,
		MinGPU:      gpuNumber,
	}

	// TODO RESIZE 1st check new requirements vs old requirements
	host := mh.Get()
	host, err = handler.service.InspectHost(host)
	if err != nil {
		switch err.(type) {
		case resources.ErrTimeout, retry.ErrTimeout, resources.ErrResourceNotFound:
			return nil, infraErr(err)
		default:
			return nil, infraErr(err)
		}
	}

	if host.Properties.Lookup(HostProperty.SizingV1) {
		descent := false
		err = host.Properties.LockForRead(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
			nhs := v.(*propsv1.HostSizing)
			descent = descent || (hostSizeRequest.MinCores < nhs.RequestedSize.Cores)
			descent = descent || (hostSizeRequest.MinRAMSize < nhs.RequestedSize.RAMSize)
			descent = descent || (hostSizeRequest.MinGPU < nhs.RequestedSize.GPUNumber)
			descent = descent || (hostSizeRequest.MinFreq < nhs.RequestedSize.CPUFreq)
			descent = descent || (hostSizeRequest.MinDiskSize < nhs.RequestedSize.DiskSize)
			return nil
		})
		if err != nil {
			return nil, infraErrf(err, "Unable to parse host metadata '%s", ref)
		}
		if descent {
			log.Warn("Asking for less resources..., ain't gonna happen :(")
		}
	}

	newHost, err = handler.service.ResizeHost(id, hostSizeRequest)
	if err != nil {
		switch err.(type) {
		case resources.ErrTimeout, retry.ErrTimeout, resources.ErrResourceNotFound:
			return nil, infraErrf(err, "Error resizing host '%s'", ref)
		default:
			return nil, infraErrf(err, "Error resizing host '%s'", ref)
		}
	}
	if newHost == nil {
		return nil, throwErrf("Unknown error resizing host '%s'", ref)
	}

	return newHost, err
}

// Create creates a host
// func (handler *HostHandler) Create(
// 	ctx context.Context,
// 	name string, net string, cpu int, ram float32, disk int, los string, public bool, gpuNumber int, freq float32,
// 	force bool,
func (handler *HostHandler) Create(
	ctx context.Context,
	name string, net string, los string, public bool, sizingParam interface{}, force bool,
) (newHost *resources.Host, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::Create(%s) called", name), &err, log.TraceLevel)()

	if handler == nil {
		return nil, utils.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, utils.InvalidParameterError("ctx", "can't be nil")
	}
	if name == "" {
		return nil, utils.InvalidParameterError("name", "can't be empty string")
	}

	var (
		sizing       *resources.SizingRequirements
		templateName string
	)
	switch sizingParam.(type) {
	case *resources.SizingRequirements:
		sizing = sizingParam.(*resources.SizingRequirements)
	case string:
		templateName = sizingParam.(string)
	default:
		return nil, utils.InvalidParameterError("sizing", "must be *resources.SizingRequirements or string")
	}

	host, err := handler.service.GetHostByName(name)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound:
		case retry.ErrTimeout, resources.ErrTimeout:
			return nil, infraErrf(err, "failure creating host: failed to check if host resource name '%s' is already used: %v", name, err)
		default:
			return nil, infraErrf(err, "failure creating host: failed to check if host resource name '%s' is already used: %v", name, err)
		}
	} else {
		return nil, logicErr(fmt.Errorf("failed to create host '%s': name is already used", name))
	}

	var (
		networks       []*resources.Network
		defaultNetwork *resources.Network
		primaryGateway *resources.Host
		// secondaryGateway *resources.Host
		defaultRouteIP string
	)
	if net != "" && net != "net-safescale" {
		networkHandler := NewNetworkHandler(handler.service)
		defaultNetwork, err = networkHandler.Inspect(ctx, net)
		if err != nil {
			if _, ok := err.(resources.ErrResourceNotFound); ok {
				return nil, infraErr(err)
			}
			return nil, infraErrf(err, "failed to get network resource data: '%s'", net)
		}
		if defaultNetwork == nil {
			return nil, logicErr(fmt.Errorf("failed to find network '%s'", net))
		}
		networks = append(networks, defaultNetwork)

		mgw, err := metadata.LoadHost(handler.service, defaultNetwork.GatewayID)
		if err != nil {
			return nil, infraErr(err)
		}
		if mgw == nil {
			return nil, logicErr(fmt.Errorf("failed to find gateway of network '%s'", net))
		}
		primaryGateway = mgw.Get()
		if defaultNetwork.VIP != nil {
			defaultRouteIP = defaultNetwork.VIP.PrivateIP
		} else {
			defaultRouteIP = primaryGateway.GetPrivateIP()
		}
	} else {
		net, err := handler.getOrCreateDefaultNetwork()
		if err != nil {
			return nil, infraErr(err)
		}
		networks = append(networks, net)
	}

	var template *resources.HostTemplate
	if sizing != nil {
		templates, err := handler.service.SelectTemplatesBySize(*sizing, force)
		if err != nil {
			switch err.(type) {
			case resources.ErrResourceNotFound, retry.ErrTimeout, resources.ErrTimeout:
				return nil, infraErrf(err, "failed to find template corresponding to requested resources")
			default:
				return nil, infraErrf(err, "failed to find template corresponding to requested resources")
			}
		}
		if len(templates) > 0 {
			template = templates[0]
			msg := fmt.Sprintf("Selected host template: '%s' (%d core%s", template.Name, template.Cores, utils.Plural(template.Cores))
			if template.CPUFreq > 0 {
				msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
			}
			msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
			if template.GPUNumber > 0 {
				msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, utils.Plural(template.GPUNumber))
				if template.GPUType != "" {
					msg += fmt.Sprintf(" %s", template.GPUType)
				}
			}
			msg += ")"
			log.Infof(msg)
		} else {
			log.Errorf("failed to find template corresponding to requested resources")
			return nil, logicErrf(fmt.Errorf(""), "failed to find template corresponding to requested resources")
		}
	} else {
		template, err = handler.service.SelectTemplateByName(templateName)
		if err != nil {
			switch err.(type) {
			case resources.ErrResourceNotFound, retry.ErrTimeout, resources.ErrTimeout:
				return nil, err
			default:
				return nil, err
			}
		}
	}

	var img *resources.Image
	err = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			img, innerErr = handler.service.SearchImage(los)
			return innerErr
		},
		2*utils.GetDefaultDelay(),
	)
	if err != nil {
		defaultErr := infraErrf(err, "failed to find image to use on compute resource")
		switch err.(type) {
		case resources.ErrResourceNotFound, retry.ErrTimeout, resources.ErrTimeout:
			return nil, defaultErr
		default:
			return nil, defaultErr
		}
	}

	hostRequest := resources.HostRequest{
		ImageID:        img.ID,
		ResourceName:   name,
		TemplateID:     template.ID,
		PublicIP:       public,
		Networks:       networks,
		DefaultRouteIP: defaultRouteIP,
		DefaultGateway: primaryGateway,
	}

	var userData *userdata.Content
	host, userData, err = handler.service.CreateHost(hostRequest)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceInvalidRequest:
			return nil, infraErr(err)
		case resources.ErrResourceNotFound, retry.ErrTimeout, resources.ErrTimeout:
			return nil, infraErrf(err, "failed to create compute resource '%s'", hostRequest.ResourceName)
		default:
			return nil, infraErrf(err, "failed to create compute resource '%s'", hostRequest.ResourceName)
		}
	}
	defer func() {
		if err != nil {
			derr := handler.service.DeleteHost(host.ID)
			if derr != nil {
				switch derr.(type) {
				case resources.ErrResourceNotFound:
					log.Errorf("Failed to delete host '%s', resource not found: %v", host.Name, derr)
				case retry.ErrTimeout, resources.ErrTimeout:
					log.Errorf("Failed to delete host '%s', timeout: %v", host.Name, derr)
				default:
					log.Errorf("Failed to delete host '%s', other reason: %v", host.Name, derr)
				}
			}
		}
	}()

	// Updates property propsv1.HostSizing
	if host == nil {
		return nil, throwErrf("unexpected error creating host instance: host is nil !")
	}
	if host.Properties == nil {
		return nil, throwErrf("error populating host properties: host.Properties is nil !")
	}

	// Updates host metadata
	mh := metadata.NewHost(handler.service)
	err = mh.Carry(host).Write()
	if err != nil {
		return nil, infraErrf(err, "Metadata creation failed")
	}
	log.Infof("Compute resource created: '%s'", host.Name)

	// Starting from here, remove metadata if exiting with error
	defer func() {
		if err != nil {
			derr := mh.Delete()
			if derr != nil {
				log.Errorf("failed to remove host metadata after host creation failure")
			}
		}
	}()

	if sizing != nil {
		err = host.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
			hostSizingV1 := v.(*propsv1.HostSizing)
			hostSizingV1.Template = hostRequest.TemplateID
			hostSizingV1.RequestedSize = &propsv1.HostSize{
				Cores:     sizing.MinCores,
				RAMSize:   sizing.MinRAMSize,
				DiskSize:  sizing.MinDiskSize,
				GPUNumber: sizing.MinGPU,
				CPUFreq:   sizing.MinFreq,
			}
			return nil
		})
	} else {
		err = host.Properties.LockForWrite(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
			hostSizingV1 := v.(*propsv1.HostSizing)
			hostSizingV1.Template = hostRequest.TemplateID
			hostSizingV1.RequestedSize = &propsv1.HostSize{
				Cores:     template.Cores,
				RAMSize:   template.RAMSize,
				DiskSize:  template.DiskSize,
				GPUNumber: template.GPUNumber,
				CPUFreq:   template.CPUFreq,
			}
			return nil
		})
	}
	if err != nil {
		return nil, infraErr(err)
	}

	// Sets host extension DescriptionV1
	creator := ""
	hostname, _ := os.Hostname()
	if curUser, err := user.Current(); err == nil {
		creator := curUser.Username
		if hostname != "" {
			creator += "@" + hostname
		}
		if curUser.Name != "" {
			creator += " (" + curUser.Name + ")"
		}
	} else {
		creator = "unknown@" + hostname
	}
	err = host.Properties.LockForWrite(HostProperty.DescriptionV1).ThenUse(func(v interface{}) error {
		hostDescriptionV1 := v.(*propsv1.HostDescription)
		hostDescriptionV1.Created = time.Now()
		hostDescriptionV1.Creator = creator
		return nil
	})
	if err != nil {
		return nil, infraErr(err)
	}

	// Updates host property propsv1.HostNetwork
	var (
		defaultNetworkID string
		gatewayID        string
	)
	err = host.Properties.LockForWrite(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 := v.(*propsv1.HostNetwork)
		defaultNetworkID = hostNetworkV1.DefaultNetworkID // set earlier by handler.service.CreateHost()
		if !public {
			if len(networks) > 0 {
				mgw, err := metadata.LoadGateway(handler.service, defaultNetworkID)
				if err == nil {
					gatewayID = mgw.Get().ID
				}
			}
		}
		hostNetworkV1.DefaultGatewayID = gatewayID

		if net != "" {
			mn, err := metadata.LoadNetwork(handler.service, net)
			if err != nil {
				return err
			}
			network := mn.Get()
			hostNetworkV1.NetworksByID[network.ID] = network.Name
			hostNetworkV1.NetworksByName[network.Name] = network.ID
		}

		return nil
	})
	if err != nil {
		return nil, infraErr(err)
	}

	// Updates host metadata
	err = mh.Write()
	if err != nil {
		return nil, infraErrf(err, "Metadata creation failed")
	}

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	log.Infof("Waiting start of SSH service on remote host '%s' ...", host.Name)
	sshHandler := NewSSHHandler(handler.service)
	sshCfg, err := sshHandler.GetConfig(ctx, host.ID)
	if err != nil {
		return nil, infraErr(err)
	}

	_, err = sshCfg.WaitServerReady("phase1", utils.GetHostCreationTimeout()) // FIXME Force Initial SSH_TIMEOUT on phase1, see the code error
	if err != nil {
		derr := err
		err = nil
		if client.IsTimeoutError(derr) {
			return nil, infraErrf(derr, "timeout waiting host '%s' to become ready", host.Name)
		}

		if client.IsProvisioningError(derr) {
			log.Errorf("%+v", derr)
			return nil, fmt.Errorf("failed to provision host '%s', please check safescaled logs", host.Name)
		}

		return nil, infraErrf(derr, "failed to wait host '%s' to become ready", host.Name)
	}

	// Updates host link with networks
	for _, i := range networks {
		err = i.Properties.LockForWrite(NetworkProperty.HostsV1).ThenUse(func(v interface{}) error {
			networkHostsV1 := v.(*propsv1.NetworkHosts)
			networkHostsV1.ByName[host.Name] = host.ID
			networkHostsV1.ByID[host.ID] = host.Name
			return nil
		})
		if err != nil {
			log.Errorf(err.Error())
			continue
		}
		_, err = metadata.SaveNetwork(handler.service, i)
		if err != nil {
			log.Errorf(err.Error())
		}
	}

	// Executes userdata phase2 script to finalize host installation
	userDataPhase2, err := userData.Generate("phase2")
	if err != nil {
		return nil, err
	}

	filepath := srvutils.TempFolder + "/user_data.phase2.sh"
	err = install.UploadStringToRemoteFile(string(userDataPhase2), srvutils.ToPBHost(host), filepath, "", "", "")
	if err != nil {
		return nil, err
	}
	command := fmt.Sprintf("sudo bash %s; exit $?", filepath)
	// Executes the script on the remote host
	retcode, stdout, stderr, err := sshHandler.Run(ctx, host.Name, command)
	if err != nil {
		retrieveForensicsData(sshHandler, host)

		return nil, err
	}
	if retcode != 0 {
		// Setting err will trigger defers
		err = fmt.Errorf("failed to finalize host installation: stdout[%s], stderr[%s]", stdout, stderr)
		if client.IsProvisioningError(err) {
			log.Error(err)
		}

		retrieveForensicsData(sshHandler, host)

		return nil, err
	}

	// Reboot host
	command = "sudo systemctl reboot"
	retcode, _, stderr, err = sshHandler.Run(ctx, host.Name, command)
	if err != nil {
		return nil, err
	}

	// Wait like 2 min for the machine to reboot
	_, err = sshCfg.WaitServerReady("ready", utils.GetConnectSSHTimeout())
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, infraErrf(err, "Timeout creating host '%s'", host.Name)
		}

		if client.IsProvisioningError(err) {
			log.Errorf("%+v", err)
			return nil, fmt.Errorf("error creating host '%s', error provisioning the new host, please check safescaled logs", host.Name)
		}

		return nil, infraErr(err)
	}
	log.Infof("SSH service started on host '%s'.", host.Name)

	select {
	case <-ctx.Done():
		err = fmt.Errorf("host creation cancelled by safescale")
		log.Warn(err)
		return nil, err
	default:
	}

	return host, nil
}

func retrieveForensicsData(sshHandler *SSHHandler, host *resources.Host) {
	if sshHandler == nil || host == nil {
		return
	}
	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", host.Name)), 0777)
		dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", host.Name, "phase2"))
		_, _, _, _ = sshHandler.Copy(context.TODO(), host.Name+":/opt/safescale/var/tmp/user_data.phase2.sh", dumpName+"sh")
		_, _, _, _ = sshHandler.Copy(context.TODO(), host.Name+":/opt/safescale/var/log/user_data.phase2.log", dumpName+"log")
	}
}

// getOrCreateDefaultNetwork gets network resources.SingleHostNetworkName or create it if necessary
// We don't want metadata on this network, so we use directly provider api instead of services
func (handler *HostHandler) getOrCreateDefaultNetwork() (network *resources.Network, err error) {
	network, err = handler.service.GetNetworkByName(resources.SingleHostNetworkName)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceInvalidRequest, resources.ErrResourceNotFound, retry.ErrTimeout, resources.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}
	if network != nil {
		return network, nil
	}

	request := resources.NetworkRequest{
		Name:      resources.SingleHostNetworkName,
		IPVersion: IPVersion.IPv4,
		CIDR:      "10.0.0.0/8",
	}

	network, err = handler.service.CreateNetwork(request)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceInvalidRequest, resources.ErrResourceNotFound, retry.ErrTimeout, resources.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	if network == nil {
		return nil, fmt.Errorf("failure getting or creating default network")
	}

	return network, nil
}

// List returns the host list
func (handler *HostHandler) List(ctx context.Context, all bool) (hosts []*resources.Host, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::List(%v) called", all), &err, log.TraceLevel)()

	if all {
		return handler.service.ListHosts()
	}

	m := metadata.NewHost(handler.service)
	err = m.Browse(func(host *resources.Host) error {
		hosts = append(hosts, host)
		return nil
	})
	if err != nil {
		return hosts, infraErrf(err, "Error listing monitored hosts: browse")
	}
	return hosts, nil
}

// ForceInspect ...
// If not found, return (nil, err)
func (handler *HostHandler) ForceInspect(ctx context.Context, ref string) (host *resources.Host, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::ForceInspect(%s) called", ref), &err, log.TraceLevel)()

	host, err = handler.Inspect(ctx, ref)
	if err != nil {
		return nil, throwErr(err)
	}

	return host, nil
}

// Inspect returns the host identified by ref, ref can be the name or the id
// If not found, returns (nil, nil)
func (handler *HostHandler) Inspect(ctx context.Context, ref string) (host *resources.Host, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::Inspect(%s) called", ref), &err, log.TraceLevel)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return nil, resources.ResourceNotFoundError("host", ref)
		}
		return nil, throwErr(err)
	}

	host = mh.Get()
	host, err = handler.service.InspectHost(host)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceInvalidRequest, resources.ErrResourceNotFound, retry.ErrTimeout, resources.ErrTimeout:
			return nil, infraErr(err)
		default:
			return nil, infraErr(err)
		}
	}

	if host == nil {
		return nil, fmt.Errorf("failure inspecting host [%s]", ref)
	}

	return host, nil
}

// Delete deletes host referenced by ref
func (handler *HostHandler) Delete(ctx context.Context, ref string) (err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::Delete(%s) called", ref), &err, log.TraceLevel)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return resources.ResourceNotFoundError("host", ref)
		}
		return infraErrf(err, "can't delete host '%s'", ref)
	}

	host := mh.Get()
	// Don't remove a host having shares that are currently remotely mounted
	var shares map[string]*propsv1.HostShare
	err = host.Properties.LockForRead(HostProperty.SharesV1).ThenUse(func(v interface{}) error {
		shares = v.(*propsv1.HostShares).ByID
		for _, share := range shares {
			count := len(share.ClientsByID)
			if count > 0 {
				count = len(shares)
				return logicErr(fmt.Errorf("can't delete host, exports %d share%s where at least one is used", count, utils.Plural(count)))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Don't remove a host with volumes attached
	err = host.Properties.LockForRead(HostProperty.VolumesV1).ThenUse(func(v interface{}) error {
		nAttached := len(v.(*propsv1.HostVolumes).VolumesByID)
		if nAttached > 0 {
			return logicErr(fmt.Errorf("host has %d volume%s attached", nAttached, utils.Plural(nAttached)))
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Don't remove a host that is a gateway
	err = host.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		if v.(*propsv1.HostNetwork).IsGateway {
			return logicErr(fmt.Errorf("can't delete host, it's a gateway that can only be deleted through its network"))
		}
		return nil
	})
	if err != nil {
		return err
	}

	// If host mounted shares, unmounts them before anything else
	shareHandler := NewShareHandler(handler.service)
	var mounts []*propsv1.HostShare
	err = host.Properties.LockForRead(HostProperty.MountsV1).ThenUse(func(v interface{}) error {
		hostMountsV1 := v.(*propsv1.HostMounts)
		for _, i := range hostMountsV1.RemoteMountsByPath {
			// Gets share data
			_, share, _, err := shareHandler.Inspect(ctx, i.ShareID)
			if err != nil {
				return infraErr(err)
			}
			if share == nil {
				return resources.ResourceNotFoundError("share", i.ShareID)
			}
			mounts = append(mounts, share)
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Unmounts tier shares mounted on host (done outside the previous host.Properties.Reading() section, because
	// Unmount() have to lock for write, and won't succeed while host.Properties.Reading() is running,
	// leading to a deadlock)
	for _, share := range mounts {
		err = shareHandler.Unmount(ctx, share.Name, host.Name)
		if err != nil {
			return infraErr(err)
		}
	}

	// if host exports shares, delete them
	for _, share := range shares {
		err = shareHandler.Delete(ctx, share.Name)
		if err != nil {
			return throwErr(err)
		}
	}

	// Update networks property prosv1.NetworkHosts to remove the reference to the host
	netHandler := NewNetworkHandler(handler.service)
	err = host.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
		hostNetworkV1 := v.(*propsv1.HostNetwork)
		for k := range hostNetworkV1.NetworksByID {
			network, err := netHandler.Inspect(ctx, k)
			if err != nil {
				log.Errorf(err.Error())
				continue
			}
			err = network.Properties.LockForWrite(NetworkProperty.HostsV1).ThenUse(func(v interface{}) error {
				networkHostsV1 := v.(*propsv1.NetworkHosts)
				delete(networkHostsV1.ByID, host.ID)
				delete(networkHostsV1.ByName, host.Name)
				return nil
			})
			if err != nil {
				log.Errorf(err.Error())
			}
			_, err = metadata.SaveNetwork(handler.service, network)
			if err != nil {
				log.Errorf(err.Error())
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Conditions are met, delete host
	var deleteMetadataOnly bool
	var moreTimeNeeded bool
	err = handler.service.DeleteHost(host.ID)
	if err != nil {
		switch err.(type) {
		case resources.ErrResourceNotFound:
			deleteMetadataOnly = true
		case resources.ErrTimeout:
			moreTimeNeeded = true
		case retry.ErrTimeout:
			moreTimeNeeded = true
		default:
			return infraErrf(err, "can't delete host")
		}
	}

	// FIXME Add GetHostState verification
	if moreTimeNeeded {
		if state, ok := handler.service.GetHostState(host.ID); ok == nil { // FIXME Unhandled timeout
			log.Warnf("While deleting the status was [%s]", state)
			if state != HostState.ERROR {
				deleteMetadataOnly = true
			} else {
				return infraErrf(err, "can't delete host")
			}
		} else {
			return infraErrf(err, "can't delete host")
		}
	}

	err = mh.Delete()
	if err != nil {
		return infraErr(err)
	}

	if deleteMetadataOnly {
		return fmt.Errorf("Unable to find the host even if it is described by metadatas\nIncoherent metadatas have been supressed")
	}

	select {
	case <-ctx.Done():
		log.Warnf("Host delete cancelled by safescale")
		var hostBis *resources.Host
		err2 := host.Properties.LockForRead(HostProperty.SizingV1).ThenUse(func(v interface{}) error {
			hostSizingV1 := v.(*propsv1.HostSizing)
			return host.Properties.LockForRead(HostProperty.NetworkV1).ThenUse(func(v interface{}) error {
				hostNetworkV1 := v.(*propsv1.HostNetwork)
				//FIXME: host's os name is not stored in metadatas so we used ubuntu 18.04 by default
				var err3 error
				sizing := resources.SizingRequirements{
					MinCores:    hostSizingV1.AllocatedSize.Cores,
					MaxCores:    hostSizingV1.AllocatedSize.Cores,
					MinFreq:     hostSizingV1.AllocatedSize.CPUFreq,
					MinGPU:      hostSizingV1.AllocatedSize.GPUNumber,
					MinRAMSize:  hostSizingV1.AllocatedSize.RAMSize,
					MaxRAMSize:  hostSizingV1.AllocatedSize.RAMSize,
					MinDiskSize: hostSizingV1.AllocatedSize.DiskSize,
				}
				hostBis, err3 = handler.Create(context.Background(), host.Name, hostNetworkV1.DefaultNetworkID, "ubuntu 18.04", (len(hostNetworkV1.PublicIPv4)+len(hostNetworkV1.PublicIPv6)) != 0, &sizing, true)
				if err3 != nil {
					return fmt.Errorf("failed to stop host deletion : %s", err3.Error())
				}
				return nil
			})
		})
		if err2 != nil {
			return fmt.Errorf("failed to cancel host deletion : %s", err2.Error())
		}

		buf, err2 := hostBis.Serialize()
		if err2 != nil {
			return fmt.Errorf("deleted Host recreated by safescale")
		}
		return fmt.Errorf("deleted Host recreated by safescale : %s", buf)

	default:
	}

	return nil
}

// SSH returns ssh parameters to access the host referenced by ref
func (handler *HostHandler) SSH(ctx context.Context, ref string) (sshConfig *system.SSHConfig, err error) {
	defer utils.TimerErrWithLevel(fmt.Sprintf("lib.server.handlers.HostHandler::SSH(%s) called", ref), &err, log.TraceLevel)()

	// host, err := svc.Inspect(ref)
	// if err != nil {
	// 	return nil, logicErrf(err, fmt.Sprintf("can't access ssh parameters of host '%s': failed to query host", ref), "")
	// }

	sshHandler := NewSSHHandler(handler.service)
	sshConfig, err = sshHandler.GetConfig(ctx, ref)
	if err != nil {
		return nil, logicErr(err)
	}
	return sshConfig, nil
}
