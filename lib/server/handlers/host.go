/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/networkproperty"
	propsv1 "github.com/CS-SI/SafeScale/lib/server/iaas/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/server/install"
	"github.com/CS-SI/SafeScale/lib/server/metadata"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/retry/enums/verdict"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

//go:generate mockgen -destination=../mocks/mock_hostapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers HostAPI

// TODO At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// HostAPI defines API to manipulate hosts
type HostAPI interface {
	Create(ctx context.Context, name string, net string, os string, public bool, sizingParam interface{}, force bool, domain string) (*resources.Host, error)
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
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		return err
	}
	if mh == nil {
		return resources.ResourceNotFoundError("host", ref)
	}

	mhm, err := mh.Get()
	if err != nil {
		return err
	}

	id := mhm.ID
	err = handler.service.StartHost(id)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound, scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}

	err = handler.service.WaitHostState(id, hoststate.STARTED, temporal.GetHostTimeout())
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound, scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}

	return err
}

// Stop stops a host
func (handler *HostHandler) Stop(ctx context.Context, ref string) (err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		return err
	}
	if mh == nil {
		return resources.ResourceNotFoundError("host", ref)
	}

	mhm, err := mh.Get()
	if err != nil {
		return err
	}

	id := mhm.ID
	err = handler.service.StopHost(id)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound, scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}

	err = handler.service.WaitHostState(id, hoststate.STOPPED, temporal.GetHostTimeout())
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound, scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}
	return err
}

// Reboot reboots a host
func (handler *HostHandler) Reboot(ctx context.Context, ref string) (err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		return err
	}
	if mh == nil {
		return fmt.Errorf("host '%s' not found", ref)
	}
	mhm, err := mh.Get()
	if err != nil {
		return err
	}

	id := mhm.ID
	err = handler.service.RebootHost(id)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound, scerr.ErrTimeout:
			return err
		default:
			return err
		}
	}
	retryErr := retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return handler.service.WaitHostState(id, hoststate.STARTED, temporal.GetHostTimeout())
		},
		temporal.GetHostTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case scerr.ErrTimeout:
			return retryErr
		case scerr.ErrNotFound:
			return retryErr
		default:
			return retryErr
		}
	}

	return nil
}

// Resize ...
func (handler *HostHandler) Resize(ctx context.Context, ref string, cpu int, ram float32, disk int, gpuNumber int, freq float32) (newHost *resources.Host, err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', %d, %.02f, %d, %d, %.02f)", ref, cpu, ram, disk, gpuNumber, freq), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		return nil, err
	}
	if mh == nil {
		return nil, resources.ResourceNotFoundError("host", ref)
	}

	mhm, err := mh.Get()
	if err != nil {
		return nil, err
	}

	id := mhm.ID
	hostSizeRequest := resources.SizingRequirements{
		MinDiskSize: disk,
		MinRAMSize:  ram,
		MinCores:    cpu,
		MinFreq:     freq,
		MinGPU:      gpuNumber,
	}

	// TODO RESIZE 1st check new requirements vs old requirements
	host, err := mh.Get()
	if err != nil {
		return nil, err
	}
	host, err = handler.service.InspectHost(host)
	if err != nil {
		switch err.(type) {
		case scerr.ErrTimeout, scerr.ErrNotFound:
			return nil, err
		default:
			return nil, err
		}
	}

	if host.Properties.Lookup(hostproperty.SizingV1) {
		descent := false
		err = host.Properties.LockForRead(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
			nhs := clonable.(*propsv1.HostSizing)
			descent = descent || (hostSizeRequest.MinCores < nhs.RequestedSize.Cores)
			descent = descent || (hostSizeRequest.MinRAMSize < nhs.RequestedSize.RAMSize)
			descent = descent || (hostSizeRequest.MinGPU < nhs.RequestedSize.GPUNumber)
			descent = descent || (hostSizeRequest.MinFreq < nhs.RequestedSize.CPUFreq)
			descent = descent || (hostSizeRequest.MinDiskSize < nhs.RequestedSize.DiskSize)
			return nil
		})
		if err != nil {
			return nil, err
		}
		if descent {
			logrus.Warn("Asking for less resources..., ain't gonna happen :(")
		}
	}

	newHost, err = handler.service.ResizeHost(id, hostSizeRequest)
	if err != nil {
		switch err.(type) {
		case scerr.ErrTimeout, scerr.ErrNotFound:
			return nil, err
		default:
			return nil, err
		}
	}
	if newHost == nil {
		return nil, fmt.Errorf("unknown error resizing host '%s'", ref)
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
	name string, net string, los string, public bool, sizingParam interface{}, force bool, domain string,
) (newHost *resources.Host, err error) {

	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s', '%s', '%s', %v, <sizingParam>, %v)", name, net, los, public, force), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		sizing       *resources.SizingRequirements
		templateName string
	)
	switch sizingParam := sizingParam.(type) {
	case *resources.SizingRequirements:
		sizing = sizingParam
	case string:
		templateName = sizingParam
	default:
		return nil, scerr.InvalidParameterError("sizing", "must be *resources.SizingRequirements or string")
	}

	host, err := handler.service.GetHostByName(name)
	if err != nil {
		switch err.(type) {
		case scerr.ErrNotFound:
		case scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	} else {
		hostThere, hsErr := handler.service.GetHostState(name)
		if hsErr == nil {
			logrus.Warnf("we have a host %s with status: %s", name, hostThere.String())
			if hostThere != hoststate.TERMINATED {
				return nil, resources.ResourceDuplicateError("host", name)
			}
		}
		return nil, resources.ResourceDuplicateError("host", name)
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
			if _, ok := err.(scerr.ErrNotFound); ok {
				return nil, err
			}
			return nil, err
		}
		if defaultNetwork == nil {
			return nil, fmt.Errorf("failed to find network '%s'", net)
		}
		networks = append(networks, defaultNetwork)

		mgw, err := metadata.LoadHost(handler.service, defaultNetwork.GatewayID)
		if err != nil {
			return nil, err
		}
		if mgw == nil {
			return nil, fmt.Errorf("failed to find gateway of network '%s'", net)
		}
		primaryGateway, err = mgw.Get()
		if err != nil {
			return nil, err
		}
		if defaultNetwork.VIP != nil {
			defaultRouteIP = defaultNetwork.VIP.PrivateIP
		} else {
			defaultRouteIP = primaryGateway.GetPrivateIP()
		}
	} else {
		net, err := handler.getOrCreateDefaultNetwork()
		if err != nil {
			return nil, err
		}
		networks = append(networks, net)
	}

	var template *resources.HostTemplate
	if sizing != nil {
		templates, err := handler.service.SelectTemplatesBySize(*sizing, force)
		if err != nil {
			switch err.(type) {
			case scerr.ErrNotFound, scerr.ErrTimeout:
				return nil, err
			default:
				return nil, err
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
			logrus.Infof(msg)
		} else {
			return nil, fmt.Errorf("failed to find template corresponding to requested resources")
		}
	} else {
		template, err = handler.service.SelectTemplateByName(templateName)
		if err != nil {
			switch err.(type) {
			case scerr.ErrNotFound, scerr.ErrTimeout:
				return nil, err
			default:
				return nil, err
			}
		}
	}

	var img *resources.Image
	retryErr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var innerErr error
			img, innerErr = handler.service.SearchImage(los)
			return innerErr
		},
		2*temporal.GetDefaultDelay(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case scerr.ErrNotFound, scerr.ErrTimeout:
			return nil, retryErr
		default:
			return nil, retryErr
		}
	}

	if domain == "" {
		domain = defaultNetwork.Domain
	}
	domain = strings.Trim(domain, ".")
	if domain != "" {
		domain = "." + domain
	}

	hostRequest := resources.HostRequest{
		ImageID:        img.ID,
		ResourceName:   name,
		HostName:       name + domain,
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
		case scerr.ErrInvalidRequest:
			return nil, err
		case scerr.ErrNotFound, scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}
	defer func() {
		if err != nil {
			derr := handler.service.DeleteHost(host.ID)
			if derr != nil {
				switch derr.(type) {
				case scerr.ErrNotFound:
					logrus.Errorf("failed to delete host '%s', resource not found: %v", host.Name, derr)
				case scerr.ErrTimeout:
					logrus.Errorf("failed to delete host '%s', timeout: %v", host.Name, derr)
				default:
					logrus.Errorf("failed to delete host '%s', other reason: %v", host.Name, derr)
				}
			}
			err = scerr.AddConsequence(err, derr)
		}
	}()

	if host == nil {
		return nil, fmt.Errorf("unexpected error creating host instance: host is nil")
	}
	if host.Properties == nil {
		return nil, fmt.Errorf("error populating host properties: host.Properties is nil")
	}

	// Updates host metadata
	mh, err := metadata.NewHost(handler.service)
	if err != nil {
		return nil, err
	}

	ch, err := mh.Carry(host)
	if err != nil {
		return nil, err
	}

	err = ch.Write()
	if err != nil {
		return nil, err
	}
	logrus.Infof("Compute resource created: '%s'", host.Name)

	// Starting from here, remove metadata if exiting with error
	defer func() {
		if err != nil {
			derr := mh.Delete()
			if derr != nil {
				logrus.Errorf("failed to remove host metadata after host creation failure")
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	// Updates property propsv1.HostSizing
	if sizing != nil {
		err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
			hostSizingV1 := clonable.(*propsv1.HostSizing)
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
		err = host.Properties.LockForWrite(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
			hostSizingV1 := clonable.(*propsv1.HostSizing)
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
		return nil, err
	}

	// Sets host extension DescriptionV1
	creator := ""
	hostname, _ := os.Hostname()
	if curUser, err := user.Current(); err == nil {
		creator = curUser.Username
		if hostname != "" {
			creator += "@" + hostname
		}
		if curUser.Name != "" {
			creator += " (" + curUser.Name + ")"
		}
	} else {
		creator = "unknown@" + hostname
	}
	err = host.Properties.LockForWrite(hostproperty.DescriptionV1).ThenUse(func(clonable data.Clonable) error {
		hostDescriptionV1 := clonable.(*propsv1.HostDescription)
		hostDescriptionV1.Created = time.Now()
		hostDescriptionV1.Creator = creator
		hostDescriptionV1.Domain = domain
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Updates host property propsv1.HostNetwork
	var (
		defaultNetworkID string
		gatewayID        string
	)
	err = host.Properties.LockForWrite(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
		hostNetworkV1 := clonable.(*propsv1.HostNetwork)
		defaultNetworkID = hostNetworkV1.DefaultNetworkID // set earlier by handler.service.CreateHost()
		if !public {
			if len(networks) > 0 {
				mgw, err := metadata.LoadGateway(handler.service, defaultNetworkID)
				if err == nil {
					mgwm, merr := mgw.Get()
					if merr != nil {
						return merr
					}

					gatewayID = mgwm.ID
				}
			}
		}
		hostNetworkV1.DefaultGatewayID = gatewayID

		if net != "" {
			mn, err := metadata.LoadNetwork(handler.service, net)
			if err != nil {
				return err
			}
			network, err := mn.Get()
			if err != nil {
				return err
			}
			hostNetworkV1.NetworksByID[network.ID] = network.Name
			hostNetworkV1.NetworksByName[network.Name] = network.ID
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	// Updates host metadata
	err = mh.Write()
	if err != nil {
		return nil, err
	}

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting start of SSH service on remote host '%s' ...", host.Name)
	sshHandler := NewSSHHandler(handler.service)
	sshCfg, err := sshHandler.GetConfig(ctx, host.ID)
	if err != nil {
		return nil, err
	}

	_, err = sshCfg.WaitServerReady("phase1", temporal.GetHostCreationTimeout())
	if err != nil {
		derr := err
		err = nil
		if client.IsTimeoutError(derr) {
			return nil, scerr.Wrap(derr, fmt.Sprintf("timeout waiting host '%s' to become ready", host.Name))
		}

		if client.IsProvisioningError(derr) {
			logrus.Errorf("%+v", derr)
			retrieveForensicsData(ctx, sshHandler, host)
			return nil, fmt.Errorf("failed to provision host '%s', please check safescaled logs", host.Name)
		}

		return nil, scerr.Wrap(derr, fmt.Sprintf("failed to wait host '%s' to become ready", host.Name))
	}

	// Updates host link with networks
	for _, i := range networks {
		err = i.Properties.LockForWrite(networkproperty.HostsV1).ThenUse(func(clonable data.Clonable) error {
			networkHostsV1 := clonable.(*propsv1.NetworkHosts)
			networkHostsV1.ByName[host.Name] = host.ID
			networkHostsV1.ByID[host.ID] = host.Name
			return nil
		})
		if err != nil {
			logrus.Errorf(err.Error())
			continue
		}
		_, err = metadata.SaveNetwork(handler.service, i)
		if err != nil {
			logrus.Errorf(err.Error())
		}
	}

	// Executes userdata phase2 script to finalize host installation
	userDataPhase2, err := userData.Generate("phase2")
	if err != nil {
		return nil, err
	}

	filepath := utils.TempFolder + "/user_data.phase2.sh"
	err = install.UploadStringToRemoteFile(string(userDataPhase2), srvutils.ToPBHost(host), filepath, "", "", "")
	if err != nil {
		return nil, err
	}

	sshConfig, err := sshHandler.GetConfig(ctx, host)
	if err != nil {
		return nil, err
	}

	command := fmt.Sprintf("sudo bash %s; exit $?", filepath)
	sshCmd, err := sshConfig.Command(command)
	if err != nil {
		return nil, err
	}

	// Executes the script on the remote host
	// retcode, stdout, stderr, err := sshHandler.Run(ctx, host.Name, command)
	var (
		retcode        int
		stdout, stderr string
	)
	retryErr = retry.WhileUnsuccessfulDelay1SecondWithNotify(
		func() error {
			var inErr error
			retcode, _, _, inErr = sshCmd.RunWithTimeout(nil, outputs.COLLECT, 0)
			return inErr
		},
		temporal.GetHostTimeout(),
		func(t retry.Try, v verdict.Enum) {
			if v == verdict.Retry {
				logrus.Debugf("Remote SSH service on host '%s' isn't ready, retrying...", host.Name)
			}
		},
	)
	if retryErr != nil {
		retrieveForensicsData(ctx, sshHandler, host)
		return nil, err
	}
	if retcode != 0 {
		retrieveForensicsData(ctx, sshHandler, host)

		// Setting err will trigger defers
		err = fmt.Errorf("failed to finalize host '%s' installation: retcode=%d, stdout[%s], stderr[%s]", host.Name, retcode, stdout, stderr)
		if client.IsProvisioningError(err) {
			retrieveForensicsData(ctx, sshHandler, host)
			logrus.Error(err)
		}

		return nil, err
	}

	// FIXME: AWS Retrieve data anyway
	retrieveForensicsData(ctx, sshHandler, host)

	// Reboot host
	command = "sudo systemctl reboot"
	retcode, _, _, err = sshHandler.Run(ctx, host.Name, command, outputs.COLLECT)
	if err != nil {
		return nil, err
	}
	if retcode != 0 && retcode != 255 {
		return nil, scerr.Wrap(fmt.Errorf("retcode=%d", retcode), "reboot command failed")
	}

	// Wait like 2 min for the machine to reboot
	_, err = sshCfg.WaitServerReady("ready", temporal.GetConnectSSHTimeout())
	if err != nil {
		if client.IsTimeoutError(err) {
			return nil, err
		}

		if client.IsProvisioningError(err) {
			retrieveForensicsData(ctx, sshHandler, host)
			return nil, fmt.Errorf("error creating host '%s', error provisioning the new host, please check safescaled logs", host.Name)
		}

		return nil, err
	}
	logrus.Infof("SSH service started on host '%s'.", host.Name)

	select {
	case <-ctx.Done():
		err = fmt.Errorf("host creation cancelled by safescale")
		logrus.Warn(err)
		return nil, err
	default:
	}

	return host, nil
}

func getPhaseWarningsAndErrors(ctx context.Context, sshHandler *SSHHandler, host *resources.Host) ([]string, []string) {
	if sshHandler == nil || host == nil {
		return []string{}, []string{}
	}

	recoverCode, recoverStdOut, _, recoverErr := sshHandler.Run(ctx, host.Name, fmt.Sprintf("cat %s/user_data.phase2.log; exit $?", utils.LogFolder), outputs.COLLECT)
	var warnings []string
	var errs []string

	if recoverCode == 0 && recoverErr == nil {
		lines := strings.Split(recoverStdOut, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "An error occurred in line") {
				warnings = append(warnings, line)
			}
			if strings.HasPrefix(line, "PROVISIONING_ERROR:") {
				errs = append(errs, line)
			}
		}
	}

	return warnings, errs
}

func retrieveForensicsData(ctx context.Context, sshHandler *SSHHandler, host *resources.Host) {
	if sshHandler == nil || host == nil {
		return
	}
	if forensics := os.Getenv("SAFESCALE_FORENSICS"); forensics != "" {
		_ = os.MkdirAll(utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s", host.Name)), 0777)
		dumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", host.Name, "phase1"))
		etcDumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/etcdata.tar.gz", host.Name))
		textDumpName := utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/textdata.tar.gz", host.Name))

		_, _, _, err := sshHandler.RunWithTimeout(ctx, host.Name, "whoami", outputs.COLLECT, 10*time.Second)
		if err == nil { // If there's no ssh connection, no need to wait
			_, _, _, _ = sshHandler.Run(ctx, host.Name, "sudo tar -czvf etcdir.tar.gz /etc", outputs.COLLECT)
			_, _, _, _ = sshHandler.Run(ctx, host.Name, "sudo tar -czvf etcdir.tar.gz /etc", outputs.COLLECT)
			_, _, _, _ = sshHandler.Run(ctx, host.Name, "systemd-resolve --status > /tmp/systemd-resolve.txt", outputs.COLLECT)
			_, _, _, _ = sshHandler.Run(ctx, host.Name, "netplan ip leases eth0 > /tmp/netplan.txt", outputs.COLLECT)
			_, _, _, _ = sshHandler.Run(ctx, host.Name, "sudo tar -czvf textdumps.tar.gz /tmp/*.txt", outputs.COLLECT)
			_, _, _, _ = sshHandler.Copy(ctx, host.Name+":/home/safescale/etcdir.tar.gz", etcDumpName)
			_, _, _, _ = sshHandler.Copy(ctx, host.Name+":/home/safescale/textdumps.tar.gz", textDumpName)

			_, _, _, _ = sshHandler.Copy(ctx, host.Name+":"+utils.TempFolder+"/user_data.phase1.sh", dumpName+"sh")
			_, _, _, _ = sshHandler.Copy(ctx, host.Name+":"+utils.LogFolder+"/user_data.phase1.log", dumpName+"log")

			dumpName = utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/userdata-%s.", host.Name, "phase2"))
			_, _, _, _ = sshHandler.Copy(ctx, host.Name+":"+utils.TempFolder+"/user_data.phase2.sh", dumpName+"sh")
			_, _, _, _ = sshHandler.Copy(ctx, host.Name+":"+utils.LogFolder+"/user_data.phase2.log", dumpName+"log")
			_, _, _, _ = sshHandler.Copy(ctx, host.Name+":"+utils.LogFolder+"/packages_installed_before.phase2.list", utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/packages_installed_before.%s.list", host.Name, "phase2")))
			_, _, _, _ = sshHandler.Copy(ctx, host.Name+":"+utils.LogFolder+"/packages_installed_after.phase2.list", utils.AbsPathify(fmt.Sprintf("$HOME/.safescale/forensics/%s/packages_installed_after.%s.list", host.Name, "phase2")))
		}
	}
}

// getOrCreateDefaultNetwork gets network resources.SingleHostNetworkName or create it if necessary
// We don't want metadata on this network, so we use directly provider api instead of services
func (handler *HostHandler) getOrCreateDefaultNetwork() (network *resources.Network, err error) {
	network, err = handler.service.GetNetworkByName(resources.SingleHostNetworkName)
	if err != nil {
		switch err.(type) {
		case scerr.ErrInvalidRequest, scerr.ErrNotFound, scerr.ErrTimeout:
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
		IPVersion: ipversion.IPv4,
		CIDR:      "10.0.0.0/8",
	}

	network, err = handler.service.CreateNetwork(request)
	if err != nil {
		switch err.(type) {
		case scerr.ErrInvalidRequest, scerr.ErrNotFound, scerr.ErrTimeout:
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
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if all {
		return handler.service.ListHosts()
	}

	m, err := metadata.NewHost(handler.service)
	if err != nil {
		return nil, err
	}
	err = m.Browse(func(host *resources.Host) error {
		hosts = append(hosts, host)
		return nil
	})
	if err != nil {
		return hosts, err
	}
	return hosts, nil
}

// ForceInspect ...
// If not found, return (nil, err)
func (handler *HostHandler) ForceInspect(ctx context.Context, ref string) (host *resources.Host, err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	host, err = handler.Inspect(ctx, ref)
	if err != nil {
		return nil, err
	}

	return host, nil
}

// Inspect returns the host identified by ref, ref can be the name or the id
// If not found, returns (nil, nil)
func (handler *HostHandler) Inspect(ctx context.Context, ref string) (host *resources.Host, err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return nil, resources.ResourceNotFoundError("host", ref)
		}
		return nil, err
	}

	host, err = mh.Get()
	if err != nil {
		return nil, err
	}
	host, err = handler.service.InspectHost(host)
	if err != nil {
		switch err.(type) {
		case scerr.ErrInvalidRequest, scerr.ErrNotFound, scerr.ErrTimeout:
			return nil, err
		default:
			return nil, err
		}
	}

	if host == nil {
		return nil, fmt.Errorf("failure inspecting host [%s]", ref)
	}

	return host, nil
}

// Delete deletes host referenced by ref
func (handler *HostHandler) Delete(ctx context.Context, ref string) (err error) {
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	mh, err := metadata.LoadHost(handler.service, ref)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return resources.ResourceNotFoundError("host", ref)
		}
		return err
	}

	host, err := mh.Get()
	if err != nil {
		return err
	}
	// Don't remove a host having shares that are currently remotely mounted
	var shares map[string]*propsv1.HostShare
	err = host.Properties.LockForRead(hostproperty.SharesV1).ThenUse(func(clonable data.Clonable) error {
		shares = clonable.(*propsv1.HostShares).ByID
		for _, share := range shares {
			count := len(share.ClientsByID)
			if count > 0 {
				count = len(shares)
				return fmt.Errorf("cannot delete host, exports %d share%s where at least one is used", count, utils.Plural(count))
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Don't remove a host with volumes attached
	err = host.Properties.LockForRead(hostproperty.VolumesV1).ThenUse(func(clonable data.Clonable) error {
		nAttached := len(clonable.(*propsv1.HostVolumes).VolumesByID)
		if nAttached > 0 {
			return fmt.Errorf("host has %d volume%s attached", nAttached, utils.Plural(nAttached))
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Don't remove a host that is a gateway
	err = host.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
		if clonable.(*propsv1.HostNetwork).IsGateway {
			return fmt.Errorf("cannot delete host, it's a gateway that can only be deleted through its network")
		}
		return nil
	})
	if err != nil {
		return err
	}

	// If host mounted shares, unmounts them before anything else
	shareHandler := NewShareHandler(handler.service)
	var mounts []*propsv1.HostShare
	err = host.Properties.LockForRead(hostproperty.MountsV1).ThenUse(func(clonable data.Clonable) error {
		hostMountsV1 := clonable.(*propsv1.HostMounts)
		for _, i := range hostMountsV1.RemoteMountsByPath {
			// Gets share data
			_, share, _, err := shareHandler.Inspect(ctx, i.ShareID)
			if err != nil {
				return err
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
			return err
		}
	}

	// if host exports shares, delete them
	for _, share := range shares {
		err = shareHandler.Delete(ctx, share.Name)
		if err != nil {
			return err
		}
	}

	// Update networks property prosv1.NetworkHosts to remove the reference to the host
	netHandler := NewNetworkHandler(handler.service)
	err = host.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
		hostNetworkV1 := clonable.(*propsv1.HostNetwork)
		for k := range hostNetworkV1.NetworksByID {
			network, err := netHandler.Inspect(ctx, k)
			if err != nil {
				logrus.Errorf(err.Error())
				continue
			}
			err = network.Properties.LockForWrite(networkproperty.HostsV1).ThenUse(func(clonable data.Clonable) error {
				networkHostsV1 := clonable.(*propsv1.NetworkHosts)
				delete(networkHostsV1.ByID, host.ID)
				delete(networkHostsV1.ByName, host.Name)
				return nil
			})
			if err != nil {
				logrus.Errorf(err.Error())
			}
			_, err = metadata.SaveNetwork(handler.service, network)
			if err != nil {
				logrus.Errorf(err.Error())
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
		case scerr.ErrNotFound:
			deleteMetadataOnly = true
		case scerr.ErrTimeout:
			moreTimeNeeded = true
		default:
			return err
		}
	}

	// FIXME Add GetHostState verification
	if moreTimeNeeded {
		if state, ok := handler.service.GetHostState(host.ID); ok == nil { // FIXME Unhandled timeout
			logrus.Warnf("While deleting the status was [%s]", state)
			if state != hoststate.ERROR {
				deleteMetadataOnly = true
			} else {
				return err
			}
		} else {
			return err
		}
	}

	err = mh.Delete()
	if err != nil {
		return err
	}

	if deleteMetadataOnly {
		return fmt.Errorf("unable to find the host even if it is described by metadata. Dirty metadata have been deleted")
	}

	select {
	case <-ctx.Done():
		logrus.Warnf("Host delete cancelled by safescale")
		var hostBis *resources.Host
		err2 := host.Properties.LockForRead(hostproperty.SizingV1).ThenUse(func(clonable data.Clonable) error {
			hostSizingV1 := clonable.(*propsv1.HostSizing)
			return host.Properties.LockForRead(hostproperty.DescriptionV1).ThenUse(func(clonable data.Clonable) error {
				hostDescriptionV1 := clonable.(*propsv1.HostDescription)
				return host.Properties.LockForRead(hostproperty.NetworkV1).ThenUse(func(clonable data.Clonable) error {
					hostNetworkV1 := clonable.(*propsv1.HostNetwork)
					// FIXME: host's os name is not stored in metadata so we used ubuntu 18.04 by default
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
					hostBis, err3 = handler.Create(context.Background(), host.Name, hostNetworkV1.DefaultNetworkID, "ubuntu 18.04", (len(hostNetworkV1.PublicIPv4)+len(hostNetworkV1.PublicIPv6)) != 0, &sizing, true, hostDescriptionV1.Domain)
					if err3 != nil {
						return fmt.Errorf("failed to stop host deletion : %s", err3.Error())
					}
					return nil
				})
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
	tracer := concurrency.NewTracer(nil, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	sshHandler := NewSSHHandler(handler.service)
	sshConfig, err = sshHandler.GetConfig(ctx, ref)
	if err != nil {
		return nil, err
	}
	return sshConfig, nil
}
