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

package handlers

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/CS-SI/SafeScale/providers/model/enums/HostState"
	"github.com/CS-SI/SafeScale/providers/model/enums/NetworkProperty"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/broker/client"
	brokerutils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	"github.com/CS-SI/SafeScale/providers/model/enums/IPVersion"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/retry"
)

//go:generate mockgen -destination=../mocks/mock_hostapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/handlers HostAPI

// TODO At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// HostAPI defines API to manipulate hosts
type HostAPI interface {
	Create(name string, net string, cpu int, ram float32, disk int, os string, public bool, gpuNumber int, freq float32, force bool) (*model.Host, error)
	List(all bool) ([]*model.Host, error)
	ForceInspect(ref string) (*model.Host, error)
	Inspect(ref string) (*model.Host, error)
	Delete(ref string) error
	SSH(ref string) (*system.SSHConfig, error)
	Reboot(ref string) error
	Start(ref string) error
	Stop(ref string) error
}

// HostHandler host service
type HostHandler struct {
	provider *providers.Service
}

// NewHostHandler ...
func NewHostHandler(api *providers.Service) HostAPI {
	return &HostHandler{
		provider: api,
	}
}

// Start starts a host
func (svc *HostHandler) Start(ref string) error {
	log.Debugf("server.services.HostHandler.Start(%s) called", ref)
	defer log.Debugf("server.services.HostHandler.Start(%s) done", ref)

	mh, err := metadata.LoadHost(svc.provider, ref)
	if err != nil {
		// TODO Introduce error level as parameter
		return infraErrf(err, "Error getting ssh config of host '%s': loading host metadata", ref)
	}
	if mh == nil {
		return infraErr(fmt.Errorf("host '%s' not found", ref))
	}
	id := mh.Get().ID
	err = svc.provider.StartHost(id)
	if err != nil {
		return infraErr(err)
	}
	return infraErr(svc.provider.WaitHostState(id, HostState.STARTED, brokerutils.GetTimeoutCtxHost()))
}

// Stop stops a host
func (svc *HostHandler) Stop(ref string) error {
	log.Debugf("server.services.HostHandler.Stop(%s) called", ref)
	defer log.Debugf("server.services.HostHandler.Stop(%s) done", ref)

	mh, err := metadata.LoadHost(svc.provider, ref)
	if err != nil {
		// TODO Introduce error level as parameter
		return infraErrf(err, "Error getting ssh config of host '%s': loading host metadata", ref)
	}
	if mh == nil {
		return infraErr(fmt.Errorf("host '%s' not found", ref))
	}
	id := mh.Get().ID
	err = svc.provider.StopHost(id)
	if err != nil {
		return infraErr(err)
	}
	return infraErr(svc.provider.WaitHostState(id, HostState.STOPPED, brokerutils.GetTimeoutCtxHost()))
}

// Reboot reboots a host
func (svc *HostHandler) Reboot(ref string) error {
	log.Debugf("server.services.HostHandler.Reboot(%s) called", ref)
	defer log.Debugf("server.services.HostHandler.Reboot(%s) done", ref)

	mh, err := metadata.LoadHost(svc.provider, ref)
	if err != nil {
		return infraErr(fmt.Errorf("failed to load metadata of host '%s': %v", ref, err))
	}
	if mh == nil {
		return infraErr(fmt.Errorf("host '%s' not found", ref))
	}
	id := mh.Get().ID
	err = svc.provider.RebootHost(id)
	if err != nil {
		return infraErr(err)
	}
	err = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return svc.provider.WaitHostState(id, HostState.STARTED, brokerutils.GetTimeoutCtxHost())
		},
		5*time.Minute,
	)
	if err != nil {
		return infraErrf(err, "timeout waiting host '%s' to be rebooted", ref)
	}
	return nil
}

// Create creates a host
func (svc *HostHandler) Create(
	name string, net string, cpu int, ram float32, disk int, los string, public bool, gpuNumber int, freq float32, force bool,
) (*model.Host, error) {

	log.Debugf("HostHandler.Create('%s') called", name)
	defer log.Debugf("HostHandler.Create('%s') done", name)

	host, err := svc.provider.GetHostByName(name)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
		default:
			return nil, infraErrf(err, "failure creating host: failed to check if host resource name '%s' is already used: %v", name, err)
		}
	} else {
		return nil, logicErr(fmt.Errorf("failed to create host '%s': name is already used", name))
	}

	var networks []*model.Network
	var gw *model.Host
	if len(net) != 0 {
		networkHandler := NewNetworkHandler(svc.provider)
		n, err := networkHandler.Inspect(net)
		if err != nil {
			switch err.(type) {
			case model.ErrResourceNotFound:
				return nil, infraErr(err)
			default:
				return nil, infraErrf(err, "Failed to get network resource data: '%s'.", net)
			}
		}
		if n == nil {
			return nil, logicErr(fmt.Errorf("Failed to find network '%s'", net))
		}
		networks = append(networks, n)
		mgw, err := metadata.LoadHost(svc.provider, n.GatewayID)
		if err != nil {
			return nil, infraErr(err)
		}
		if mgw == nil {
			return nil, logicErr(fmt.Errorf("failed to find gateway of network '%s'", net))
		}
		gw = mgw.Get()
	} else {
		net, err := svc.getOrCreateDefaultNetwork()
		if err != nil {
			return nil, infraErr(err)
		}
		networks = append(networks, net)
	}

	msg := fmt.Sprintf("Requested template satisfying: %d core%s", cpu, utils.Plural(cpu))
	if freq > 0 {
		msg += fmt.Sprintf(" at %.01f GHz", freq)
	}
	msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", ram, disk)
	if gpuNumber > 0 {
		msg += fmt.Sprintf(", %d GPU%s", gpuNumber, utils.Plural(gpuNumber))
	}
	log.Infof(msg)
	templates, err := svc.provider.SelectTemplatesBySize(
		model.SizingRequirements{
			MinCores:    cpu,
			MinRAMSize:  ram,
			MinDiskSize: disk,
			MinGPU:      gpuNumber,
			MinFreq:     freq,
		}, force)
	if err != nil {
		return nil, infraErrf(err, "failed to find template corresponding to requested resources")
	}
	var template model.HostTemplate
	if len(templates) > 0 {
		template = templates[0]
		msg := fmt.Sprintf("Selected template: '%s' (%d core%s", template.Name, cpu, utils.Plural(cpu))
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
	}

	img, err := svc.provider.SearchImage(los)
	if err != nil {
		return nil, infraErr(errors.Wrap(err, "Failed to find image to use on compute resource."))
	}
	hostRequest := model.HostRequest{
		ImageID:        img.ID,
		ResourceName:   name,
		TemplateID:     template.ID,
		PublicIP:       public,
		Networks:       networks,
		DefaultGateway: gw,
	}

	host, err = svc.provider.CreateHost(hostRequest)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceInvalidRequest:
			return nil, infraErr(err)
		default:
			return nil, infraErrf(err, "failed to create compute resource '%s'", hostRequest.ResourceName)
		}
	}

	defer func() {
		if err != nil {
			derr := svc.provider.DeleteHost(host.ID)
			if derr != nil {
				log.Errorf("Failed to delete host '%s': %v", host.Name, derr)
			}
		}
	}()

	// Updates property propsv1.HostSizing
	hostSizingV1 := propsv1.NewHostSizing()
	err = host.Properties.Get(HostProperty.SizingV1, hostSizingV1)
	if err != nil {
		return nil, infraErr(err)
	}
	hostSizingV1.Template = hostRequest.TemplateID
	hostSizingV1.RequestedSize = &propsv1.HostSize{
		Cores:     cpu,
		RAMSize:   ram,
		DiskSize:  disk,
		GPUNumber: gpuNumber,
		CPUFreq:   freq,
	}
	err = host.Properties.Set(HostProperty.SizingV1, hostSizingV1)
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
	err = host.Properties.Set(string(HostProperty.DescriptionV1), &propsv1.HostDescription{
		Created: time.Now(),
		Creator: creator,
	})

	// Updates host property propsv1.HostNetwork
	hostNetworkV1 := propsv1.NewHostNetwork()
	err = host.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return nil, infraErr(err)
	}
	defaultNetworkID := hostNetworkV1.DefaultNetworkID // set earlier by svc.provider.CreateHost()
	gatewayID := ""
	if !public {
		if len(networks) > 0 {
			mgw, err := metadata.LoadGateway(svc.provider, defaultNetworkID)
			if err == nil {
				gatewayID = mgw.Get().ID
			}
		}
	}
	hostNetworkV1.DefaultGatewayID = gatewayID
	err = host.Properties.Set(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return nil, infraErr(err)
	}
	if net != "" {
		mn, err := metadata.LoadNetwork(svc.provider, net)
		if err != nil {
			return nil, infraErr(err)
		}
		if mn == nil {
			return nil, logicErr(fmt.Errorf("failed to load metadata of network '%s'", net))
		}
		network := mn.Get()
		hostNetworkV1.NetworksByID[network.ID] = network.Name
		hostNetworkV1.NetworksByName[network.Name] = network.ID
	}

	// Updates metadata
	err = metadata.NewHost(svc.provider).Carry(host).Write()
	if err != nil {
		return nil, infraErrf(err, "Metadata creation failed")
	}
	log.Infof("Compute resource created: '%s'", host.Name)

	networkHostsV1 := propsv1.NewNetworkHosts()
	for _, i := range networks {
		err = i.Properties.Get(NetworkProperty.HostsV1, networkHostsV1)
		if err != nil {
			log.Errorf(err.Error())
			continue
		}
		networkHostsV1.ByName[host.Name] = host.ID
		networkHostsV1.ByID[host.ID] = host.Name
		err = i.Properties.Set(NetworkProperty.HostsV1, networkHostsV1)
		if err != nil {
			log.Errorf(err.Error())
		}

		err = metadata.SaveNetwork(svc.provider, i)
		if err != nil {
			log.Errorf(err.Error())
		}
	}

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	log.Infof("Waiting start of SSH service on remote host '%s' ...", host.Name)
	sshHandler := NewSSHHandler(svc.provider)
	sshCfg, err := sshHandler.GetConfig(host.ID)
	if err != nil {
		return nil, infraErr(err)
	}

	sshDefaultTimeout := int(brokerutils.GetTimeoutCtxHost().Minutes())

	if sshDefaultTimeoutCandidate := os.Getenv("SSH_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		num, err := strconv.Atoi(sshDefaultTimeoutCandidate)
		if err == nil {
			log.Debugf("Using custom timeout of %d minutes", num)
			sshDefaultTimeout = num
		}
	}

	// TODO configurable timeout here
	err = sshCfg.WaitServerReady(time.Duration(sshDefaultTimeout) * time.Minute)
	if err != nil {
		return nil, infraErr(err)
	}
	if client.IsTimeout(err) {
		return nil, infraErrf(err, "Timeout creating a host")
	}
	log.Infof("SSH service started on host '%s'.", host.Name)

	return host, nil
}

// getOrCreateDefaultNetwork gets network model.SingleHostNetworkName or create it if necessary
// We don't want metadata on this network, so we use directly provider api instead of services
func (svc *HostHandler) getOrCreateDefaultNetwork() (*model.Network, error) {
	network, err := svc.provider.GetNetworkByName(model.SingleHostNetworkName)
	if err != nil {
		switch err.(type) {
		case model.ErrResourceNotFound:
		default:
			return nil, infraErr(err)
		}
	}
	if network != nil {
		return network, nil
	}

	request := model.NetworkRequest{
		Name:      model.SingleHostNetworkName,
		IPVersion: IPVersion.IPv4,
		CIDR:      "10.0.0.0/8",
	}

	mnet, err := svc.provider.CreateNetwork(request)
	return mnet, infraErr(err)
}

// List returns the host list
func (svc *HostHandler) List(all bool) ([]*model.Host, error) {
	log.Debugf("HostHandler.List(%v) called", all)
	defer log.Debugf("HostHandler.List(%v) done", all)

	if all {
		return svc.provider.ListHosts()
	}

	var hosts []*model.Host
	m := metadata.NewHost(svc.provider)
	err := m.Browse(func(host *model.Host) error {
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
func (svc *HostHandler) ForceInspect(ref string) (*model.Host, error) {
	log.Debugf("HostHandler.ForceInspect(%s) called", ref)
	defer log.Debugf("HostHandler.ForceInspect(%s) done", ref)

	host, err := svc.Inspect(ref)
	if err != nil {
		return nil, infraErr(errors.Wrap(err, "failed to load host metadata"))
	}
	if host == nil {
		return nil, logicErr(fmt.Errorf("failed to find host '%s'", ref))
	}
	return host, nil
}

// Inspect returns the host identified by ref, ref can be the name or the id
// If not found, returns (nil, nil)
func (svc *HostHandler) Inspect(ref string) (*model.Host, error) {
	log.Debugf("HostHandler.Inspect(%s) called", ref)
	defer log.Debugf("HostHandler.Inspect(%s) done", ref)

	mh, err := metadata.LoadHost(svc.provider, ref)
	if err != nil {
		return nil, throwErr(errors.Wrap(err, "failed to load host metadata"))
	}
	if mh == nil {
		return nil, nil
	}
	host := mh.Get()
	host, err = svc.provider.GetHost(host)
	if err != nil {
		return nil, infraErr(err)
	}
	return host, nil
}

// Delete deletes host referenced by ref
func (svc *HostHandler) Delete(ref string) error {
	log.Debugf("HostHandler.Delete(%s) called", ref)
	defer log.Debugf("HostHandler.Delete(%s) done", ref)

	mh, err := metadata.LoadHost(svc.provider, ref)
	if err != nil {
		return infraErrf(err, "can't delete host '%s'", ref)
	}
	if mh == nil {
		return logicErr(model.ResourceNotFoundError("host", ref))
	}
	host := mh.Get()

	// Don't remove a host having shares
	hostSharesV1 := propsv1.NewHostShares()
	err = host.Properties.Get(HostProperty.SharesV1, hostSharesV1)
	if err != nil {
		return logicErrf(err, "can't delete host '%s'", ref)
	}
	nShares := len(hostSharesV1.ByID)
	if nShares > 0 {
		return logicErr(fmt.Errorf("can't delete host, exports %d share%s", nShares, utils.Plural(nShares)))
	}

	// Don't remove a host with volumes attached
	hostVolumesV1 := propsv1.NewHostVolumes()
	err = host.Properties.Get(HostProperty.VolumesV1, hostVolumesV1)
	if err != nil {
		return logicErr(err)
	}
	nAttached := len(hostVolumesV1.VolumesByID)
	if nAttached > 0 {
		return logicErr(fmt.Errorf("host has %d volume%s attached", nAttached, utils.Plural(nAttached)))
	}

	// Don't remove a host that is a gateway
	hostNetworkV1 := propsv1.NewHostNetwork()
	err = host.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return logicErr(err)
	}
	if hostNetworkV1.IsGateway {
		return logicErr(fmt.Errorf("can't delete host, it's a gateway that can't be deleted but with its network"))
	}

	// If host mounted shares, unmounts them before anything else
	hostMountsV1 := propsv1.NewHostMounts()
	err = host.Properties.Get(HostProperty.MountsV1, hostMountsV1)
	if err != nil {
		return logicErr(err)
	}
	shareHandler := NewShareHandler(svc.provider)
	for _, i := range hostMountsV1.RemoteMountsByPath {
		// Gets share data
		_, share, _, err := shareHandler.Inspect(i.ShareID)
		if err != nil {
			return infraErr(err)
		}

		// Unmounts share from host
		err = shareHandler.Unmount(share.Name, host.Name)
		if err != nil {
			return infraErr(err)
		}
	}

	// if host has shares, delete them
	for _, share := range hostSharesV1.ByID {
		err = shareHandler.Delete(share.Name)
		if err != nil {
			return throwErr(err)
		}
	}

	// Conditions are met, delete host
	err = svc.provider.DeleteHost(host.ID)
	if err != nil {
		return infraErrf(err, "can't delete host")
	}

	// Update networks property prosv1.NetworkHosts to remove the reference to the host
	networkHostsV1 := propsv1.NewNetworkHosts()
	netHandler := NewNetworkHandler(svc.provider)
	for k := range hostNetworkV1.NetworksByID {
		network, err := netHandler.Inspect(k)
		if err != nil {
			log.Errorf(err.Error())
		}
		err = network.Properties.Get(NetworkProperty.HostsV1, networkHostsV1)
		if err != nil {
			log.Errorf(err.Error())
		}
		delete(networkHostsV1.ByID, host.ID)
		delete(networkHostsV1.ByName, host.Name)
		err = network.Properties.Set(NetworkProperty.HostsV1, networkHostsV1)
		if err != nil {
			log.Errorf(err.Error())
		}
		err = metadata.SaveNetwork(svc.provider, network)
		if err != nil {
			log.Errorf(err.Error())
		}
	}

	// Finally, delete metadata of host
	trydelete := mh.Delete()
	return infraErr(trydelete)
}

// SSH returns ssh parameters to access the host referenced by ref
func (svc *HostHandler) SSH(ref string) (*system.SSHConfig, error) {
	log.Debugf("HostHandler.SSH(%s) called", ref)
	defer log.Debugf("HostHandler.SSH(%s) done", ref)

	host, err := svc.Inspect(ref)
	if err != nil {
		return nil, logicErrf(err, fmt.Sprintf("Can't access ssh parameters of host '%s': failed to query host", ref))
	}
	if host == nil {
		return nil, logicErr(fmt.Errorf("Can't access ssh parameters of host '%s': host not found", ref))
	}
	sshHandler := NewSSHHandler(svc.provider)
	sshConfig, err := sshHandler.GetConfig(host.ID)
	if err != nil {
		return nil, logicErr(err)
	}
	return sshConfig, nil
}
