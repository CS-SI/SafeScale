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

package services

import (
	"fmt"
	"os"
	"os/user"
	"time"

	"github.com/pkg/errors"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/broker/client"
	brokerutils "github.com/CS-SI/SafeScale/broker/utils"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/HostProperty"
	propsv1 "github.com/CS-SI/SafeScale/providers/model/properties/v1"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils"
)

//go:generate mockgen -destination=../mocks/mock_hostapi.go -package=mocks github.com/CS-SI/SafeScale/broker/server/services HostAPI

// HostAPI defines API to manipulate hosts
type HostAPI interface {
	Create(name string, net string, cpu int, ram float32, disk int, os string, public bool) (*model.Host, error)
	List(all bool) ([]*model.Host, error)
	Get(ref string) (*model.Host, error)
	Delete(ref string) error
	SSH(ref string) (*system.SSHConfig, error)
	Reboot(ref string) error
	Start(ref string) error
	Stop(ref string) error
}

// HostService host service
type HostService struct {
	provider *providers.Service
}

// NewHostService ...
func NewHostService(api *providers.Service) HostAPI {
	return &HostService{
		provider: api,
	}
}

// Start starts a host
func (svc *HostService) Start(ref string) error {
	log.Printf("Starting host '%s'...", ref)
	return svc.provider.StartHost(ref)
}

// Stop stops a host
func (svc *HostService) Stop(ref string) error {
	log.Printf("Stopping host '%s'...", ref)
	return svc.provider.StopHost(ref)
}

// Reboot reboots a host
func (svc *HostService) Reboot(ref string) error {
	log.Println("Rebooting host '%s'...", ref)
	return svc.provider.RebootHost(ref)
}

// Create creates a host
func (svc *HostService) Create(
	name string, net string, cpu int, ram float32, disk int, los string, public bool,
) (*model.Host, error) {

	log.Infof("Creating compute resource '%s' ...", name)
	networks := []string{}
	if len(net) != 0 {
		networkSvc := NewNetworkService(svc.provider)
		n, err := networkSvc.Get(net)
		if err != nil {
			tbr := errors.Wrapf(err, "Failed to get network resource data: '%s'.", net)
			log.Errorf("%+v", tbr)
			return nil, tbr
		}
		if n == nil {
			return nil, fmt.Errorf("Failed to find network '%s'", net)
		}
		networks = append(networks, n.ID)
	}

	// TODO GITHUB https://github.com/CS-SI/SafeScale/issues/30
	// TODO Add GPU and Freq requirements here

	tpls, err := svc.provider.SelectTemplatesBySize(model.SizingRequirements{
		MinCores:    cpu,
		MinRAMSize:  ram,
		MinDiskSize: disk,
	})
	img, err := svc.provider.SearchImage(los)
	if err != nil {
		tbr := errors.Wrap(err, "Failed to find image to use on compute resource.")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	hostRequest := model.HostRequest{
		ImageID:      img.ID,
		ResourceName: name,
		TemplateID:   tpls[0].ID,
		// IsGateway:  false,
		PublicIP:   public,
		NetworkIDs: networks,
	}

	if exists, err := svc.provider.GetHostByName(name); exists != nil && err == nil {
		tbr := errors.Errorf("Failure creating host: host '%s' already exists.", name)
		log.Errorf("%v", tbr)
		return nil, tbr
	}

	host, err := svc.provider.CreateHost(hostRequest)
	if err != nil {
		tbr := errors.Wrapf(err, "failed to create compute resource '%s'", hostRequest.ResourceName)
		log.Errorf("%+v", tbr)
		return nil, tbr
	}

	// Updates property propsv1.HostSizing
	hostSizingV1 := propsv1.NewHostSizing()
	err = host.Properties.Get(HostProperty.SizingV1, hostSizingV1)
	if err != nil {
		return nil, err
	}
	hostSizingV1.Template = hostRequest.TemplateID
	hostSizingV1.RequestedSize = &propsv1.HostSize{
		Cores:    cpu,
		RAMSize:  ram,
		DiskSize: disk,
	}
	err = host.Properties.Set(HostProperty.SizingV1, hostSizingV1)
	if err != nil {
		return nil, err
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

	// Updates host extension NetworkV1
	gatewayID := ""
	if len(networks) > 0 {
		mgw, err := metadata.LoadGateway(svc.provider, networks[0])
		if err == nil {
			gatewayID = mgw.Get().ID
		}
		hostNetworkV1 := propsv1.NewHostNetwork()
		err = host.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
		if err != nil {
			return nil, err
		}
		// hpNetworkV1.Networks = networks
		hostNetworkV1.DefaultGatewayID = gatewayID
		err = host.Properties.Set(HostProperty.NetworkV1, hostNetworkV1)
		if err != nil {
			return nil, err
		}
	}

	// Updates metadata
	err = metadata.NewHost(svc.provider).Carry(host).Write()
	if err != nil {
		tbr := errors.Wrapf(err, "Metadata creation failed")
		svc.provider.DeleteHost(host.ID)
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	log.Infof("Compute resource created: '%s'", host.Name)

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	log.Infof("Waiting start of SSH service on remote host '%s' ...", host.Name)
	sshSvc := NewSSHService(svc.provider)
	sshCfg, err := sshSvc.GetConfig(host.ID)
	if err != nil {
		derr := svc.provider.DeleteHost(host.ID)
		if derr != nil {
			log.Warnf("Error deleting host after failing to get its ssh config: %v", derr)
			tbr := errors.Wrap(err, "Error getting ssh configuration")
			log.Errorf("%+v", tbr)
			return nil, tbr
		}
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	err = sshCfg.WaitServerReady(brokerutils.TimeoutCtxHost)
	if err != nil {
		tbr := errors.Wrap(err, "")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	if client.IsTimeout(err) {
		derr := svc.provider.DeleteHost(host.ID)
		if derr != nil {
			log.Warnf("Error deleting host after a timeout: %v", derr)
			tbr := errors.Wrap(err, "Timeout creating a host")
			log.Errorf("%+v", tbr)
			return nil, tbr
		}
		tbr := errors.Wrap(err, "Timeout creating a host")
		log.Errorf("%+v", tbr)
		return nil, tbr
	}
	log.Infof("SSH service started on host '%s'.", host.Name)

	return host, nil
}

// List returns the host list
func (svc *HostService) List(all bool) ([]*model.Host, error) {
	return svc.provider.ListHosts(all)
}

// Get returns the host identified by ref, ref can be the name or the id
func (svc *HostService) Get(ref string) (*model.Host, error) {
	// Uses metadata to recover Host id
	mh := metadata.NewHost(svc.provider)
	found, err := mh.ReadByID(ref)
	if err != nil {
		return nil, err
	}
	if !found {
		found, err = mh.ReadByName(ref)
		if err != nil {
			return nil, err
		}
	}
	if !found {
		return nil, fmt.Errorf("host '%s' not found", ref)
	}
	return mh.Get(), nil
}

// Delete deletes host referenced by ref
func (svc *HostService) Delete(ref string) error {
	host, err := svc.Get(ref)
	if err != nil {
		return err
	}

	// Don't remove a host having shares
	hostSharesV1 := propsv1.NewHostShares()
	err = host.Properties.Get(HostProperty.SharesV1, hostSharesV1)
	if err != nil {
		return err
	}
	nShares := len(hostSharesV1.ByID)
	if nShares > 0 {
		return fmt.Errorf("Can't delete host, exports %d share%s", nShares, utils.Plural(nShares))
	}

	// Don't remove a host with volumes attached
	hostVolumesV1 := propsv1.NewHostVolumes()
	err = host.Properties.Get(HostProperty.VolumesV1, hostVolumesV1)
	if err != nil {
		return err
	}
	nAttached := len(hostVolumesV1.VolumesByID)
	if nAttached > 0 {
		return fmt.Errorf("host has %d volume%s attached", nAttached, utils.Plural(nAttached))
	}

	// Don't remove a host that is a gateway
	hostNetworkV1 := propsv1.NewHostNetwork()
	err = host.Properties.Get(HostProperty.NetworkV1, hostNetworkV1)
	if err != nil {
		return err
	}
	if hostNetworkV1.IsGateway {
		return fmt.Errorf("can't delete host, it's a gateway that can't be deleted but with its network")
	}

	// If host mounted shares, unmounts them before anything else
	hostMountsV1 := propsv1.NewHostMounts()
	err = host.Properties.Get(HostProperty.MountsV1, hostMountsV1)
	if err != nil {
		return err
	}
	shareSvc := NewShareService(svc.provider)
	for _, i := range hostMountsV1.RemoteMountsByPath {
		// Gets share data
		_, share, err := shareSvc.Inspect(i.ShareID)
		if err != nil {
			return err
		}

		// Unmounts share from host
		err = shareSvc.Unmount(share.Name, host.Name)
		if err != nil {
			return err
		}
	}

	// Conditions are met, delete host
	err = svc.provider.DeleteHost(ref)
	if err != nil {
		return err
	}
	return metadata.NewHost(svc.provider).Carry(host).Delete()
}

// SSH returns ssh parameters to access the host referenced by ref
func (svc *HostService) SSH(ref string) (*system.SSHConfig, error) {
	host, err := svc.Get(ref)
	if err != nil {
		return nil, fmt.Errorf("failed to query host '%s'", ref)
	}
	if host == nil {
		return nil, fmt.Errorf("host '%s' not found", ref)
	}
	sshSvc := NewSSHService(svc.provider)
	return sshSvc.GetConfig(host.ID)
}
