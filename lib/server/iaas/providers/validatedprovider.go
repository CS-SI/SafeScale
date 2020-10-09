/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package providers

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ValidatedProvider ...
type ValidatedProvider WrappedProvider

func (w ValidatedProvider) CreateVIP(netID string, name string) (*abstract.VirtualIP, fail.Error) {
	// FIXME: Add OK method to vip, then check return value
	return w.InnerProvider.CreateVIP(netID, name)
}

func (w ValidatedProvider) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	// FIXME: Add OK method to vip
	return w.InnerProvider.AddPublicIPToVIP(vip)
}

func (w ValidatedProvider) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	// FIXME: Add OK method to vip
	return w.InnerProvider.BindHostToVIP(vip, hostID)
}

func (w ValidatedProvider) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	// FIXME:  Add OK method to vip
	return w.InnerProvider.UnbindHostFromVIP(vip, hostID)
}

func (w ValidatedProvider) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	// FIXME: Add OK method to vip
	return w.InnerProvider.DeleteVIP(vip)
}

func (w ValidatedProvider) GetCapabilities() Capabilities {
	return w.InnerProvider.GetCapabilities()
}

func (w ValidatedProvider) GetTenantParameters() map[string]interface{} {
	return w.InnerProvider.GetTenantParameters()
}

// Provider specific functions

func (w ValidatedProvider) Build(something map[string]interface{}) (p Provider, err fail.Error) {
	return w.InnerProvider.Build(something)
}

func (w ValidatedProvider) ListImages(all bool) (res []abstract.Image, err fail.Error) {
	res, err = w.InnerProvider.ListImages(all)
	if err != nil {
		for _, image := range res {
			if !image.OK() {
				logrus.Warnf("Invalid image: %v", image)
			}
		}
	}
	return res, err
}

func (w ValidatedProvider) ListTemplates(all bool) (res []abstract.HostTemplate, err fail.Error) {
	res, err = w.InnerProvider.ListTemplates(all)
	if err != nil {
		for _, hostTemplate := range res {
			if !hostTemplate.OK() {
				logrus.Warnf("Invalid host template: %v", hostTemplate)
			}
		}
	}
	return res, err
}

func (w ValidatedProvider) GetAuthenticationOptions() (Config, fail.Error) {
	return w.InnerProvider.GetAuthenticationOptions()
}

func (w ValidatedProvider) GetConfigurationOptions() (Config, fail.Error) {
	return w.InnerProvider.GetConfigurationOptions()
}

func (w ValidatedProvider) GetName() string {
	return w.InnerProvider.GetName()
}

// Stack specific functions

// NewValidatedProvider ...
func NewValidatedProvider(innerProvider Provider, name string) *ValidatedProvider {
	return &ValidatedProvider{InnerProvider: innerProvider, Label: name}
}

// ListAvailabilityZones ...
func (w ValidatedProvider) ListAvailabilityZones() (map[string]bool, fail.Error) {
	return w.InnerProvider.ListAvailabilityZones()
}

// ListRegions ...
func (w ValidatedProvider) ListRegions() ([]string, fail.Error) {
	return w.InnerProvider.ListRegions()
}

// GetImage ...
func (w ValidatedProvider) GetImage(id string) (res *abstract.Image, err fail.Error) {
	res, err = w.InnerProvider.InspectImage(id)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid image: %v", *res)
			}
		}
	}

	return res, err
}

// GetTemplate ...
func (w ValidatedProvider) GetTemplate(id string) (res *abstract.HostTemplate, err fail.Error) {
	res, err = w.InnerProvider.InspectTemplate(id)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid template: %v", *res)
			}
		}
	}
	return res, err
}

// CreateKeyPair ...
func (w ValidatedProvider) CreateKeyPair(name string) (kp *abstract.KeyPair, err fail.Error) {
	kp, err = w.InnerProvider.CreateKeyPair(name)
	if err != nil {
		if kp == nil {
			logrus.Warn("Invalid keypair !")
		}
	}
	return kp, err
}

// GetKeyPair ...
func (w ValidatedProvider) GetKeyPair(id string) (kp *abstract.KeyPair, err fail.Error) {
	kp, err = w.InnerProvider.InspectKeyPair(id)
	if err != nil {
		if kp == nil {
			logrus.Warn("Invalid keypair !")
		}
	}
	return kp, err
}

// ListKeyPairs ...
func (w ValidatedProvider) ListKeyPairs() (res []abstract.KeyPair, err fail.Error) {
	return w.InnerProvider.ListKeyPairs()
}

// DeleteKeyPair ...
func (w ValidatedProvider) DeleteKeyPair(id string) (xerr fail.Error) {
	return w.InnerProvider.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w ValidatedProvider) CreateNetwork(req abstract.NetworkRequest) (res *abstract.Network, err fail.Error) {
	res, err = w.InnerProvider.CreateNetwork(req)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid network: %v", *res)
			}
		}
	}
	return res, err
}

// GetNetwork ...
func (w ValidatedProvider) GetNetwork(id string) (res *abstract.Network, err fail.Error) {
	res, err = w.InnerProvider.InspectNetwork(id)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid network: %v", *res)
			}
		}
	}
	return res, err
}

// GetNetworkByName ...
func (w ValidatedProvider) GetNetworkByName(name string) (res *abstract.Network, err fail.Error) {
	res, err = w.InnerProvider.InspectNetworkByName(name)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid network: %v", *res)
			}
		}
	}
	return res, err
}

// ListNetworks ...
func (w ValidatedProvider) ListNetworks() (res []*abstract.Network, err fail.Error) {
	res, err = w.InnerProvider.ListNetworks()
	if err != nil {
		for _, item := range res {
			if item != nil {
				if !item.OK() {
					logrus.Warnf("Invalid network: %v", *item)
				}
			}
		}
	}
	return res, err
}

// DeleteNetwork ...
func (w ValidatedProvider) DeleteNetwork(id string) (xerr fail.Error) {
	return w.InnerProvider.DeleteNetwork(id)
}

// // CreateGateway ...
// func (w ValidatedProvider) CreateGateway(req abstract.GatewayRequest) (res *abstract.HostFull, data *userdata.Content, err fail.Error) {
// 	res, data, err = w.InnerProvider.CreateGateway(req)
// 	if err != nil {
// 		if res != nil {
// 			if !res.OK() {
// 				logrus.Warnf("Invalid host: %v", *res)
// 			}
// 		}
// 		if data != nil {
// 			if !data.OK() {
// 				logrus.Warnf("Invalid userdata: %v", *data)
// 			}
// 		}
// 	}
// 	return res, data, err
// }
//
// // DeleteGateway ...
// func (w ValidatedProvider) DeleteGateway(networkID string) (xerr fail.Error) {
// 	return w.InnerProvider.DeleteGateway(networkID)
// }

// CreateHost ...
func (w ValidatedProvider) CreateHost(request abstract.HostRequest) (res *abstract.HostFull, ud *userdata.Content, err fail.Error) {
	res, ud, err = w.InnerProvider.CreateHost(request)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
		if ud != nil {
			if !ud.OK() {
				logrus.Warnf("Invalid userdata: %v", *ud)
			}
		}
	}
	return res, ud, err
}

// InspectHost ...
func (w ValidatedProvider) InspectHost(hostParam stacks.HostParameter) (res *abstract.HostFull, err fail.Error) {
	res, err = w.InnerProvider.InspectHost(hostParam)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
	}
	return res, err
}

// WaitHostReady ...
func (w ValidatedProvider) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	return w.InnerProvider.WaitHostReady(hostParam, timeout)
}

// GetHostByName ...
func (w ValidatedProvider) GetHostByName(name string) (res *abstract.HostCore, err fail.Error) {
	res, err = w.InnerProvider.InspectHostByName(name)
	if err != nil {
		if res != nil {
			logrus.Warnf("Invalid host: %v", *res)
		}
	}
	return res, err
}

// GetHostState ...
func (w ValidatedProvider) GetHostState(hostParam stacks.HostParameter) (res hoststate.Enum, err fail.Error) {
	return w.InnerProvider.GetHostState(hostParam)
}

// ListHosts ...
func (w ValidatedProvider) ListHosts(details bool) (res abstract.HostList, err fail.Error) {
	res, err = w.InnerProvider.ListHosts(details)
	if err != nil {
		for _, item := range res {
			if item != nil {
				if !item.OK() {
					logrus.Warnf("Invalid host: %v", *item)
				}
			}
		}
	}
	return res, err
}

// DeleteHost ...
func (w ValidatedProvider) DeleteHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	return w.InnerProvider.DeleteHost(hostParam)
}

// StopHost ...
func (w ValidatedProvider) StopHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	return w.InnerProvider.StopHost(hostParam)
}

// StartHost ...
func (w ValidatedProvider) StartHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	return w.InnerProvider.StartHost(hostParam)
}

// RebootHost ...
func (w ValidatedProvider) RebootHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	return w.InnerProvider.RebootHost(hostParam)
}

// ResizeHost ...
func (w ValidatedProvider) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (res *abstract.HostFull, err fail.Error) {
	res, err = w.InnerProvider.ResizeHost(hostParam, request)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
	}
	return res, err
}

// CreateVolume ...
func (w ValidatedProvider) CreateVolume(request abstract.VolumeRequest) (res *abstract.Volume, err fail.Error) {
	res, err = w.InnerProvider.CreateVolume(request)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid volume: %v", *res)
			}
		}
	}
	return res, err
}

// GetVolume ...
func (w ValidatedProvider) GetVolume(id string) (res *abstract.Volume, err fail.Error) {
	res, err = w.InnerProvider.InspectVolume(id)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid volume: %v", *res)
			}
		}
	}
	return res, err
}

// ListVolumes ...
func (w ValidatedProvider) ListVolumes() (res []abstract.Volume, err fail.Error) {
	res, err = w.InnerProvider.ListVolumes()
	if err != nil {
		for _, item := range res {
			if !item.OK() {
				logrus.Warnf("Invalid host: %v", item)
			}
		}
	}
	return res, err
}

// DeleteVolume ...
func (w ValidatedProvider) DeleteVolume(id string) (xerr fail.Error) {
	return w.InnerProvider.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w ValidatedProvider) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (id string, err fail.Error) {
	return w.InnerProvider.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w ValidatedProvider) GetVolumeAttachment(serverID, id string) (res *abstract.VolumeAttachment, err fail.Error) {
	res, err = w.InnerProvider.InspectVolumeAttachment(serverID, id)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid volume attachment: %v", *res)
			}
		}
	}
	return res, err
}

// ListVolumeAttachments ...
func (w ValidatedProvider) ListVolumeAttachments(serverID string) (res []abstract.VolumeAttachment, err fail.Error) {
	res, err = w.InnerProvider.ListVolumeAttachments(serverID)
	if err != nil {
		for _, item := range res {
			if !item.OK() {
				logrus.Warnf("Invalid volume attachment: %v", item)
			}
		}
	}
	return res, err
}

// DeleteVolumeAttachment ...
func (w ValidatedProvider) DeleteVolumeAttachment(serverID, id string) (err fail.Error) {
	return w.InnerProvider.DeleteVolumeAttachment(serverID, id)
}
