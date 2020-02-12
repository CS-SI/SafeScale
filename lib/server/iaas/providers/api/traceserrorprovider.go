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

package api

import (
	"fmt"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
)

// ErrorTraceProvider ...
type ErrorTraceProvider WrappedProvider

// WaitHostReady ...
func (w ErrorTraceProvider) WaitHostReady(hostParam interface{}, timeout time.Duration) (host *abstracts.HostCore, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:WaitHostReady", w.Label))
	return w.InnerProvider.WaitHostReady(hostParam, timeout)
}

// Provider specific functions

// Build ...
func (w ErrorTraceProvider) Build(something map[string]interface{}) (p Provider, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:Build", w.Label))
	return w.InnerProvider.Build(something)
}

// ListImages ...
func (w ErrorTraceProvider) ListImages(all bool) (images []abstracts.Image, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListImages", w.Label))
	return w.InnerProvider.ListImages(all)
}

// ListTemplates ...
func (w ErrorTraceProvider) ListTemplates(all bool) (templates []abstracts.HostTemplate, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListTemplates", w.Label))
	return w.InnerProvider.ListTemplates(all)
}

// AuthenticationOptions ...
func (w ErrorTraceProvider) AuthenticationOptions() (cfg providers.Config, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:AuthenticationOptions", w.Label))

	return w.InnerProvider.AuthenticationOptions()
}

// ConfigurationOptions ...
func (w ErrorTraceProvider) ConfigurationOptions() (cfg providers.Config, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ConfigurationOptions", w.Label))
	return w.InnerProvider.ConfigurationOptions()
}

// Name ...
func (w ErrorTraceProvider) Name() string {
	return w.InnerProvider.Name()
}

// TenantParameters ...
func (w ErrorTraceProvider) TenantParameters() map[string]interface{} {
	return w.InnerProvider.TenantParameters()
}

// Stack specific functions

// NewErrorTraceProvider ...
func NewErrorTraceProvider(innerProvider Provider, name string) ErrorTraceProvider {
	return ErrorTraceProvider{InnerProvider: innerProvider, Label: name}
}

// ListAvailabilityZones ...
func (w ErrorTraceProvider) ListAvailabilityZones() (zones map[string]bool, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListAvailabilityZones", w.Label))
	return w.InnerProvider.ListAvailabilityZones()
}

// ListRegions ...
func (w ErrorTraceProvider) ListRegions() (regions []string, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListRegions", w.Label))
	return w.InnerProvider.ListRegions()
}

// GetImage ...
func (w ErrorTraceProvider) GetImage(id string) (images *abstracts.Image, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetImage", w.Label))
	return w.InnerProvider.GetImage(id)
}

// GetTemplate ...
func (w ErrorTraceProvider) GetTemplate(id string) (templates *abstracts.HostTemplate, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetTemplate", w.Label))
	return w.InnerProvider.GetTemplate(id)
}

// CreateKeyPair ...
func (w ErrorTraceProvider) CreateKeyPair(name string) (pairs *abstracts.KeyPair, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateKeyPair", w.Label))
	return w.InnerProvider.CreateKeyPair(name)
}

// GetKeyPair ...
func (w ErrorTraceProvider) GetKeyPair(id string) (pairs *abstracts.KeyPair, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetKeyPair", w.Label))
	return w.InnerProvider.GetKeyPair(id)
}

// ListKeyPairs ...
func (w ErrorTraceProvider) ListKeyPairs() (pairs []abstracts.KeyPair, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListKeyPairs", w.Label))
	return w.InnerProvider.ListKeyPairs()
}

// DeleteKeyPair ...
func (w ErrorTraceProvider) DeleteKeyPair(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteKeyPair", w.Label))
	return w.InnerProvider.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w ErrorTraceProvider) CreateNetwork(req abstracts.NetworkRequest) (net *abstracts.Network, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateNetwork", w.Label))
	return w.InnerProvider.CreateNetwork(req)
}

// GetNetwork ...
func (w ErrorTraceProvider) GetNetwork(id string) (net *abstracts.Network, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetNetwork", w.Label))
	return w.InnerProvider.GetNetwork(id)
}

// GetNetworkByName ...
func (w ErrorTraceProvider) GetNetworkByName(name string) (net *abstracts.Network, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetNetworkByName", w.Label))
	return w.InnerProvider.GetNetworkByName(name)
}

// ListNetworks ...
func (w ErrorTraceProvider) ListNetworks() (net []*abstracts.Network, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListNetworks", w.Label))
	return w.InnerProvider.ListNetworks()
}

// DeleteNetwork ...
func (w ErrorTraceProvider) DeleteNetwork(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteNetwork", w.Label))
	return w.InnerProvider.DeleteNetwork(id)
}

// CreateGateway ...
func (w ErrorTraceProvider) CreateGateway(req abstracts.GatewayRequest) (_ *abstracts.HostFull, _ *userdata.Content, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateGateway", w.Label))
	return w.InnerProvider.CreateGateway(req)
}

// DeleteGateway ...
func (w ErrorTraceProvider) DeleteGateway(networkID string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteGateway", w.Label))
	return w.InnerProvider.DeleteGateway(networkID)
}

// CreateVIP ...
func (w ErrorTraceProvider) CreateVIP(networkID string, description string) (_ *abstracts.VirtualIP, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateVIP", w.Label))
	return w.InnerProvider.CreateVIP(networkID, description)
}

// AddPublicIPToVIP adds a public IP to VIP
func (w ErrorTraceProvider) AddPublicIPToVIP(vip *abstracts.VirtualIP) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:AddPublicIPToVIP", w.Label))
	return w.InnerProvider.AddPublicIPToVIP(vip)
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (w ErrorTraceProvider) BindHostToVIP(vip *abstracts.VirtualIP, hostID string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:BindHostToVIP", w.Label))
	return w.InnerProvider.BindHostToVIP(vip, hostID)
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (w ErrorTraceProvider) UnbindHostFromVIP(vip *abstracts.VirtualIP, hostID string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:UnbindHostFromVIP", w.Label))
	return w.InnerProvider.UnbindHostFromVIP(vip, hostID)
}

// DeleteVIP deletes the port corresponding to the VIP
func (w ErrorTraceProvider) DeleteVIP(vip *abstracts.VirtualIP) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteVIP", w.Label))
	return w.InnerProvider.DeleteVIP(vip)
}

// CreateHost ...
func (w ErrorTraceProvider) CreateHost(request abstracts.HostRequest) (_ *abstracts.HostFull, _ *userdata.Content, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateHost", w.Label))
	return w.InnerProvider.CreateHost(request)
}

// InspectHost ...
func (w ErrorTraceProvider) InspectHost(something interface{}) (_ *abstracts.HostFull, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:InspectHost", w.Label))
	return w.InnerProvider.InspectHost(something)
}

// GetHostByName ...
func (w ErrorTraceProvider) GetHostByName(name string) (_ string, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetHostByName", w.Label))
	return w.InnerProvider.GetHostByName(name)
}

// GetHostState ...
func (w ErrorTraceProvider) GetHostState(something interface{}) (_ hoststate.Enum, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetHostState", w.Label))
	return w.InnerProvider.GetHostState(something)
}

// ListHosts ...
func (w ErrorTraceProvider) ListHosts(details bool) (_ []*abstracts.HostFull, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListHosts", w.Label))
	return w.InnerProvider.ListHosts(details)
}

// DeleteHost ...
func (w ErrorTraceProvider) DeleteHost(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteHost", w.Label))
	return w.InnerProvider.DeleteHost(id)
}

// StopHost ...
func (w ErrorTraceProvider) StopHost(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:StopHost", w.Label))
	return w.InnerProvider.StopHost(id)
}

// StartHost ...
func (w ErrorTraceProvider) StartHost(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:StartHost", w.Label))
	return w.InnerProvider.StartHost(id)
}

// RebootHost ...
func (w ErrorTraceProvider) RebootHost(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:RebootHost", w.Label))
	return w.InnerProvider.RebootHost(id)
}

// ResizeHost ...
func (w ErrorTraceProvider) ResizeHost(id string, request abstracts.HostSizingRequirements) (_ *abstracts.HostFull, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ResizeHost", w.Label))
	return w.InnerProvider.ResizeHost(id, request)
}

// CreateVolume ...
func (w ErrorTraceProvider) CreateVolume(request abstracts.VolumeRequest) (_ *abstracts.Volume, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateVolume", w.Label))
	return w.InnerProvider.CreateVolume(request)
}

// GetVolume ...
func (w ErrorTraceProvider) GetVolume(id string) (_ *abstracts.Volume, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetVolume", w.Label))
	return w.InnerProvider.GetVolume(id)
}

// ListVolumes ...
func (w ErrorTraceProvider) ListVolumes() (_ []abstracts.Volume, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListVolumes", w.Label))
	return w.InnerProvider.ListVolumes()
}

// DeleteVolume ...
func (w ErrorTraceProvider) DeleteVolume(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteVolume", w.Label))
	return w.InnerProvider.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w ErrorTraceProvider) CreateVolumeAttachment(request abstracts.VolumeAttachmentRequest) (_ string, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateVolumeAttachment", w.Label))
	return w.InnerProvider.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w ErrorTraceProvider) GetVolumeAttachment(serverID, id string) (_ *abstracts.VolumeAttachment, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetVolumeAttachment", w.Label))
	return w.InnerProvider.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments ...
func (w ErrorTraceProvider) ListVolumeAttachments(serverID string) (_ []abstracts.VolumeAttachment, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListVolumeAttachments", w.Label))
	return w.InnerProvider.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment ...
func (w ErrorTraceProvider) DeleteVolumeAttachment(serverID, id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteVolumeAttachment", w.Label))
	return w.InnerProvider.DeleteVolumeAttachment(serverID, id)
}

// GetCapabilities ...
func (w ErrorTraceProvider) Capabilities() providers.Capabilities {
	return w.InnerProvider.Capabilities()
}
