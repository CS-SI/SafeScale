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
	propsv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propsv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
)

// ErrorTraceProvider ...
type ErrorTraceProvider WrappedProvider

func (w ErrorTraceProvider) WaitHostReady(hostParam interface{}, timeout time.Duration) (host *abstracts.Host, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:WaitHostReady", w.Name))
	return w.InnerProvider.WaitHostReady(hostParam, timeout)
}

// Provider specific functions

// Build ...
func (w ErrorTraceProvider) Build(something map[string]interface{}) (p Provider, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:Build", w.Name))
	return w.InnerProvider.Build(something)
}

// ListImages ...
func (w ErrorTraceProvider) ListImages(all bool) (images []abstracts.Image, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListImages", w.Name))
	return w.InnerProvider.ListImages(all)
}

// ListTemplates ...
func (w ErrorTraceProvider) ListTemplates(all bool) (templates []abstracts.HostTemplate, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListTemplates", w.Name))
	return w.InnerProvider.ListTemplates(all)
}

// GetAuthenticationOptions ...
func (w ErrorTraceProvider) GetAuthenticationOptions() (cfg providers.Config, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetAuthenticationOptions", w.Name))

	return w.InnerProvider.GetAuthenticationOptions()
}

// GetConfigurationOptions ...
func (w ErrorTraceProvider) GetConfigurationOptions() (cfg providers.Config, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetConfigurationOptions", w.Name))
	return w.InnerProvider.GetConfigurationOptions()
}

// GetName ...
func (w ErrorTraceProvider) GetName() string {
	return w.InnerProvider.GetName()
}

// GetTenantParameters ...
func (w ErrorTraceProvider) GetTenantParameters() map[string]interface{} {
	return w.InnerProvider.GetTenantParameters()
}

// Stack specific functions

// NewErrorTraceProvider ...
func NewErrorTraceProvider(innerProvider Provider, name string) ErrorTraceProvider {
	return ErrorTraceProvider{InnerProvider: innerProvider, Name: name}
}

// ListAvailabilityZones ...
func (w ErrorTraceProvider) ListAvailabilityZones() (zones map[string]bool, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListAvailabilityZones", w.Name))
	return w.InnerProvider.ListAvailabilityZones()
}

// ListRegions ...
func (w ErrorTraceProvider) ListRegions() (regions []string, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListRegions", w.Name))
	return w.InnerProvider.ListRegions()
}

// GetImage ...
func (w ErrorTraceProvider) GetImage(id string) (images *abstracts.Image, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetImage", w.Name))
	return w.InnerProvider.GetImage(id)
}

// GetTemplate ...
func (w ErrorTraceProvider) GetTemplate(id string) (templates *abstracts.HostTemplate, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetTemplate", w.Name))
	return w.InnerProvider.GetTemplate(id)
}

// CreateKeyPair ...
func (w ErrorTraceProvider) CreateKeyPair(name string) (pairs *abstracts.KeyPair, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateKeyPair", w.Name))
	return w.InnerProvider.CreateKeyPair(name)
}

// GetKeyPair ...
func (w ErrorTraceProvider) GetKeyPair(id string) (pairs *abstracts.KeyPair, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetKeyPair", w.Name))
	return w.InnerProvider.GetKeyPair(id)
}

// ListKeyPairs ...
func (w ErrorTraceProvider) ListKeyPairs() (pairs []abstracts.KeyPair, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListKeyPairs", w.Name))
	return w.InnerProvider.ListKeyPairs()
}

// DeleteKeyPair ...
func (w ErrorTraceProvider) DeleteKeyPair(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteKeyPair", w.Name))
	return w.InnerProvider.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w ErrorTraceProvider) CreateNetwork(req abstracts.NetworkRequest) (net *abstracts.Network, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateNetwork", w.Name))
	return w.InnerProvider.CreateNetwork(req)
}

// GetNetwork ...
func (w ErrorTraceProvider) GetNetwork(id string) (net *abstracts.Network, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetNetwork", w.Name))
	return w.InnerProvider.GetNetwork(id)
}

// GetNetworkByName ...
func (w ErrorTraceProvider) GetNetworkByName(name string) (net *abstracts.Network, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetNetworkByName", w.Name))
	return w.InnerProvider.GetNetworkByName(name)
}

// ListNetworks ...
func (w ErrorTraceProvider) ListNetworks() (net []*abstracts.Network, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListNetworks", w.Name))
	return w.InnerProvider.ListNetworks()
}

// DeleteNetwork ...
func (w ErrorTraceProvider) DeleteNetwork(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteNetwork", w.Name))
	return w.InnerProvider.DeleteNetwork(id)
}

// CreateGateway ...
func (w ErrorTraceProvider) CreateGateway(req abstracts.GatewayRequest) (_ *abstracts.Host, _ *propsv2.HostSizing, _ *propsv1.HostNetwork, _ *userdata.Content, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateGateway", w.Name))
	return w.InnerProvider.CreateGateway(req)
}

// DeleteGateway ...
func (w ErrorTraceProvider) DeleteGateway(networkID string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteGateway", w.Name))
	return w.InnerProvider.DeleteGateway(networkID)
}

// CreateVIP ...
func (w ErrorTraceProvider) CreateVIP(networkID string, description string) (_ *abstracts.VIP, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateVIP", w.Name))
	return w.InnerProvider.CreateVIP(networkID, description)
}

// AddPublicIPToVIP adds a public IP to VIP
func (w ErrorTraceProvider) AddPublicIPToVIP(vip *abstracts.VIP) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:AddPublicIPToVIP", w.Name))
	return w.InnerProvider.AddPublicIPToVIP(vip)
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (w ErrorTraceProvider) BindHostToVIP(vip *abstracts.VIP, hostID string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:BindHostToVIP", w.Name))
	return w.InnerProvider.BindHostToVIP(vip, hostID)
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (w ErrorTraceProvider) UnbindHostFromVIP(vip *abstracts.VIP, hostID string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:UnbindHostFromVIP", w.Name))
	return w.InnerProvider.UnbindHostFromVIP(vip, hostID)
}

// DeleteVIP deletes the port corresponding to the VIP
func (w ErrorTraceProvider) DeleteVIP(vip *abstracts.VIP) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteVIP", w.Name))
	return w.InnerProvider.DeleteVIP(vip)
}

// CreateHost ...
func (w ErrorTraceProvider) CreateHost(request abstracts.HostRequest) (_ *abstracts.Host, _ *propsv2.HostSizing, _ *propsv1.HostNetwork, _ *userdata.Content, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateHost", w.Name))
	return w.InnerProvider.CreateHost(request)
}

// InspectHost ...
func (w ErrorTraceProvider) InspectHost(something interface{}) (_ *abstracts.Host, _ *propsv2.HostSizing, _ *propsv1.HostNetwork, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:InspectHost", w.Name))
	return w.InnerProvider.InspectHost(something)
}

// GetHostByName ...
func (w ErrorTraceProvider) GetHostByName(name string) (_ string, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetHostByName", w.Name))
	return w.InnerProvider.GetHostByName(name)
}

// GetHostState ...
func (w ErrorTraceProvider) GetHostState(something interface{}) (_ hoststate.Enum, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetHostState", w.Name))
	return w.InnerProvider.GetHostState(something)
}

// ListHosts ...
func (w ErrorTraceProvider) ListHosts() (_ []*abstracts.Host, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListHosts", w.Name))
	return w.InnerProvider.ListHosts()
}

// DeleteHost ...
func (w ErrorTraceProvider) DeleteHost(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteHost", w.Name))
	return w.InnerProvider.DeleteHost(id)
}

// StopHost ...
func (w ErrorTraceProvider) StopHost(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:StopHost", w.Name))
	return w.InnerProvider.StopHost(id)
}

// StartHost ...
func (w ErrorTraceProvider) StartHost(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:StartHost", w.Name))
	return w.InnerProvider.StartHost(id)
}

// RebootHost ...
func (w ErrorTraceProvider) RebootHost(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:RebootHost", w.Name))
	return w.InnerProvider.RebootHost(id)
}

// ResizeHost ...
func (w ErrorTraceProvider) ResizeHost(id string, request abstracts.SizingRequirements) (_ *abstracts.Host, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ResizeHost", w.Name))
	return w.InnerProvider.ResizeHost(id, request)
}

// CreateVolume ...
func (w ErrorTraceProvider) CreateVolume(request abstracts.VolumeRequest) (_ *abstracts.Volume, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateVolume", w.Name))
	return w.InnerProvider.CreateVolume(request)
}

// GetVolume ...
func (w ErrorTraceProvider) GetVolume(id string) (_ *abstracts.Volume, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetVolume", w.Name))
	return w.InnerProvider.GetVolume(id)
}

// ListVolumes ...
func (w ErrorTraceProvider) ListVolumes() (_ []abstracts.Volume, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListVolumes", w.Name))
	return w.InnerProvider.ListVolumes()
}

// DeleteVolume ...
func (w ErrorTraceProvider) DeleteVolume(id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteVolume", w.Name))
	return w.InnerProvider.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w ErrorTraceProvider) CreateVolumeAttachment(request abstracts.VolumeAttachmentRequest) (_ string, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:CreateVolumeAttachment", w.Name))
	return w.InnerProvider.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w ErrorTraceProvider) GetVolumeAttachment(serverID, id string) (_ *abstracts.VolumeAttachment, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:GetVolumeAttachment", w.Name))
	return w.InnerProvider.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments ...
func (w ErrorTraceProvider) ListVolumeAttachments(serverID string) (_ []abstracts.VolumeAttachment, err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:ListVolumeAttachments", w.Name))
	return w.InnerProvider.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment ...
func (w ErrorTraceProvider) DeleteVolumeAttachment(serverID, id string) (err error) {
	defer func(prefix string) {
		if err != nil {
			logrus.Warnf("%s : Intercepted error: %v", prefix, err)
		}
	}(fmt.Sprintf("%s:DeleteVolumeAttachment", w.Name))
	return w.InnerProvider.DeleteVolumeAttachment(serverID, id)
}

// GetCapabilities ...
func (w ErrorTraceProvider) GetCapabilities() providers.Capabilities {
	return w.InnerProvider.GetCapabilities()
}
