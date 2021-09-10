package api

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ErrorTraceProvider ...
type ErrorTraceProvider WrappedProvider

// Provider specific functions

// Build ...
func (w ErrorTraceProvider) Build(something map[string]interface{}) (p Provider, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:Build", w.Name))
	return w.InnerProvider.Build(something)
}

// ListImages ...
func (w ErrorTraceProvider) ListImages(all bool) (images []abstract.Image, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListImages", w.Name))
	return w.InnerProvider.ListImages(all)
}

// ListTemplates ...
func (w ErrorTraceProvider) ListTemplates(all bool) (templates []abstract.HostTemplate, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListTemplates", w.Name))
	return w.InnerProvider.ListTemplates(all)
}

// GetAuthenticationOptions ...
func (w ErrorTraceProvider) GetAuthenticationOptions() (cfg providers.Config, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetAuthenticationOptions", w.Name))

	return w.InnerProvider.GetAuthenticationOptions()
}

// GetConfigurationOptions ...
func (w ErrorTraceProvider) GetConfigurationOptions() (cfg providers.Config, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
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
func NewErrorTraceProvider(innerProvider Provider, name string) *ErrorTraceProvider {
	return &ErrorTraceProvider{InnerProvider: innerProvider, Name: name}
}

// ListAvailabilityZones ...
func (w ErrorTraceProvider) ListAvailabilityZones() (zones map[string]bool, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListAvailabilityZones", w.Name))
	return w.InnerProvider.ListAvailabilityZones()
}

// ListRegions ...
func (w ErrorTraceProvider) ListRegions() (regions []string, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListRegions", w.Name))
	return w.InnerProvider.ListRegions()
}

// GetImage ...
func (w ErrorTraceProvider) GetImage(id string) (images *abstract.Image, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetImage", w.Name))
	return w.InnerProvider.GetImage(id)
}

// GetTemplate ...
func (w ErrorTraceProvider) GetTemplate(id string) (templates *abstract.HostTemplate, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetTemplate", w.Name))
	return w.InnerProvider.GetTemplate(id)
}

// CreateKeyPair ...
func (w ErrorTraceProvider) CreateKeyPair(name string) (pairs *abstract.KeyPair, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:CreateKeyPair", w.Name))
	return w.InnerProvider.CreateKeyPair(name)
}

// GetKeyPair ...
func (w ErrorTraceProvider) GetKeyPair(id string) (pairs *abstract.KeyPair, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetKeyPair", w.Name))
	return w.InnerProvider.GetKeyPair(id)
}

// ListKeyPairs ...
func (w ErrorTraceProvider) ListKeyPairs() (pairs []abstract.KeyPair, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListKeyPairs", w.Name))
	return w.InnerProvider.ListKeyPairs()
}

// DeleteKeyPair ...
func (w ErrorTraceProvider) DeleteKeyPair(id string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:DeleteKeyPair", w.Name))
	return w.InnerProvider.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w ErrorTraceProvider) CreateNetwork(req abstract.NetworkRequest) (net *abstract.Network, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:CreateNetwork", w.Name))
	return w.InnerProvider.CreateNetwork(req)
}

// GetNetwork ...
func (w ErrorTraceProvider) GetNetwork(id string) (net *abstract.Network, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetNetwork", w.Name))
	return w.InnerProvider.GetNetwork(id)
}

// GetNetworkByName ...
func (w ErrorTraceProvider) GetNetworkByName(name string) (net *abstract.Network, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetNetworkByName", w.Name))
	return w.InnerProvider.GetNetworkByName(name)
}

// ListNetworks ...
func (w ErrorTraceProvider) ListNetworks() (net []*abstract.Network, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListNetworks", w.Name))
	return w.InnerProvider.ListNetworks()
}

// DeleteNetwork ...
func (w ErrorTraceProvider) DeleteNetwork(id string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:DeleteNetwork", w.Name))
	return w.InnerProvider.DeleteNetwork(id)
}

// CreateGateway ...
func (w ErrorTraceProvider) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (host *abstract.Host, content *userdata.Content, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:CreateGateway", w.Name))
	return w.InnerProvider.CreateGateway(req, sizing)
}

// DeleteGateway ...
func (w ErrorTraceProvider) DeleteGateway(networkID string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:DeleteGateway", w.Name))
	return w.InnerProvider.DeleteGateway(networkID)
}

// CreateVIP ...
func (w ErrorTraceProvider) CreateVIP(networkID string, description string) (_ *abstract.VirtualIP, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:CreateVIP", w.Name))
	return w.InnerProvider.CreateVIP(networkID, description)
}

// AddPublicIPToVIP adds a public IP to VIP
func (w ErrorTraceProvider) AddPublicIPToVIP(vip *abstract.VirtualIP) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:AddPublicIPToVIP", w.Name))
	return w.InnerProvider.AddPublicIPToVIP(vip)
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (w ErrorTraceProvider) BindHostToVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:BindHostToVIP", w.Name))
	return w.InnerProvider.BindHostToVIP(vip, hostID)
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (w ErrorTraceProvider) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:UnbindHostFromVIP", w.Name))
	return w.InnerProvider.UnbindHostFromVIP(vip, hostID)
}

// DeleteVIP deletes the port corresponding to the VIP
func (w ErrorTraceProvider) DeleteVIP(vip *abstract.VirtualIP) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:DeleteVIP", w.Name))
	return w.InnerProvider.DeleteVIP(vip)
}

// CreateHost ...
func (w ErrorTraceProvider) CreateHost(request abstract.HostRequest) (_ *abstract.Host, _ *userdata.Content, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:CreateHost", w.Name))
	return w.InnerProvider.CreateHost(request)
}

// InspectHost ...
func (w ErrorTraceProvider) InspectHost(something interface{}) (_ *abstract.Host, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:InspectHost", w.Name))
	return w.InnerProvider.InspectHost(something)
}

// GetHostByName ...
func (w ErrorTraceProvider) GetHostByName(name string) (_ *abstract.Host, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetHostByName", w.Name))
	return w.InnerProvider.GetHostByName(name)
}

// GetHostState ...
func (w ErrorTraceProvider) GetHostState(something interface{}) (_ hoststate.Enum, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetHostState", w.Name))
	return w.InnerProvider.GetHostState(something)
}

// ListHosts ...
func (w ErrorTraceProvider) ListHosts() (_ []*abstract.Host, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListHosts", w.Name))
	return w.InnerProvider.ListHosts()
}

// DeleteHost ...
func (w ErrorTraceProvider) DeleteHost(id string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:DeleteHost", w.Name))
	return w.InnerProvider.DeleteHost(id)
}

// StopHost ...
func (w ErrorTraceProvider) StopHost(id string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:StopHost", w.Name))
	return w.InnerProvider.StopHost(id)
}

// StartHost ...
func (w ErrorTraceProvider) StartHost(id string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:StartHost", w.Name))
	return w.InnerProvider.StartHost(id)
}

// RebootHost ...
func (w ErrorTraceProvider) RebootHost(id string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:RebootHost", w.Name))
	return w.InnerProvider.RebootHost(id)
}

// ResizeHost ...
func (w ErrorTraceProvider) ResizeHost(id string, request abstract.SizingRequirements) (_ *abstract.Host, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ResizeHost", w.Name))
	return w.InnerProvider.ResizeHost(id, request)
}

// CreateVolume ...
func (w ErrorTraceProvider) CreateVolume(request abstract.VolumeRequest) (_ *abstract.Volume, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:CreateVolume", w.Name))
	return w.InnerProvider.CreateVolume(request)
}

// GetVolume ...
func (w ErrorTraceProvider) GetVolume(id string) (_ *abstract.Volume, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetVolume", w.Name))
	return w.InnerProvider.GetVolume(id)
}

// ListVolumes ...
func (w ErrorTraceProvider) ListVolumes() (_ []abstract.Volume, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListVolumes", w.Name))
	return w.InnerProvider.ListVolumes()
}

// DeleteVolume ...
func (w ErrorTraceProvider) DeleteVolume(id string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:DeleteVolume", w.Name))
	return w.InnerProvider.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w ErrorTraceProvider) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (_ string, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:CreateVolumeAttachment", w.Name))
	return w.InnerProvider.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w ErrorTraceProvider) GetVolumeAttachment(serverID, id string) (_ *abstract.VolumeAttachment, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:GetVolumeAttachment", w.Name))
	return w.InnerProvider.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments ...
func (w ErrorTraceProvider) ListVolumeAttachments(serverID string) (_ []abstract.VolumeAttachment, xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:ListVolumeAttachments", w.Name))
	return w.InnerProvider.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment ...
func (w ErrorTraceProvider) DeleteVolumeAttachment(serverID, id string) (xerr fail.Error) {
	defer func(prefix string) {
		if xerr != nil {
			logrus.Debugf("%s : Intercepted error: %v", prefix, xerr)
		}
	}(fmt.Sprintf("%s:DeleteVolumeAttachment", w.Name))
	return w.InnerProvider.DeleteVolumeAttachment(serverID, id)
}

// GetCapabilities ...
func (w ErrorTraceProvider) GetCapabilities() providers.Capabilities {
	return w.InnerProvider.GetCapabilities()
}
