package api

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/sirupsen/logrus"
)

// ErrorTraceProvider ...
type ErrorTraceProvider WrappedProvider

// Provider specific functions

func (w ErrorTraceProvider) Build(something map[string]interface{}) (p Provider, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.Build(something)
}

func (w ErrorTraceProvider) ListImages(all bool) (images []resources.Image, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListImages(all)
}

func (w ErrorTraceProvider) ListTemplates(all bool) (templates []resources.HostTemplate, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListTemplates(all)
}

func (w ErrorTraceProvider) GetAuthenticationOptions() (cfg providers.Config, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()

	return w.InnerProvider.GetAuthenticationOptions()
}

func (w ErrorTraceProvider) GetConfigurationOptions() (cfg providers.Config, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetConfigurationOptions()
}

func (w ErrorTraceProvider) GetName() string {
	return w.InnerProvider.GetName()
}

// Stack specific functions


// NewErrorTraceProvider ...
func NewErrorTraceProvider(InnerProvider Provider, name string) *ErrorTraceProvider {
	return &ErrorTraceProvider{InnerProvider: InnerProvider, Name: name}
}

// ListAvailabilityZones ...
func (w ErrorTraceProvider) ListAvailabilityZones() (zones map[string]bool, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListAvailabilityZones()
}

// ListRegions ...
func (w ErrorTraceProvider) ListRegions() (regions []string, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListRegions()
}

// GetImage ...
func (w ErrorTraceProvider) GetImage(id string) (images *resources.Image, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetImage(id)
}

// GetTemplate ...
func (w ErrorTraceProvider) GetTemplate(id string) (templates *resources.HostTemplate, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetTemplate(id)
}

// CreateKeyPair ...
func (w ErrorTraceProvider) CreateKeyPair(name string) (pairs *resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.CreateKeyPair(name)
}

// GetKeyPair ...
func (w ErrorTraceProvider) GetKeyPair(id string) (pairs *resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetKeyPair(id)
}

// ListKeyPairs ...
func (w ErrorTraceProvider) ListKeyPairs() (pairs []resources.KeyPair, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListKeyPairs()
}

// DeleteKeyPair ...
func (w ErrorTraceProvider) DeleteKeyPair(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w ErrorTraceProvider) CreateNetwork(req resources.NetworkRequest) (net *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.CreateNetwork(req)
}

// GetNetwork ...
func (w ErrorTraceProvider) GetNetwork(id string) (net *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetNetwork(id)
}

// GetNetworkByName ...
func (w ErrorTraceProvider) GetNetworkByName(name string) (net *resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetNetworkByName(name)
}

// ListNetworks ...
func (w ErrorTraceProvider) ListNetworks() (net []*resources.Network, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListNetworks()
}

// DeleteNetwork ...
func (w ErrorTraceProvider) DeleteNetwork(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.DeleteNetwork(id)
}

// CreateGateway ...
func (w ErrorTraceProvider) CreateGateway(req resources.GatewayRequest) (host *resources.Host, content *userdata.Content, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.CreateGateway(req)
}

// DeleteGateway ...
func (w ErrorTraceProvider) DeleteGateway(networkID string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.DeleteGateway(networkID)
}

// CreateHost ...
func (w ErrorTraceProvider) CreateHost(request resources.HostRequest) (_ *resources.Host, _ *userdata.Content, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.CreateHost(request)
}

// InspectHost ...
func (w ErrorTraceProvider) InspectHost(something interface{}) (_ *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.InspectHost(something)
}

// GetHostByName ...
func (w ErrorTraceProvider) GetHostByName(name string) (_ *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetHostByName(name)
}

// GetHostState ...
func (w ErrorTraceProvider) GetHostState(something interface{}) (_ HostState.Enum, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetHostState(something)
}

// ListHosts ...
func (w ErrorTraceProvider) ListHosts() (_ []*resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListHosts()
}

// DeleteHost ...
func (w ErrorTraceProvider) DeleteHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.DeleteHost(id)
}

// StopHost ...
func (w ErrorTraceProvider) StopHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.StopHost(id)
}

// StartHost ...
func (w ErrorTraceProvider) StartHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.StartHost(id)
}

// RebootHost ...
func (w ErrorTraceProvider) RebootHost(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.RebootHost(id)
}

// ResizeHost ...
func (w ErrorTraceProvider) ResizeHost(id string, request resources.SizingRequirements) (_ *resources.Host, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ResizeHost(id, request)
}

// CreateVolume ...
func (w ErrorTraceProvider) CreateVolume(request resources.VolumeRequest) (_ *resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.CreateVolume(request)
}

// GetVolume ...
func (w ErrorTraceProvider) GetVolume(id string) (_ *resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetVolume(id)
}

// ListVolumes ...
func (w ErrorTraceProvider) ListVolumes() (_ []resources.Volume, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListVolumes()
}

// DeleteVolume ...
func (w ErrorTraceProvider) DeleteVolume(id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w ErrorTraceProvider) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (_ string, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w ErrorTraceProvider) GetVolumeAttachment(serverID, id string) (_ *resources.VolumeAttachment, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments ...
func (w ErrorTraceProvider) ListVolumeAttachments(serverID string) (_ []resources.VolumeAttachment, err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment ...
func (w ErrorTraceProvider) DeleteVolumeAttachment(serverID, id string) (err error) {
	defer func() {
		if err != nil {
			logrus.Tracef("Intercepted error: %v", err)
		}
	}()
	return w.InnerProvider.DeleteVolumeAttachment(serverID, id)
}
