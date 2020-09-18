package api

import (
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// ValidatedProvider ...
type ValidatedProvider WrappedProvider

func (w ValidatedProvider) CreateVIP(first string, second string) (_ *resources.VirtualIP, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.CreateVIP(first, second)
}

func (w ValidatedProvider) AddPublicIPToVIP(res *resources.VirtualIP) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.AddPublicIPToVIP(res)
}

func (w ValidatedProvider) BindHostToVIP(res *resources.VirtualIP, ip string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.BindHostToVIP(res, ip)
}

func (w ValidatedProvider) UnbindHostFromVIP(res *resources.VirtualIP, ip string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.UnbindHostFromVIP(res, ip)
}

func (w ValidatedProvider) DeleteVIP(vip *resources.VirtualIP) (err error) {
	defer scerr.OnPanic(&err)()

	if vip == nil {
		return scerr.InvalidParameterError("vip", "cannot be nil")
	}

	return w.InnerProvider.DeleteVIP(vip)
}

func (w ValidatedProvider) GetCapabilities() providers.Capabilities {
	return w.InnerProvider.GetCapabilities()
}

func (w ValidatedProvider) GetTenantParameters() map[string]interface{} {
	return w.InnerProvider.GetTenantParameters()
}

// Provider specific functions

func (w ValidatedProvider) Build(something map[string]interface{}) (p Provider, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.Build(something)
}

func (w ValidatedProvider) ListImages(all bool) (res []resources.Image, err error) {
	defer scerr.OnPanic(&err)()

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

func (w ValidatedProvider) ListTemplates(all bool) (res []resources.HostTemplate, err error) {
	defer scerr.OnPanic(&err)()

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

func (w ValidatedProvider) GetAuthenticationOptions() (_ providers.Config, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.GetAuthenticationOptions()
}

func (w ValidatedProvider) GetConfigurationOptions() (_ providers.Config, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.GetConfigurationOptions()
}

func (w ValidatedProvider) GetName() string {
	return w.InnerProvider.GetName()
}

// Stack specific functions

// NewValidatedProvider ...
func NewValidatedProvider(InnerProvider Provider, name string) *ValidatedProvider {
	return &ValidatedProvider{InnerProvider: InnerProvider, Name: name}
}

// ListAvailabilityZones ...
func (w ValidatedProvider) ListAvailabilityZones() (_ map[string]bool, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.ListAvailabilityZones()
}

// ListRegions ...
func (w ValidatedProvider) ListRegions() (_ []string, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.ListRegions()
}

// GetImage ...
func (w ValidatedProvider) GetImage(id string) (res *resources.Image, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.GetImage(id)
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
func (w ValidatedProvider) GetTemplate(id string) (res *resources.HostTemplate, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.GetTemplate(id)
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
func (w ValidatedProvider) CreateKeyPair(name string) (kp *resources.KeyPair, err error) {
	defer scerr.OnPanic(&err)()

	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty")
	}

	kp, err = w.InnerProvider.CreateKeyPair(name)
	if err != nil {
		if kp == nil {
			logrus.Warn("Invalid keypair !")
		}
	}
	return kp, err
}

// GetKeyPair ...
func (w ValidatedProvider) GetKeyPair(id string) (kp *resources.KeyPair, err error) {
	defer scerr.OnPanic(&err)()

	kp, err = w.InnerProvider.GetKeyPair(id)
	if err != nil {
		if kp == nil {
			logrus.Warn("Invalid keypair !")
		}
	}
	return kp, err
}

// ListKeyPairs ...
func (w ValidatedProvider) ListKeyPairs() (res []resources.KeyPair, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.ListKeyPairs()
}

// DeleteKeyPair ...
func (w ValidatedProvider) DeleteKeyPair(id string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w ValidatedProvider) CreateNetwork(req resources.NetworkRequest) (res *resources.Network, err error) {
	defer scerr.OnPanic(&err)()

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
func (w ValidatedProvider) GetNetwork(id string) (res *resources.Network, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.GetNetwork(id)
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
func (w ValidatedProvider) GetNetworkByName(name string) (res *resources.Network, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.GetNetworkByName(name)
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
func (w ValidatedProvider) ListNetworks() (res []*resources.Network, err error) {
	defer scerr.OnPanic(&err)()

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
func (w ValidatedProvider) DeleteNetwork(id string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.DeleteNetwork(id)
}

// CreateGateway ...
func (w ValidatedProvider) CreateGateway(req resources.GatewayRequest, sizing *resources.SizingRequirements) (res *resources.Host, data *userdata.Content, err error) {
	defer scerr.OnPanic(&err)()

	res, data, err = w.InnerProvider.CreateGateway(req, sizing)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
		if data != nil {
			if !data.OK() {
				logrus.Warnf("Invalid userdata: %v", *data)
			}
		}
	}
	return res, data, err
}

// DeleteGateway ...
func (w ValidatedProvider) DeleteGateway(networkID string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.DeleteGateway(networkID)
}

// CreateHost ...
func (w ValidatedProvider) CreateHost(request resources.HostRequest) (res *resources.Host, data *userdata.Content, err error) {
	defer scerr.OnPanic(&err)()

	res, data, err = w.InnerProvider.CreateHost(request)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
		if data != nil {
			if !data.OK() {
				logrus.Warnf("Invalid userdata: %v", *data)
			}
		}
	}
	return res, data, err
}

// InspectHost ...
func (w ValidatedProvider) InspectHost(something interface{}) (res *resources.Host, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.InspectHost(something)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
	}
	return res, err
}

// GetHostByName ...
func (w ValidatedProvider) GetHostByName(name string) (res *resources.Host, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.GetHostByName(name)
	if err != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
	}
	return res, err
}

// GetHostState ...
func (w ValidatedProvider) GetHostState(something interface{}) (res hoststate.Enum, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.GetHostState(something)
}

// ListHosts ...
func (w ValidatedProvider) ListHosts() (res []*resources.Host, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.ListHosts()
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
func (w ValidatedProvider) DeleteHost(id string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.DeleteHost(id)
}

// StopHost ...
func (w ValidatedProvider) StopHost(id string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.StopHost(id)
}

// StartHost ...
func (w ValidatedProvider) StartHost(id string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.StartHost(id)
}

// RebootHost ...
func (w ValidatedProvider) RebootHost(id string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.RebootHost(id)
}

// ResizeHost ...
func (w ValidatedProvider) ResizeHost(id string, request resources.SizingRequirements) (res *resources.Host, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.ResizeHost(id, request)
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
func (w ValidatedProvider) CreateVolume(request resources.VolumeRequest) (res *resources.Volume, err error) {
	defer scerr.OnPanic(&err)()

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
func (w ValidatedProvider) GetVolume(id string) (res *resources.Volume, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.GetVolume(id)
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
func (w ValidatedProvider) ListVolumes() (res []resources.Volume, err error) {
	defer scerr.OnPanic(&err)()

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
func (w ValidatedProvider) DeleteVolume(id string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w ValidatedProvider) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (id string, err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w ValidatedProvider) GetVolumeAttachment(serverID, id string) (res *resources.VolumeAttachment, err error) {
	defer scerr.OnPanic(&err)()

	res, err = w.InnerProvider.GetVolumeAttachment(serverID, id)
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
func (w ValidatedProvider) ListVolumeAttachments(serverID string) (res []resources.VolumeAttachment, err error) {
	defer scerr.OnPanic(&err)()

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
func (w ValidatedProvider) DeleteVolumeAttachment(serverID, id string) (err error) {
	defer scerr.OnPanic(&err)()

	return w.InnerProvider.DeleteVolumeAttachment(serverID, id)
}
