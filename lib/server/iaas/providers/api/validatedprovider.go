package api

import (
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ValidatedProvider ...
type ValidatedProvider WrappedProvider

func (w ValidatedProvider) CreateVIP(first string, second string) (_ *abstract.VirtualIP, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.CreateVIP(first, second)
}

func (w ValidatedProvider) AddPublicIPToVIP(res *abstract.VirtualIP) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.AddPublicIPToVIP(res)
}

func (w ValidatedProvider) BindHostToVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	return w.InnerProvider.BindHostToVIP(vip, hostID)
}

func (w ValidatedProvider) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
	}
	if hostID == "" {
		return fail.InvalidParameterError("host", "cannot be empty string")
	}

	return w.InnerProvider.UnbindHostFromVIP(vip, hostID)
}

func (w ValidatedProvider) DeleteVIP(vip *abstract.VirtualIP) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if vip == nil {
		return fail.InvalidParameterError("vip", "cannot be nil")
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

func (w ValidatedProvider) Build(something map[string]interface{}) (p Provider, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.Build(something)
}

func (w ValidatedProvider) ListImages(all bool) (res []abstract.Image, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	res, xerr = w.InnerProvider.ListImages(all)
	if xerr != nil {
		for _, image := range res {
			if !image.OK() {
				logrus.Warnf("Invalid image: %v", image)
			}
		}
	}
	return res, xerr
}

func (w ValidatedProvider) ListTemplates(all bool) (res []abstract.HostTemplate, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	res, xerr = w.InnerProvider.ListTemplates(all)
	if xerr != nil {
		for _, hostTemplate := range res {
			if !hostTemplate.OK() {
				logrus.Warnf("Invalid host template: %v", hostTemplate)
			}
		}
	}
	return res, xerr
}

func (w ValidatedProvider) GetAuthenticationOptions() (_ providers.Config, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.GetAuthenticationOptions()
}

func (w ValidatedProvider) GetConfigurationOptions() (_ providers.Config, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

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
func (w ValidatedProvider) ListAvailabilityZones() (_ map[string]bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.ListAvailabilityZones()
}

// ListRegions ...
func (w ValidatedProvider) ListRegions() (_ []string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.ListRegions()
}

// GetImage ...
func (w ValidatedProvider) GetImage(id string) (res *abstract.Image, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.GetImage(id)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid image: %v", *res)
			}
		}
	}

	return res, xerr
}

// GetTemplate ...
func (w ValidatedProvider) GetTemplate(id string) (res *abstract.HostTemplate, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.GetTemplate(id)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid template: %v", *res)
			}
		}
	}
	return res, xerr
}

// CreateKeyPair ...
func (w ValidatedProvider) CreateKeyPair(name string) (kp *abstract.KeyPair, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	kp, xerr = w.InnerProvider.CreateKeyPair(name)
	if xerr != nil {
		if kp == nil {
			logrus.Warn("Invalid keypair !")
		}
	}
	return kp, xerr
}

// GetKeyPair ...
func (w ValidatedProvider) GetKeyPair(id string) (kp *abstract.KeyPair, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be nil")
	}

	kp, xerr = w.InnerProvider.GetKeyPair(id)
	if xerr != nil {
		if kp == nil {
			logrus.Warn("Invalid keypair !")
		}
	}
	return kp, xerr
}

// ListKeyPairs ...
func (w ValidatedProvider) ListKeyPairs() (res []abstract.KeyPair, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.ListKeyPairs()
}

// DeleteKeyPair ...
func (w ValidatedProvider) DeleteKeyPair(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	return w.InnerProvider.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w ValidatedProvider) CreateNetwork(req abstract.NetworkRequest) (res *abstract.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	res, xerr = w.InnerProvider.CreateNetwork(req)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid network: %v", *res)
			}
		}
	}
	return res, xerr
}

// GetNetwork ...
func (w ValidatedProvider) GetNetwork(id string) (res *abstract.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.GetNetwork(id)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid network: %v", *res)
			}
		}
	}
	return res, xerr
}

// GetNetworkByName ...
func (w ValidatedProvider) GetNetworkByName(name string) (res *abstract.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.GetNetworkByName(name)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid network: %v", *res)
			}
		}
	}
	return res, xerr
}

// ListNetworks ...
func (w ValidatedProvider) ListNetworks() (res []*abstract.Network, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	res, xerr = w.InnerProvider.ListNetworks()
	if xerr != nil {
		for _, item := range res {
			if item != nil {
				if !item.OK() {
					logrus.Warnf("Invalid network: %v", *item)
				}
			}
		}
	}
	return res, xerr
}

// DeleteNetwork ...
func (w ValidatedProvider) DeleteNetwork(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.DeleteNetwork(id)
}

// CreateGateway ...
func (w ValidatedProvider) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (res *abstract.Host, data *userdata.Content, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if req.KeyPair == nil {
		return nil, nil, fail.InvalidParameterError("request.KeyPair", "cannot be nil")
	}

	if req.Network == nil {
		return nil, nil, fail.InvalidParameterError("req.Network", "cannot be nil")
	}

	res, data, xerr = w.InnerProvider.CreateGateway(req, sizing)
	if xerr != nil {
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
	return res, data, xerr
}

// DeleteGateway ...
func (w ValidatedProvider) DeleteGateway(networkID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if networkID == "" {
		return fail.InvalidParameterError("networkID", "cannot be empty string")
	}

	return w.InnerProvider.DeleteGateway(networkID)
}

// CreateHost ...
func (w ValidatedProvider) CreateHost(request abstract.HostRequest) (res *abstract.Host, data *userdata.Content, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if request.KeyPair == nil {
		return nil, nil, fail.InvalidParameterError("request.KeyPair", "cannot be nil")
	}

	res, data, xerr = w.InnerProvider.CreateHost(request)
	if xerr != nil {
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
	return res, data, xerr
}

// InspectHost ...
func (w ValidatedProvider) InspectHost(something interface{}) (res *abstract.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	res, xerr = w.InnerProvider.InspectHost(something)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
	}
	return res, xerr
}

// GetHostByName ...
func (w ValidatedProvider) GetHostByName(name string) (res *abstract.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.GetHostByName(name)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
	}
	return res, xerr
}

// GetHostByID ...
func (w ValidatedProvider) GetHostByID(name string) (res *abstract.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.GetHostByID(name)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
	}
	return res, xerr
}

// GetHostState ...
func (w ValidatedProvider) GetHostState(something interface{}) (res hoststate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	return w.InnerProvider.GetHostState(something)
}

// ListHosts ...
func (w ValidatedProvider) ListHosts() (res []*abstract.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	res, xerr = w.InnerProvider.ListHosts()
	if xerr != nil {
		for _, item := range res {
			if item != nil {
				if !item.OK() {
					logrus.Warnf("Invalid host: %v", *item)
				}
			}
		}
	}
	return res, xerr
}

// DeleteHost ...
func (w ValidatedProvider) DeleteHost(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	return w.InnerProvider.DeleteHost(id)
}

// StopHost ...
func (w ValidatedProvider) StopHost(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	return w.InnerProvider.StopHost(id)
}

// StartHost ...
func (w ValidatedProvider) StartHost(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	return w.InnerProvider.StartHost(id)
}

// RebootHost ...
func (w ValidatedProvider) RebootHost(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	return w.InnerProvider.RebootHost(id)
}

// ResizeHost ...
func (w ValidatedProvider) ResizeHost(id string, request abstract.SizingRequirements) (res *abstract.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.ResizeHost(id, request)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid host: %v", *res)
			}
		}
	}
	return res, xerr
}

// CreateVolume ...
func (w ValidatedProvider) CreateVolume(request abstract.VolumeRequest) (res *abstract.Volume, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if request.Name == "" {
		return nil, fail.InvalidParameterError("request.Name", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.CreateVolume(request)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid volume: %v", *res)
			}
		}
	}
	return res, xerr
}

// GetVolume ...
func (w ValidatedProvider) GetVolume(id string) (res *abstract.Volume, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.GetVolume(id)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid volume: %v", *res)
			}
		}
	}
	return res, xerr
}

// ListVolumes ...
func (w ValidatedProvider) ListVolumes() (res []abstract.Volume, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	res, xerr = w.InnerProvider.ListVolumes()
	if xerr != nil {
		for _, item := range res {
			if !item.OK() {
				logrus.Warnf("Invalid host: %v", item)
			}
		}
	}
	return res, xerr
}

// DeleteVolume ...
func (w ValidatedProvider) DeleteVolume(id string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	return w.InnerProvider.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w ValidatedProvider) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (id string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if request.Name == "" {
		return "", fail.InvalidParameterError("request.Name", "cannot be empty string")
	}
	if request.HostID == "" {
		return "", fail.InvalidParameterError("HostID", "cannot be empty string")
	}
	if request.VolumeID == "" {
		return "", fail.InvalidParameterError("VolumeID", "cannot be empty string")
	}

	return w.InnerProvider.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w ValidatedProvider) GetVolumeAttachment(serverID, id string) (res *abstract.VolumeAttachment, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if serverID == "" {
		return nil, fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.GetVolumeAttachment(serverID, id)
	if xerr != nil {
		if res != nil {
			if !res.OK() {
				logrus.Warnf("Invalid volume attachment: %v", *res)
			}
		}
	}
	return res, xerr
}

// ListVolumeAttachments ...
func (w ValidatedProvider) ListVolumeAttachments(serverID string) (res []abstract.VolumeAttachment, xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if serverID == "" {
		return nil, fail.InvalidParameterError("serverID", "cannot be empty string")
	}

	res, xerr = w.InnerProvider.ListVolumeAttachments(serverID)
	if xerr != nil {
		for _, item := range res {
			if !item.OK() {
				logrus.Warnf("Invalid volume attachment: %v", item)
			}
		}
	}
	return res, xerr
}

// DeleteVolumeAttachment ...
func (w ValidatedProvider) DeleteVolumeAttachment(serverID, vaID string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)()

	if serverID == "" {
		return fail.InvalidParameterError("serverID", "cannot be empty string")
	}
	if vaID == "" {
		return fail.InvalidParameterError("vaID", "cannot be empty string")
	}

	return w.InnerProvider.DeleteVolumeAttachment(serverID, vaID)
}
