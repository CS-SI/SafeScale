package api

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
)

// ValidStack ...
type ValidStack WrappedStack

// NewValidStack ...
func NewValidStack(innerStack Stack, name string) *ValidStack {
	return &ValidStack{InnerStack: innerStack, Name: name}
}

// ListAvailabilityZones ...
func (w ValidStack) ListAvailabilityZones() (map[string]bool, error) {
	return w.InnerStack.ListAvailabilityZones()
}

// ListRegions ...
func (w ValidStack) ListRegions() ([]string, error) {
	return w.InnerStack.ListRegions()
}

// func (w ValidStack) ListImages() ([]resources.Image, error) {
// 	return w.InnerStack.ListImages()
// }

func (w ValidStack) GetImage(id string) (*resources.Image, error) {
	return w.InnerStack.GetImage(id)
}

func (w ValidStack) GetTemplate(id string) (*resources.HostTemplate, error) {
	return w.InnerStack.GetTemplate(id)
}

// func (w ValidStack) ListTemplates() ([]resources.HostTemplate, error) {
// 	hostTemplates, err := w.InnerStack.ListTemplates()
// 	return hostTemplates, err
// }

func (w ValidStack) CreateKeyPair(name string) (*resources.KeyPair, error) {
	return w.InnerStack.CreateKeyPair(name)
}

func (w ValidStack) GetKeyPair(id string) (*resources.KeyPair, error) {
	return w.InnerStack.GetKeyPair(id)
}

func (w ValidStack) ListKeyPairs() ([]resources.KeyPair, error) {
	return w.InnerStack.ListKeyPairs()
}

func (w ValidStack) DeleteKeyPair(id string) error {
	return w.InnerStack.DeleteKeyPair(id)
}

func (w ValidStack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	return w.InnerStack.CreateNetwork(req)
}

func (w ValidStack) GetNetwork(id string) (*resources.Network, error) {
	return w.InnerStack.GetNetwork(id)
}

func (w ValidStack) GetNetworkByName(name string) (*resources.Network, error) {
	return w.InnerStack.GetNetworkByName(name)
}

func (w ValidStack) ListNetworks() ([]*resources.Network, error) {
	return w.InnerStack.ListNetworks()
}

func (w ValidStack) DeleteNetwork(id string) error {
	return w.InnerStack.DeleteNetwork(id)
}

func (w ValidStack) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	return w.InnerStack.CreateGateway(req)
}

func (w ValidStack) DeleteGateway(networkID string) error {
	return w.InnerStack.DeleteGateway(networkID)
}

func (w ValidStack) CreateHost(request resources.HostRequest) (*resources.Host, *userdata.Content, error) {
	return w.InnerStack.CreateHost(request)
}

func (w ValidStack) InspectHost(something interface{}) (*resources.Host, error) {
	return w.InnerStack.InspectHost(something)
}

func (w ValidStack) GetHostByName(name string) (*resources.Host, error) {
	return w.InnerStack.GetHostByName(name)
}

func (w ValidStack) GetHostState(something interface{}) (HostState.Enum, error) {
	return w.InnerStack.GetHostState(something)
}

func (w ValidStack) ListHosts() ([]*resources.Host, error) {
	return w.InnerStack.ListHosts()
}

func (w ValidStack) DeleteHost(id string) error {
	return w.InnerStack.DeleteHost(id)
}

func (w ValidStack) StopHost(id string) error {
	return w.InnerStack.StopHost(id)
}

func (w ValidStack) StartHost(id string) error {
	return w.InnerStack.StartHost(id)
}

func (w ValidStack) RebootHost(id string) error {
	return w.InnerStack.RebootHost(id)
}

func (w ValidStack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	return w.InnerStack.ResizeHost(id, request)
}

func (w ValidStack) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	return w.InnerStack.CreateVolume(request)
}

func (w ValidStack) GetVolume(id string) (*resources.Volume, error) {
	return w.InnerStack.GetVolume(id)
}

func (w ValidStack) ListVolumes() ([]resources.Volume, error) {
	return w.InnerStack.ListVolumes()
}

func (w ValidStack) DeleteVolume(id string) error {
	return w.InnerStack.DeleteVolume(id)
}

func (w ValidStack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	return w.InnerStack.CreateVolumeAttachment(request)
}

func (w ValidStack) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	return w.InnerStack.GetVolumeAttachment(serverID, id)
}

func (w ValidStack) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	return w.InnerStack.ListVolumeAttachments(serverID)
}

func (w ValidStack) DeleteVolumeAttachment(serverID, id string) error {
	return w.InnerStack.DeleteVolumeAttachment(serverID, id)
}

// func (w ValidStack) GetConfigurationOptions() stacks.ConfigurationOptions {
// 	return w.InnerStack.GetConfigurationOptions()
// }

// func (w ValidStack) GetAuthenticationOptions() stacks.AuthenticationOptions {
// 	return w.InnerStack.GetAuthenticationOptions()
// }
