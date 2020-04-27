package api

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
)

type StackProxy WrappedStack

func errorTranslator(inErr error) (outErr error) {
	if inErr == nil {
		return inErr
	}

	// TODO Wrap inErr if needed here

	return inErr
}

func (sp StackProxy) ListAvailabilityZones() (map[string]bool, error) {
	panic("implement me")
}

func (sp StackProxy) ListRegions() ([]string, error) {
	panic("implement me")
}

func (sp StackProxy) GetImage(id string) (*resources.Image, error) {
	panic("implement me")
}

func (sp StackProxy) GetTemplate(id string) (*resources.HostTemplate, error) {
	panic("implement me")
}

func (sp StackProxy) CreateKeyPair(name string) (*resources.KeyPair, error) {
	panic("implement me")
}

func (sp StackProxy) GetKeyPair(id string) (*resources.KeyPair, error) {
	panic("implement me")
}

func (sp StackProxy) ListKeyPairs() ([]resources.KeyPair, error) {
	panic("implement me")
}

func (sp StackProxy) DeleteKeyPair(id string) error {
	panic("implement me")
}

func (sp StackProxy) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	panic("implement me")
}

func (sp StackProxy) GetNetwork(id string) (*resources.Network, error) {
	panic("implement me")
}

func (sp StackProxy) GetNetworkByName(name string) (*resources.Network, error) {
	panic("implement me")
}

func (sp StackProxy) ListNetworks() ([]*resources.Network, error) {
	panic("implement me")
}

func (sp StackProxy) DeleteNetwork(id string) error {
	panic("implement me")
}

func (sp StackProxy) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	panic("implement me")
}

func (sp StackProxy) DeleteGateway(networkID string) error {
	panic("implement me")
}

func (sp StackProxy) CreateVIP(s string, s2 string) (*resources.VirtualIP, error) {
	panic("implement me")
}

func (sp StackProxy) AddPublicIPToVIP(ip *resources.VirtualIP) error {
	panic("implement me")
}

func (sp StackProxy) BindHostToVIP(ip *resources.VirtualIP, s string) error {
	panic("implement me")
}

func (sp StackProxy) UnbindHostFromVIP(ip *resources.VirtualIP, s string) error {
	panic("implement me")
}

func (sp StackProxy) DeleteVIP(ip *resources.VirtualIP) error {
	panic("implement me")
}

func (sp StackProxy) CreateHost(request resources.HostRequest) (*resources.Host, *userdata.Content, error) {
	panic("implement me")
}

func (sp StackProxy) InspectHost(i interface{}) (*resources.Host, error) {
	panic("implement me")
}

func (sp StackProxy) GetHostByName(s string) (*resources.Host, error) {
	panic("implement me")
}

func (sp StackProxy) GetHostState(i interface{}) (hoststate.Enum, error) {
	panic("implement me")
}

func (sp StackProxy) ListHosts() ([]*resources.Host, error) {
	panic("implement me")
}

func (sp StackProxy) DeleteHost(id string) error {
	panic("implement me")
}

func (sp StackProxy) StopHost(id string) error {
	panic("implement me")
}

func (sp StackProxy) StartHost(id string) error {
	panic("implement me")
}

func (sp StackProxy) RebootHost(id string) error {
	panic("implement me")
}

func (sp StackProxy) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	panic("implement me")
}

func (sp StackProxy) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	panic("implement me")
}

func (sp StackProxy) GetVolume(id string) (*resources.Volume, error) {
	panic("implement me")
}

func (sp StackProxy) ListVolumes() ([]resources.Volume, error) {
	panic("implement me")
}

func (sp StackProxy) DeleteVolume(id string) error {
	panic("implement me")
}

func (sp StackProxy) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	panic("implement me")
}

func (sp StackProxy) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	panic("implement me")
}

func (sp StackProxy) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	panic("implement me")
}

func (sp StackProxy) DeleteVolumeAttachment(serverID, id string) error {
	panic("implement me")
}
