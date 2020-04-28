package api

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

type StackProxy WrappedStack

func errorTranslator(inErr error) (outErr error) {
	if inErr == nil {
		return inErr
	}

	if scerr.ImplementsCauser(inErr) || scerr.ImplementsConsequencer(inErr) {
		return inErr
	}

	return scerr.Wrap(inErr, "wrapped error")
}

func (sp StackProxy) ListAvailabilityZones() (map[string]bool, error) {
	rv, err := sp.InnerStack.ListAvailabilityZones()
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListRegions() ([]string, error) {
	rv, err := sp.InnerStack.ListRegions()
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetImage(id string) (*resources.Image, error) {
	rv, err := sp.InnerStack.GetImage(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetTemplate(id string) (*resources.HostTemplate, error) {
	rv, err := sp.InnerStack.GetTemplate(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) CreateKeyPair(name string) (*resources.KeyPair, error) {
	rv, err := sp.InnerStack.CreateKeyPair(name)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetKeyPair(id string) (*resources.KeyPair, error) {
	rv, err := sp.InnerStack.GetKeyPair(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListKeyPairs() ([]resources.KeyPair, error) {
	rv, err := sp.InnerStack.ListKeyPairs()
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteKeyPair(id string) error {
	err := sp.InnerStack.DeleteKeyPair(id)
	return errorTranslator(err)
}

func (sp StackProxy) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	rv, err := sp.InnerStack.CreateNetwork(req)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetNetwork(id string) (*resources.Network, error) {
	rv, err := sp.InnerStack.GetNetwork(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetNetworkByName(name string) (*resources.Network, error) {
	rv, err := sp.InnerStack.GetNetworkByName(name)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListNetworks() ([]*resources.Network, error) {
	rv, err := sp.InnerStack.ListNetworks()
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteNetwork(id string) error {
	err := sp.InnerStack.DeleteNetwork(id)
	return errorTranslator(err)
}

func (sp StackProxy) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	rv, rv2, err := sp.InnerStack.CreateGateway(req)
	return rv, rv2, errorTranslator(err)
}

func (sp StackProxy) DeleteGateway(networkID string) error {
	err := sp.InnerStack.DeleteGateway(networkID)
	return errorTranslator(err)
}

func (sp StackProxy) CreateVIP(s string, s2 string) (*resources.VirtualIP, error) {
	rv, err := sp.InnerStack.CreateVIP(s, s2)
	return rv, errorTranslator(err)
}

func (sp StackProxy) AddPublicIPToVIP(ip *resources.VirtualIP) error {
	err := sp.InnerStack.AddPublicIPToVIP(ip)
	return errorTranslator(err)
}

func (sp StackProxy) BindHostToVIP(ip *resources.VirtualIP, s string) error {
	err := sp.InnerStack.BindHostToVIP(ip, s)
	return errorTranslator(err)
}

func (sp StackProxy) UnbindHostFromVIP(ip *resources.VirtualIP, s string) error {
	err := sp.InnerStack.UnbindHostFromVIP(ip, s)
	return errorTranslator(err)
}

func (sp StackProxy) DeleteVIP(ip *resources.VirtualIP) error {
	err := sp.InnerStack.DeleteVIP(ip)
	return errorTranslator(err)
}

func (sp StackProxy) CreateHost(request resources.HostRequest) (*resources.Host, *userdata.Content, error) {
	rv, rv2, err := sp.InnerStack.CreateHost(request)
	return rv, rv2, errorTranslator(err)
}

func (sp StackProxy) InspectHost(i interface{}) (*resources.Host, error) {
	rv, err := sp.InnerStack.InspectHost(i)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetHostByName(s string) (*resources.Host, error) {
	rv, err := sp.InnerStack.GetHostByName(s)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetHostState(i interface{}) (hoststate.Enum, error) {
	rv, err := sp.InnerStack.GetHostState(i)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListHosts() ([]*resources.Host, error) {
	rv, err := sp.InnerStack.ListHosts()
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteHost(id string) error {
	err := sp.InnerStack.DeleteHost(id)
	return errorTranslator(err)
}

func (sp StackProxy) StopHost(id string) error {
	err := sp.InnerStack.StopHost(id)
	return errorTranslator(err)
}

func (sp StackProxy) StartHost(id string) error {
	err := sp.InnerStack.StartHost(id)
	return errorTranslator(err)
}

func (sp StackProxy) RebootHost(id string) error {
	err := sp.InnerStack.RebootHost(id)
	return errorTranslator(err)
}

func (sp StackProxy) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	rv, err := sp.InnerStack.ResizeHost(id, request)
	return rv, errorTranslator(err)
}

func (sp StackProxy) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	rv, err := sp.InnerStack.CreateVolume(request)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetVolume(id string) (*resources.Volume, error) {
	rv, err := sp.InnerStack.GetVolume(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListVolumes() ([]resources.Volume, error) {
	rv, err := sp.InnerStack.ListVolumes()
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteVolume(id string) error {
	err := sp.InnerStack.DeleteVolume(id)
	return errorTranslator(err)
}

func (sp StackProxy) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	rv, err := sp.InnerStack.CreateVolumeAttachment(request)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	rv, err := sp.InnerStack.GetVolumeAttachment(serverID, id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	rv, err := sp.InnerStack.ListVolumeAttachments(serverID)
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteVolumeAttachment(serverID, id string) error {
	err := sp.InnerStack.DeleteVolumeAttachment(serverID, id)
	return errorTranslator(err)
}
