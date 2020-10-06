package api

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/userdata"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

type StackProxy WrappedStack

func errorTranslator(inErr fail.Error) (outErr fail.Error) {
	if inErr == nil {
		return inErr
	}

	if fail.ImplementsCauser(inErr) || fail.ImplementsConsequencer(inErr) {
		return inErr
	}

	return fail.Wrap(inErr, "wrapped error")
}

func (sp StackProxy) ListAvailabilityZones() (map[string]bool, fail.Error) {
	rv, err := sp.InnerStack.ListAvailabilityZones()
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListRegions() ([]string, fail.Error) {
	rv, err := sp.InnerStack.ListRegions()
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetImage(id string) (*abstract.Image, fail.Error) {
	rv, err := sp.InnerStack.GetImage(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetTemplate(id string) (*abstract.HostTemplate, fail.Error) {
	rv, err := sp.InnerStack.GetTemplate(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	rv, err := sp.InnerStack.CreateKeyPair(name)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	rv, err := sp.InnerStack.GetKeyPair(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	rv, err := sp.InnerStack.ListKeyPairs()
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteKeyPair(id string) error {
	err := sp.InnerStack.DeleteKeyPair(id)
	return errorTranslator(err)
}

func (sp StackProxy) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	rv, err := sp.InnerStack.CreateNetwork(req)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetNetwork(id string) (*abstract.Network, fail.Error) {
	rv, err := sp.InnerStack.GetNetwork(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetNetworkByName(name string) (*abstract.Network, fail.Error) {
	rv, err := sp.InnerStack.GetNetworkByName(name)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListNetworks() ([]*abstract.Network, fail.Error) {
	rv, err := sp.InnerStack.ListNetworks()
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteNetwork(id string) error {
	err := sp.InnerStack.DeleteNetwork(id)
	return errorTranslator(err)
}

func (sp StackProxy) CreateGateway(req abstract.GatewayRequest, sizing *abstract.SizingRequirements) (*abstract.Host, *userdata.Content, fail.Error) {
	rv, rv2, err := sp.InnerStack.CreateGateway(req, sizing)
	return rv, rv2, errorTranslator(err)
}

func (sp StackProxy) DeleteGateway(networkID string) error {
	err := sp.InnerStack.DeleteGateway(networkID)
	return errorTranslator(err)
}

func (sp StackProxy) CreateVIP(s string, s2 string) (*abstract.VirtualIP, fail.Error) {
	rv, err := sp.InnerStack.CreateVIP(s, s2)
	return rv, errorTranslator(err)
}

func (sp StackProxy) AddPublicIPToVIP(ip *abstract.VirtualIP) error {
	err := sp.InnerStack.AddPublicIPToVIP(ip)
	return errorTranslator(err)
}

func (sp StackProxy) BindHostToVIP(ip *abstract.VirtualIP, s string) error {
	err := sp.InnerStack.BindHostToVIP(ip, s)
	return errorTranslator(err)
}

func (sp StackProxy) UnbindHostFromVIP(ip *abstract.VirtualIP, s string) error {
	err := sp.InnerStack.UnbindHostFromVIP(ip, s)
	return errorTranslator(err)
}

func (sp StackProxy) DeleteVIP(ip *abstract.VirtualIP) error {
	err := sp.InnerStack.DeleteVIP(ip)
	return errorTranslator(err)
}

func (sp StackProxy) CreateHost(request abstract.HostRequest) (*abstract.Host, *userdata.Content, fail.Error) {
	rv, rv2, err := sp.InnerStack.CreateHost(request)
	return rv, rv2, errorTranslator(err)
}

func (sp StackProxy) InspectHost(i interface{}) (*abstract.Host, fail.Error) {
	rv, err := sp.InnerStack.InspectHost(i)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetHostByName(s string) (*abstract.Host, fail.Error) {
	rv, err := sp.InnerStack.GetHostByName(s)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetHostState(i interface{}) (hoststate.Enum, fail.Error) {
	rv, err := sp.InnerStack.GetHostState(i)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListHosts() ([]*abstract.Host, fail.Error) {
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

func (sp StackProxy) ResizeHost(id string, request abstract.SizingRequirements) (*abstract.Host, fail.Error) {
	rv, err := sp.InnerStack.ResizeHost(id, request)
	return rv, errorTranslator(err)
}

func (sp StackProxy) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	rv, err := sp.InnerStack.CreateVolume(request)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetVolume(id string) (*abstract.Volume, fail.Error) {
	rv, err := sp.InnerStack.GetVolume(id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListVolumes() ([]abstract.Volume, fail.Error) {
	rv, err := sp.InnerStack.ListVolumes()
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteVolume(id string) error {
	err := sp.InnerStack.DeleteVolume(id)
	return errorTranslator(err)
}

func (sp StackProxy) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	rv, err := sp.InnerStack.CreateVolumeAttachment(request)
	return rv, errorTranslator(err)
}

func (sp StackProxy) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	rv, err := sp.InnerStack.GetVolumeAttachment(serverID, id)
	return rv, errorTranslator(err)
}

func (sp StackProxy) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	rv, err := sp.InnerStack.ListVolumeAttachments(serverID)
	return rv, errorTranslator(err)
}

func (sp StackProxy) DeleteVolumeAttachment(serverID, id string) error {
	err := sp.InnerStack.DeleteVolumeAttachment(serverID, id)
	return errorTranslator(err)
}
