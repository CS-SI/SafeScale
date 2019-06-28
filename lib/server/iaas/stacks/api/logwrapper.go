package api

import (
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/sirupsen/logrus"
)

// LoggedStack ...
type LoggedStack WrappedStack

// tgrace ...
func (w LoggedStack) trace(s string) (string, time.Time) {
	logrus.Debugf(">>> stacks.%s::%s() called", w.Name, s)
	return s, time.Now()
}

// prepare ...
func (w LoggedStack) prepare(s string, startTime time.Time) {
	logrus.Debugf("<<< stacks.%s::%s() done in %d ms", w.Name, s, time.Since(startTime).Nanoseconds()/1000000)
}

// NewLoggedStack ...
func NewLoggedStack(innerStack Stack, name string) *LoggedStack {
	return &LoggedStack{InnerStack: innerStack, Name: name}
}

// ListAvailabilityZones ...
func (w LoggedStack) ListAvailabilityZones() (map[string]bool, error) {
	defer w.prepare(w.trace("ListAvailabilityZones"))
	return w.InnerStack.ListAvailabilityZones()
}

// ListRegions ...
func (w LoggedStack) ListRegions() ([]string, error) {
	defer w.prepare(w.trace("ListRegions"))
	return w.InnerStack.ListRegions()
}

// func (w LoggedStack) ListImages() ([]resources.Image, error) {
// 	defer w.prepare(w.trace("ListImages"))
// 	return w.InnerStack.ListImages()
// }

// GetImage ...
func (w LoggedStack) GetImage(id string) (*resources.Image, error) {
	defer w.prepare(w.trace("GetImage"))
	return w.InnerStack.GetImage(id)
}

// GetTemplate ...
func (w LoggedStack) GetTemplate(id string) (*resources.HostTemplate, error) {
	defer w.prepare(w.trace("GetTemplate"))
	return w.InnerStack.GetTemplate(id)
}

// // ListTemplates ...
// func (w LoggedStack) ListTemplates(all bool) ([]resources.HostTemplate, error) {
// 	defer w.prepare(w.trace("ListTemplates"))
// 	return w.InnerStack.ListTemplates(all)
// }

// CreateKeyPair ...
func (w LoggedStack) CreateKeyPair(name string) (*resources.KeyPair, error) {
	defer w.prepare(w.trace("CreateKeyPair"))
	return w.InnerStack.CreateKeyPair(name)
}

// GetKeyPair ...
func (w LoggedStack) GetKeyPair(id string) (*resources.KeyPair, error) {
	defer w.prepare(w.trace("GetKeyPair"))
	return w.InnerStack.GetKeyPair(id)
}

// ListKeyPairs ...
func (w LoggedStack) ListKeyPairs() ([]resources.KeyPair, error) {
	defer w.prepare(w.trace("ListKeyPairs"))
	return w.InnerStack.ListKeyPairs()
}

// DeleteKeyPair ...
func (w LoggedStack) DeleteKeyPair(id string) error {
	defer w.prepare(w.trace("DeleteKeyPair"))
	return w.InnerStack.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w LoggedStack) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	defer w.prepare(w.trace("CreateNetwork"))
	return w.InnerStack.CreateNetwork(req)
}

// GetNetwork ...
func (w LoggedStack) GetNetwork(id string) (*resources.Network, error) {
	defer w.prepare(w.trace("GetNetwork"))
	return w.InnerStack.GetNetwork(id)
}

// GetNetworkByName ...
func (w LoggedStack) GetNetworkByName(name string) (*resources.Network, error) {
	defer w.prepare(w.trace("GetNetworkByName"))
	return w.InnerStack.GetNetworkByName(name)
}

// ListNetworks ...
func (w LoggedStack) ListNetworks() ([]*resources.Network, error) {
	defer w.prepare(w.trace("ListNetworks"))
	return w.InnerStack.ListNetworks()
}

// DeleteNetwork ...
func (w LoggedStack) DeleteNetwork(id string) error {
	defer w.prepare(w.trace("DeleteNetwork"))
	return w.InnerStack.DeleteNetwork(id)
}

// CreateGateway ...
func (w LoggedStack) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	defer w.prepare(w.trace("CreateGateway"))
	return w.InnerStack.CreateGateway(req)
}

// DeleteGateway ...
func (w LoggedStack) DeleteGateway(networkID string) error {
	defer w.prepare(w.trace("DeleteGateway"))
	return w.InnerStack.DeleteGateway(networkID)
}

// CreateHost ...
func (w LoggedStack) CreateHost(request resources.HostRequest) (*resources.Host, *userdata.Content, error) {
	defer w.prepare(w.trace("CreateHost"))
	return w.InnerStack.CreateHost(request)
}

// InspectHost ...
func (w LoggedStack) InspectHost(something interface{}) (*resources.Host, error) {
	defer w.prepare(w.trace("InspectHost"))
	return w.InnerStack.InspectHost(something)
}

// GetHostByName ...
func (w LoggedStack) GetHostByName(name string) (*resources.Host, error) {
	defer w.prepare(w.trace("GetHostByName"))
	return w.InnerStack.GetHostByName(name)
}

// GetHostState ...
func (w LoggedStack) GetHostState(something interface{}) (HostState.Enum, error) {
	defer w.prepare(w.trace("GetHostState"))
	return w.InnerStack.GetHostState(something)
}

// ListHosts ...
func (w LoggedStack) ListHosts() ([]*resources.Host, error) {
	defer w.prepare(w.trace("ListHosts"))
	return w.InnerStack.ListHosts()
}

// DeleteHost ...
func (w LoggedStack) DeleteHost(id string) error {
	defer w.prepare(w.trace("DeleteHost"))
	return w.InnerStack.DeleteHost(id)
}

// StopHost ...
func (w LoggedStack) StopHost(id string) error {
	defer w.prepare(w.trace("StopHost"))
	return w.InnerStack.StopHost(id)
}

// StartHost ...
func (w LoggedStack) StartHost(id string) error {
	defer w.prepare(w.trace("StartHost"))
	return w.InnerStack.StartHost(id)
}

// RebootHost ...
func (w LoggedStack) RebootHost(id string) error {
	defer w.prepare(w.trace("RebootHost"))
	return w.InnerStack.RebootHost(id)
}

// ResizeHost ...
func (w LoggedStack) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	defer w.prepare(w.trace("ResizeHost"))
	return w.InnerStack.ResizeHost(id, request)
}

// CreateVolume ...
func (w LoggedStack) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	defer w.prepare(w.trace("CreateVolume"))
	return w.InnerStack.CreateVolume(request)
}

// GetVolume ...
func (w LoggedStack) GetVolume(id string) (*resources.Volume, error) {
	defer w.prepare(w.trace("GetVolume"))
	return w.InnerStack.GetVolume(id)
}

// ListVolumes ...
func (w LoggedStack) ListVolumes() ([]resources.Volume, error) {
	defer w.prepare(w.trace("ListVolumes"))
	return w.InnerStack.ListVolumes()
}

// DeleteVolume ...
func (w LoggedStack) DeleteVolume(id string) error {
	defer w.prepare(w.trace("DeleteVolume"))
	return w.InnerStack.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w LoggedStack) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	defer w.prepare(w.trace("CreateVolumeAttachment"))
	return w.InnerStack.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w LoggedStack) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	defer w.prepare(w.trace("GetVolumeAttachment"))
	return w.InnerStack.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments ...
func (w LoggedStack) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	defer w.prepare(w.trace("ListVolumeAttachments"))
	return w.InnerStack.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment ...
func (w LoggedStack) DeleteVolumeAttachment(serverID, id string) error {
	defer w.prepare(w.trace("DeleteVolumeAttachment"))
	return w.InnerStack.DeleteVolumeAttachment(serverID, id)
}

// // GetConfigurationOptions ...
// func (w LoggedStack) GetConfigurationOptions() stacks.ConfigurationOptions {
// 	defer w.prepare(w.trace("GetConfigurationOptions"))
// 	return w.InnerStack.GetConfigurationOptions()
// }

// // GetAuthenticationOptions ...
// func (w LoggedStack) GetAuthenticationOptions() stacks.AuthenticationOptions {
// 	defer w.prepare(w.trace("GetAuthenticationOptions"))
// 	return w.InnerStack.GetAuthenticationOptions()
// }
