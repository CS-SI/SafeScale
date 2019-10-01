package api

import (
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/HostState"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/userdata"
	"github.com/CS-SI/SafeScale/lib/utils"
)

// LoggedProvider ...
type LoggedProvider WrappedProvider

// Provider specific functions

// Build ...
func (w LoggedProvider) Build(something map[string]interface{}) (Provider, error) {
	defer w.prepare(w.trace("Build"))
	return w.InnerProvider.Build(something)
}

// ListImages ...
func (w LoggedProvider) ListImages(all bool) ([]resources.Image, error) {
	defer w.prepare(w.trace("ListImages"))
	return w.InnerProvider.ListImages(all)
}

// ListTemplates ...
func (w LoggedProvider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	defer w.prepare(w.trace("ListTemplates"))
	return w.InnerProvider.ListTemplates(all)
}

// GetAuthenticationOptions ...
func (w LoggedProvider) GetAuthenticationOptions() (providers.Config, error) {
	defer w.prepare(w.trace("GetAuthenticationOptions"))
	return w.InnerProvider.GetAuthenticationOptions()
}

// GetConfigurationOptions ...
func (w LoggedProvider) GetConfigurationOptions() (providers.Config, error) {
	defer w.prepare(w.trace("GetConfigurationOptions"))
	return w.InnerProvider.GetConfigurationOptions()
}

// GetName ...
func (w LoggedProvider) GetName() string {
	defer w.prepare(w.trace("GetName"))
	return w.InnerProvider.GetName()
}

// GetTenantParameters ...
func (w LoggedProvider) GetTenantParameters() map[string]interface{} {
	defer w.prepare(w.trace("GetTenantParameters"))
	return w.InnerProvider.GetTenantParameters()
}

// Stack specific functions

// trace ...
func (w LoggedProvider) trace(s string) (string, time.Time) {
	logrus.Tracef("stacks.%s::%s() called", w.Name, s)
	return s, time.Now()
}

// prepare ...
func (w LoggedProvider) prepare(s string, startTime time.Time) {
	logrus.Tracef("stacks.%s::%s() done in [%s]", w.Name, s, utils.FormatDuration(time.Since(startTime)))
}

// NewLoggedProvider ...
func NewLoggedProvider(InnerProvider Provider, name string) *LoggedProvider {
	return &LoggedProvider{InnerProvider: InnerProvider, Name: name}
}

// ListAvailabilityZones ...
func (w LoggedProvider) ListAvailabilityZones() (map[string]bool, error) {
	defer w.prepare(w.trace("ListAvailabilityZones"))
	return w.InnerProvider.ListAvailabilityZones()
}

// ListRegions ...
func (w LoggedProvider) ListRegions() ([]string, error) {
	defer w.prepare(w.trace("ListRegions"))
	return w.InnerProvider.ListRegions()
}

// GetImage ...
func (w LoggedProvider) GetImage(id string) (*resources.Image, error) {
	defer w.prepare(w.trace("GetImage"))
	return w.InnerProvider.GetImage(id)
}

// GetTemplate ...
func (w LoggedProvider) GetTemplate(id string) (*resources.HostTemplate, error) {
	defer w.prepare(w.trace("GetTemplate"))
	return w.InnerProvider.GetTemplate(id)
}

// CreateKeyPair ...
func (w LoggedProvider) CreateKeyPair(name string) (*resources.KeyPair, error) {
	defer w.prepare(w.trace("CreateKeyPair"))
	return w.InnerProvider.CreateKeyPair(name)
}

// GetKeyPair ...
func (w LoggedProvider) GetKeyPair(id string) (*resources.KeyPair, error) {
	defer w.prepare(w.trace("GetKeyPair"))
	return w.InnerProvider.GetKeyPair(id)
}

// ListKeyPairs ...
func (w LoggedProvider) ListKeyPairs() ([]resources.KeyPair, error) {
	defer w.prepare(w.trace("ListKeyPairs"))
	return w.InnerProvider.ListKeyPairs()
}

// DeleteKeyPair ...
func (w LoggedProvider) DeleteKeyPair(id string) error {
	defer w.prepare(w.trace("DeleteKeyPair"))
	return w.InnerProvider.DeleteKeyPair(id)
}

// CreateNetwork ...
func (w LoggedProvider) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	defer w.prepare(w.trace("CreateNetwork"))
	return w.InnerProvider.CreateNetwork(req)
}

// GetNetwork ...
func (w LoggedProvider) GetNetwork(id string) (*resources.Network, error) {
	defer w.prepare(w.trace("GetNetwork"))
	return w.InnerProvider.GetNetwork(id)
}

// GetNetworkByName ...
func (w LoggedProvider) GetNetworkByName(name string) (*resources.Network, error) {
	defer w.prepare(w.trace("GetNetworkByName"))
	return w.InnerProvider.GetNetworkByName(name)
}

// ListNetworks ...
func (w LoggedProvider) ListNetworks() ([]*resources.Network, error) {
	defer w.prepare(w.trace("ListNetworks"))
	return w.InnerProvider.ListNetworks()
}

// DeleteNetwork ...
func (w LoggedProvider) DeleteNetwork(id string) error {
	defer w.prepare(w.trace("DeleteNetwork"))
	return w.InnerProvider.DeleteNetwork(id)
}

// CreateGateway ...
func (w LoggedProvider) CreateGateway(req resources.GatewayRequest) (*resources.Host, *userdata.Content, error) {
	defer w.prepare(w.trace("CreateGateway"))
	return w.InnerProvider.CreateGateway(req)
}

// DeleteGateway ...
func (w LoggedProvider) DeleteGateway(networkID string) error {
	defer w.prepare(w.trace("DeleteGateway"))
	return w.InnerProvider.DeleteGateway(networkID)
}

// CreateVIP ...
func (w LoggedProvider) CreateVIP(networkID string, description string) (*resources.VIP, error) {
	defer w.prepare(w.trace("CreateVIP"))
	return w.InnerProvider.CreateVIP(networkID, description)
}

// AddPublicIPToVIP adds a public IP to VIP
func (w LoggedProvider) AddPublicIPToVIP(vip *resources.VIP) error {
	defer w.prepare(w.trace("AddPublicIPToVIP"))
	return w.InnerProvider.AddPublicIPToVIP(vip)
}

// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
func (w LoggedProvider) BindHostToVIP(vip *resources.VIP, host *resources.Host) error {
	defer w.prepare(w.trace("BindHostToVIP"))
	return w.InnerProvider.BindHostToVIP(vip, host)
}

// UnbindHostFromVIP removes the bind between the VIP and a host
func (w LoggedProvider) UnbindHostFromVIP(vip *resources.VIP, host *resources.Host) error {
	defer w.prepare(w.trace("UnbindHostFromVIP"))
	return w.InnerProvider.UnbindHostFromVIP(vip, host)
}

// DeleteVIP deletes the port corresponding to the VIP
func (w LoggedProvider) DeleteVIP(vip *resources.VIP) error {
	defer w.prepare(w.trace("DeleteVIP"))
	return w.InnerProvider.DeleteVIP(vip)
}

// CreateHost ...
func (w LoggedProvider) CreateHost(request resources.HostRequest) (*resources.Host, *userdata.Content, error) {
	defer w.prepare(w.trace("CreateHost"))
	return w.InnerProvider.CreateHost(request)
}

// InspectHost ...
func (w LoggedProvider) InspectHost(something interface{}) (*resources.Host, error) {
	defer w.prepare(w.trace("InspectHost"))
	return w.InnerProvider.InspectHost(something)
}

// GetHostByName ...
func (w LoggedProvider) GetHostByName(name string) (*resources.Host, error) {
	defer w.prepare(w.trace("GetHostByName"))
	return w.InnerProvider.GetHostByName(name)
}

// GetHostState ...
func (w LoggedProvider) GetHostState(something interface{}) (HostState.Enum, error) {
	defer w.prepare(w.trace("GetHostState"))
	return w.InnerProvider.GetHostState(something)
}

// ListHosts ...
func (w LoggedProvider) ListHosts() ([]*resources.Host, error) {
	defer w.prepare(w.trace("ListHosts"))
	return w.InnerProvider.ListHosts()
}

// DeleteHost ...
func (w LoggedProvider) DeleteHost(id string) error {
	defer w.prepare(w.trace("DeleteHost"))
	return w.InnerProvider.DeleteHost(id)
}

// StopHost ...
func (w LoggedProvider) StopHost(id string) error {
	defer w.prepare(w.trace("StopHost"))
	return w.InnerProvider.StopHost(id)
}

// StartHost ...
func (w LoggedProvider) StartHost(id string) error {
	defer w.prepare(w.trace("StartHost"))
	return w.InnerProvider.StartHost(id)
}

// RebootHost ...
func (w LoggedProvider) RebootHost(id string) error {
	defer w.prepare(w.trace("RebootHost"))
	return w.InnerProvider.RebootHost(id)
}

// ResizeHost ...
func (w LoggedProvider) ResizeHost(id string, request resources.SizingRequirements) (*resources.Host, error) {
	defer w.prepare(w.trace("ResizeHost"))
	return w.InnerProvider.ResizeHost(id, request)
}

// CreateVolume ...
func (w LoggedProvider) CreateVolume(request resources.VolumeRequest) (*resources.Volume, error) {
	defer w.prepare(w.trace("CreateVolume"))
	return w.InnerProvider.CreateVolume(request)
}

// GetVolume ...
func (w LoggedProvider) GetVolume(id string) (*resources.Volume, error) {
	defer w.prepare(w.trace("GetVolume"))
	return w.InnerProvider.GetVolume(id)
}

// ListVolumes ...
func (w LoggedProvider) ListVolumes() ([]resources.Volume, error) {
	defer w.prepare(w.trace("ListVolumes"))
	return w.InnerProvider.ListVolumes()
}

// DeleteVolume ...
func (w LoggedProvider) DeleteVolume(id string) error {
	defer w.prepare(w.trace("DeleteVolume"))
	return w.InnerProvider.DeleteVolume(id)
}

// CreateVolumeAttachment ...
func (w LoggedProvider) CreateVolumeAttachment(request resources.VolumeAttachmentRequest) (string, error) {
	defer w.prepare(w.trace("CreateVolumeAttachment"))
	return w.InnerProvider.CreateVolumeAttachment(request)
}

// GetVolumeAttachment ...
func (w LoggedProvider) GetVolumeAttachment(serverID, id string) (*resources.VolumeAttachment, error) {
	defer w.prepare(w.trace("GetVolumeAttachment"))
	return w.InnerProvider.GetVolumeAttachment(serverID, id)
}

// ListVolumeAttachments ...
func (w LoggedProvider) ListVolumeAttachments(serverID string) ([]resources.VolumeAttachment, error) {
	defer w.prepare(w.trace("ListVolumeAttachments"))
	return w.InnerProvider.ListVolumeAttachments(serverID)
}

// DeleteVolumeAttachment ...
func (w LoggedProvider) DeleteVolumeAttachment(serverID, id string) error {
	defer w.prepare(w.trace("DeleteVolumeAttachment"))
	return w.InnerProvider.DeleteVolumeAttachment(serverID, id)
}

// GetCapabilities returns the capabilities of the provider
func (w LoggedProvider) GetCapabilities() providers.Capabilities {
	defer w.prepare(w.trace("Getcapabilities"))
	return w.InnerProvider.GetCapabilities()
}
