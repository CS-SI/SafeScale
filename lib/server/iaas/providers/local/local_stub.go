//+build !libvirt

/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package local

import (
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	providerapi "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

var gError = scerr.NotAvailableError("libvirt Driver is not enabled, use the libvirt option while compiling (make libvirt all)")

// provider is the implementation of the local driver regarding to the api.Provider
type provider struct {
	tenantParameters map[string]interface{}
}

//AuthOptions fields are the union of those recognized by each identity implementation and provider.
type AuthOptions struct {
}

// CfgOptions configuration options
type CfgOptions struct {
}

func (provider *provider) WaitHostReady(hostParam interface{}, timeout time.Duration) error {
	return gError
}

func (provider *provider) Build(params map[string]interface{}) (providerapi.Provider, error) {
	provider.tenantParameters = map[string]interface{}{}
	return nil, gError
}
func (provider *provider) GetAuthenticationOptions() (providers.Config, error) {
	return nil, gError
}
func (provider *provider) GetConfigurationOptions() (providers.Config, error) {
	return nil, gError
}

func (provider *provider) ListAvailabilityZones() (map[string]bool, error) {
	return nil, gError
}

// ListRegions returns a list with the regions available
func (provider *provider) ListRegions() ([]string, error) {
	return nil, gError
}

func (provider *provider) ListImages(all bool) ([]abstract.Image, error) {
	return nil, gError
}
func (provider *provider) GetImage(id string) (*abstract.Image, error) {
	return nil, gError
}

func (provider *provider) GetTemplate(id string) (*abstract.HostTemplate, error) {
	return nil, gError
}
func (provider *provider) ListTemplates(all bool) ([]abstract.HostTemplate, error) {
	return nil, gError
}

func (provider *provider) CreateKeyPair(name string) (*abstract.KeyPair, error) {
	return nil, gError
}
func (provider *provider) GetKeyPair(id string) (*abstract.KeyPair, error) {
	return nil, gError
}
func (provider *provider) ListKeyPairs() ([]abstract.KeyPair, error) {
	return nil, gError
}
func (provider *provider) DeleteKeyPair(id string) error {
	return gError
}

func (provider *provider) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, error) {
	return nil, gError
}
func (provider *provider) GetNetwork(id string) (*abstract.Network, error) {
	return nil, gError
}
func (provider *provider) GetNetworkByName(name string) (*abstract.Network, error) {
	return nil, gError
}
func (provider *provider) ListNetworks() ([]*abstract.Network, error) {
	return nil, gError
}
func (provider *provider) DeleteNetwork(id string) error {
	return gError
}
func (provider *provider) CreateGateway(req abstract.GatewayRequest) (*abstract.HostFull, *userdata.Content, error) {
	return nil, nil, gError
}
func (provider *provider) DeleteGateway(string) error {
	return gError
}
func (provider *provider) CreateVIP(networkID string, description string) (*abstract.VirtualIP, error) {
	return nil, gError
}
func (provider *provider) AddPublicIPToVIP(vip *abstract.VirtualIP) error {
	return gError
}
func (provider *provider) BindHostToVIP(vip *abstract.VirtualIP, hostID string) error {
	return gError
}
func (provider *provider) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) error {
	return gError
}
func (provider *provider) DeleteVIP(vip *abstract.VirtualIP) error {
	return gError
}

func (provider *provider) CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, error) {
	return nil, nil, gError
}
func (provider *provider) ResizeHost(id string, request abstract.HostSizingRequirements) (*abstract.HostFull, error) {
	return nil, gError
}
func (provider *provider) InspectHost(interface{}) (*abstract.HostFull, error) {
	return nil, gError
}
func (provider *provider) GetHostByName(string) (*abstract.HostCore, error) {
	return nil, gError
}
func (provider *provider) GetHostState(interface{}) (hoststate.Enum, error) {
	return hoststate.ERROR, gError
}
func (provider *provider) ListHosts(bool) (abstract.HostList, error) {
	return nil, gError
}
func (provider *provider) DeleteHost(id string) error {
	return gError
}
func (provider *provider) StartHost(id string) error {
	return gError
}
func (provider *provider) StopHost(id string) error {
	return gError
}
func (provider *provider) RebootHost(id string) error {
	return gError
}

func (provider *provider) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, error) {
	return nil, gError
}
func (provider *provider) GetVolume(id string) (*abstract.Volume, error) {
	return nil, gError
}
func (provider *provider) ListVolumes() ([]abstract.Volume, error) {
	return nil, gError
}
func (provider *provider) DeleteVolume(id string) error {
	return gError
}

func (provider *provider) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, error) {
	return "", gError
}
func (provider *provider) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, error) {
	return nil, gError
}
func (provider *provider) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, error) {
	return nil, gError
}
func (provider *provider) DeleteVolumeAttachment(serverID, id string) error {
	return gError
}
func (provider *provider) GetName() string {
	return "local_disabled"
}
func (provider *provider) GetTenantParameters() map[string]interface{} {
	return nil
}

// GetCapabilities returns the capabilities of the provider
func (provider *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{}
}

func init() {
	// log.Debug("Registering fake local provider")
	iaas.Register("local", &provider{})
}
