// +build !libvirt

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
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var gReport = fail.NotAvailableError("libvirt Driver is not enabled, use the libvirt option while compiling (make libvirt all)")

// provider is the implementation of the local driver regarding to the api.Provider
type provider struct {
	tenantParameters map[string]interface{}
}

// AuthOptions fields are the union of those recognized by each identity implementation and provider.
type AuthOptions struct {
}

// CfgOptions configuration options
type CfgOptions struct {
}

func (provider *provider) WaitHostReady(hostParam interface{}, timeout time.Duration) fail.Error {
	return gReport
}

func (provider *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	provider.tenantParameters = map[string]interface{}{}
	return nil, gReport
}
func (provider *provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	return nil, gReport
}
func (provider *provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	return nil, gReport
}

func (provider *provider) ListAvailabilityZones() (map[string]bool, fail.Error) {
	return nil, gReport
}

// ListRegions returns a list with the regions available
func (provider *provider) ListRegions() ([]string, fail.Error) {
	return nil, gReport
}

func (provider *provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
	return nil, gReport
}
func (provider *provider) GetImage(id string) (*abstract.Image, fail.Error) {
	return nil, gReport
}

func (provider *provider) GetTemplate(id string) (*abstract.HostTemplate, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	return nil, gReport
}

func (provider *provider) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	return nil, gReport
}
func (provider *provider) GetKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteKeyPair(id string) fail.Error {
	return gReport
}

func (provider *provider) CreateNetwork(req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	return nil, gReport
}
func (provider *provider) GetNetwork(id string) (*abstract.Network, fail.Error) {
	return nil, gReport
}
func (provider *provider) GetNetworkByName(name string) (*abstract.Network, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListNetworks() ([]*abstract.Network, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteNetwork(id string) fail.Error {
	return gReport
}

// func (provider *provider) CreateGateway(req abstract.GatewayRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {
// 	return nil, nil, gReport
// }
// func (provider *provider) DeleteGateway(string) fail.Error {
// 	return gReport
// }
func (provider *provider) CreateVIP(networkID string, description string) (*abstract.VirtualIP, fail.Error) {
	return nil, gReport
}
func (provider *provider) AddPublicIPToVIP(vip *abstract.VirtualIP) fail.Error {
	return gReport
}
func (provider *provider) BindHostToVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	return gReport
}
func (provider *provider) UnbindHostFromVIP(vip *abstract.VirtualIP, hostID string) fail.Error {
	return gReport
}
func (provider *provider) DeleteVIP(vip *abstract.VirtualIP) fail.Error {
	return gReport
}

func (provider *provider) CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {
	return nil, nil, gReport
}
func (provider *provider) ResizeHost(id string, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	return nil, gReport
}
func (provider *provider) InspectHost(interface{}) (*abstract.HostFull, fail.Error) {
	return nil, gReport
}
func (provider *provider) GetHostByName(string) (*abstract.HostCore, fail.Error) {
	return nil, gReport
}
func (provider *provider) GetHostState(interface{}) (hoststate.Enum, fail.Error) {
	return hoststate.ERROR, gReport
}
func (provider *provider) ListHosts(bool) (abstract.HostList, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteHost(id string) fail.Error {
	return gReport
}
func (provider *provider) StartHost(id string) fail.Error {
	return gReport
}
func (provider *provider) StopHost(id string) fail.Error {
	return gReport
}
func (provider *provider) RebootHost(id string) fail.Error {
	return gReport
}

func (provider *provider) CreateVolume(request abstract.VolumeRequest) (*abstract.Volume, fail.Error) {
	return nil, gReport
}
func (provider *provider) GetVolume(id string) (*abstract.Volume, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListVolumes() ([]abstract.Volume, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteVolume(id string) fail.Error {
	return gReport
}

func (provider *provider) CreateVolumeAttachment(request abstract.VolumeAttachmentRequest) (string, fail.Error) {
	return "", gReport
}
func (provider *provider) GetVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	return nil, gReport
}
func (provider *provider) ListVolumeAttachments(serverID string) ([]abstract.VolumeAttachment, fail.Error) {
	return nil, gReport
}
func (provider *provider) DeleteVolumeAttachment(serverID, id string) fail.Error {
	return gReport
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
