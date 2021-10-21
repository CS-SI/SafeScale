//go:build libvirt
// +build libvirt

/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"regexp"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	libStack "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/libvirt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// provider is the provider implementation of the local provider
type provider struct {
	api.Stack

	tenantParameters map[string]interface{}
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

func (p *provider) InspectImage(id string) (*abstract.Image, fail.Error) {
	panic("implement me")
}

func (p *provider) InspectKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	panic("implement me")
}

func (p *provider) ListNetworks() ([]*abstract.Network, fail.Error) {
	panic("implement me")
}

func (p *provider) BindHostToVIP(ip *abstract.VirtualIP, s string) fail.Error {
	panic("implement me")
}

func (p *provider) UnbindHostFromVIP(ip *abstract.VirtualIP, s string) fail.Error {
	panic("implement me")
}

func (p *provider) CreateHost(request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error) {
	panic("implement me")
}

func (p *provider) InspectHostByName(s string) (*abstract.HostCore, fail.Error) {
	panic("implement me")
}

func (p *provider) ListHosts(b bool) (abstract.HostList, fail.Error) {
	panic("implement me")
}

func (p *provider) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	panic("implement me")
}

func (p *provider) BindSecurityGroupToHost(hostParam stacks.HostParameter, sgParam stacks.SecurityGroupParameter) fail.Error {
	panic("implement me")
}

func (p *provider) InspectVolumeAttachment(serverID, id string) (*abstract.VolumeAttachment, fail.Error) {
	panic("implement me")
}

// New creates a new instance of local provider
func New() providers.Provider {
	return &provider{}
}

// AuthOptions fields are the union of those recognized by each identity implementation and provider.
type AuthOptions struct {
}

// CfgOptions configuration options
type CfgOptions struct {
	// MetadataBucketName contains the name of the bucket storing metadata
	MetadataBucketName string
	// Name of the default network of the provider
	ProviderNetwork string
	// AutoHostNetworkInterfaces indicates if network interfaces are configured automatically by the provider or needs a post configuration
	AutoHostNetworkInterfaces bool
	// UseLayer3Networking indicates if layer 3 networking features (router) can be used
	// if UseFloatingIP is true UseLayer3Networking must be true
	UseLayer3Networking bool
	// Local Path of the json file defining the images
	ImagesJSONPath string
	// Local Path of the json file defining the templates
	TemplatesJSONPath string
	// Local Path of the libvirt pool where all disks created by libvirt come from and are stored
	LibvirtStorage string
	// Connection identifier to the virtualisation device
	URI string
}

// &stacks.ConfigurationOptions{
// 	ProviderNetwork:           "safescale", //at least for qemu / KVM
// 	AutoHostNetworkInterfaces: false,
// 	UseLayer3Networking:       false,
// }

// Build Create and initialize a ClientAPI
// Can be called from nil
func (p *provider) Build(params map[string]interface{}) (providers.Provider, error) {
	authOptions := stacks.AuthenticationOptions{}
	localConfig := stacks.LocalConfiguration{}
	config := stacks.ConfigurationOptions{}

	config.ProviderNetwork = "safescale"
	config.AutoHostNetworkInterfaces = false
	config.UseLayer3Networking = false
	bucketName, err := objectstorage.BuildMetadataBucketName("local", "", "", "")
	if err != nil {
		return nil, fail.Wrap(err, "failed to build metadata bucket name")
	}
	config.MetadataBucket = bucketName

	// Add custom dns
	// config.DNSList = []string{"1.1.1.1"}

	compute, _ := params["compute"].(map[string]interface{})

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = abstract.DefaultUser
		}
	}
	config.OperatorUsername = operatorUsername

	uri, found := compute["uri"].(string)
	if !found {
		return nil, fail.SyntaxError("URI is not set")
	}
	imagesJSONPath, found := compute["imagesJSONPath"].(string)
	if !found {
		return nil, fail.SyntaxError("imagesJsonPath is not set")
	}
	templatesJSONPath, found := compute["templatesJSONPath"].(string)
	if !found {
		return nil, fail.SyntaxError("templatesJsonPath is not set")
	}
	libvirtStorage, found := compute["libvirtStorage"].(string)
	if !found {
		return nil, fail.SyntaxError("libvirtStorage is not set")
	}

	localConfig.ImagesJSONPath = imagesJSONPath
	localConfig.TemplatesJSONPath = templatesJSONPath
	localConfig.LibvirtStorage = libvirtStorage
	localConfig.URI = uri

	libvirtStack, err := libStack.New(authOptions, localConfig, config)
	if err != nil {
		return nil, fail.Wrap(err, "failed to create a new libvirt stack")
	}

	localProvider := &provider{
		Stack:            libvirtStack,
		tenantParameters: params,
	}

	return localProvider, nil
}

// GetAuthOpts returns authentication options as a Config
func (p provider) GetAuthenticationOptions() (providers.Config, error) {
	cfg := providers.Config{}
	if s.IsNull() {
		return cfg, fail.InvalidInstanceError()
	}

	cfg.Set("Region", "Local")
	return cfg, nil
}

// GetCfgOpts returns configuration options as a Config
func (p provider) GetConfigurationOptions() (providers.Config, error) {
	config := providers.Config{}
	if s.IsNull() {
		return config, fail.InvalidInstanceError()
	}

	config.Set("AutoHostNetworkInterfaces", p.Config.AutoHostNetworkInterfaces)
	config.Set("UseLayer3Networking", p.Config.UseLayer3Networking)
	config.Set("MetadataBucketName", p.Config.MetadataBucket)
	config.Set("ProviderNetwork", p.Config.ProviderNetwork)
	config.Set("OperatorUsername", p.Config.OperatorUsername)
	config.Set("ProviderName", p.GetName())
	cfg.Set("UseNATService", opts.UseNATService)

	return config, nil
}

func (p provider) GetName() string {
	return "local"
}

//
// // ListImages ...
// func (p provider) ListImages(all bool) ([]abstract.Image, error) {
//	return p.Stack.ListImages()
// }
//
// // ListTemplates ...
// func (p provider) ListTemplates(all bool) ([]abstract.HostTemplate, error) {
//	return p.Stack.ListTemplates()
// }
//
// func (p provider) ListAvailabilityZones() (map[string]bool, error) {
//	return p.Stack.ListAvailabilityZones()
// }
//
// // GetTenantParameters returns the tenant parameters as-is
// func (p *provider) GetTenantParameters() map[string]interface{} {
//	return p.tenantParameters
// }
//
// // GetCapabilities returns the capabilities of the provider
// func (p *provider) GetCapabilities() providers.Capabilities {
//	return providers.Capabilities{}
// }

// AddRuleToSecurityGroup adds a rule to a security group
func (p *provider) AddRuleToSecurityGroup(groupRef string, rule abstract.SecurityGroupRule) fail.Error {
	return fail.NotImplementedError()
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() []*regexp.Regexp {
	var emptySlice []*regexp.Regexp
	if p.IsNull() {
		return emptySlice
	}

	var (
		templatesWithGPU = []string{
			// "g.*-.*",
			// "t.*-.*",
		}
		out []*regexp.Regexp
	)
	for _, v := range templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return emptySlice
		}
		out = append(out, re)
	}

	return out
}

func init() {
	// log.Debug("Registering local provider")
	iaas.Register("local", &provider{})
}
