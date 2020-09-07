// +build libvirt

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
    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/server/iaas"
    "github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
    "github.com/CS-SI/SafeScale/lib/server/iaas/providers"
    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
    libStack "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/libvirt"
    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
)

// provider is the provider implementation of the local provider
type provider struct {
    *libStack.Stack

    tenantParameters map[string]interface{}
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
        return nil, fail.Wrap(err, "failed to create a new libvirt Stack")
    }

    localProvider := &provider{
        Stack:            libvirtStack,
        tenantParameters: params,
    }

    return localProvider, nil
}

// GetAuthOpts returns authentication options as a Config
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {
    cfg := abstract.ConfigMap{}
    cfg.Set("Region", "Local")
    return cfg, nil
}

// GetCfgOpts returns configuration options as a Config
func (p *provider) GetConfigurationOptions() (providers.Config, error) {
    config := abstract.ConfigMap{}

    config.Set("AutoHostNetworkInterfaces", p.Config.AutoHostNetworkInterfaces)
    config.Set("UseLayer3Networking", p.Config.UseLayer3Networking)
    config.Set("MetadataBucketName", p.Config.MetadataBucket)
    config.Set("ProviderNetwork", p.Config.ProviderNetwork)
    config.Set("OperatorUsername", p.Config.OperatorUsername)
    config.Set("ProviderName", p.GetName())

    return config, nil
}

func (p *provider) GetName() string {
    return "local"
}

// ListImages ...
func (p *provider) ListImages(all bool) ([]abstract.Image, error) {
    return p.Stack.ListImages()
}

// ListTemplates ...
func (p *provider) ListTemplates(all bool) ([]abstract.HostTemplate, error) {
    return p.Stack.ListTemplates()
}

func (p *provider) ListAvailabilityZones() (map[string]bool, error) {
    return p.Stack.ListAvailabilityZones()
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() map[string]interface{} {
    return p.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
    return providers.Capabilities{}
}

// AddRuleToSecurityGroup adds a rule to a security group
func (p *provider) AddRuleToSecurityGroup(groupRef string, rule abstract.SecurityGroupRule) fail.Error {
    return fail.NotImplementedError()
}

func init() {
    // log.Debug("Registering local provider")
    iaas.Register("local", &provider{})
}
