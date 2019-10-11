//+build libvirt

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
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	providerapi "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	libStack "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/libvirt"
)

// provider is the provider implementation of the local provider
type provider struct {
	*libStack.Stack

	tenantParameters map[string]interface{}
}

// New creates a new instance of local provider
func New() providerapi.Provider {
	return &provider{}
}

//AuthOptions fields are the union of those recognized by each identity implementation and provider.
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
	// Connection identifier to the visualisation device
	URI string
}

// &stacks.ConfigurationOptions{
// 	ProviderNetwork:           "safescale", //at least for qemu / KVM
// 	AutoHostNetworkInterfaces: false,
// 	UseLayer3Networking:       false,
// }

// Build Create and initialize a ClientAPI
func (prov *provider) Build(params map[string]interface{}) (providerapi.Provider, error) {
	authOptions := stacks.AuthenticationOptions{}
	localConfig := stacks.LocalConfiguration{}
	config := stacks.ConfigurationOptions{}

	config.ProviderNetwork = "safescale"
	config.AutoHostNetworkInterfaces = false
	config.UseLayer3Networking = false
	bucketName, err := objectstorage.BuildMetadataBucketName("local", "", "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to build metadata bucket name %v", err)
	}
	config.MetadataBucket = bucketName

	// Add custom dns
	// config.DNSList = []string{"1.1.1.1"}

	compute, _ := params["compute"].(map[string]interface{})

	operatorUsername := resources.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = resources.DefaultUser
		}
	}
	config.OperatorUsername = operatorUsername

	uri, found := compute["uri"].(string)
	if !found {
		return nil, fmt.Errorf("URI is not set")
	}
	imagesJSONPath, found := compute["imagesJSONPath"].(string)
	if !found {
		return nil, fmt.Errorf("imagesJsonPath is not set")
	}
	templatesJSONPath, found := compute["templatesJSONPath"].(string)
	if !found {
		return nil, fmt.Errorf("templatesJsonPath is not set")
	}
	libvirtStorage, found := compute["libvirtStorage"].(string)
	if !found {
		return nil, fmt.Errorf("libvirtStorage is not set")
	}

	localConfig.ImagesJSONPath = imagesJSONPath
	localConfig.TemplatesJSONPath = templatesJSONPath
	localConfig.LibvirtStorage = libvirtStorage
	localConfig.URI = uri

	libvirtStack, err := libStack.New(authOptions, localConfig, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create a new libvirt Stack : %v", err)
	}

	localProvider := &provider{
		Stack:            libvirtStack,
		tenantParameters: params,
	}

	return localProvider, nil
}

// GetAuthOpts returns authentication options as a Config
func (prov *provider) GetAuthenticationOptions() (providers.Config, error) {
	cfg := resources.ConfigMap{}
	cfg.Set("Region", "Local")
	return cfg, nil
}

// GetCfgOpts returns configuration options as a Config
func (prov *provider) GetConfigurationOptions() (providers.Config, error) {
	config := resources.ConfigMap{}

	config.Set("AutoHostNetworkInterfaces", prov.Config.AutoHostNetworkInterfaces)
	config.Set("UseLayer3Networking", prov.Config.UseLayer3Networking)
	config.Set("MetadataBucketName", prov.Config.MetadataBucket)
	config.Set("ProviderNetwork", prov.Config.ProviderNetwork)
	config.Set("OperatorUsername", prov.Config.OperatorUsername)

	return config, nil
}

func (prov *provider) GetName() string {
	return "local"
}

// ListImages ...
func (prov *provider) ListImages(all bool) ([]resources.Image, error) {
	return prov.Stack.ListImages()
}

// ListTemplates ...
func (prov *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	return prov.Stack.ListTemplates()
}

func (prov *provider) ListAvailabilityZones() (map[string]bool, error) {
	return prov.Stack.ListAvailabilityZones()
}

// GetTenantParameters returns the tenant parameters as-is
func (prov *provider) GetTenantParameters() map[string]interface{} {
	return prov.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (prov *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{}
}

func init() {
	// log.Debug("Registering local provider")
	iaas.Register("local", &provider{})
}
