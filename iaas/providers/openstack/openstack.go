/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or provideried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package openstack

import (
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/providers"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/resources/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/stacks"
	"github.com/CS-SI/SafeScale/iaas/stacks/openstack"
)

const (
	defaultSecurityGroup = "default"
)

// provider is the providerementation of the openstack provider respecting api.Provider
type provider struct {
	*openstack.Stack

	SecurityGroup     *secgroups.SecurityGroup
	ExternalNetworkID string
}

// New creates a new instance of pure openstack provider
func New() providers.Provider {
	return &provider{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})

	identityEndpoint, _ := identity["IdentityEndpoint"].(string)
	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	tenantName, _ := compute["TenantName"].(string)
	region, _ := compute["Region"].(string)
	floatingIPPool, _ := network["FloatingIPPool"].(string)
	providerNetwork, _ := network["ExternalNetwork"].(string)
	if providerNetwork == "" {
		providerNetwork = "public"
	}
	defaultImage, _ := compute["DefaultImage"].(string)
	dnsServers, _ := network["DNSServers"].([]string)
	if len(dnsServers) <= 0 {
		dnsServers = []string{"8.8.8.8", "1.1.1.1"}
	}
	operatorUsername := resources.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
	}

	authOptions := stacks.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		TenantName:       tenantName,
		Region:           region,
		FloatingIPPool:   floatingIPPool,
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("openstack", region, tenantName, "0")
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		ProviderNetwork:           providerNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"standard":   VolumeSpeed.COLD,
			"performant": VolumeSpeed.HDD,
		},
		DNSList:          dnsServers,
		DefaultImage:     defaultImage,
		MetadataBucket:   metadataBucketName,
		OperatorUsername: operatorUsername,
	}

	stack, err := openstack.New(authOptions, nil, cfgOptions, nil)
	if err != nil {
		return nil, err
	}
	newP := &provider{Stack: stack}

	err = stack.InitDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}
	return newP, nil
}

// GetAuthOpts returns the auth options
func (p *provider) GetAuthOpts() (providers.Config, error) {

	opts := p.Stack.GetAuthenticationOptions()
	cfg := providers.ConfigMap{}
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)

	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (p *provider) GetCfgOpts() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("ProviderNetwork", opts.ProviderNetwork)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)

	return cfg, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates(all)
	if err != nil {
		return nil, err
	}
	return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p *provider) ListImages(all bool) ([]resources.Image, error) {
	allImages, err := p.Stack.ListImages(all)
	if err != nil {
		return nil, err
	}
	return allImages, nil
}

// GetName returns the providerName
func (p *provider) GetName() string {
	return "openstack"
}

// init registers the openstack provider
func init() {
	iaas.Register("openstack", &provider{})
}
