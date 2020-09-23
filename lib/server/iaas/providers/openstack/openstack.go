/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package openstack

import (
	"fmt"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	apiprovider "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
)

// const (
// 	defaultSecurityGroup = "default"
// )

// provider is the provider implementation of the openstack provider respecting api.Provider
type provider struct {
	*openstack.Stack

	SecurityGroup     *secgroups.SecurityGroup
	ExternalNetworkID string

	tenantParameters map[string]interface{}
}

// New creates a new instance of pure openstack provider
func New() apiprovider.Provider {
	return &provider{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (apiprovider.Provider, error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})
	metadata, _ := params["metadata"].(map[string]interface{})

	identityEndpoint, _ := identity["IdentityEndpoint"].(string)
	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	tenantName, _ := compute["TenantName"].(string)
	region, _ := compute["Region"].(string)
	zone, _ := compute["AvailabilityZone"].(string)
	floatingIPPool, _ := network["FloatingIPPool"].(string)
	providerNetwork, _ := network["ExternalNetwork"].(string)
	if providerNetwork == "" {
		providerNetwork = "public"
	}
	defaultImage, _ := compute["DefaultImage"].(string)
	dnsServers, _ := network["DNSServers"].([]string)
	if len(dnsServers) == 0 {
		dnsServers = []string{"8.8.8.8", "1.1.1.1"}
	}
	operatorUsername := resources.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = resources.DefaultUser
		}
	}

	authOptions := stacks.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		TenantName:       tenantName,
		Region:           region,
		AvailabilityZone: zone,
		FloatingIPPool:   floatingIPPool,
	}

	providerName := "openstack"

	var (
		metadataBucketName string
		err                error
		ok                 bool
	)
	if metadataBucketName, ok = metadata["Bucket"].(string); !ok || metadataBucketName == "" {
		metadataBucketName, err = objectstorage.BuildMetadataBucketName(providerName, region, tenantName, "0")
		if err != nil {
			return nil, err
		}
	}

	cfgOptions := stacks.ConfigurationOptions{
		ProviderNetwork:           providerNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard":   volumespeed.COLD,
			"performant": volumespeed.HDD,
		},
		DNSList:          dnsServers,
		DefaultImage:     defaultImage,
		MetadataBucket:   metadataBucketName,
		OperatorUsername: operatorUsername,
		ProviderName:     providerName,
	}

	stack, err := openstack.New(authOptions, nil, cfgOptions, nil)
	if err != nil {
		return nil, err
	}
	newP := &provider{
		Stack:            stack,
		tenantParameters: params,
	}

	err = stack.InitDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}

	validRegions, err := stack.ListRegions()
	if err != nil {
		if len(validRegions) != 0 {
			return nil, err
		}
	}
	if len(validRegions) != 0 {
		regionIsValidInput := false
		for _, vr := range validRegions {
			if region == vr {
				regionIsValidInput = true
			}
		}
		if !regionIsValidInput {
			return nil, scerr.InvalidParameterError("region", fmt.Sprintf("invalid Region: '%s'", region))
		}
	}

	validAvailabilityZones, err := stack.ListAvailabilityZones()
	if err != nil {
		if len(validAvailabilityZones) != 0 {
			return nil, err
		}
	}

	if len(validAvailabilityZones) != 0 {
		var validZones []string
		zoneIsValidInput := false
		for az, valid := range validAvailabilityZones {
			if valid {
				if az == zone {
					zoneIsValidInput = true
				}
				validZones = append(validZones, az)
			}
		}
		if !zoneIsValidInput {
			return nil, scerr.InvalidParameterError(
				"zone", fmt.Sprintf("invalid Availability zone: '%s', valid zones are %v", zone, validZones),
			)
		}
	}

	evalid := apiprovider.NewValidatedProvider(newP, providerName)
	etrace := apiprovider.NewErrorTraceProvider(evalid, providerName)
	prov := apiprovider.NewLoggedProvider(etrace, providerName)
	return prov, nil
}

// GetAuthenticationOptions returns the auth options
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {

	opts := p.Stack.GetAuthenticationOptions()
	cfg := providers.ConfigMap{}
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	cfg.Set("DomainName", opts.DomainName)

	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p *provider) GetConfigurationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("ProviderNetwork", opts.ProviderNetwork)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("ProviderName", p.GetName())

	return cfg, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p *provider) ListImages(all bool) ([]resources.Image, error) {
	allImages, err := p.Stack.ListImages()
	if err != nil {
		return nil, err
	}
	return allImages, nil
}

// GetName returns the providerName
func (p *provider) GetName() string {
	return "openstack"
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() map[string]interface{} {
	return p.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{
		PrivateVirtualIP: true,
	}
}

// init registers the openstack provider
func init() {
	iaas.Register("openstack", &provider{})
}
