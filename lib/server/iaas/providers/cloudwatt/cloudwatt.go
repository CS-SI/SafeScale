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

package cloudwatt

import (
	"fmt"
	"regexp"

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	providerapi "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
)

var (
	externalNetwork          = "public"
	dnsServers               = []string{"185.23.94.244", "185.23.94.245"}
	identityEndpointTemplate = "https://identity.%s.cloudwatt.com/v2.0"
)

// provider is the implementation of the Cloudwatt provider
type provider struct {
	*openstack.Stack

	tenantParameters map[string]interface{}
}

// New creates a new instance of cloudwatt provider
func New() providerapi.Provider {
	return &provider{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providerapi.Provider, error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})

	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	tenantName, _ := compute["TenantName"].(string)
	region, _ := compute["Region"].(string)
	zone, _ := compute["AvailabilityZone"].(string)
	identityEndpoint := fmt.Sprintf(identityEndpointTemplate, region)
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
		FloatingIPPool:   "public",
	}

	govalidator.TagMap["alphanumwithdashesandunderscores"] = govalidator.Validator(func(str string) bool {
		rxp := regexp.MustCompile(stacks.AlphanumericWithDashesAndUnderscores)
		return rxp.Match([]byte(str))
	})

	_, err := govalidator.ValidateStruct(authOptions)
	if err != nil {
		return nil, err
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("openstack", region, tenantName, "0")
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		ProviderNetwork:           externalNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard":   volumespeed.COLD,
			"performant": volumespeed.HDD,
		},
		DNSList:          dnsServers,
		MetadataBucket:   metadataBucketName,
		OperatorUsername: operatorUsername,
	}

	stack, err := openstack.New(authOptions, nil, cfgOptions, nil)
	if err != nil {
		return nil, err
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
			return nil, fmt.Errorf("invalid Region: '%s'", region)
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
			return nil, fmt.Errorf("invalid Availability zone: '%s', valid zones are %v", zone, validZones)
		}
	}

	newP := &provider{
		Stack:            stack,
		tenantParameters: params,
	}
	return newP, nil
}

// GetAuthenticationOptions returns the auth options
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetAuthenticationOptions()
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p *provider) GetConfigurationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)

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
	return "cloudwatt"
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

func init() {
	iaas.Register("cloudwatt", &provider{})
}
