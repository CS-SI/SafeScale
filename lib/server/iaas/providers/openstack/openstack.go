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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or provideried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package openstack

import (
    "github.com/sirupsen/logrus"

    "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"

    "github.com/CS-SI/SafeScale/lib/server/iaas"
    "github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
    "github.com/CS-SI/SafeScale/lib/server/iaas/providers"
    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
    "github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// provider is the provider implementation of the openstack provider respecting api.Provider
type provider struct {
    *openstack.Stack

    SecurityGroup     *secgroups.SecurityGroup
    ExternalNetworkID string

    tenantParameters map[string]interface{}
}

// New creates a new instance of pure openstack provider
func New() providers.Provider {
    return &provider{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
    identity, _ := params["identity"].(map[string]interface{})
    compute, _ := params["compute"].(map[string]interface{})
    network, _ := params["network"].(map[string]interface{})

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
    operatorUsername := abstract.DefaultUser
    if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
        operatorUsername = operatorUsernameIf.(string)
        if operatorUsername == "" {
            logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
            operatorUsername = abstract.DefaultUser
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
    metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, tenantName, "0")
    if xerr != nil {
        return nil, xerr
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

    stack, xerr := openstack.New(authOptions, nil, cfgOptions, nil)
    if xerr != nil {
        return nil, xerr
    }
    newP := &provider{
        Stack:            stack,
        tenantParameters: params,
    }

    xerr = stack.InitDefaultSecurityGroup()
    if xerr != nil {
        return nil, xerr
    }

    validRegions, xerr := stack.ListRegions()
    if xerr != nil {
        return nil, xerr
    }
    if len(validRegions) != 0 {
        regionIsValidInput := false
        for _, vr := range validRegions {
            if region == vr {
                regionIsValidInput = true
            }
        }
        if !regionIsValidInput {
            return nil, fail.InvalidRequestError("invalid Region '%s'", region)
        }
    }

    validAvailabilityZones, xerr := stack.ListAvailabilityZones()
    if xerr != nil {
        return nil, xerr
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
            return nil, fail.InvalidRequestError("invalid Availability zone '%s', valid zones are %v", zone, validZones)
        }
    }

    return newP, nil
}

// GetAuthenticationOptions returns the auth options
func (p *provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
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
func (p *provider) GetConfigurationOptions() (providers.Config, fail.Error) {
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
func (p *provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
    allTemplates, xerr := p.Stack.ListTemplates()
    if xerr != nil {
        return nil, xerr
    }
    return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p *provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
    allImages, xerr := p.Stack.ListImages()
    if xerr != nil {
        return nil, xerr
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
