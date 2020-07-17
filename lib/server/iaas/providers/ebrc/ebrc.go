// +build ignore
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

package ebrc

import (
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/vclouddirector"
)

// provider is the provider implementation of the Ebrc provider
type provider struct {
	*vclouddirector.Stack

	tenantParameters map[string]interface{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})

	username, _ := identity["User"].(string)
	password, _ := identity["Password"].(string)
	insecure, _ := identity["Insecure"].(string)
	region, _ := compute["Region"].(string)
	vdc, _ := compute["Vdc"].(string)
	org, _ := identity["Org"].(string)
	identityEndpoint, _ := identity["EntryPoint"].(string)

	authOptions := stacks.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		Region:           region,
		ProjectName:      org,
		ProjectID:        vdc,
		FloatingIPPool:   "public",
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("vclouddirector", region, "", vdc)
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:                   []string{"176.65.72.102", "176.65.72.106"},
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard":   volumespeed.COLD,
			"performant": volumespeed.HDD,
		},
		MetadataBucket: metadataBucketName,
	}

	notsafe := false
	if strings.EqualFold(insecure, "True") {
		notsafe = true
	}

	ebrcOptions := stacks.VCloudConfigurationOptions{Insecure: notsafe}

	stack, err := vclouddirector.New(authOptions, ebrcOptions, cfgOptions)
	if err != nil {
		return nil, err
	}

	return &provider{
		Stack:            stack,
		tenantParameters: params,
	}, nil
}

// GetAuthOpts returns the auth options
func (p *provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}
	opts := p.Stack.GetAuthenticationOptions()

	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	cfg.Set("Org", opts.ProjectName)
	cfg.Set("Vdc", opts.ProjectID)

	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (p *provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}
	opts := p.Stack.GetConfigurationOptions()

	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("ProviderNetwork", opts.ProviderNetwork)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)

	return cfg, nil
}

// GetName returns the providerName
func (p *provider) GetName() string {
	return "vclouddirector"
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() map[string]interface{} {
	return p.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{}
}

func init() {
	iaas.Register("vclouddirector", &provider{})
}
