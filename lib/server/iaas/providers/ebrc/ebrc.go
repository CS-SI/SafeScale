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

package ebrc

import (
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	apiprovider "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/ebrc"
)

// provider is the provider implementation of the Ebrc provider
type provider struct {
	*ebrc.StackEbrc

	tenantParameters map[string]interface{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (apiprovider.Provider, error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	metadata, _ := params["metadata"].(map[string]interface{})

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

	providerName := "vclouddirector"

	var (
		metadataBucketName string
		ok                 bool
		err                error
	)
	if metadataBucketName, ok = metadata["Bucket"].(string); !ok || metadataBucketName == "" {
		metadataBucketName, err = objectstorage.BuildMetadataBucketName("ebrc", region, "", vdc)
		if err != nil {
			return nil, err
		}
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

	stack, err := ebrc.New(authOptions, ebrcOptions, cfgOptions)
	if err != nil {
		return nil, err
	}

	newP := &provider{
		StackEbrc:        stack,
		tenantParameters: params,
	}

	evalid := apiprovider.NewValidatedProvider(newP, providerName)
	etrace := apiprovider.NewErrorTraceProvider(evalid, providerName)
	prov := apiprovider.NewLoggedProvider(etrace, providerName)

	return prov, nil
}

// GetAuthOpts returns the auth options
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}
	opts := p.StackEbrc.GetAuthenticationOptions()

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
func (p *provider) GetConfigurationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}
	opts := p.StackEbrc.GetConfigurationOptions()

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
	return "ebrc"
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
	iaas.Register("ebrc", &provider{})
}
