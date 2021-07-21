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

package gcp

import (
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/gcp"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	gcpDefaultImage = "Ubuntu 20.04"
)

// provider is the provider implementation of the Gcp provider
type provider struct {
	api.Stack

	templatesWithGPU []string
	tenantParameters map[string]interface{}
}

// New creates a new instance of gcp provider
func New() providers.Provider {
	return &provider{}
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build build a new Client from configuration parameter
// Can be called from nil
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	// tenantName, _ := params["name"].(string)

	identityCfg, ok := params["identity"].(map[string]interface{})
	if !ok {
		return &provider{}, fail.SyntaxError("section 'identity' not found in tenants.toml")
	}

	computeCfg, ok := params["compute"].(map[string]interface{})
	if !ok {
		return &provider{}, fail.SyntaxError("section 'compute' not found in tenants.toml")
	}

	networkName := "safescale"

	networkCfg, ok := params["network"].(map[string]interface{})
	if ok { // Do not log missing network section, it may happen without issue
		newNetworkName, _ := networkCfg["ProviderNetwork"].(string)
		if newNetworkName != "" {
			networkName = newNetworkName
		}
	}

	gcpprojectID, _ := identityCfg["project_id"].(string)
	privateKeyID, _ := identityCfg["private_key_id"].(string)
	privateKey, _ := identityCfg["private_key"].(string)
	clientEmail, _ := identityCfg["client_email"].(string)
	clientID, _ := identityCfg["client_id"].(string)
	authURI, _ := identityCfg["auth_uri"].(string)
	tokenURI, _ := identityCfg["token_uri"].(string)
	authProvider, _ := identityCfg["auth_provider_x509_cert_url"].(string)
	clientCertURL, _ := identityCfg["client_x509_cert_url"].(string)
	region, _ := computeCfg["Region"].(string)
	zone, _ := computeCfg["Zone"].(string)

	gcpConf := stacks.GCPConfiguration{
		Type:         "service_account",
		ProjectID:    gcpprojectID,
		PrivateKeyID: privateKeyID,
		PrivateKey:   privateKey,
		ClientEmail:  clientEmail,
		ClientID:     clientID,
		AuthURI:      authURI,
		TokenURI:     tokenURI,
		AuthProvider: authProvider,
		ClientCert:   clientCertURL,
		Region:       region,
		Zone:         zone,
		NetworkName:  networkName,
	}

	username, _ := identityCfg["Username"].(string)
	password, _ := identityCfg["Password"].(string)
	identityEndpoint, _ := identityCfg["auth_uri"].(string)

	projectName, _ := computeCfg["ProjectName"].(string)
	projectID, _ := computeCfg["ProjectID"].(string)
	defaultImage, _ := computeCfg["DefaultImage"].(string)
	if defaultImage == "" {
		defaultImage = gcpDefaultImage
	}

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, ok := computeCfg["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
	}

	authOptions := stacks.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		Region:           region,
		ProjectName:      projectName,
		ProjectID:        projectID,
		FloatingIPPool:   "public",
	}

	providerName := "gcp"
	metadataBucketName, err := objectstorage.BuildMetadataBucketName(providerName, region, "", projectID)
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:                   []string{"8.8.8.8", "1.1.1.1"},
		UseFloatingIP:             true,
		AutoHostNetworkInterfaces: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard":   volumespeed.Cold,
			"performant": volumespeed.Hdd,
		},
		MetadataBucket:   metadataBucketName,
		DefaultImage:     defaultImage,
		OperatorUsername: operatorUsername,
		UseNATService:    true,
		ProviderName:     providerName,
	}

	gcpStack, xerr := gcp.New(authOptions, gcpConf, cfgOptions)
	if xerr != nil {
		return nil, xerr
	}
	newP := &provider{
		Stack:            gcpStack,
		tenantParameters: params,
	}

	return newP, nil
}

// GetAuthenticationOptions returns the auth options
func (p provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.(api.ReservedForProviderUse).GetAuthenticationOptions()
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.(api.ReservedForProviderUse).GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("UseNATService", opts.UseNATService)
	cfg.Set("ProviderName", p.GetName())
	return cfg, nil
}

// GetName returns the providerName
func (p provider) GetName() string {
	return "gcp"
}

// ListImages ...
func (p provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
	if p.IsNull() {
		return []abstract.Image{}, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListImages()
}

// ListTemplates ...
func (p provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	if p.IsNull() {
		return []abstract.HostTemplate{}, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListTemplates()
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() map[string]interface{} {
	return p.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{
		CanDisableSecurityGroup: true,
	}
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() []*regexp.Regexp {
	var emptySlice []*regexp.Regexp
	if p.IsNull() {
		return emptySlice
	}

	var (
		out []*regexp.Regexp
	)
	for _, v := range p.templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return emptySlice
		}
		out = append(out, re)
	}

	return out
}

func init() {
	iaas.Register("gcp", &provider{})
}
