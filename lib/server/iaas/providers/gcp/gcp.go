/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/gcp"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/asaskevich/govalidator"
)

const (
	gcpDefaultImage = "Ubuntu 20.04"
)

var (
	dnsServers = []string{"8.8.8.8", "1.1.1.1"}
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

// Build builds a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	// tenantName, _ := params["name"].(string) // nolint

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
		newNetworkName, _ := networkCfg["ProviderNetwork"].(string) // nolint
		if newNetworkName != "" {
			networkName = newNetworkName
		}
	}

	gcpprojectID, _ := identityCfg["project_id"].(string)                  // nolint
	privateKeyID, _ := identityCfg["private_key_id"].(string)              // nolint
	privateKey, _ := identityCfg["private_key"].(string)                   // nolint
	clientEmail, _ := identityCfg["client_email"].(string)                 // nolint
	clientID, _ := identityCfg["client_id"].(string)                       // nolint
	authURI, _ := identityCfg["auth_uri"].(string)                         // nolint
	tokenURI, _ := identityCfg["token_uri"].(string)                       // nolint
	authProvider, _ := identityCfg["auth_provider_x509_cert_url"].(string) // nolint
	clientCertURL, _ := identityCfg["client_x509_cert_url"].(string)       // nolint
	region, _ := computeCfg["Region"].(string)                             // nolint
	zone, _ := computeCfg["Zone"].(string)                                 // nolint

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

	username, _ := identityCfg["Username"].(string)         // nolint
	password, _ := identityCfg["Password"].(string)         // nolint
	identityEndpoint, _ := identityCfg["auth_uri"].(string) // nolint

	projectName, _ := computeCfg["ProjectName"].(string)   // nolint
	projectID, _ := computeCfg["ProjectID"].(string)       // nolint
	defaultImage, _ := computeCfg["DefaultImage"].(string) // nolint
	if defaultImage == "" {
		defaultImage = gcpDefaultImage
	}

	maxLifeTime := 0
	if _, ok := computeCfg["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(computeCfg["MaxLifetimeInHours"].(string))
	}

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, ok := computeCfg["OperatorUsername"]; ok {
		if operatorUsername, ok = operatorUsernameIf.(string); !ok {
			return nil, fail.InconsistentError("'OperatorUsername' should be a string")
		}
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

	customDNS, _ := computeCfg["DNS"].(string) // nolint
	if customDNS != "" {
		if strings.Contains(customDNS, ",") {
			fragments := strings.Split(customDNS, ",")
			for _, fragment := range fragments {
				fragment = strings.TrimSpace(fragment)
				if govalidator.IsIP(fragment) {
					dnsServers = append(dnsServers, fragment)
				}
			}
		} else {
			fragment := strings.TrimSpace(customDNS)
			if govalidator.IsIP(fragment) {
				dnsServers = append(dnsServers, fragment)
			}
		}
	}

	providerName := "gcp"
	metadataBucketName, err := objectstorage.BuildMetadataBucketName(providerName, region, "", projectID)
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:                   dnsServers,
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
		MaxLifeTime:      maxLifeTime,
	}

	gcpStack, xerr := gcp.New(authOptions, gcpConf, cfgOptions)
	if xerr != nil {
		return nil, xerr
	}

	// Note: if timings have to be tuned, update gcpStack.MutableTimings

	wrapped := api.StackProxy{
		FullStack: gcpStack,
		Name:      "google",
	}

	newP := &provider{
		Stack:            wrapped,
		tenantParameters: params,
	}

	wp := providers.ProviderProxy{
		Provider: newP,
		Name:     wrapped.Name,
	}

	return wp, nil
}

// GetAuthenticationOptions returns the auth options
func (p provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts, err := p.Stack.(api.ReservedForProviderUse).GetRawAuthenticationOptions()
	if err != nil {
		return nil, err
	}
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthURL", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts, err := p.Stack.(api.ReservedForProviderUse).GetRawConfigurationOptions()
	if err != nil {
		return nil, err
	}

	provName, xerr := p.GetName()
	if xerr != nil {
		return nil, xerr
	}

	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("UseNATService", opts.UseNATService)
	cfg.Set("ProviderName", provName)
	cfg.Set("MaxLifeTimeInHours", opts.MaxLifeTime)
	return cfg, nil
}

// GetName returns the providerName
func (p provider) GetName() (string, fail.Error) {
	return "gcp", nil
}

// GetStack returns the stack object used by the provider
// Note: use with caution, last resort option
func (p provider) GetStack() (api.Stack, fail.Error) {
	return p.Stack, nil
}

// ListImages ...
func (p provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
	if p.IsNull() {
		return []abstract.Image{}, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListImages(all)
}

// ListTemplates ...
func (p provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	if p.IsNull() {
		return []abstract.HostTemplate{}, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListTemplates(all)
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	return p.tenantParameters, nil
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() (providers.Capabilities, fail.Error) {
	return providers.Capabilities{
		CanDisableSecurityGroup: true,
	}, nil
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	var emptySlice []*regexp.Regexp
	if p.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	var (
		out []*regexp.Regexp
	)
	for _, v := range p.templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return emptySlice, fail.ConvertError(err)
		}
		out = append(out, re)
	}

	return out, nil
}

func init() {
	iaas.Register("gcp", &provider{})
}
