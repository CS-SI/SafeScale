/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/gcp"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
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

func recast(in any) (map[string]any, error) {
	out := make(map[string]any)
	if in == nil {
		return out, nil
	}

	if input, ok := in.(map[string]any); ok {
		return input, nil
	}

	input, ok := in.(map[any]any)
	if !ok {
		return nil, fmt.Errorf("invalid input type: %T", in)
	}

	for k, v := range input {
		nk, ok := k.(string)
		if !ok {
			return nil, fmt.Errorf("invalid key type: %T", k)
		}
		out[nk] = v
	}
	return out, nil
}

// Build builds a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	// tenantName, _ := params["name"].(string) // nolint

	identityCfg, err := recast(params["identity"])
	if err != nil {
		return &provider{}, fail.ConvertError(err)
	}

	computeCfg, err := recast(params["compute"])
	if err != nil {
		return &provider{}, fail.ConvertError(err)
	}

	networkName := "safescale"

	networkCfg, err := recast(params["network"])
	if err != nil {
		return &provider{}, fail.ConvertError(err)
	}

	newNetworkName, _ := networkCfg["ProviderNetwork"].(string) // nolint
	if newNetworkName != "" {
		networkName = newNetworkName
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

	var maxLifeTime int64 = 0
	if val, ok := computeCfg["MaxLifetimeInHours"].(int64); ok {
		maxLifeTime = val
	}

	machineCreationLimit := 8
	if _, ok := computeCfg["ConcurrentMachineCreationLimit"].(string); ok {
		machineCreationLimit, _ = strconv.Atoi(computeCfg["ConcurrentMachineCreationLimit"].(string))
	}

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, ok := computeCfg["OperatorUsername"]; ok {
		if operatorUsername, ok = operatorUsernameIf.(string); !ok {
			return nil, fail.InconsistentError("'OperatorUsername' should be a string")
		}
	}

	isSafe, ok := computeCfg["Safe"].(bool) // nolint
	if !ok {
		isSafe = true
	}
	params["Safe"] = isSafe

	logrus.WithContext(context.Background()).Infof("Setting safety to: %t", isSafe)

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
				if valid.IsIP(fragment) {
					dnsServers = append(dnsServers, fragment)
				}
			}
		} else {
			fragment := strings.TrimSpace(customDNS)
			if valid.IsIP(fragment) {
				dnsServers = append(dnsServers, fragment)
			}
		}
	}

	suffix := getSuffix(params)

	providerName := "gcp"
	metadataBucketName, err := objectstorage.BuildMetadataBucketName(providerName, region, "", projectID, suffix)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	metadataBucketName = strings.ReplaceAll(metadataBucketName, ".", "-")

	var timings *temporal.MutableTimings
	if tc, ok := params["timings"]; ok {
		if theRecoveredTiming, ok := tc.(map[string]interface{}); ok {
			s := &temporal.MutableTimings{}
			err := mapstructure.Decode(theRecoveredTiming, &s)
			if err != nil {
				goto next
			}
			timings = s
		}
	}
next:

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:                   dnsServers,
		UseFloatingIP:             true,
		AutoHostNetworkInterfaces: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard":   volumespeed.Cold,
			"performant": volumespeed.Hdd,
		},
		MetadataBucket:                 metadataBucketName,
		DefaultImage:                   defaultImage,
		OperatorUsername:               operatorUsername,
		UseNATService:                  true,
		ProviderName:                   providerName,
		MaxLifeTime:                    maxLifeTime,
		Timings:                        timings,
		Safe:                           isSafe,
		ConcurrentMachineCreationLimit: machineCreationLimit,
	}

	serviceVersions := map[string]string{}

	if maybe, ok := computeCfg["ComputeEndpointVersion"]; ok {
		if version, ok := maybe.(string); ok {
			serviceVersions["compute"] = version
		}
	}

	gcpStack, xerr := gcp.New(authOptions, gcpConf, cfgOptions, serviceVersions)
	if xerr != nil {
		return nil, xerr
	}

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

func getSuffix(params map[string]interface{}) string {
	suffix := ""
	if osto, err := recast(params["objectstorage"]); err == nil {
		if val, ok := osto["Suffix"].(string); ok {
			suffix = val
			if suffix != "" {
				return suffix
			}
		}
	}
	if meta, err := recast(params["metadata"]); err == nil {
		if val, ok := meta["Suffix"].(string); ok {
			suffix = val
		}
	}
	return suffix
}

// GetAuthenticationOptions returns the auth options
func (p provider) GetAuthenticationOptions(ctx context.Context) (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts, err := p.Stack.(api.ReservedForProviderUse).GetRawAuthenticationOptions(ctx)
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
func (p provider) GetConfigurationOptions(ctx context.Context) (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts, err := p.Stack.(api.ReservedForProviderUse).GetRawConfigurationOptions(ctx)
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
	cfg.Set("Safe", opts.Safe)
	cfg.Set("ConcurrentMachineCreationLimit", opts.ConcurrentMachineCreationLimit)
	return cfg, nil
}

// GetName returns the providerName
func (p provider) GetName() (string, fail.Error) {
	return "gcp", nil
}

// GetStack returns the stack object used by the provider
func (p provider) GetStack() (api.Stack, fail.Error) {
	return p.Stack, nil
}

// ListImages ...
func (p provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListImages(ctx, all)
}

// ListTemplates ...
func (p provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListTemplates(ctx, all)
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	return p.tenantParameters, nil
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities(context.Context) (providers.Capabilities, fail.Error) {
	return providers.Capabilities{
		CanDisableSecurityGroup: true,
	}, nil
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	var (
		out []*regexp.Regexp
	)
	for _, v := range p.templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		out = append(out, re)
	}

	return out, nil
}

func init() {
	iaas.Register("gcp", &provider{})
}
