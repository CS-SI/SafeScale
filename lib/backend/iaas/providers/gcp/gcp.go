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
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/gcp"
	stackoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/terraformer"
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
	capabilities = providers.Capabilities{
		CanDisableSecurityGroup: true,
	}
	dnsServers = []string{"8.8.8.8", "1.1.1.1"}
)

// provider is the provider implementation of the Gcp provider
type provider struct {
	stacks.Stack

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

	isSafe, ok := computeCfg["Safe"].(bool) // nolint
	if !ok {
		isSafe = true
	}
	params["Safe"] = isSafe

	logrus.Warningf("Setting safety to: %t", isSafe)

	authOptions := stackoptions.Authentication{
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

	providerName := "gcp"
	metadataBucketName, err := objectstorage.BuildMetadataBucketName(providerName, region, "", projectID)
	if err != nil {
		return nil, err
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

	cfgOptions := stackoptions.Configuration{
		DNSServers:                dnsServers,
		UseFloatingIP:             true,
		AutoHostNetworkInterfaces: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard":   volumespeed.Cold,
			"performant": volumespeed.Hdd,
		},
		MetadataBucketName: metadataBucketName,
		DefaultImage:       defaultImage,
		OperatorUsername:   operatorUsername,
		UseNATService:      true,
		ProviderName:       providerName,
		MaxLifeTime:        maxLifeTime,
		Timings:            timings,
		Safe:               isSafe,
	}

	gcpStack, xerr := gcp.New(authOptions, gcpConf, cfgOptions)
	if xerr != nil {
		return nil, xerr
	}

	// Note: if timings have to be tuned, update gcpStack.MutableTimings

	wrapped := stacks.Remediator{
		Stack: gcpStack,
		Name:  "google",
	}

	newP := &provider{
		Stack:            wrapped,
		tenantParameters: params,
	}

	wp := providers.Remediator{
		Provider: newP,
		Name:     wrapped.Name,
	}

	return wp, nil
}

// BuildWithTerraformer needs to be called when terraformer is used
func (p *provider) BuildWithTerraformer(params map[string]any, config terraformer.Configuration) (providers.Provider, fail.Error) {
	return nil, fail.NotImplementedError()
}

// AuthenticationOptions returns the auth options
func (p provider) AuthenticationOptions() (stackoptions.Authentication, fail.Error) {
	if valid.IsNull(p) {
		return stackoptions.Authentication{}, fail.InvalidInstanceError()
	}
	if valid.IsNull(p.Stack) {
		return stackoptions.Authentication{}, fail.InvalidInstanceContentError("p.Stack", "must be a valid 'Stack'")
	}

	return p.Stack.(providers.StackReservedForProviderUse).AuthenticationOptions()
}

// ConfigurationOptions return configuration parameters
func (p provider) ConfigurationOptions() (stackoptions.Configuration, fail.Error) {
	if valid.IsNull(p) {
		return stackoptions.Configuration{}, fail.InvalidInstanceError()
	}
	if valid.IsNull(p.Stack) {
		return stackoptions.Configuration{}, fail.InvalidInstanceContentError("p.Stack", "must be a valid 'Stack'")
	}

	opts, xerr := p.Stack.(providers.StackReservedForProviderUse).ConfigurationOptions()
	if xerr != nil {
		return stackoptions.Configuration{}, xerr
	}

	opts.ProviderName, xerr = p.GetName()
	if xerr != nil {
		return stackoptions.Configuration{}, xerr
	}

	return opts, nil
}

// GetName returns the providerName
func (p *provider) GetName() (string, fail.Error) {
	return "gcp", nil
}

// GetStack returns the stack object used by the provider
// Note: use with caution, last resort option
func (p provider) GetStack() (stacks.Stack, fail.Error) {
	return p.Stack, nil
}

// ListImages ...
func (p *provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	if p.Stack == nil {
		return nil, fail.InvalidInstanceContentError("p.Stack", "cannot be nil")
	}

	return p.Stack.(providers.StackReservedForProviderUse).ListImages(ctx, all)
}

// ListTemplates ...
func (p *provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	if p.Stack == nil {
		return nil, fail.InvalidInstanceContentError("p.Stack", "cannot be nil")
	}

	return p.Stack.(providers.StackReservedForProviderUse).ListTemplates(ctx, all)
}

// TenantParameters returns the tenant parameters as-is
func (p *provider) TenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.tenantParameters, nil
}

// Capabilities returns the capabilities of the provider
func (p *provider) Capabilities() providers.Capabilities {
	return capabilities
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p *provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	var emptySlice []*regexp.Regexp
	if valid.IsNil(p) {
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

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (p *provider) HasDefaultNetwork() (bool, fail.Error) {
	return false, nil
}

// DefaultNetwork returns the *abstract.Network corresponding to the default network
func (p *provider) DefaultNetwork(_ context.Context) (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("this provider has no default network")
}

func init() {
	profile := providers.NewProfile(
		capabilities,
		func() providers.Provider { return &provider{} },
		nil,
	)
	iaas.Register("gcp", profile)
}
