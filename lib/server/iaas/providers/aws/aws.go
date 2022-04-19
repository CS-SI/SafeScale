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

package aws

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/stacks/aws"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

//goland:noinspection GoPreferNilSlice
var (
	dnsServers = []string{}
)

// provider is the provider implementation of the Aws provider
type provider struct {
	api.Stack

	tenantParameters map[string]interface{}
	templatesWithGPU []string
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

func (p provider) AddPublicIPToVIP(ip *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (p provider) BindHostToVIP(*abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (p provider) UnbindHostFromVIP(*abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME: Technical debt
}

func (p provider) DeleteVIP(*abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}

func (p provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNil(p) {
		return map[string]interface{}{}, fail.InvalidInstanceError()
	}
	return p.tenantParameters, nil
}

// New creates a new instance of aws provider
func New() providers.Provider {
	return &provider{}
}

// Build builds a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	// tenantName, _ := params["name"].(string)

	identityCfg, ok := params["identity"].(map[string]interface{})
	if !ok {
		return &provider{}, fail.SyntaxError("section 'identity' not found in tenants.toml")
	}

	computeCfg, ok := params["compute"].(map[string]interface{})
	if !ok {
		return &provider{}, fail.SyntaxError("section compute not found in tenants.toml")
	}

	var networkName string
	networkCfg, ok := params["network"].(map[string]interface{})
	if ok {
		networkName, _ = networkCfg["ProviderNetwork"].(string) // nolint
	}
	if networkName == "" {
		networkName = "safescale"
	}

	region, ok := computeCfg["Region"].(string)
	if !ok {
		return &provider{}, fail.SyntaxError("field 'Region' in section 'compute' not found in tenants.toml")
	}
	zone, ok := computeCfg["Zone"].(string)
	if !ok {
		return &provider{}, fail.SyntaxError("field 'Zone' in section 'compute' not found in tenants.toml")
	}

	var owners []string
	if _, ok = computeCfg["Owners"]; ok {
		ownerList, ok := computeCfg["Owners"].(string)
		if !ok {
			logrus.Debugf("error reading owners: %v", computeCfg["Owners"])
		} else {
			frag := strings.Split(ownerList, ",")
			for _, item := range frag {
				owners = append(owners, strings.TrimSpace(item))
			}
		}
	}

	awsConf := stacks.AWSConfiguration{
		// S3Endpoint:  s3Endpoint,
		Ec2Endpoint: fmt.Sprintf("https://ec2.%s.amazonaws.com", region),
		SsmEndpoint: fmt.Sprintf("https://ssm.%s.amazonaws.com", region),
		Region:      region,
		Zone:        zone,
		NetworkName: networkName,
		Owners:      owners,
	}

	username, ok := identityCfg["Username"].(string) // nolint
	if !ok || username == "" {
		username, _ = identityCfg["Username"].(string) // nolint
	}
	password, _ := identityCfg["Password"].(string) // nolint

	accessKeyID, ok := identityCfg["AccessKeyID"].(string)
	if !ok || accessKeyID == "" {
		return &provider{}, fail.SyntaxError("field 'AccessKeyID' in section 'identity' not found in tenants.toml")
	}

	secretAccessKey, ok := identityCfg["SecretAccessKey"].(string) // nolint
	if !ok || secretAccessKey == "" {
		return &provider{}, fail.SyntaxError("no secret access key provided in tenants.toml")
	}

	identityEndpoint, _ := identityCfg["IdentityEndpoint"].(string) // nolint
	if identityEndpoint == "" {
		identityEndpoint, ok = identityCfg["auth_uri"].(string) // deprecated, kept until next release
		if !ok || identityEndpoint == "" {
			identityEndpoint = "https://iam.amazonaws.com"
		}
	}

	projectName, _ := computeCfg["ProjectName"].(string)   // nolint
	projectID, _ := computeCfg["ProjectID"].(string)       // nolint
	defaultImage, _ := computeCfg["DefaultImage"].(string) // nolint

	maxLifeTime := 0
	if _, ok := computeCfg["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(computeCfg["MaxLifetimeInHours"].(string))
	}

	operatorUsername, _ := computeCfg["OperatorUsername"].(string) // nolint
	if operatorUsername == "" {
		operatorUsername = abstract.DefaultUser
	}

	authOptions := stacks.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		AccessKeyID:      accessKeyID,
		SecretAccessKey:  secretAccessKey,
		Region:           region,
		ProjectName:      projectName,
		ProjectID:        projectID,
		FloatingIPPool:   "public",
	}

	providerName := "aws"

	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, "", projectID)
	if xerr != nil {
		return nil, xerr
	}

	metadataBucketName = strings.ReplaceAll(metadataBucketName, ".", "-")

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
		MetadataBucket:   metadataBucketName,
		DefaultImage:     defaultImage,
		OperatorUsername: operatorUsername,
		UseNATService:    false,
		ProviderName:     providerName,
		// BuildSubnets:     false, // FIXME: AWS by default don't build subnetworks
		DefaultSecurityGroupName: "default",
		MaxLifeTime:              maxLifeTime,
		Timings:                  timings,
	}

	awsStack, err := aws.New(authOptions, awsConf, cfgOptions)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	// Note: if timings have to be tuned, update awsStack.MutableTimings

	wrapped := api.StackProxy{
		FullStack: awsStack,
		Name:      "amazon",
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
	if valid.IsNil(p) {
		return cfg, fail.InvalidInstanceError()
	}

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
func (p *provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}
	if valid.IsNil(p) {
		return cfg, fail.InvalidInstanceError()
	}

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
	cfg.Set("ProviderName", provName)
	cfg.Set("BuildSubnets", opts.BuildSubnets)
	cfg.Set("UseNATService", opts.UseNATService)
	cfg.Set("MaxLifeTimeInHours", opts.MaxLifeTime)

	return cfg, nil
}

// GetName returns the providerName
func (p provider) GetName() (string, fail.Error) {
	return "aws", nil
}

// GetStack returns the stack object used by the provider
// Note: use with caution, last resort option
func (p provider) GetStack() (api.Stack, fail.Error) {
	return p.Stack, nil
}

// ListImages overloads stack.ListImages to allow to filter the available images on the provider level
func (p provider) ListImages(all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListImages(all)
}

// ListTemplates overloads stack.ListTemplates to allow to filter the available templates on the provider level
func (p provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return []abstract.HostTemplate{}, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListTemplates(all)
}

// GetCapabilities returns the capabilities of the provider
func (p provider) GetCapabilities() (providers.Capabilities, fail.Error) {
	return providers.Capabilities{
		PrivateVirtualIP: false,
	}, nil
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
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

func init() {
	iaas.Register("aws", &provider{})
}
