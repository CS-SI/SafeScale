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
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/aws"
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

//goland:noinspection GoPreferNilSlice
var (
	capabilities = providers.Capabilities{
		PrivateVirtualIP: false,
	}

	dnsServers = []string{}
)

// provider is the provider implementation of the Aws provider
type provider struct {
	stacks.Stack

	tenantParameters map[string]interface{}
	templatesWithGPU []string
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

func (p *provider) AddPublicIPToVIP(ctx context.Context, ip *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("AddPublicIPToVIP() not implemented yet") // FIXME: Technical debt
}

func (p *provider) BindHostToVIP(context.Context, *abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("BindHostToVIP() not implemented yet") // FIXME: Technical debt
}

func (p *provider) UnbindHostFromVIP(context.Context, *abstract.VirtualIP, string) fail.Error {
	return fail.NotImplementedError("UnbindHostFromVIP() not implemented yet") // FIXME: Technical debt
}

func (p *provider) DeleteVIP(context.Context, *abstract.VirtualIP) fail.Error {
	return fail.NotImplementedError("DeleteVIP() not implemented yet") // FIXME: Technical debt
}

func (p *provider) TenantParameters() (map[string]interface{}, fail.Error) {
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
			logrus.WithContext(context.Background()).Debugf("error reading owners: %v", computeCfg["Owners"])
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
		identityEndpoint, ok = identityCfg["auth_uri"].(string) // DEPRECATED: deprecated, kept until next release
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
		UseNATService:      false,
		ProviderName:       providerName,
		// BuildSubnets:     false, // FIXME: AWS by default don't build subnetworks
		DefaultSecurityGroupName: "default",
		MaxLifeTime:              maxLifeTime,
		Timings:                  timings,
		Safe:                     isSafe,
	}

	awsStack, err := aws.New(authOptions, awsConf, cfgOptions)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	// Note: if timings have to be tuned, update awsStack.MutableTimings

	wrapped := stacks.Remediator{
		Stack: awsStack,
		Name:  "amazon",
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
func (p *provider) AuthenticationOptions() (stackoptions.Authentication, fail.Error) {
	if valid.IsNil(p) {
		return stackoptions.Authentication{}, fail.InvalidInstanceError()
	}
	if valid.IsNull(p.Stack) {
		return stackoptions.Authentication{}, fail.InvalidInstanceContentError("p.Stack", "cannot be nil")
	}

	return p.Stack.(providers.StackReservedForProviderUse).AuthenticationOptions()
}

// ConfigurationOptions return configuration parameters
func (p *provider) ConfigurationOptions() (stackoptions.Configuration, fail.Error) {
	if valid.IsNil(p) {
		return stackoptions.Configuration{}, fail.InvalidInstanceError()
	}
	if valid.IsNull(p.Stack) {
		return stackoptions.Configuration{}, fail.InvalidInstanceContentError("p.Stack", "cannot be nil")
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
	return "aws", nil
}

// GetStack returns the stack object used by the provider
// Note: use with caution, last resort option
func (p *provider) GetStack() (stacks.Stack, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	if valid.IsNull(p.Stack) {
		return nil, fail.InvalidInstanceContentError("p.Stack", "cannot be nil")
	}

	return p.Stack, nil
}

// ListImages overloads stack.ListImages to allow to filter the available images on the provider level
func (p *provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	if valid.IsNull(p.Stack) {
		return nil, fail.InvalidInstanceContentError("p.Stack", "cannot be nil")
	}

	return p.Stack.(providers.StackReservedForProviderUse).ListImages(ctx, all)
}

// ListTemplates overloads stack.ListTemplates to allow to filter the available templates on the provider level
func (p *provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	if valid.IsNull(p.Stack) {
		return nil, fail.InvalidInstanceContentError("p.Stack", "cannot be nil")
	}

	return p.Stack.(providers.StackReservedForProviderUse).ListTemplates(ctx, all)
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

func init() {
	profile := providers.NewProfile(
		capabilities,
		func() providers.Provider { return &provider{} },
		nil,
	)
	iaas.Register("aws", profile)
}
