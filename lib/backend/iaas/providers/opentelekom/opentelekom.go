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

package opentelekom

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/huaweicloud"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	opentelekomDefaultImage = "Ubuntu 20.04"

	identityEndpointTemplate string = "https://iam.%s.otc.t-systems.com"
)

var (
	capabilities = iaasapi.Capabilities{PrivateVirtualIP: true}
	dnsServers   = []string{"1.1.1.1"}

	_ iaasapi.Provider                    = (*provider)(nil) // Verify that *provider implements iaas.Provider (at compile time)
	_ providers.ReservedForTerraformerUse = (*provider)(nil)
)

// provider is the providerementation of the OpenTelekom provider
type provider struct {
	iaasapi.Stack

	templatesWithGPU []string
	tenantParameters map[string]interface{}
}

// New creates a new instance of opentelekom provider
func New() iaasapi.Provider {
	return &provider{}
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build builds a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}, _ options.Options) (iaasapi.Provider, fail.Error) {
	identity, _ := params["identity"].(map[string]interface{}) // nolint
	compute, _ := params["compute"].(map[string]interface{})   // nolint
	network, _ := params["network"].(map[string]interface{})   // nolint

	username, _ := identity["Username"].(string)         // nolint
	password, _ := identity["Password"].(string)         // nolint
	domainName, _ := identity["DomainName"].(string)     // nolint
	projectID, _ := compute["ProjectID"].(string)        // nolint
	region, _ := compute["Region"].(string)              // nolint
	zone, _ := compute["AvailabilityZone"].(string)      // nolint
	vpcName, _ := network["DefaultNetworkName"].(string) // nolint
	vpcCIDR, _ := network["DefaultNetworkCIDR"].(string) // nolint

	identityEndpoint, _ := identity["IdentityEndpoint"].(string) // nolint
	if identityEndpoint == "" {
		identityEndpoint = fmt.Sprintf(identityEndpointTemplate, region)
	}

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername, ok = operatorUsernameIf.(string)
		if ok {
			if operatorUsername == "" {
				logrus.WithContext(context.Background()).Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
				operatorUsername = abstract.DefaultUser
			}
		}
	}

	isSafe, ok := compute["Safe"].(bool) // nolint
	if !ok {
		isSafe = true
	}
	params["Safe"] = isSafe

	logrus.Warningf("Setting safety to: %t", isSafe)

	defaultImage, _ := compute["DefaultImage"].(string) // nolint
	if defaultImage == "" {
		defaultImage = opentelekomDefaultImage
	}

	maxLifeTime := 0
	if _, ok := compute["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(compute["MaxLifetimeInHours"].(string))
	}

	machineCreationLimit := 8
	if _, ok := compute["ConcurrentMachineCreationLimit"].(string); ok {
		machineCreationLimit, _ = strconv.Atoi(compute["ConcurrentMachineCreationLimit"].(string))
	}

	authOptions := iaasoptions.Authentication{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		DomainName:       domainName,
		ProjectID:        projectID,
		Region:           region,
		AvailabilityZone: zone,
		AllowReauth:      true,
	}

	err := validation.ValidateStruct(&authOptions,
		validation.Field(&authOptions.Region, validation.Required, validation.Match(regexp.MustCompile("^[-a-zA-Z0-9-_]+$"))),
		validation.Field(&authOptions.AvailabilityZone, validation.Required, validation.Match(regexp.MustCompile("^[-a-zA-Z0-9-_]+$"))),
	)
	if err != nil {
		return nil, fail.NewError("Structure validation failure: %v", err)
	}

	providerName := "huaweicloud"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, domainName, projectID)
	if xerr != nil {
		return nil, xerr
	}

	customDNS, _ := compute["DNS"].(string) // . nolint
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

	cfgOptions := iaasoptions.Configuration{
		DNSServers:          dnsServers,
		UseFloatingIP:       true,
		UseLayer3Networking: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"SATA": volumespeed.Cold,
			"SAS":  volumespeed.Hdd,
			"Ssd":  volumespeed.Ssd,
		},
		MetadataBucketName:             metadataBucketName,
		OperatorUsername:               operatorUsername,
		ProviderName:                   providerName,
		DefaultNetworkName:             vpcName,
		DefaultNetworkCIDR:             vpcCIDR,
		DefaultImage:                   defaultImage,
		MaxLifeTime:                    maxLifeTime,
		Timings:                        timings,
		Safe:                           isSafe,
		ConcurrentMachineCreationLimit: machineCreationLimit,
	}
	stack, xerr := huaweicloud.New(authOptions, cfgOptions)
	if xerr != nil {
		return nil, xerr
	}

	// Note: if timings have to be tuned, update stack.MutableTimings

	wrapped := stacks.Remediator{
		Stack: stack,
		Name:  "opentelekomm",
	}

	newP := provider{
		Stack:            wrapped,
		tenantParameters: params,
	}

	wp := providers.Remediator{
		Provider: &newP,
		Name:     wrapped.Name,
	}

	return wp, nil
}

// ListTemplates ... ; overloads stack.ListTemplates() to allow to filter templates to show
// Value of all has no impact on the result
func (p *provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.Stack.(providers.StackReservedForProviderUse).ListTemplates(ctx, all)
}

// ListImages ... ; overloads stack.ListImages() to allow to filter images to show
// Value of all has no impact on the result
func (p *provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.Stack.(providers.StackReservedForProviderUse).ListImages(ctx, all)
}

// AuthenticationOptions returns the auth options
func (p *provider) AuthenticationOptions() (iaasoptions.Authentication, fail.Error) {
	if valid.IsNull(p) {
		return iaasoptions.Authentication{}, fail.InvalidInstanceError()
	}

	return p.Stack.(providers.StackReservedForProviderUse).AuthenticationOptions()
}

// ConfigurationOptions return configuration parameters
func (p *provider) ConfigurationOptions() (iaasoptions.Configuration, fail.Error) {
	if valid.IsNull(p) {
		return iaasoptions.Configuration{}, fail.InvalidInstanceError()
	}

	opts, err := p.Stack.(providers.StackReservedForProviderUse).ConfigurationOptions()
	if err != nil {
		return iaasoptions.Configuration{}, err
	}

	provName, xerr := p.GetName()
	if xerr != nil {
		return iaasoptions.Configuration{}, xerr
	}

	opts.ProviderName = provName
	return opts, nil
}

// GetName ...
func (p provider) GetName() (string, fail.Error) {
	return "opentelekom", nil
}

// StackDriver returns the stack object used by the provider
// Note: use with caution, last resort option
func (p provider) StackDriver() (iaasapi.Stack, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.Stack, nil
}

// TenantParameters ...
func (p *provider) TenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.tenantParameters, nil
}

// Capabilities returns the capabilities of the provider
func (p *provider) Capabilities() iaasapi.Capabilities {
	return capabilities
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p *provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	if valid.IsNull(p) {
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
	if valid.IsNull(p) {
		return false, fail.InvalidInstanceError()
	}

	options, xerr := p.ConfigurationOptions()
	if xerr != nil {
		return false, xerr
	}

	return options.DefaultNetworkName != "", nil
}

// DefaultNetwork returns the *abstract.Network corresponding to the default network
func (p provider) DefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	options, xerr := p.ConfigurationOptions()
	if xerr != nil {
		return nil, xerr
	}

	if options.DefaultNetworkName != "" {
		networkAbstract, xerr := p.InspectNetwork(ctx, options.DefaultNetworkCIDR)
		if xerr != nil {
			return nil, xerr
		}

		return networkAbstract, nil
	}

	return nil, fail.NotFoundError("this provider has no default network")
}

func (p *provider) ConsolidateNetworkSnippet(_ *abstract.Network) fail.Error {
	return nil
}

func (p *provider) ConsolidateSubnetSnippet(_ *abstract.Subnet) fail.Error {
	return nil
}

func (p *provider) ConsolidateSecurityGroupSnippet(_ *abstract.SecurityGroup) fail.Error {
	return nil
}

func (p *provider) ConsolidateHostSnippet(_ *abstract.HostCore) fail.Error {
	return nil
}

func (p *provider) ConsolidateVolumeSnippet(_ *abstract.Volume) fail.Error {
	return nil
}

// init registers the opentelekom provider
func init() {
	profile := providers.NewProfile(
		capabilities,
		func() iaasapi.Provider { return &provider{} },
		nil,
	)
	iaas.RegisterProviderProfile("opentelekom", profile)
}
