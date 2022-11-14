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

package cloudferro

import (
	"context"
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
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

var (
	capabilities = iaasapi.Capabilities{
		PrivateVirtualIP: true,
	}
	cloudferroIdentityEndpoint = "https://cf2.cloudferro.com:5000/v3"
	cloudferroDefaultImage     = "Ubuntu 20.04"
	cloudferroDNSServers       = []string{"185.48.234.234", "185.48.234.238"}
)

// provider is the implementation of the CloudFerro provider
type provider struct {
	iaasapi.Stack

	tenantParameters map[string]interface{}
	templatesWithGPU []string
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build builds a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}, _ options.Options) (iaasapi.Provider, fail.Error) {
	// tenantName, _ := params["name"].(string)

	identity, _ := params["identity"].(map[string]interface{}) // nolint
	compute, _ := params["compute"].(map[string]interface{})   // nolint
	network, _ := params["network"].(map[string]interface{})   // nolint

	username, _ := identity["Username"].(string)     // nolint
	password, _ := identity["Password"].(string)     // nolint
	domainName, _ := identity["DomainName"].(string) // nolint

	// region, _ := compute["Region"].(string) // nolint
	region := "RegionOne"
	// zone, _ := compute["AvailabilityZone"].(string) // nolint
	zone := "nova"
	projectName, _ := compute["ProjectName"].(string) // nolint
	// projectID, _ := compute["ProjectID"].(string) // nolint
	defaultImage, _ := compute["DefaultImage"].(string) // nolint
	if defaultImage == "" {
		defaultImage = cloudferroDefaultImage
	}

	isSafe, ok := compute["Safe"].(bool) // nolint
	if !ok {
		isSafe = true
	}
	params["Safe"] = isSafe

	logrus.Warningf("Setting safety to: %t", isSafe)

	maxLifeTime := 0
	if _, ok := compute["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(compute["MaxLifetimeInHours"].(string))
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

	providerNetwork, _ := network["ProviderNetwork"].(string) // nolint
	if providerNetwork == "" {
		providerNetwork = "external"
	}
	floatingIPPool, _ := network["FloatingIPPool"].(string) // nolint
	if floatingIPPool == "" {
		floatingIPPool = providerNetwork
	}

	authOptions := iaasoptions.Authentication{
		IdentityEndpoint: cloudferroIdentityEndpoint,
		Username:         username,
		Password:         password,
		DomainName:       domainName,
		TenantName:       projectName,
		Region:           region,
		AvailabilityZone: zone,
		FloatingIPPool:   floatingIPPool,
		AllowReauth:      true,
	}

	err := validation.ValidateStruct(&authOptions,
		validation.Field(&authOptions.Region, validation.Required, validation.Match(regexp.MustCompile("^[-a-zA-Z0-9-_]+$"))),
		validation.Field(&authOptions.AvailabilityZone, validation.Required, validation.Match(regexp.MustCompile("^[-a-zA-Z0-9-_]+$"))),
	)
	if err != nil {
		return nil, fail.NewError("Structure validation failure: %v", err)
	}

	providerName := "openstack"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, domainName, projectName)
	if xerr != nil {
		return nil, xerr
	}

	customDNS, _ := compute["DNS"].(string) // nolint
	if customDNS != "" {
		if strings.Contains(customDNS, ",") {
			fragments := strings.Split(customDNS, ",")
			for _, fragment := range fragments {
				fragment = strings.TrimSpace(fragment)
				if valid.IsIP(fragment) {
					cloudferroDNSServers = append(cloudferroDNSServers, fragment)
				}
			}
		} else {
			fragment := strings.TrimSpace(customDNS)
			if valid.IsIP(fragment) {
				cloudferroDNSServers = append(cloudferroDNSServers, fragment)
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
		ProviderNetwork:           providerNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"Hdd": volumespeed.Hdd,
			"Ssd": volumespeed.Ssd,
		},
		MetadataBucketName:       metadataBucketName,
		DNSServers:               cloudferroDNSServers,
		DefaultImage:             defaultImage,
		OperatorUsername:         operatorUsername,
		ProviderName:             providerName,
		DefaultSecurityGroupName: "default",
		MaxLifeTime:              maxLifeTime,
		Timings:                  timings,
		Safe:                     isSafe,
	}

	stack, xerr := openstack.New(authOptions, nil, cfgOptions, nil)
	if xerr != nil {
		return nil, xerr
	}

	// Note: if timings have to be tuned, update stack.MutableTimings

	wrapped := stacks.Remediator{
		Stack: stack,
		Name:  "cloudferro",
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

// AuthenticationOptions returns the auth options
func (p *provider) AuthenticationOptions() (iaasoptions.Authentication, fail.Error) {
	if valid.IsNil(p) {
		return iaasoptions.Authentication{}, fail.InvalidInstanceError()
	}

	return p.Stack.(providers.StackReservedForProviderUse).AuthenticationOptions()
}

// ConfigurationOptions return configuration parameters
func (p provider) ConfigurationOptions() (iaasoptions.Configuration, fail.Error) {
	if valid.IsNil(p) {
		return iaasoptions.Configuration{}, fail.InvalidInstanceError()
	}

	opts, xerr := p.Stack.(providers.StackReservedForProviderUse).ConfigurationOptions()
	if xerr != nil {
		return iaasoptions.Configuration{}, xerr
	}

	opts.ProviderName, xerr = p.GetName()
	if xerr != nil {
		return iaasoptions.Configuration{}, xerr
	}

	return opts, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	allTemplates, xerr := p.Stack.(providers.StackReservedForProviderUse).ListTemplates(ctx, all)
	if xerr != nil {
		return nil, xerr
	}
	return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	allImages, xerr := p.Stack.(providers.StackReservedForProviderUse).ListImages(ctx, all)
	if xerr != nil {
		return nil, xerr
	}
	return allImages, nil
}

// GetName returns the providerName
func (p *provider) GetName() (string, fail.Error) {
	return "cloudferro", nil
}

// StackDriver returns the stack object used by the provider
// Note: use with caution, last resort option
func (p *provider) StackDriver() (iaasapi.Stack, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.Stack, nil
}

// TenantParameters returns the tenant parameters as-is
func (p *provider) TenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNil(p) {
		return map[string]interface{}{}, fail.InvalidInstanceError()
	}

	return p.tenantParameters, nil
}

// Capabilities returns the capabilities of the provider
func (p *provider) Capabilities() iaasapi.Capabilities {
	return capabilities
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p *provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
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
func (p *provider) DefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error) {
	return nil, fail.NotFoundError("this provider has no default network")
}

func init() {
	profile := providers.NewProfile(
		capabilities,
		func() iaasapi.Provider { return &provider{} },
		nil,
	)
	iaas.RegisterProviderProfile("cloudferro", profile)
}
