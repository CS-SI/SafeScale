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

package cloudferro

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var (
	cloudferroIdentityEndpoint = "https://cf2.cloudferro.com:5000/v3"
	cloudferroDefaultImage     = "Ubuntu 20.04"
	cloudferroDNSServers       = []string{"185.48.234.234", "185.48.234.238"}
)

// provider is the implementation of the CloudFerro provider
type provider struct {
	api.Stack

	tenantParameters map[string]interface{}
	templatesWithGPU []string
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build builds a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
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

	logrus.WithContext(context.Background()).Infof("Setting safety to: %t", isSafe)

	var maxLifeTime int64 = 0
	if val, ok := compute["MaxLifetimeInHours"].(int64); ok {
		maxLifeTime = val
	}

	machineCreationLimit := 8
	if _, ok = compute["ConcurrentMachineCreationLimit"].(string); ok {
		machineCreationLimit, _ = strconv.Atoi(compute["ConcurrentMachineCreationLimit"].(string))
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

	authOptions := stacks.AuthenticationOptions{
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

	suffix := getSuffix(params)
	providerName := "openstack"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, domainName, projectName, suffix)
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

	cfgOptions := stacks.ConfigurationOptions{
		ProviderNetwork:           providerNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"Hdd": volumespeed.Hdd,
			"Ssd": volumespeed.Ssd,
		},
		MetadataBucket:                 metadataBucketName,
		DNSList:                        cloudferroDNSServers,
		DefaultImage:                   defaultImage,
		OperatorUsername:               operatorUsername,
		ProviderName:                   providerName,
		DefaultSecurityGroupName:       "default",
		MaxLifeTime:                    maxLifeTime,
		Timings:                        timings,
		Safe:                           isSafe,
		ConcurrentMachineCreationLimit: machineCreationLimit,
	}

	serviceVersions := map[string]string{"volume": "v2"}

	if maybe, ok := compute["IdentityEndpointVersion"]; ok {
		if val, ok := maybe.(string); ok {
			serviceVersions["identity"] = val
		}
	}

	if maybe, ok := compute["ComputeEndpointVersion"]; ok {
		if val, ok := maybe.(string); ok {
			serviceVersions["compute"] = val
		}
	}

	if maybe, ok := compute["VolumeEndpointVersion"]; ok {
		if val, ok := maybe.(string); ok {
			serviceVersions["volume"] = val
		}
	}

	if maybe, ok := network["NetworkEndpointVersion"]; ok {
		if val, ok := maybe.(string); ok {
			serviceVersions["network"] = val
		}
	}

	stack, xerr := openstack.New(authOptions, nil, cfgOptions, serviceVersions)
	if xerr != nil {
		return nil, xerr
	}

	wrapped := api.StackProxy{
		FullStack: stack,
		Name:      "cloudferro",
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
	if osto, ok := params["objectstorage"].(map[string]interface{}); ok {
		if val, ok := osto["Suffix"].(string); ok {
			suffix = val
			if suffix != "" {
				return suffix
			}
		}
	}
	if meta, ok := params["metadata"].(map[string]interface{}); ok {
		if val, ok := meta["Suffix"].(string); ok {
			suffix = val
		}
	}
	return suffix
}

// GetAuthenticationOptions returns the auth options
func (p provider) GetAuthenticationOptions(ctx context.Context) (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}
	if valid.IsNil(p) {
		return cfg, fail.InvalidInstanceError()
	}

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
	if valid.IsNil(p) {
		return cfg, fail.InvalidInstanceError()
	}

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
	cfg.Set("ProviderName", provName)
	cfg.Set("UseNATService", opts.UseNATService)
	cfg.Set("MaxLifeTimeInHours", opts.MaxLifeTime)
	cfg.Set("Safe", opts.Safe)
	cfg.Set("ConcurrentMachineCreationLimit", opts.ConcurrentMachineCreationLimit)

	return cfg, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	allTemplates, xerr := p.Stack.(api.ReservedForProviderUse).ListTemplates(ctx, all)
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

	allImages, xerr := p.Stack.(api.ReservedForProviderUse).ListImages(ctx, all)
	if xerr != nil {
		return nil, xerr
	}
	return allImages, nil
}

// GetName returns the providerName
func (p provider) GetName() (string, fail.Error) {
	return "cloudferro", nil
}

// GetStack returns the stack object used by the provider
func (p provider) GetStack() (api.Stack, fail.Error) {
	return p.Stack, nil
}

// GetTenantParameters returns the tenant parameters as-is
func (p provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNil(p) {
		return map[string]interface{}{}, fail.InvalidInstanceError()
	}

	return p.tenantParameters, nil
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities(context.Context) (providers.Capabilities, fail.Error) {
	if valid.IsNil(p) {
		return providers.Capabilities{}, fail.InvalidInstanceError()
	}

	return providers.Capabilities{
		PrivateVirtualIP: true,
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
	iaas.Register("cloudferro", &provider{})
}
