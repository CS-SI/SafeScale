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

package openstack

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"

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

const (
	openstackDefaultImage = "Ubuntu 20.04"
)

var (
	dnsServers = []string{"8.8.8.8", "1.1.1.1"}
)

// provider is the provider implementation of the openstack provider respecting api.Provider
type provider struct {
	api.Stack

	SecurityGroup     *secgroups.SecurityGroup
	ExternalNetworkID string

	templatesWithGPU []string
	tenantParameters map[string]interface{}
}

// New creates a new instance of pure openstack provider
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
	identity, err := recast(params["identity"])
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	compute, err := recast(params["compute"])
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	network, err := recast(params["network"])
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	identityEndpoint, _ := identity["IdentityEndpoint"].(string) // nolint
	username, _ := identity["Username"].(string)                 // nolint
	password, _ := identity["Password"].(string)                 // nolint
	tenantName, _ := compute["TenantName"].(string)              // nolint
	tenantID, _ := compute["TenantID"].(string)                  // nolint
	region, _ := compute["Region"].(string)                      // nolint
	zone, _ := compute["AvailabilityZone"].(string)              // nolint
	if zone == "" {
		zone = "nova"
	}
	providerNetwork, _ := network["ExternalNetwork"].(string) // nolint
	if providerNetwork == "" {
		providerNetwork = "public"
	}
	floatingIPPool, _ := network["FloatingIPPool"].(string) // nolint
	if floatingIPPool == "" {
		floatingIPPool = providerNetwork
	}
	defaultImage, _ := compute["DefaultImage"].(string) // nolint
	if defaultImage == "" {
		defaultImage = openstackDefaultImage
	}

	var maxLifeTime int64 = 0
	if val, ok := compute["MaxLifetimeInHours"].(int64); ok {
		maxLifeTime = val
	}

	machineCreationLimit := 8
	if _, ok := compute["ConcurrentMachineCreationLimit"].(string); ok {
		machineCreationLimit, _ = strconv.Atoi(compute["ConcurrentMachineCreationLimit"].(string))
	}

	customDNS, _ := compute["DNS"].(string) // nolint
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

	logrus.WithContext(context.Background()).Infof("Setting safety to: %t", isSafe)

	authOptions := stacks.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		TenantID:         tenantID,
		TenantName:       tenantName,
		Region:           region,
		AvailabilityZone: zone,
		FloatingIPPool:   floatingIPPool,
	}

	suffix := getSuffix(params)

	providerName := "openstack"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, tenantID, "0", suffix)
	if xerr != nil {
		return nil, xerr
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
		DNSList:                   dnsServers,
		DefaultImage:              defaultImage,
		MetadataBucket:            metadataBucketName,
		OperatorUsername:          operatorUsername,
		ProviderName:              providerName,
		DefaultSecurityGroupName:  "default",
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard":   volumespeed.Cold,
			"performant": volumespeed.Hdd,
		},
		MaxLifeTime:                    maxLifeTime,
		Timings:                        timings,
		Safe:                           isSafe,
		ConcurrentMachineCreationLimit: machineCreationLimit,
	}

	stack, xerr := openstack.New(authOptions, nil, cfgOptions, nil)
	if xerr != nil {
		return nil, xerr
	}

	wrapped := api.StackProxy{
		FullStack: stack,
		Name:      "openstack",
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
func (p *provider) GetAuthenticationOptions(ctx context.Context) (providers.Config, fail.Error) {
	opts, err := p.Stack.(api.ReservedForProviderUse).GetRawAuthenticationOptions(ctx)
	if err != nil {
		return nil, err
	}
	cfg := providers.ConfigMap{}
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthURL", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	cfg.Set("DomainName", opts.DomainName)

	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p *provider) GetConfigurationOptions(ctx context.Context) (providers.Config, fail.Error) {
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
	cfg.Set("ProviderNetwork", opts.ProviderNetwork)
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
func (p *provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListTemplates(ctx, all)
}

// ListImages ...
// Value of all has no impact on the result
func (p *provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListImages(ctx, all)
}

// GetName returns the providerName
func (p *provider) GetName() (string, fail.Error) {
	return "openstack", nil
}

// GetStack returns the stack object used by the provider
func (p provider) GetStack() (api.Stack, fail.Error) {
	return p.Stack, nil
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	return p.tenantParameters, nil
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities(context.Context) (providers.Capabilities, fail.Error) {
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

// init registers the openstack provider
func init() {
	iaas.Register("openstack", &provider{})
}
