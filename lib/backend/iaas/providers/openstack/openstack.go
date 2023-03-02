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
	"regexp"
	"strconv"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"

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
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	openstackDefaultImage = "Ubuntu 20.04"
)

var (
	capabilities = iaasapi.Capabilities{
		PrivateVirtualIP: true,
	}
	dnsServers = []string{"8.8.8.8", "1.1.1.1"}

	_ iaasapi.Provider                    = (*provider)(nil) // Verify that *provider implements iaas.Provider (at compile time)
	_ providers.ReservedForTerraformerUse = (*provider)(nil)
)

// provider is the implementation of the openstack provider respecting provider interface
type provider struct {
	iaasapi.Stack

	SecurityGroup     *secgroups.SecurityGroup
	ExternalNetworkID string

	templatesWithGPU []string
	tenantParameters map[string]interface{}
}

// New creates a new instance of pure openstack provider
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

	maxLifeTime := 0
	if _, ok := compute["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(compute["MaxLifetimeInHours"].(string))
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

	authOptions := iaasoptions.Authentication{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		TenantID:         tenantID,
		TenantName:       tenantName,
		Region:           region,
		AvailabilityZone: zone,
		FloatingIPPool:   floatingIPPool,
	}

	providerName := "openstack"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, tenantID, "0")
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

	cfgOptions := iaasoptions.Configuration{
		ProviderNetwork:           providerNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		DNSServers:                dnsServers,
		DefaultImage:              defaultImage,
		MetadataBucketName:        metadataBucketName,
		OperatorUsername:          operatorUsername,
		ProviderName:              providerName,
		DefaultSecurityGroupName:  "default",
		VolumeSpeeds: map[string]volumespeed.Enum{
			"standard":   volumespeed.Cold,
			"performant": volumespeed.Hdd,
		},
		VolumeTypes: map[volumespeed.Enum]string{
			volumespeed.Cold: "standard",
			volumespeed.Hdd:  "performant",
			volumespeed.Ssd:  "performant",
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

	// Note: if timings have to be tuned, update stack.MutableTimings

	wrapped := stacks.Remediator{
		Stack: stack,
		Name:  "openstack",
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

	opts, xerr := p.Stack.(providers.StackReservedForProviderUse).ConfigurationOptions()
	if xerr != nil {
		return iaasoptions.Configuration{}, xerr
	}

	provName, xerr := p.GetName()
	if xerr != nil {
		return iaasoptions.Configuration{}, xerr
	}

	opts.ProviderName = provName
	return opts, nil
}

// ListTemplates ...
// HolderOf of all has no impact on the result
func (p *provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.Stack.(providers.StackReservedForProviderUse).ListTemplates(ctx, all)
}

// ListImages ...
// HolderOf of all has no impact on the result
func (p *provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.Stack.(providers.StackReservedForProviderUse).ListImages(ctx, all)
}

// GetName returns the providerName
func (p *provider) GetName() (string, fail.Error) {
	return "openstack", nil
}

// StackDriver returns the stack object used by the provider
// Note: use with caution, last resort option
func (p *provider) StackDriver() (iaasapi.Stack, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	return p.Stack, nil
}

// TenantParameters returns the tenant parameters as-is
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
			return emptySlice, fail.Wrap(err)
		}
		out = append(out, re)
	}

	return out, nil
}

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (p provider) HasDefaultNetwork() (bool, fail.Error) {
	return false, nil
}

// DefaultNetwork returns the *abstract.Network corresponding to the default network
func (p provider) DefaultNetwork(context.Context) (*abstract.Network, fail.Error) {
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

// init registers the openstack provider
func init() {
	profile := providers.NewProfile(
		capabilities,
		func() iaasapi.Provider { return &provider{} },
		nil,
	)
	iaas.RegisterProviderProfile("openstack", profile)
}
