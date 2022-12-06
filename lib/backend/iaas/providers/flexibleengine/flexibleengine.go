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

package flexibleengine

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
	imagefilters "github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract/filters/images"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	flexibleEngineDefaultImage = "Ubuntu 20.04"

	authURL string = "https://iam.%s.prod-cloud-ocb.orange-business.com/v3"
)

var (
	capabilities = iaasapi.Capabilities{
		PrivateVirtualIP: true,
	}
	dnsServers = []string{"100.125.0.41", "100.126.0.41"}

	_ iaasapi.Provider                    = (*provider)(nil) // Verify that *provider implements iaas.Provider (at compile time)
	_ providers.ReservedForTerraformerUse = (*provider)(nil)
)

type gpuCfg struct {
	GPUNumber int
	GPUType   string
}

var gpuMap = map[string]gpuCfg{
	"g1.xlarge": {
		GPUNumber: 1,
		GPUType:   "UNKNOWN",
	},
	"g1.2xlarge": {
		GPUNumber: 1,
		GPUType:   "UNKNOWN",
	},
	"g1.2xlarge.8": {
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
	},
}

// provider is the implementation of FlexibleEngine provider
type provider struct {
	iaasapi.Stack

	// defaultSecurityGroupName string

	tenantParameters map[string]interface{}
}

// New creates a new instance of flexibleengine provider
func New() iaasapi.Provider {
	return &provider{}
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build initializes a new FlexibleEngine instance from parameters
func (p *provider) Build(params map[string]interface{}, _ options.Options) (iaasapi.Provider, fail.Error) {
	identity, _ := params["identity"].(map[string]interface{}) // nolint
	compute, _ := params["compute"].(map[string]interface{})   // nolint
	network, _ := params["network"].(map[string]interface{})   // nolint

	identityEndpoint, _ := identity["EndPoint"].(string) // nolint
	if identityEndpoint == "" {
		identityEndpoint = fmt.Sprintf(authURL, compute["Region"])
	}
	username, _ := identity["Username"].(string)         // nolint
	password, _ := identity["Password"].(string)         // nolint
	domainName, _ := identity["DomainName"].(string)     // nolint
	projectID, _ := compute["ProjectID"].(string)        // nolint
	vpcName, _ := network["DefaultNetworkName"].(string) // nolint
	if vpcName == "" {
		vpcName, _ = network["VPCName"].(string) // nolint
	}
	vpcCIDR, _ := network["DefaultNetworkCIDR"].(string) // nolint
	if vpcCIDR == "" {
		vpcCIDR, _ = network["VPCCIDR"].(string) // nolint
	}
	region, _ := compute["Region"].(string)         // nolint
	zone, _ := compute["AvailabilityZone"].(string) // nolint
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

	defaultImage, _ := compute["DefaultImage"].(string) // nolint
	if defaultImage == "" {
		defaultImage = flexibleEngineDefaultImage
	}

	isSafe, ok := compute["Safe"].(bool) // nolint
	if !ok {
		isSafe = true
	}
	params["Safe"] = isSafe

	logrus.WithContext(context.Background()).Infof("Setting safety to: %t", isSafe)

	maxLifeTime := 0
	if _, ok := compute["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(compute["MaxLifetimeInHours"].(string)) // nolint
	}

	machineCreationLimit := 4
	if _, ok = compute["ConcurrentMachineCreationLimit"].(string); ok {
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
			"Ssd":  volumespeed.Ssd,
		},
		MetadataBucketName:       metadataBucketName,
		OperatorUsername:         operatorUsername,
		ProviderName:             providerName,
		DefaultSecurityGroupName: "default",
		DefaultNetworkName:       vpcName,
		DefaultNetworkCIDR:       vpcCIDR,
		DefaultImage:             defaultImage,
		// WhitelistTemplateRegexp: whitelistTemplatePattern,
		// BlacklistTemplateRegexp: blacklistTemplatePattern,
		// WhitelistImageRegexp:    whitelistImagePattern,
		// BlacklistImageRegexp:    blacklistImagePattern,
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
		Name:  "flexibleengine",
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

func addGPUCfg(tpl *abstract.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// InspectTemplate returns the Template referenced by id; overloads stack.InspectTemplate to inject templates with GPU
func (p *provider) InspectTemplate(ctx context.Context, id string) (*abstract.HostTemplate, fail.Error) {
	tpl, xerr := p.Stack.InspectTemplate(ctx, id)
	if xerr != nil {
		return nil, xerr
	}

	addGPUCfg(tpl)
	return tpl, nil
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (p *provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	allTemplates, xerr := p.Stack.(providers.StackReservedForProviderUse).ListTemplates(ctx, all)
	if xerr != nil {
		return nil, xerr
	}

	var tpls []*abstract.HostTemplate
	for _, tpl := range allTemplates {
		// Ignore templates containing ".mcs."
		if strings.Contains(tpl.Name, ".mcs.") {
			continue
		}
		// Ignore template starting with "physical."
		if strings.HasPrefix(tpl.Name, "physical.") {
			continue
		}

		addGPUCfg(tpl)
		tpls = append(tpls, tpl)
	}

	return tpls, nil
}

func isWindowsImage(image *abstract.Image) bool {
	return strings.Contains(strings.ToLower(image.Name), "windows")
}

func isBMSImage(image *abstract.Image) bool {
	return strings.HasPrefix(strings.ToUpper(image.Name), "OBS-BMS") ||
		strings.HasPrefix(strings.ToUpper(image.Name), "OBS_BMS")
}

// ListImages lists available OS images
func (p *provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	images, xerr := p.Stack.(providers.StackReservedForProviderUse).ListImages(ctx, all)
	if xerr != nil {
		return nil, xerr
	}

	if !all {
		filter := imagefilters.NewFilter(isWindowsImage).Not().And(imagefilters.NewFilter(isBMSImage).Not())
		images = imagefilters.FilterImages(images, filter)
	}
	return images, nil
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

	opts.ProviderName, xerr = p.GetName()
	if xerr != nil {
		return iaasoptions.Configuration{}, xerr
	}

	return opts, nil
}

// GetName returns the providerName
func (p *provider) GetName() (string, fail.Error) {
	return "flexibleengine", nil
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
		templatesWithGPU = []string{
			"g1-.*",
		}
		out []*regexp.Regexp
	)
	for _, v := range templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return emptySlice, fail.ConvertError(err)
		}
		out = append(out, re)
	}

	return out, nil
}

// HasDefaultNetwork returns true if the stack as a default network set (coming from tenants file)
func (p provider) HasDefaultNetwork() (bool, fail.Error) {
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

func init() {
	profile := providers.NewProfile(
		capabilities,
		func() iaasapi.Provider { return &provider{} },
		nil,
	)
	iaas.RegisterProviderProfile("flexibleengine", profile)
}
