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

package flexibleengine

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
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/huaweicloud"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	imagefilters "github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract/filters/images"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	flexibleEngineDefaultImage = "Ubuntu 20.04"

	authURL string = "https://iam.%s.prod-cloud-ocb.orange-business.com/v3"
)

var (
	dnsServers = []string{"100.125.0.41", "100.126.0.41"}
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
	api.Stack

	// defaultSecurityGroupName string

	tenantParameters map[string]interface{}
}

// New creates a new instance of flexibleengine provider
func New() providers.Provider {
	return &provider{}
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build initializes a new FlexibleEngine instance from parameters
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
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

	var maxLifeTime int64 = 0
	if val, ok := compute["MaxLifetimeInHours"].(int64); ok {
		maxLifeTime = val
	}

	machineCreationLimit := 4
	if _, ok = compute["ConcurrentMachineCreationLimit"].(string); ok {
		machineCreationLimit, _ = strconv.Atoi(compute["ConcurrentMachineCreationLimit"].(string))
	}

	authOptions := stacks.AuthenticationOptions{
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

	suffix := getSuffix(params)
	providerName := "huaweicloud"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, domainName, projectID, suffix)
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

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:             dnsServers,
		UseFloatingIP:       true,
		UseLayer3Networking: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"SATA": volumespeed.Cold,
			"Ssd":  volumespeed.Ssd,
		},
		MetadataBucket:                 metadataBucketName,
		OperatorUsername:               operatorUsername,
		ProviderName:                   providerName,
		DefaultSecurityGroupName:       "default",
		DefaultNetworkName:             vpcName,
		DefaultNetworkCIDR:             vpcCIDR,
		DefaultImage:                   defaultImage,
		MaxLifeTime:                    maxLifeTime,
		Timings:                        timings,
		Safe:                           isSafe,
		ConcurrentMachineCreationLimit: machineCreationLimit,
	}

	serviceVersions := map[string]string{}

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

	if maybe, ok := network["NetworkClientEndpointVersion"]; ok {
		if val, ok := maybe.(string); ok {
			serviceVersions["networkclient"] = val
		}
	}

	stack, xerr := huaweicloud.New(authOptions, cfgOptions, serviceVersions)
	if xerr != nil {
		return nil, xerr
	}

	wrapped := api.StackProxy{
		FullStack: stack,
		Name:      "flexibleengine",
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
	allTemplates, xerr := p.Stack.(api.ReservedForProviderUse).ListTemplates(ctx, all)
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
	images, xerr := p.Stack.(api.ReservedForProviderUse).ListImages(ctx, all)
	if xerr != nil {
		return nil, xerr
	}

	if !all {
		filter := imagefilters.NewFilter(isWindowsImage).Not().And(imagefilters.NewFilter(isBMSImage).Not())
		images = imagefilters.FilterImages(images, filter)
	}
	return images, nil
}

// GetAuthenticationOptions returns the auth options
func (p *provider) GetAuthenticationOptions(ctx context.Context) (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts, err := p.Stack.(api.ReservedForProviderUse).GetRawAuthenticationOptions(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Set("DomainName", opts.DomainName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthURL", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)

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
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("ProviderName", provName)
	cfg.Set("DefaultNetworkName", opts.DefaultNetworkName)
	cfg.Set("DefaultNetworkCIDR", opts.DefaultNetworkCIDR)
	cfg.Set("MaxLifeTimeInHours", opts.MaxLifeTime)
	cfg.Set("Safe", opts.Safe)
	cfg.Set("ConcurrentMachineCreationLimit", opts.ConcurrentMachineCreationLimit)
	// cfg.Set("Customizations", opts.Customizations)

	return cfg, nil
}

// GetName returns the providerName
func (p *provider) GetName() (string, fail.Error) {
	return "flexibleengine", nil
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
		templatesWithGPU = []string{
			"g1-.*",
		}
		out []*regexp.Regexp
	)
	for _, v := range templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		out = append(out, re)
	}

	return out, nil
}

func init() {
	iaas.Register("flexibleengine", &provider{})
}
