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

package ovh

import (
	"context"
	"regexp"
	"strconv"
	"strings"

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
	filters "github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract/filters/templates"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	ovhDefaultImage = "Ubuntu 20.04"
)

type gpuCfg struct {
	GPUNumber int
	GPUType   string
}

var gpuMap = map[string]gpuCfg{
	"g2-15": {
		GPUNumber: 1,
		GPUType:   "NVIDIA 1070",
	},
	"g2-30": {
		GPUNumber: 1,
		GPUType:   "NVIDIA 1070",
	},
	"g3-120": {
		GPUNumber: 3,
		GPUType:   "NVIDIA 1080 TI",
	},
	"g3-30": {
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
	},
}

var (
	identityEndpoint = "https://auth.cloud.ovh.net/v3"
	externalNetwork  = "Ext-Net"
	dnsServers       = []string{"213.186.33.99", "1.1.1.1"}
)

// provider is the provider implementation of the OVH provider
type provider struct {
	api.Stack

	ExternalNetworkID string

	tenantParameters map[string]interface{}
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build builds a new instance of Ovh using configuration parameters
// Can be called from nil
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	var validInput bool

	identityParams, _ := params["identity"].(map[string]interface{}) // nolint
	compute, _ := params["compute"].(map[string]interface{})         // nolint
	// networkParams, _ := params["network"].(map[string]interface{}) // nolint

	applicationKey, _ := identityParams["ApplicationKey"].(string)       // nolint
	openstackID, _ := identityParams["OpenstackID"].(string)             // nolint
	openstackPassword, _ := identityParams["OpenstackPassword"].(string) // nolint
	region, _ := compute["Region"].(string)                              // nolint
	zone, ok := compute["AvailabilityZone"].(string)
	if !ok {
		zone = "nova"
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

	projectName, validInput := compute["ProjectName"].(string)
	if !validInput {
		return nil, fail.NewError("Invalid input for 'ProjectName'")
	}

	var alternateAPIApplicationKey string
	var alternateAPIApplicationSecret string
	var alternateAPIConsumerKey string
	val1, ok1 := identityParams["AlternateApiApplicationKey"]
	val2, ok2 := identityParams["AlternateApiApplicationSecret"]
	val3, ok3 := identityParams["AlternateApiConsumerKey"]
	if ok1 && ok2 && ok3 {
		alternateAPIApplicationKey, validInput = val1.(string)
		if !validInput {
			return nil, fail.NewError("Invalid input for 'AlternateApiApplicationKey'")
		}
		alternateAPIApplicationSecret, validInput = val2.(string)
		if !validInput {
			return nil, fail.NewError("Invalid input for 'AlternateApiApplicationSecret'")
		}
		alternateAPIConsumerKey, validInput = val3.(string)
		if !validInput {
			return nil, fail.NewError("Invalid input for 'AlternateApiConsumerKey'")
		}
	}

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, there := compute["OperatorUsername"]; there {
		operatorUsername, ok = operatorUsernameIf.(string)
		if !ok {
			return nil, fail.InconsistentError("'OperatorUsername' should be a string")
		}
		if operatorUsername == "" {
			logrus.WithContext(context.Background()).Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = abstract.DefaultUser
		}
	}

	isSafe, ok := compute["Safe"].(bool) // nolint
	if !ok {
		isSafe = false // all providers are safe by default except this, due to Stein
	}
	params["Safe"] = isSafe

	logrus.WithContext(context.Background()).Infof("Setting safety to: %t", isSafe)

	defaultImage, ok := compute["DefaultImage"].(string)
	if !ok {
		defaultImage = ovhDefaultImage
	}

	maxLifeTime := 0
	if _, ok = compute["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(compute["MaxLifetimeInHours"].(string))
	}

	machineCreationLimit := 8
	if _, ok = compute["ConcurrentMachineCreationLimit"].(string); ok {
		machineCreationLimit, _ = strconv.Atoi(compute["ConcurrentMachineCreationLimit"].(string))
	}

	authOptions := stacks.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         openstackID,
		Password:         openstackPassword,
		TenantID:         applicationKey,
		TenantName:       projectName,
		Region:           region,
		AvailabilityZone: zone,
		AllowReauth:      true,
		AK:               alternateAPIApplicationKey,
		AS:               alternateAPIApplicationSecret,
		CK:               alternateAPIConsumerKey,
	}

	err := validation.ValidateStruct(&authOptions,
		validation.Field(&authOptions.Region, validation.Required, validation.Match(regexp.MustCompile("^[-a-zA-Z0-9-_]+$"))),
		validation.Field(&authOptions.AvailabilityZone, validation.Required, validation.Match(regexp.MustCompile("^[-a-zA-Z0-9-_]+$"))),
	)
	if err != nil {
		return nil, fail.NewError("Structure validation failure: %v", err)
	}

	providerName := "openstack"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, applicationKey, projectName)
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
		ProviderNetwork:           externalNetwork,
		UseFloatingIP:             false,
		UseLayer3Networking:       false,
		AutoHostNetworkInterfaces: false,
		DNSList:                   dnsServers,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"classic":    volumespeed.Cold,
			"high-speed": volumespeed.Hdd,
		},
		MetadataBucket:                 metadataBucketName,
		OperatorUsername:               operatorUsername,
		ProviderName:                   providerName,
		DefaultSecurityGroupName:       "default",
		DefaultImage:                   defaultImage,
		MaxLifeTime:                    maxLifeTime,
		Timings:                        timings,
		Safe:                           isSafe,
		ConcurrentMachineCreationLimit: machineCreationLimit,
	}

	serviceVersions := map[string]string{"volume": "v2"}

	stack, xerr := openstack.New(authOptions, nil, cfgOptions, serviceVersions)
	if xerr != nil {
		return nil, xerr
	}

	wrapped := api.StackProxy{
		FullStack: stack,
		Name:      "ovh",
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
	cfg.Set("TenantID", opts.TenantID)
	cfg.Set("DomainName", opts.DomainName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthURL", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	cfg.Set("AlternateApiApplicationKey", opts.AK)
	cfg.Set("AlternateApiApplicationSecret", opts.AS)
	cfg.Set("AlternateApiConsumerKey", opts.CK)
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

// InspectTemplate overload OpenStack GetTemplate method to add GPU configuration
func (p provider) InspectTemplate(ctx context.Context, id string) (*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	tpl, xerr := p.Stack.InspectTemplate(ctx, id)
	if xerr != nil {
		return nil, xerr
	}
	addGPUCfg(tpl)
	return tpl, nil
}

func addGPUCfg(tpl *abstract.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// ListImages overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (p provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListImages(ctx, all)
}

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (p provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	allTemplates, xerr := p.Stack.(api.ReservedForProviderUse).ListTemplates(ctx, false)
	if xerr != nil {
		return nil, xerr
	}

	if !all {
		// flavor["osType"].(string) == "linux" ?
		filter := filters.NewFilter(isWindowsTemplate).Not().And(filters.NewFilter(isFlexTemplate).Not())
		allTemplates = filters.FilterTemplates(allTemplates, filter)
	}

	// check flavor availability through OVH-API
	_, err := p.GetAuthenticationOptions(ctx)
	if err != nil {
		logrus.WithContext(context.Background()).Warnf("failed to get Authentication options, flavors availability will not be checked: %v", err)
		return allTemplates, nil
	}

	var listAvailableTemplates []*abstract.HostTemplate
	listAvailableTemplates = allTemplates

	// update incomplete disk size of some templates
	for k, template := range listAvailableTemplates {
		if strings.HasPrefix(template.Name, "i1-") {
			listAvailableTemplates[k].DiskSize += 2000
		} else {
			switch template.Name {
			case "t1-180", "t2-180":
				listAvailableTemplates[k].DiskSize += 2000
			default:
			}
		}
	}

	return listAvailableTemplates, nil
}

func isWindowsTemplate(t *abstract.HostTemplate) bool {
	return strings.HasPrefix(strings.ToLower(t.Name), "win-")
}

func isFlexTemplate(t *abstract.HostTemplate) bool {
	return strings.HasSuffix(strings.ToLower(t.Name), "flex")
}

// CreateNetwork is overloaded to handle specific OVH situation
func (p provider) CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (*abstract.Network, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	// Special treatment for OVH : no dnsServers means __NO__ DNS servers, not default ones
	// The way to do so, accordingly to OVH support, is to set DNS servers to 0.0.0.0
	if len(req.DNSServers) == 0 {
		req.DNSServers = []string{"0.0.0.0"}
	}
	return p.Stack.CreateNetwork(ctx, req)
}

// GetName returns the name of the driver
func (p provider) GetName() (string, fail.Error) {
	return "ovh", nil
}

// GetStack returns the stack object used by the provider
func (p provider) GetStack() (api.Stack, fail.Error) {
	return p.Stack, nil
}

func (p provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNil(p) {
		return map[string]interface{}{}, fail.InvalidInstanceError()
	}
	return p.tenantParameters, nil
}

// GetCapabilities returns the capabilities of the provider
func (p provider) GetCapabilities(context.Context) (providers.Capabilities, fail.Error) {
	return providers.Capabilities{
		PrivateVirtualIP: true,
	}, nil
}

// BindHostToVIP overridden because OVH doesn't honor allowed_address_pairs, providing its own, automatic way to deal with spoofing
func (p provider) BindHostToVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(p) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("host")
	}

	return nil
}

// UnbindHostFromVIP overridden because OVH doesn't honor allowed_address_pairs, providing its own, automatic way to deal with spoofing
func (p provider) UnbindHostFromVIP(ctx context.Context, vip *abstract.VirtualIP, hostID string) fail.Error {
	if valid.IsNil(p) {
		return fail.InvalidInstanceError()
	}
	if vip == nil {
		return fail.InvalidParameterCannotBeNilError("vip")
	}
	if hostID == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("host")
	}

	return nil
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	var (
		templatesWithGPU = []string{
			"t1-.*",
			"g2-.*",
			"g3-.*",
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
	iaas.Register("ovh", &provider{})
}
