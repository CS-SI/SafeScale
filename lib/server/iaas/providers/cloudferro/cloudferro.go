/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"regexp"
	"strconv"

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

var (
	cloudferroIdentityEndpoint = "https://cf2.cloudferro.com:5000/v3"
	cloudferroDefaultImage     = "Ubuntu 20.04"
	cloudferroDNSServers       = []string{"185.48.234.234", "185.48.234.238"}
)

// provider is the implementation of the CloudFerro provider
type provider struct {
	api.Stack /**openstack.stack*/

	tenantParameters map[string]interface{}
	templatesWithGPU []string
}

// New creates a new instance of cloudferro provider
func New() providers.Provider {
	return &provider{}
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build builds a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	// tenantName, _ := params["name"].(string)

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})

	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	domainName, _ := identity["DomainName"].(string)

	// region, _ := compute["Region"].(string)
	region := "RegionOne"
	// zone, _ := compute["AvailabilityZone"].(string)
	zone := "nova"
	projectName, _ := compute["ProjectName"].(string)
	// projectID, _ := compute["ProjectID"].(string)
	defaultImage, _ := compute["DefaultImage"].(string)
	if defaultImage == "" {
		defaultImage = cloudferroDefaultImage
	}

	maxLifeTime := 0
	if _, ok := compute["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(compute["MaxLifetimeInHours"].(string))
	}

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = abstract.DefaultUser
		}
	}

	providerNetwork, _ := network["ProviderNetwork"].(string)
	if providerNetwork == "" {
		providerNetwork = "external"
	}
	floatingIPPool, _ := network["FloatingIPPool"].(string)
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
		FloatingIPPool:   floatingIPPool, // FIXME: move in ConfigurationOptions
		AllowReauth:      true,
	}

	govalidator.TagMap["alphanumwithdashesandunderscores"] = func(str string) bool {
		rxp := regexp.MustCompile(stacks.AlphanumericWithDashesAndUnderscores)
		return rxp.Match([]byte(str))
	}

	if _, err := govalidator.ValidateStruct(authOptions); err != nil {
		return nil, fail.ConvertError(err)
	}

	providerName := "openstack"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, domainName, projectName)
	if xerr != nil {
		return nil, xerr
	}

	cfgOptions := stacks.ConfigurationOptions{
		ProviderNetwork:           providerNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"Hdd": volumespeed.Hdd,
			"Ssd": volumespeed.Ssd,
		},
		MetadataBucket:           metadataBucketName,
		DNSList:                  cloudferroDNSServers,
		DefaultImage:             defaultImage,
		OperatorUsername:         operatorUsername,
		ProviderName:             providerName,
		DefaultSecurityGroupName: "default",
		MaxLifeTime:              maxLifeTime,
	}

	stack, xerr := openstack.New(authOptions, nil, cfgOptions, nil)
	if xerr != nil {
		return nil, xerr
	}

	wrapped := api.StackProxy{
		InnerStack: stack,
		Name:       "cloudferro",
	}

	newP := &provider{
		Stack:            wrapped,
		tenantParameters: params,
	}

	wp := providers.ProviderProxy{
		InnerProvider: newP,
		Name:          wrapped.Name,
	}

	return wp, nil
}

// GetAuthenticationOptions returns the auth options
func (p provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}
	if p.IsNull() {
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
func (p provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}
	if p.IsNull() {
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
	cfg.Set("UseNATService", opts.UseNATService)
	cfg.Set("MaxLifeTimeInHours", opts.MaxLifeTime)

	return cfg, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	if p.IsNull() {
		return []abstract.HostTemplate{}, fail.InvalidInstanceError()
	}

	allTemplates, xerr := p.Stack.(api.ReservedForProviderUse).ListTemplates(all)
	if xerr != nil {
		return []abstract.HostTemplate{}, xerr
	}
	return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
	if p.IsNull() {
		return []abstract.Image{}, fail.InvalidInstanceError()
	}

	allImages, xerr := p.Stack.(api.ReservedForProviderUse).ListImages(all)
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
// Note: use with caution, last resort option
func (p provider) GetStack() (api.Stack, fail.Error) {
	return p.Stack, nil
}

// GetTenantParameters returns the tenant parameters as-is
func (p provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	if p.IsNull() {
		return map[string]interface{}{}, nil
	}

	return p.tenantParameters, nil
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() (providers.Capabilities, fail.Error) {
	if p.IsNull() {
		return providers.Capabilities{}, nil
	}

	return providers.Capabilities{
		PrivateVirtualIP: true,
	}, nil
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	var emptySlice []*regexp.Regexp
	if p.IsNull() {
		return emptySlice, nil
	}

	var (
		out []*regexp.Regexp
	)
	for _, v := range p.templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return emptySlice, nil
		}
		out = append(out, re)
	}

	return out, nil
}

func init() {
	iaas.Register("cloudferro", &provider{})
}
