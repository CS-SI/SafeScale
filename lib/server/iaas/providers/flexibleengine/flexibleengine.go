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

package flexibleengine

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/huaweicloud"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	imagefilters "github.com/CS-SI/SafeScale/lib/server/resources/abstract/filters/images"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	flexibleEngineDefaultImage = "Ubuntu 20.04"

	authURL string = "https://iam.%s.prod-cloud-ocb.orange-business.com/v3"
)

type gpuCfg struct {
	GPUNumber int
	GPUType   string
}

var gpuMap = map[string]gpuCfg{
	"g1.xlarge": {
		GPUNumber: 1,
		GPUType:   "UNKNOW",
	},
	"g1.2xlarge": {
		GPUNumber: 1,
		GPUType:   "UNKNOW",
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
// Can be called from nil
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})

	identityEndpoint, _ := identity["EndPoint"].(string)
	if identityEndpoint == "" {
		identityEndpoint = fmt.Sprintf(authURL, compute["Region"])
	}
	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	domainName, _ := identity["DomainName"].(string)
	projectID, _ := compute["ProjectID"].(string)
	vpcName, _ := network["DefaultNetworkName"].(string)
	if vpcName == "" {
		vpcName, _ = network["VPCName"].(string)
	}
	vpcCIDR, _ := network["DefaultNetworkCIDR"].(string)
	if vpcCIDR == "" {
		vpcCIDR, _ = network["VPCCIDR"].(string)
	}
	region, _ := compute["Region"].(string)
	zone, _ := compute["AvailabilityZone"].(string)
	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = abstract.DefaultUser
		}
	}

	defaultImage, _ := compute["DefaultImage"].(string)
	if defaultImage == "" {
		defaultImage = flexibleEngineDefaultImage
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

	govalidator.TagMap["alphanumwithdashesandunderscores"] = govalidator.Validator(func(str string) bool {
		rxp := regexp.MustCompile(stacks.AlphanumericWithDashesAndUnderscores)
		return rxp.Match([]byte(str))
	})

	_, err := govalidator.ValidateStruct(authOptions)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	providerName := "huaweicloud"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, domainName, projectID)
	if xerr != nil {
		return nil, xerr
	}

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:             []string{"100.125.0.41", "100.126.0.41"},
		UseFloatingIP:       true,
		UseLayer3Networking: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"SATA": volumespeed.Cold,
			"Ssd":  volumespeed.Ssd,
		},
		MetadataBucket:           metadataBucketName,
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
	}

	stack, xerr := huaweicloud.New(authOptions, cfgOptions)
	if xerr != nil {
		return nil, xerr
	}

	newP := &provider{
		Stack:            stack,
		tenantParameters: params,
	}
	return newP, nil
}

func addGPUCfg(tpl *abstract.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// InspectTemplate returns the Template referenced by id; overloads Stack.InspectTemplate to inject templates with GPU
func (p *provider) InspectTemplate(id string) (abstract.HostTemplate, fail.Error) {
	nullAHT := abstract.HostTemplate{}
	tpl, xerr := p.Stack.InspectTemplate(id)
	if xerr != nil {
		return nullAHT, xerr
	}
	addGPUCfg(&tpl)
	return tpl, nil
}

// ListTemplates lists available host templates
// IPAddress templates are sorted using Dominant Resource Fairness Algorithm
func (p *provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	allTemplates, xerr := p.Stack.(api.ReservedForProviderUse).ListTemplates()
	if xerr != nil {
		return nil, xerr
	}

	var tpls []abstract.HostTemplate
	for _, tpl := range allTemplates {
		addGPUCfg(&tpl)
		tpls = append(tpls, tpl)
	}

	return tpls, nil
}

func isWindowsImage(image abstract.Image) bool {
	return strings.Contains(strings.ToLower(image.Name), "windows")
}

func isBMSImage(image abstract.Image) bool {
	return strings.HasPrefix(strings.ToUpper(image.Name), "OBS-BMS") ||
		strings.HasPrefix(strings.ToUpper(image.Name), "OBS_BMS")
}

// ListImages lists available OS images
func (p *provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
	images, xerr := p.Stack.(api.ReservedForProviderUse).ListImages()
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
func (p *provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.(api.ReservedForProviderUse).GetAuthenticationOptions()
	cfg.Set("DomainName", opts.DomainName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)

	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p *provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.(api.ReservedForProviderUse).GetConfigurationOptions()
	// caps := p.GetCapabilities()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("ProviderName", p.GetName())
	cfg.Set("DefaultNetworkName", opts.DefaultNetworkName)
	cfg.Set("DefaultNetworkCIDR", opts.DefaultNetworkCIDR)
	// cfg.Set("Customizations", opts.Customizations)

	return cfg, nil
}

// GetName returns the providerName
func (p *provider) GetName() string {
	return "flexibleengine"
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() map[string]interface{} {
	return p.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{
		PrivateVirtualIP: true,
	}
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() []*regexp.Regexp {
	var emptySlice []*regexp.Regexp
	if p.IsNull() {
		return emptySlice
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
			return emptySlice
		}
		out = append(out, re)
	}

	return out
}

func init() {
	iaas.Register("flexibleengine", &provider{})
}
