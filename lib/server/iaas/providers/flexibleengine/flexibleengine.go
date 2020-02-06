/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or provideried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package flexibleengine

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	providerapi "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/huaweicloud"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	imagefilters "github.com/CS-SI/SafeScale/lib/server/resources/abstracts/filters/images"
	templatefilters "github.com/CS-SI/SafeScale/lib/server/resources/abstracts/filters/templates"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
)

const (
	authURL string = "https://iam.%s.prod-cloud-ocb.orange-business.com/v3"
)

type gpuCfg struct {
	GPUNumber int
	GPUType   string
}

var gpuMap = map[string]gpuCfg{
	"g1.xlarge": gpuCfg{
		GPUNumber: 1,
		GPUType:   "UNKNOW",
	},
	"g1.2xlarge": gpuCfg{
		GPUNumber: 1,
		GPUType:   "UNKNOW",
	},
	"g1.2xlarge.8": gpuCfg{
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
	},
}

// provider is the implementation of FlexibleEngine provider
type provider struct {
	*huaweicloud.Stack

	defaultSecurityGroupName string

	tenantParameters map[string]interface{}
}

// New creates a new instance of flexibleengine provider
func New() providerapi.Provider {
	return &provider{}
}

// Build initializes a new FlexibleEngine instance from parameters
func (p *provider) Build(params map[string]interface{}) (providerapi.Provider, error) {
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
	vpcName, _ := network["VPCName"].(string)
	vpcCIDR, _ := network["VPCCIDR"].(string)
	region, _ := compute["Region"].(string)
	zone, _ := compute["AvailabilityZone"].(string)
	operatorUsername := abstracts.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = abstracts.DefaultUser
		}
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
		VPCName:          vpcName,
		VPCCIDR:          vpcCIDR,
	}

	govalidator.TagMap["alphanumwithdashesandunderscores"] = govalidator.Validator(func(str string) bool {
		rxp := regexp.MustCompile(stacks.AlphanumericWithDashesAndUnderscores)
		return rxp.Match([]byte(str))
	})

	_, err := govalidator.ValidateStruct(authOptions)
	if err != nil {
		return nil, err
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("huaweicloud", region, domainName, projectID)
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:             []string{"100.125.0.41", "100.126.0.41"},
		UseFloatingIP:       true,
		UseLayer3Networking: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"SATA": volumespeed.COLD,
			"SSD":  volumespeed.SSD,
		},
		MetadataBucket:   metadataBucketName,
		OperatorUsername: operatorUsername,
		// WhitelistTemplateRegexp: whitelistTemplatePattern,
		// BlacklistTemplateRegexp: blacklistTemplatePattern,
		// WhitelistImageRegexp:    whitelistImagePattern,
		// BlacklistImageRegexp:    blacklistImagePattern,
	}

	stack, err := huaweicloud.New(authOptions, cfgOptions)
	if err != nil {
		return nil, err
	}
	err = stack.InitDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}

	validRegions, err := stack.ListRegions()
	if err != nil {
		if len(validRegions) != 0 {
			return nil, err
		}
	}
	if len(validRegions) != 0 {
		regionIsValidInput := false
		for _, vr := range validRegions {
			if region == vr {
				regionIsValidInput = true
			}
		}
		if !regionIsValidInput {
			return nil, fmt.Errorf("invalid Region: '%s'", region)
		}
	}

	validAvailabilityZones, err := stack.ListAvailabilityZones()
	if err != nil {
		if len(validAvailabilityZones) != 0 {
			return nil, err
		}
	}

	if len(validAvailabilityZones) != 0 {
		var validZones []string
		zoneIsValidInput := false
		for az, valid := range validAvailabilityZones {
			if valid {
				if az == zone {
					zoneIsValidInput = true
				}
				validZones = append(validZones, az)
			}
		}
		if !zoneIsValidInput {
			return nil, fmt.Errorf("invalid Availability zone: '%s', valid zones are %v", zone, validZones)
		}
	}

	newP := &provider{
		Stack:            stack,
		tenantParameters: params,
	}
	return newP, nil
}

func addGPUCfg(tpl *abstracts.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// GetTemplate returns the Template referenced by id
func (p *provider) GetTemplate(id string) (*abstracts.HostTemplate, error) {
	tpl, err := p.Stack.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (p *provider) ListTemplates(all bool) ([]abstracts.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates()
	if err != nil {
		return nil, err
	}

	var tpls []abstracts.HostTemplate
	for _, tpl := range allTemplates {
		addGPUCfg(&tpl)
		tpls = append(tpls, tpl)
	}

	return tpls, nil
}

func isWindowsImage(image abstracts.Image) bool {
	return strings.Contains(strings.ToLower(image.Name), "windows")
}

func isBMSImage(image abstracts.Image) bool {
	return strings.HasPrefix(strings.ToUpper(image.Name), "OBS-BMS") ||
		strings.HasPrefix(strings.ToUpper(image.Name), "OBS_BMS")
}

// ListImages lists available OS images
func (p *provider) ListImages(all bool) ([]abstracts.Image, error) {
	images, err := p.Stack.ListImages()
	if err != nil {
		return nil, err
	}

	if !all {
		filter := imagefilters.NewFilter(isWindowsImage).Not().And(imagefilters.NewFilter(isBMSImage).Not())
		images = imagefilters.FilterImages(images, filter)
	}
	return images, nil
}

// GetAuthenticationOptions returns the auth options
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetAuthenticationOptions()
	cfg.Set("DomainName", opts.DomainName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	cfg.Set("VPCName", opts.VPCName)

	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p *provider) GetConfigurationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetConfigurationOptions()
	// caps := p.GetCapabilities()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
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

func init() {
	iaas.Register("flexibleengine", &provider{})
}
