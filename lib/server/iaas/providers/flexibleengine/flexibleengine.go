/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"
	"regexp"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	providerapi "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/VolumeSpeed"
	imagefilters "github.com/CS-SI/SafeScale/lib/server/iaas/resources/filters/images"
	templatefilters "github.com/CS-SI/SafeScale/lib/server/iaas/resources/filters/templates"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/huaweicloud"
)

const (
	defaultUser string = "cloud"

	authURL string = "https://iam.%s.prod-cloud-ocb.orange-business.com"
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

// provider is the providerementation of FlexibleEngine provider
type provider struct {
	*huaweicloud.Stack

	defaultSecurityGroupName string
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
	operatorUsername := resources.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = resources.DefaultUser
		}
	}
	whitelistTemplatePattern, _ := compute["WhitelistTemplateRegexp"].(string)
	blacklistTemplatePattern, _ := compute["BlacklistTemplateRegexp"].(string)
	whitelistImagePattern, _ := compute["WhitelistImageRegexp"].(string)
	blacklistImagePattern, _ := compute["BlacklistImageRegexp"].(string)

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
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"SATA": VolumeSpeed.COLD,
			"SSD":  VolumeSpeed.SSD,
		},
		MetadataBucket:   metadataBucketName,
		OperatorUsername: operatorUsername,
		Customizations: map[string]string{
			"WhitelistTemplateRegexp": whitelistTemplatePattern,
			"BlacklistTemplateRegexp": blacklistTemplatePattern,
			"WhitelistImageRegexp": whitelistImagePattern,
			"BlacklistImageRegexp": blacklistImagePattern,
		},
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

	validAvailabilityZones, err := stack.ListAvailabilityZones(true)
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

	return &provider{Stack: stack}, nil
}

func addGPUCfg(tpl *resources.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// GetTemplate returns the Template referenced by id
func (p *provider) GetTemplate(id string) (*resources.HostTemplate, error) {
	tpl, err := p.Stack.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

// func isBlacklistedTemplate(tpl resources.HostTemplate) bool {
// 	return strings.HasPrefix(strings.ToUpper(tpl.Name), "t2.")
// }

func isS3Template(tpl resources.HostTemplate) bool {
 	return strings.HasPrefix(strings.ToUpper(tpl.Name), "S3.")
}

func templateFromWhite(regr string) templatefilters.Predicate {
	return func(tpl resources.HostTemplate) bool {
		re, err := regexp.Compile(regr)
		if err != nil || len(regr) == 0 {
			return true
		}
		return re.Match([]byte(tpl.Name))
	}
}

func templateFromBlack(regr string) templatefilters.Predicate {
	return func(tpl resources.HostTemplate) bool {
		re, err := regexp.Compile(regr)
		if err != nil || len(regr) == 0 {
			return false
		}
		return re.Match([]byte(tpl.Name))
	}
}

func imageFromWhite(regr string) imagefilters.Predicate {
	return func(image resources.Image) bool {
		re, err := regexp.Compile(regr)
		if err != nil || len(regr) == 0 {
			return true
		}
		return re.Match([]byte(image.Name))
	}
}

func imageFromBlack(regr string) imagefilters.Predicate {
	return func(image resources.Image) bool {
		re, err := regexp.Compile(regr)
		if err != nil || len(regr) == 0 {
			return false
		}
		return re.Match([]byte(image.Name))
	}
}

// ListTemplates lists available host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (p *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates(all)
	if err != nil {
		return nil, err
	}

	var tpls []resources.HostTemplate
	for _, tpl := range allTemplates {
		addGPUCfg(&tpl)
		tpls = append(tpls, tpl)
	}

	if all {
	 	return tpls, nil
	}

	cfgopts := p.Stack.GetConfigurationOptions()

	whiteFilterRegexp := cfgopts.Customizations["WhitelistTemplateRegexp"]
	blackFilterRegexp := cfgopts.Customizations["BlacklistTemplateRegexp"]

	templateFilter := templatefilters.NewFilter(templateFromWhite(whiteFilterRegexp)).And(templatefilters.NewFilter(templateFromBlack(blackFilterRegexp)).Not())
	return templatefilters.FilterTemplates(tpls, templateFilter), nil
}

func isWindowsImage(image resources.Image) bool {
	return strings.Contains(strings.ToLower(image.Name), "windows")
}

func isBMSImage(image resources.Image) bool {
	return strings.HasPrefix(strings.ToUpper(image.Name), "OBS-BMS") ||
		strings.HasPrefix(strings.ToUpper(image.Name), "OBS_BMS")
}

// ListImages lists available OS images
func (p *provider) ListImages(all bool) ([]resources.Image, error) {
	images, err := p.Stack.ListImages(all)
	if err != nil {
		return nil, err
	}
	if all {
		return images, nil
	}

	cfgopts := p.Stack.GetConfigurationOptions()

	whiteFilterRegexp := cfgopts.Customizations["WhitelistImageRegexp"]
	blackFilterRegexp := cfgopts.Customizations["BlacklistImageRegexp"]

	imageFilter := imagefilters.NewFilter(isWindowsImage).Not().And(imagefilters.NewFilter(isBMSImage).Not()).And(imagefilters.NewFilter(imageFromWhite(whiteFilterRegexp))).And(imagefilters.NewFilter(imageFromBlack(blackFilterRegexp)).Not())
	return imagefilters.FilterImages(images, imageFilter), nil
}

// GetAuthOpts returns the auth options
func (p *provider) GetAuthOpts() (providers.Config, error) {
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

// GetCfgOpts return configuration parameters
func (p *provider) GetCfgOpts() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("Customizations", opts.Customizations)

	return cfg, nil
}

// GetName returns the providerName
func (p *provider) GetName() string {
	return "flexibleengine"
}

func init() {
	iaas.Register("flexibleengine", &provider{})
}
