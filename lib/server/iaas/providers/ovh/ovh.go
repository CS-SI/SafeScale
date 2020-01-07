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

package ovh

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/asaskevich/govalidator"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	providerapi "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumespeed"
	filters "github.com/CS-SI/SafeScale/lib/server/iaas/resources/filters/templates"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/openstack"
)

type gpuCfg struct {
	GPUNumber int
	GPUType   string
}

var gpuMap = map[string]gpuCfg{
	"g2-15": gpuCfg{
		GPUNumber: 1,
		GPUType:   "NVIDIA 1070",
	},
	"g2-30": gpuCfg{
		GPUNumber: 1,
		GPUType:   "NVIDIA 1070",
	},
	"g3-120": gpuCfg{
		GPUNumber: 3,
		GPUType:   "NVIDIA 1080 TI",
	},
	"g3-30": gpuCfg{
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
	},
}

var (
	identityEndpoint = "https://auth.cloud.ovh.net/v2.0"
	externalNetwork  = "Ext-Net"
	dnsServers       = []string{"213.186.33.99", "1.1.1.1"}
)

// OVH api credentials
var (
	alternateAPIApplicationKey    string
	alternateAPIApplicationSecret string
	alternateAPIConsumerKey       string
)

// provider is the provider implementation of the OVH provider
type provider struct {
	*openstack.Stack

	ExternalNetworkID string

	tenantParameters map[string]interface{}
}

// New creates a new instance of ovh provider
func New() providerapi.Provider {
	return &provider{}
}

// Build build a new instance of Ovh using configuration parameters
func (p *provider) Build(params map[string]interface{}) (providerapi.Provider, error) {
	identityParams, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	// networkParams, _ := params["network"].(map[string]interface{})

	applicationKey, _ := identityParams["ApplicationKey"].(string)
	openstackID, _ := identityParams["OpenstackID"].(string)
	openstackPassword, _ := identityParams["OpenstackPassword"].(string)
	region, _ := compute["Region"].(string)
	zone, ok := compute["AvailabilityZone"].(string)
	if !ok {
		zone = "nova"
	}

	projectName, _ := compute["ProjectName"].(string)

	val1, ok1 := identityParams["AlternateApiConsumerKey"]
	val2, ok2 := identityParams["AlternateApiApplicationSecret"]
	val3, ok3 := identityParams["AlternateApiConsumerKey"]
	if ok1 && ok2 && ok3 {
		alternateAPIApplicationKey = val1.(string)
		alternateAPIApplicationSecret = val2.(string)
		alternateAPIConsumerKey = val3.(string)
	}

	operatorUsername := resources.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			log.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = resources.DefaultUser
		}
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
	}

	govalidator.TagMap["alphanumwithdashesandunderscores"] = govalidator.Validator(func(str string) bool {
		rxp := regexp.MustCompile(stacks.AlphanumericWithDashesAndUnderscores)
		return rxp.Match([]byte(str))
	})

	_, err := govalidator.ValidateStruct(authOptions)
	if err != nil {
		return nil, err
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("openstack", region, applicationKey, projectName)
	if err != nil {
		return nil, err
	}

	cfgOptions := stacks.ConfigurationOptions{
		ProviderNetwork:           externalNetwork,
		UseFloatingIP:             false,
		UseLayer3Networking:       false,
		AutoHostNetworkInterfaces: false,
		DNSList:                   dnsServers,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"classic":    volumespeed.COLD,
			"high-speed": volumespeed.HDD,
		},
		MetadataBucket:   metadataBucketName,
		OperatorUsername: operatorUsername,
	}

	serviceVersions := map[string]string{"volume": "v1"}

	stack, err := openstack.New(authOptions, nil, cfgOptions, serviceVersions)
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
	err = stack.InitDefaultSecurityGroup()
	if err != nil {
		return nil, err
	}
	return newP, nil
}

// GetAuthenticationOptions returns the auth options
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetAuthenticationOptions()
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("TenantID", opts.TenantID)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	cfg.Set("AlternateApiConsumerKey", alternateAPIApplicationKey)
	cfg.Set("AlternateApiApplicationSecret", alternateAPIApplicationSecret)
	cfg.Set("AlternateApiConsumerKey", alternateAPIConsumerKey)
	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p *provider) GetConfigurationOptions() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	return cfg, nil
}

// GetTemplate overload OpenStack GetTemplate method to add GPU configuration
func (p *provider) GetTemplate(id string) (*resources.HostTemplate, error) {
	tpl, err := p.Stack.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

func addGPUCfg(tpl *resources.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// ListImages overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (p *provider) ListImages(all bool) ([]resources.Image, error) {
	return p.Stack.ListImages()
}

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (p *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates()
	if err != nil {
		return nil, err
	}

	if !all {
		//flavor["osType"].(string) == "linux" ?
		filter := filters.NewFilter(isWindowsTemplate).Not().And(filters.NewFilter(isFlexTemplate).Not())
		allTemplates = filters.FilterTemplates(allTemplates, filter)
	}

	// check flavor disponibilities through OVH-API
	authOpts, err := p.GetAuthenticationOptions()
	if err != nil {
		log.Warn(fmt.Sprintf("failed to get Authentication options, flavors availability won't be checked: %v", err))
		return allTemplates, nil
	}
	service := authOpts.GetString("TenantID")
	region := authOpts.GetString("Region")

	restURL := fmt.Sprintf("/cloud/project/%s/flavor?region=%s", service, region)
	flavors, err := p.requestOVHAPI(restURL, "GET")
	if err != nil {
		log.Warnf("Unable to request OVH API, flavors availability won't be checked: %v", err)
		return allTemplates, nil
	}

	flavorMap := map[string]map[string]interface{}{}
	for _, flavor := range flavors.([]interface{}) {
		// Removal of all the unavailable templates
		if flavor.(map[string]interface{})["available"].(bool) {
			flavorMap[flavor.(map[string]interface{})["id"].(string)] = flavor.(map[string]interface{})
		}
	}

	var listAvailableTemplates []resources.HostTemplate
	for _, template := range allTemplates {
		if _, ok := flavorMap[template.ID]; ok {
			listAvailableTemplates = append(listAvailableTemplates, template)
		} else {
			log.Debug(fmt.Sprintf("Flavor %s@%s is not available at the moment at is so ignored", template.Name, template.ID))
		}
	}
	allTemplates = listAvailableTemplates

	return allTemplates, nil
}

func isWindowsTemplate(t resources.HostTemplate) bool {
	return strings.HasPrefix(strings.ToLower(t.Name), "win-")
}

func isFlexTemplate(t resources.HostTemplate) bool {
	return strings.HasSuffix(strings.ToLower(t.Name), "flex")
}

// CreateNetwork is overloaded to handle specific OVH situation
func (p *provider) CreateNetwork(req resources.NetworkRequest) (*resources.Network, error) {
	// Special treatment for OVH : no dnsServers means __NO__ DNS servers, not default ones
	// The way to do so, accordingly to OVH support, is to set DNS servers to 0.0.0.0
	if len(req.DNSServers) == 0 {
		req.DNSServers = []string{"0.0.0.0"}
	}
	return p.Stack.CreateNetwork(req)
}

func (p *provider) GetName() string {
	return "ovh"
}

func (p *provider) GetTenantParameters() map[string]interface{} {
	return p.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{}
}

func init() {
	iaas.Register("ovh", &provider{})
}
