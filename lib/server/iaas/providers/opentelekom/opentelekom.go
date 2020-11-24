/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

package opentelekom

import (
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"regexp"

	"github.com/asaskevich/govalidator"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/huaweicloud"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

const (
	identityEndpointTemplate string = "https://iam.%s.otc.t-systems.com"
)

// provider is the providerementation of the OpenTelekom provider
type provider struct {
	api.Stack

	tenantParameters map[string]interface{}
}

// New creates a new instance of opentelekom provider
func New() providers.Provider {
	return &provider{}
}

// IsNull tells if the instance represents an null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})

	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	domainName, _ := identity["DomainName"].(string)
	projectID, _ := compute["ProjectID"].(string)
	region, _ := compute["Region"].(string)
	zone, _ := compute["AvailabilityZone"].(string)
	vpcName, _ := network["DefaultNetworkName"].(string)
	vpcCIDR, _ := network["DefaultNetworkCIDR"].(string)

	identityEndpoint, _ := identity["IdentityEndpoint"].(string)
	if identityEndpoint == "" {
		identityEndpoint = fmt.Sprintf(identityEndpointTemplate, region)
	}

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, ok := compute["OperatorUsername"]; ok {
		operatorUsername = operatorUsernameIf.(string)
		if operatorUsername == "" {
			logrus.Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = abstract.DefaultUser
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
		//DefaultNetworkName:          vpcName,
		//DefaultNetworkCIDR:          vpcCIDR,
	}

	govalidator.TagMap["alphanumwithdashesandunderscores"] = govalidator.Validator(func(str string) bool {
		rxp := regexp.MustCompile(stacks.AlphanumericWithDashesAndUnderscores)
		return rxp.Match([]byte(str))
	})

	_, err := govalidator.ValidateStruct(authOptions)
	if err != nil {
		return nil, fail.ToError(err)
	}

	providerName := "huaweicloud"
	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, domainName, projectID)
	if xerr != nil {
		return nil, xerr
	}

	cfgOptions := stacks.ConfigurationOptions{
		DNSList:             []string{"1.1.1.1"},
		UseFloatingIP:       true,
		UseLayer3Networking: false,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"SATA": volumespeed.COLD,
			"SAS":  volumespeed.HDD,
			"SSD":  volumespeed.SSD,
		},
		MetadataBucket:     metadataBucketName,
		OperatorUsername:   operatorUsername,
		ProviderName:       providerName,
		DefaultNetworkName: vpcName,
		DefaultNetworkCIDR: vpcCIDR,
	}
	stack, xerr := huaweicloud.New(authOptions, cfgOptions)
	if xerr != nil {
		return nil, xerr
	}
	//xerr = stack.InitDefaultSecurityGroups()
	//if xerr != nil {
	//	return nil, xerr
	//}

	// VPL: moved to stacks.openstack.New()
	// validRegions, xerr := stack.ListRegions()
	// if xerr != nil {
	// 	return nil, xerr
	// }
	// if len(validRegions) != 0 {
	// 	regionIsValidInput := false
	// 	for _, vr := range validRegions {
	// 		if region == vr {
	// 			regionIsValidInput = true
	// 		}
	// 	}
	// 	if !regionIsValidInput {
	// 		return nil, fail.InvalidRequestError("invalid Region '%s'", region)
	// 	}
	// }
	//
	// validAvailabilityZones, err := stack.ListAvailabilityZones()
	// if err != nil {
	// 	return nil, xerr
	// }
	//
	// if len(validAvailabilityZones) != 0 {
	// 	var validZones []string
	// 	zoneIsValidInput := false
	// 	for az, valid := range validAvailabilityZones {
	// 		if valid {
	// 			if az == zone {
	// 				zoneIsValidInput = true
	// 			}
	// 			validZones = append(validZones, az)
	// 		}
	// 	}
	// 	if !zoneIsValidInput {
	// 		return nil, fail.InvalidRequestError("invalid availability zone '%s', valid zones are %v", zone, validZones)
	// 	}
	// }

	newP := provider{
		Stack:            stack,
		tenantParameters: params,
	}
	return &newP, nil
}

// ListTemplates ... ; overloads Stack.ListTemplates() to allow to filter templates to show
// Value of all has no impact on the result
func (p provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	if p.IsNull() {
		return []abstract.HostTemplate{}, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListTemplates()
}

// ListImages ... ; overloads Stack.ListImages() to allow to filter images to show
// Value of all has no impact on the result
func (p provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
	if p.IsNull() {
		return []abstract.Image{}, fail.InvalidInstanceError()
	}
	return p.Stack.(api.ReservedForProviderUse).ListImages()
}

// GetAuthenticationOptions returns the auth options
func (p provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.(api.ReservedForProviderUse).GetAuthenticationOptions()
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthUrl", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)

	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}

	opts := p.Stack.(api.ReservedForProviderUse).GetConfigurationOptions()
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("ProviderName", p.GetName())

	return cfg, nil
}

// GetName ...
func (p provider) GetName() string {
	return "opentelekom"
}

// GetTenantParameters ...
func (p provider) GetTenantParameters() map[string]interface{} {
	return p.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (p provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{
		PrivateVirtualIP: true,
	}
}

// init registers the opentelekom provider
func init() {
	iaas.Register("opentelekom", &provider{})
}
