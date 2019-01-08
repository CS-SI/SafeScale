/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package cloudwatt

import (
	"fmt"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/model"
	"github.com/CS-SI/SafeScale/iaas/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/provider"
	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/stack"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"
)

var (
	externalNetwork          = "public"
	dnsServers               = []string{"185.23.94.244", "185.23.94.245"}
	identityEndpointTemplate = "https://identity.%s.cloudwatt.com/v2.0"
)

// impl is the implementation of the Cloudwatt provider
type impl struct {
	*openstack.Stack
}

// Build build a new Client from configuration parameter
func (p *impl) Build(params map[string]interface{}) (api.Provider, error) {

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})

	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	tenantName, _ := compute["TenantName"].(string)
	region, _ := compute["Region"].(string)
	identityEndpoint := fmt.Sprintf(identityEndpointTemplate, region)

	authOptions := &stack.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		TenantName:       tenantName,
		Region:           region,
		FloatingIPPool:   "public",
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("openstack", region, tenantName, "0")
	if err != nil {
		return nil, err
	}

	cfgOptions := &stack.ConfigurationOptions{
		ProviderNetwork:           externalNetwork,
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"standard":   VolumeSpeed.COLD,
			"performant": VolumeSpeed.HDD,
		},
		DNSList:        dnsServers,
		MetadataBucket: metadataBucketName,
	}

	stack, err := openstack.New(authOptions, cfgOptions)
	if err != nil {
		return nil, err
	}
	return &impl{Stack: stack}, nil
}

// GetCfgOpts return configuration parameters
func (p *impl) GetCfgOpts() (provider.Config, error) {
	cfg := provider.ConfigMap{}

	cfg.Set("DNSList", p.Stack.CfgOpts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", p.Stack.CfgOpts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", p.Stack.CfgOpts.UseLayer3Networking)

	return cfg, nil
}

// ListTemplates ...
// Value of all has no impact on the result
func (p *impl) ListTemplates(all bool) ([]model.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	return allTemplates, nil
}

// ListImages ...
// Value of all has no impact on the result
func (p *impl) ListImages(all bool) ([]model.Image, error) {
	allImages, err := p.Stack.ListImages()
	if err != nil {
		return nil, err
	}
	return allImages, nil
}

func init() {
	iaas.Register("cloudwatt", &impl{})
}
