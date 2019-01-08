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

package cloudferro

import (
	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/model"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/stack"
	"github.com/CS-SI/SafeScale/iaas/stack/huaweicloud"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
)

var (
	cloudferroIdentityEndpoint = "https://cf2.cloudferro.com:5000/v3"
	cloudferroDefaultImage     = "Ubuntu 18.04"
	cloudferroDNSServers       = []string{"185.48.234.234", "185.48.234.238"}
)

// impl is the implementation of the CloudFerro provider
type impl struct {
	*huaweicloud.Stack
}

// Build build a new Client from configuration parameter
func (p *impl) Build(params map[string]interface{}) (api.Provider, error) {
	// tenantName, _ := params["name"].(string)

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	// network, _ := params["network"].(map[string]interface{})

	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	domainName, _ := identity["DomainName"].(string)

	region, _ := compute["Region"].(string)
	projectName, _ := compute["ProjectName"].(string)
	// projectID, _ := compute["ProjectID"].(string)
	defaultImage, _ := compute["DefaultImage"].(string)
	if defaultImage == "" {
		defaultImage = cloudferroDefaultImage
	}

	authOptions = &stack.AuthenticationOptions{
		IdentityEndpoint: cloudferroIdentityEndpoint,
		Username:         username,
		Password:         password,
		DomainName:       domainName,
		TenantName:       projectName,
		Region:           region,
		FloatingIPPool:   "external",
		AllowReauth:      true,
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("huaweicloud", region, domainName, projectName)
	if err != nil {
		return nil, err
	}

	cfgOptions = &stack.ConfigurationOptions{
		ProviderNetwork:           "external",
		UseFloatingIP:             true,
		UseLayer3Networking:       true,
		AutoHostNetworkInterfaces: true,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"HDD": VolumeSpeed.HDD,
			"SSD": VolumeSpeed.SSD,
		},
		MetadataBucket: metadataBucketName,
		DNSList:        cloudferroDNSServers,
		DefaultImage:   defaultImage,
	}

	var err error
	stack, err := openstack.New(authOptionss, cfgOptions)
	if err != nil {
		return nil, err
	}

	return &impl{Stack: stack}, nil
}

// // GetCfgOpts return configuration parameters
// func (c *Client) GetCfgOpts() (model.Config, error) {
// 	cfg := model.ConfigMap{}

// 	cfg.Set("DNSList", c.Cfg.DNSList)
// 	// cfg.Set("ObjectStorageType", c.Cfg.ObjectStorageType)
// 	cfg.Set("AutoHostNetworkInterfaces", c.Cfg.AutoHostNetworkInterfaces)
// 	cfg.Set("UseLayer3Networking", c.Cfg.UseLayer3Networking)
// 	cfg.Set("MetadataBucket", c.Cfg.MetadataBucketName)

// 	return cfg, nil
// }

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
	iaas.Register("cloudferro", &impl{})
}
