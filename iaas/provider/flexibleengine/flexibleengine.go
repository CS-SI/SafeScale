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

package flexibleengine

import (
	"fmt"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/stack"
	"github.com/CS-SI/SafeScale/iaas/stack/huaweicloud"
)

const (
	defaultUser string = "cloud"

	authURL string = "https://iam.%s.prod-cloud-ocb.orange-business.com"
)

// impl is the implementation of FlexibleEngine provider
type impl struct {
	*huaweicloud.Stack
}

// Build initializes a new FlexibleEngine instance from parameters
func (p *impl) Build(params map[string]interface{}) (api.Provider, error) {

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})

	identityEndpoint, _ := identity["EndPoint"].(string)
	if identityEndpoint == "" {
		identityEndpoint = fmt.Sprintf(authUrl, Region)
	}
	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	domainName, _ := identity["DomainName"].(string)
	projectID, _ := compute["ProjectID"].(string)
	vpcName, _ := network["VPCName"].(string)
	vpcCIDR, _ := network["VPCCIDR"].(string)
	region, _ := compute["Region"].(string)

	authOptions := &stack.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         username,
		Password:         password,
		DomainName:       domainName,
		ProjectID:        projectID,
		Region:           region,
		AllowReauth:      true,
		VPCName:          vpcName,
		VPCCIDR:          vpcCIDR,
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("huaweicloud", region, domainName, projectID)
	if err != nil {
		return nil, err
	}

	cfgOptions := &stack.ConfigurationOptions{
		DNSList:             []string{"100.125.0.41", "100.126.0.41"},
		UseFloatingIP:       true,
		UseLayer3Networking: false,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"SATA": VolumeSpeed.COLD,
			"SSD":  VolumeSpeed.SSD,
		},
		MetadataBucket: metadataBucketName,
	}
	stack, err := huaweicloud.New(authOptions, cfgOptions)
	if err != nil {
		return nil, err
	}

	return &impl{Stack: stack}, nil
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
func (p *impl) ListImages(all bool) ([]model.HostImage, error) {
	allImages, err := p.Stack.ListImages()
	if err != nil {
		return nil, err
	}
	return allImages, nil
}

func init() {
	iaas.Register("flexibleengine", &impl{})
}
