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
	"github.com/CS-SI/SafeScale/iaas/provider"
	"github.com/CS-SI/SafeScale/iaas/resource/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"
)

//ProviderNetwork name of CloudWatt external network
const ProviderNetwork string = "Ext-Net"

/*AuthOptions fields are the union of those recognized by each identity implementation and
provider.
*/
type AuthOptions struct {
	Username   string
	Password   string
	TenantName string
	Region     string
}

// Cloudwatt is the implementation of the Cloudwatt provider
type Cloudwatt struct {
	AuthOpts openstack.AuthenticationOptions
	CfgOpts  openstack.ConfigurationOptions

	stack *openstack.Stack
}

// Build build a new Client from configuration parameter
func (p *Cloudwatt) Build(params map[string]interface{}) (*Cloudwatt, error) {
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	TenantName, _ := params["TenantName"].(string)
	Region, _ := params["Region"].(string)
	IdentityEndpoint := fmt.Sprintf("https://identity.%s.cloudwatt.com/v2.0", opts.Region)

	newP := Cloudwatt{
		AuthOpts: stack_penstack.AuthenticatedOptions{
			IdentityEndpoint: IdentityEndpoint,
			//UserID:           opts.OpenstackID,
			Username:       opts.Username,
			Password:       opts.Password,
			TenantName:     opts.TenantName,
			Region:         opts.Region,
			FloatingIPPool: "public",
		},
		CfgOpts: stack_openstack.ConfigurationOptions{
			ProviderNetwork:           "public",
			UseFloatingIP:             true,
			UseLayer3Networking:       true,
			AutoHostNetworkInterfaces: true,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"standard":   VolumeSpeed.COLD,
				"performant": VolumeSpeed.HDD,
			},
			DNSList: []string{"185.23.94.244", "185.23.94.245"},
		},
	}
	newP.stack, err = openstack.New(newP.AuthOpts, newP.CfgOpts)
	if err != nil {
		return nil, err
	}
	return &newP, nil
}

// GetCfgOpts return configuration parameters
func (p *Cloudwatt) GetCfgOpts() (provider.Config, error) {
	cfg := provider.ConfigMap{}

	cfg.Set("DNSList", p.CfgOpts.DNSList)
	cfg.Set("S3Protocol", p.CfgOpts.S3Protocol)
	cfg.Set("AutoHostNetworkInterfaces", p.CfgOpts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", p.CfgOpts.UseLayer3Networking)

	return cfg, nil
}

func init() {
	iaas.Register("cloudwatt", &Cloudwatt{})
}
