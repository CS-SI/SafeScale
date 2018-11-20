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

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/openstack"
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

// func parseOpenRC(openrc string) (*openstack.AuthOptions, error) {
// 	tokens := strings.Split(openrc, "export")
// }

//AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions, cfg openstack.CfgOptions) (*Client, error) {
	IdentityEndpoint := fmt.Sprintf("https://identity.%s.cloudwatt.com/v2.0", opts.Region)
	os, err := openstack.AuthenticatedClient(
		openstack.AuthOptions{
			IdentityEndpoint: IdentityEndpoint,
			//UserID:           opts.OpenstackID,
			Username:       opts.Username,
			Password:       opts.Password,
			TenantName:     opts.TenantName,
			Region:         opts.Region,
			FloatingIPPool: "public",
		},
		openstack.CfgOptions{
			ProviderNetwork:           "public",
			UseFloatingIP:             true,
			UseLayer3Networking:       true,
			AutoHostNetworkInterfaces: true,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"standard":   VolumeSpeed.COLD,
				"performant": VolumeSpeed.HDD,
			},
			DNSList:      []string{"185.23.94.244", "185.23.94.245"},
			DefaultImage: cfg.DefaultImage,
		},
	)

	if err != nil {
		return nil, err
	}
	client := &Client{
		Client: os,
		opts:   opts,
	}

	return client, nil
}

//Client is the implementation of the ovh driver regarding to the api.ClientAPI
//This client used ovh api and opensatck ovh api to maximize code reuse
type Client struct {
	*openstack.Client
	opts AuthOptions
}

//Build build a new Client from configuration parameter
func (c *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	tenantName, _ := params["name"].(string)

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	// network, _ := params["network"].(map[string]interface{})

	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)

	region, _ := compute["Region"].(string)
	defaultImage, _ := compute["DefaultImage"].(string)

	return AuthenticatedClient(
		AuthOptions{
			Username:   username,
			Password:   password,
			TenantName: tenantName,
			Region:     region,
		},
		openstack.CfgOptions{
			DefaultImage: defaultImage,
		},
	)
}

// GetCfgOpts return configuration parameters
func (c *Client) GetCfgOpts() (model.Config, error) {
	cfg := model.ConfigMap{}

	cfg.Set("DNSList", c.Cfg.DNSList)
	// cfg.Set("S3Protocol", c.Cfg.S3Protocol)
	cfg.Set("AutoHostNetworkInterfaces", c.Cfg.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", c.Cfg.UseLayer3Networking)

	return cfg, nil
}

func init() {
	providers.Register("cloudwatt", &Client{})
}
