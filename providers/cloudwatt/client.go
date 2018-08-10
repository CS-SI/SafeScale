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
	//OstUsername
	OstUsername string
	//OstPassword
	OstPassword string
	//OstDomainName
	OstDomainName string
	//OstProjectID
	OstProjectID string
	//OstAuth
	OstAuth string
	//OstRegion
	OstRegion string
	//OstSecretKey
	OstSecretKey string
	//OstTypes
	OstTypes string
}

// func parseOpenRC(openrc string) (*openstack.AuthOptions, error) {
// 	tokens := strings.Split(openrc, "export")
// }

//AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions) (*Client, error) {
	IdentityEndpoint := fmt.Sprintf("https://identity.%s.cloudwatt.com/v2.0", opts.Region)
	os, err := openstack.AuthenticatedClient(openstack.AuthOptions{
		IdentityEndpoint: IdentityEndpoint,
		//UserID:           opts.OpenstackID,
		Username:       opts.Username,
		Password:       opts.Password,
		TenantName:     opts.TenantName,
		Region:         opts.Region,
		FloatingIPPool: "public",
		/*
			OstUsername:    opts.OstUsername,
			OstPassword:    opts.OstPassword,
			OstDomainName:  opts.OstDomainName,
			OstProjectID:   opts.OstProjectID,
			OstAuth:        opts.OstAuth,
			OstRegion:      opts.OstRegion,
			OstSecretKey:   opts.OstSecretKey,
			OstTypes:       opts.OstTypes,
		*/
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
			DNSList: []string{"185.23.94.244", "185.23.94.245"},
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
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	TenantName, _ := params["TenantName"].(string)
	Region, _ := params["Region"].(string)
	/*
		OstUsername, _ := params["OstUsername"].(string)
		OstPassword, _ := params["OstPassword"].(string)
		OstDomainName, _ := params["OstDomainName"].(string)
		OstProjectID, _ := params["OstProjectID"].(string)
		OstAuth, _ := params["OstAuth"].(string)
		OstRegion, _ := params["OstRegion"].(string)
		OstSecretKey, _ := params["OstSecretKey"].(string)
		OstTypes, _ := params["OstTypes"].(string)
	*/
	return AuthenticatedClient(AuthOptions{
		Username:   Username,
		Password:   Password,
		TenantName: TenantName,
		Region:     Region,
		/*
			OstUsername:   OstUsername,
			OstPassword:   OstPassword,
			OstDomainName: OstDomainName,
			OstProjectID:  OstProjectID,
			OstAuth:       OstAuth,
			OstRegion:     OstRegion,
			OstSecretKey:  OstSecretKey,
			OstTypes:      OstTypes,
		*/
	})
}

// GetCfgOpts return configuration parameters
func (c *Client) GetCfgOpts() (model.Config, error) {
	cfg := model.ConfigMap{}

	cfg.Set("DNSList", c.Cfg.DNSList)
	cfg.Set("S3Protocol", c.Cfg.S3Protocol)
	cfg.Set("AutoHostNetworkInterfaces", c.Cfg.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", c.Cfg.UseLayer3Networking)

	return cfg, nil
}

func init() {
	providers.Register("cloudwatt", &Client{})
}
