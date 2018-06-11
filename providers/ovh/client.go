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

package ovh

import (
	"github.com/CS-SI/SafeScale/metadata"
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/openstack"

	"github.com/CS-SI/SafeScale/providers/api/VolumeSpeed"
)

//ProviderNetwork name of ovh external network
const ProviderNetwork string = "Ext-Net"

/*AuthOptions fields are the union of those recognized by each identity implementation and
provider.
*/
type AuthOptions struct {
	// // Endpoint ovh end point (ovh-eu, ovh-ca ...)
	// Endpoint string
	// //Application or Project Name
	// ApplicationName string
	//Application Key or project ID
	ApplicationKey string
	// //Consumer key
	// ConsumerKey string
	//Openstack identifier
	OpenstackID string
	//OpenStack password
	OpenstackPassword string
	//Name of the data center (GRA3, BHS3 ...)
	Region string
	//Project Name
	ProjectName string
}

// func parseOpenRC(openrc string) (*openstack.AuthOptions, error) {
// 	tokens := strings.Split(openrc, "export")
// }

//AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions) (*Client, error) {
	client := &Client{}
	//	c, err := ovh.NewClient(opts.Endpoint, opts.ApplicationName, opts.ApplicationKey, opts.ConsumerKey)
	// if err != nil {
	// 	return nil, err
	// }
	//client.ovh = c
	os, err := openstack.AuthenticatedClient(openstack.AuthOptions{
		IdentityEndpoint: "https://auth.cloud.ovh.net/v2.0",
		//UserID:           opts.OpenstackID,
		Username:   opts.OpenstackID,
		Password:   opts.OpenstackPassword,
		TenantID:   opts.ApplicationKey,
		TenantName: opts.ProjectName,
		Region:     opts.Region,
	},
		openstack.CfgOptions{
			ProviderNetwork:         ProviderNetwork,
			UseFloatingIP:           false,
			UseLayer3Networking:     false,
			AutoVMNetworkInterfaces: false,
			DNSList:                 []string{"8.8.8.8", "8.8.4.4"},
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"classic":    VolumeSpeed.COLD,
				"high-speed": VolumeSpeed.HDD,
			},
		},
	)

	if err != nil {
		return nil, err
	}
	client.Client = os

	// Creates metadata Object Storage container
	err = metadata.InitializeContainer(client)
	if err != nil {
		return nil, err
	}

	return client, nil

}

//Client is the implementation of the ovh driver regarding to the api.ClientAPI
//This client used ovh api and opensatck ovh api to maximize code reuse
type Client struct {
	*openstack.Client
	opts AuthOptions
	//ovh  *ovh.Client
}

//Build build a new Client from configuration parameter
func (c *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	ApplicationKey, _ := params["ApplicationKey"].(string)
	OpenstackID, _ := params["OpenstackID"].(string)
	OpenstackPassword, _ := params["OpenstackPassword"].(string)
	Region, _ := params["Region"].(string)
	ProjectName, _ := params["ProjectName"].(string)
	return AuthenticatedClient(AuthOptions{
		ApplicationKey:    ApplicationKey,
		OpenstackID:       OpenstackID,
		OpenstackPassword: OpenstackPassword,
		Region:            Region,
		ProjectName:       ProjectName,
	})
}

func init() {
	providers.Register("ovh", &Client{})
}
