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

package opentelekom

import (
	"fmt"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/flexibleengine"
	"github.com/CS-SI/SafeScale/providers/model"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/openstack"
)

const (
	authURL string = "https://iam.%s.otc.t-systems.com"
)

// Client is the implementation of the flexibleengine driver regarding to the api.ClientAPI
type Client struct {
	feclt *flexibleengine.Client
}

// AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts flexibleengine.AuthOptions, cfg openstack.CfgOptions) (*Client, error) {
	var err error
	client := &Client{}

	if opts.IdentityEndpoint == "" {
		opts.IdentityEndpoint = fmt.Sprintf(authURL, opts.Region)
	}
	client.feclt, err = flexibleengine.AuthenticatedClient(opts, cfg)
	if err != nil {
		return nil, err
	}
	return client, err
}

// Build build a new Client from configuration parameter
func (client *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	// tenantName, _ := params["name"].(string)

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	network, _ := params["network"].(map[string]interface{})

	identityEndpoint, _ := identity["Endpoint"].(string)
	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	domainName, _ := identity["DomainName"].(string)

	projectID, _ := compute["ProjectID"].(string)
	region, _ := compute["Region"].(string)
	defaultImage, _ := compute["DefaultImage"].(string)

	vpcName, _ := network["VPCName"].(string)
	vpcCIDR, _ := network["VPCCIDR"].(string)

	// S3AccessKeyID, _ := params["S3AccessKeyID"].(string)
	// S3AccessKeyPassword, _ := params["S3AccessKeyPassword"].(string)
	authOptions := flexibleengine.AuthOptions{
		Username:         username,
		Password:         password,
		DomainName:       domainName,
		ProjectID:        projectID,
		Region:           region,
		AllowReauth:      true,
		VPCName:          vpcName,
		VPCCIDR:          vpcCIDR,
		IdentityEndpoint: identityEndpoint,
		// S3AccessKeyID:       S3AccessKeyID,
		// S3AccessKeyPassword: S3AccessKeyPassword,
	}
	cfgOptions := openstack.CfgOptions{
		DNSList:             []string{"1.1.1.1"},
		UseFloatingIP:       true,
		UseLayer3Networking: false,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"SATA": VolumeSpeed.COLD,
			"SAS":  VolumeSpeed.HDD,
			"SSD":  VolumeSpeed.SSD,
		},
		DefaultImage: defaultImage,
	}
	return AuthenticatedClient(authOptions, cfgOptions)
}

//GetAuthOpts returns the auth options
func (client *Client) GetAuthOpts() (model.Config, error) {
	return client.feclt.GetAuthOpts()
}

// GetCfgOpts return configuration parameters
func (client *Client) GetCfgOpts() (model.Config, error) {
	return client.feclt.GetCfgOpts()
}

// init registers the opentelekom provider
func init() {
	providers.Register("opentelekom", &Client{})
}
