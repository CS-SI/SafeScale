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
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/api/VolumeSpeed"

	"github.com/CS-SI/SafeScale/providers/flexibleengine"
)

//go:generate rice embed-go

/*AuthOptions fields are the union of those recognized by each identity implementation and
provider.
*/
type AuthOptions struct {
	flexibleengine.AuthOptions
}

//CfgOptions configuration options
type CfgOptions struct {
	flexibleengine.CfgOptions
}

const (
	authURL string = "https://iam.%s.prod-cloud-ocb.orange-business.com"
)

// Client is the implementation of the flexibleengine driver regarding to the api.ClientAPI
type Client struct {
	Opts  *flexibleengine.AuthOptions
	Cfg   *flexibleengine.CfgOptions
	feclt *flexibleengine.Client
}

// AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions, cfg CfgOptions) (*Client, error) {
	var err error
	client := &Client{}
	client.feclt, err = flexibleengine.AuthenticatedClient(opts.AuthOptions, cfg.CfgOptions)
	if err != nil {
		return nil, err
	}
	client.Opts = &opts.AuthOptions
	client.Cfg = &cfg.CfgOptions
	return client, err
}

//Build build a new Client from configuration parameter
func (client *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	Username, _ := params["Username"].(string)
	Password, _ := params["Password"].(string)
	DomainName, _ := params["DomainName"].(string)
	ProjectID, _ := params["ProjectID"].(string)
	VPCName, _ := params["VPCName"].(string)
	VPCCIDR, _ := params["VPCCIDR"].(string)
	Region, _ := params["Region"].(string)
	S3AccessKeyID, _ := params["S3AccessKeyID"].(string)
	S3AccessKeyPassword, _ := params["S3AccessKeyPassword"].(string)
	authOptions := AuthOptions{
		AuthOptions: flexibleengine.AuthOptions{
			Username:            Username,
			Password:            Password,
			DomainName:          DomainName,
			ProjectID:           ProjectID,
			Region:              Region,
			AllowReauth:         true,
			VPCName:             VPCName,
			VPCCIDR:             VPCCIDR,
			S3AccessKeyID:       S3AccessKeyID,
			S3AccessKeyPassword: S3AccessKeyPassword,
		},
	}
	cfgOptions := CfgOptions{
		CfgOptions: flexibleengine.CfgOptions{
			DNSList:             []string{"1.1.1.1"},
			UseFloatingIP:       true,
			UseLayer3Networking: false,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"SATA": VolumeSpeed.COLD,
				"SAS":  VolumeSpeed.HDD,
				"SSD":  VolumeSpeed.SSD,
			},
		},
	}
	return AuthenticatedClient(authOptions, cfgOptions)
}

//GetAuthOpts returns the auth options
func (client *Client) GetAuthOpts() (api.Config, error) {
	cfg := api.ConfigMap{}

	cfg.Set("DomainName", client.Opts.DomainName)
	cfg.Set("Login", client.Opts.Username)
	cfg.Set("Password", client.Opts.Password)
	cfg.Set("AuthUrl", client.Opts.IdentityEndpoint)
	cfg.Set("Region", client.Opts.Region)
	cfg.Set("VPCName", client.Opts.VPCName)
	return cfg, nil
}

//GetCfgOpts return configuration parameters
func (client *Client) GetCfgOpts() (api.Config, error) {
	cfg := api.ConfigMap{}

	cfg.Set("DNSList", client.Cfg.DNSList)
	cfg.Set("S3Protocol", "s3")

	return cfg, nil
}

// init registers the opentelekom provider
func init() {
	providers.Register("opentelekom", &Client{})
}
