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
	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/metadata"
	"github.com/CS-SI/SafeScale/providers/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/providers/openstack"
	gc "github.com/gophercloud/gophercloud"
	ops "github.com/gophercloud/gophercloud/openstack"
)

// AuthOptions fields are the union of those recognized by each identity implementation and provider.
type AuthOptions struct {
	Username    string
	Password    string
	TenantName  string
	Region      string
	DomainName  string
	ProjectName string
	ProjectID   string
}

// func parseOpenRC(openrc string) (*openstack.AuthOptions, error) {
// 	tokens := strings.Split(openrc, "export")
// }

// AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions, cfg openstack.CfgOptions) (*Client, error) {
	const identityEndpoint = "https://cf2.cloudferro.com:5000/v3"

	os, err := openstack.AuthenticatedClient(
		openstack.AuthOptions{
			IdentityEndpoint: identityEndpoint,
			Username:         opts.Username,
			Password:         opts.Password,
			DomainName:       opts.DomainName,
			TenantName:       opts.ProjectName,
			Region:           opts.Region,
			FloatingIPPool:   "external",
			AllowReauth:      true,
		},
		openstack.CfgOptions{
			ProviderNetwork:           "external",
			UseFloatingIP:             true,
			UseLayer3Networking:       true,
			AutoHostNetworkInterfaces: true,
			VolumeSpeeds: map[string]VolumeSpeed.Enum{
				"HDD": VolumeSpeed.HDD,
				"SSD": VolumeSpeed.SSD,
			},
			MetadataBucket: metadata.BuildMetadataBucketName(opts.ProjectID),
			DNSList:        []string{"1.1.1.1", "8.8.8.8"},
			DefaultImage:   cfg.DefaultImage,
		},
	)

	if err != nil {
		return nil, err
	}

	// Storage API V2
	blocstorage, err := ops.NewBlockStorageV2(os.Provider, gc.EndpointOpts{
		Region: opts.Region,
	})
	os.Volume = blocstorage

	if err != nil {
		return nil, err
	}

	_, err = openstack.VerifyEndpoints(os)
	if err != nil {
		return nil, err
	}

	client := &Client{
		Client: os,
		opts:   opts,
	}

	return client, nil
}

// Client is the implementation of the ovh driver regarding to the api.ClientAPI
// This client used ovh api and opensatck ovh api to maximize code reuse
type Client struct {
	*openstack.Client
	opts AuthOptions
}

// Build build a new Client from configuration parameter
func (c *Client) Build(params map[string]interface{}) (api.ClientAPI, error) {
	// tenantName, _ := params["name"].(string)

	identity, _ := params["identity"].(map[string]interface{})
	compute, _ := params["compute"].(map[string]interface{})
	// network, _ := params["network"].(map[string]interface{})

	username, _ := identity["Username"].(string)
	password, _ := identity["Password"].(string)
	domainName, _ := identity["DomainName"].(string)

	region, _ := compute["Region"].(string)
	projectName, _ := compute["ProjectName"].(string)
	projectID, _ := compute["ProjectID"].(string)
	defaultImage, _ := compute["DefaultImage"].(string)

	return AuthenticatedClient(
		AuthOptions{
			Username:    username,
			Password:    password,
			Region:      region,
			DomainName:  domainName,
			ProjectName: projectName,
			ProjectID:   projectID,
		},
		openstack.CfgOptions{
			DefaultImage: defaultImage,
		},
	)
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

func init() {
	providers.Register("cloudferro", &Client{})
}
