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
	"strings"

	"github.com/CS-SI/SafeScale/providers"
	"github.com/CS-SI/SafeScale/providers/api"
	"github.com/CS-SI/SafeScale/providers/api/VolumeSpeed"
	filters "github.com/CS-SI/SafeScale/providers/api/filters/templates"
	"github.com/CS-SI/SafeScale/providers/openstack"
)

//ProviderNetwork name of ovh external network
const ProviderNetwork string = "Ext-Net"

type gpuCfg struct {
	GPUNumber int
	GPUType   string
}

var gpuMap = map[string]gpuCfg{
	"g2-15": gpuCfg{
		GPUNumber: 1,
		GPUType:   "NVIDIA 1070",
	},
	"g2-30": gpuCfg{
		GPUNumber: 1,
		GPUType:   "NVIDIA 1070",
	},
	"g3-120": gpuCfg{
		GPUNumber: 3,
		GPUType:   "NVIDIA 1080 TI",
	},
	"g3-30": gpuCfg{
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
	},
}

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
			ProviderNetwork:           ProviderNetwork,
			UseFloatingIP:             false,
			UseLayer3Networking:       false,
			AutoHostNetworkInterfaces: false,
			DNSList:                   []string{"213.186.33.99", "1.1.1.1"},
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

func addGPUCfg(tpl *api.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

//GetTemplate overload OpenStack GetTemplate method to add GPU configuration
func (c *Client) GetTemplate(id string) (*api.HostTemplate, error) {
	tpl, err := c.Client.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

// GetCfgOpts return configuration parameters
func (client *Client) GetCfgOpts() (api.Config, error) {
	cfg := api.ConfigMap{}

	cfg.Set("DNSList", client.Cfg.DNSList)
	cfg.Set("S3Protocol", client.Cfg.S3Protocol)
	cfg.Set("AutoHostNetworkInterfaces", client.Cfg.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", client.Cfg.UseLayer3Networking)

	return cfg, nil
}

func isWindowsTemplate(t api.HostTemplate) bool {
	return strings.HasPrefix(strings.ToLower(t.Name), "win-")
}
func isFlexTemplate(t api.HostTemplate) bool {
	return strings.HasSuffix(strings.ToLower(t.Name), "flex")
}

//ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (c *Client) ListTemplates(all bool) ([]api.HostTemplate, error) {
	allTemplates, err := c.Client.ListTemplates(all)
	if err != nil {
		return nil, err
	}
	if all {
		return allTemplates, nil
	}

	filter := filters.NewFilter(isWindowsTemplate).Not().And(filters.NewFilter(isFlexTemplate).Not())

	return filters.FilterTemplates(allTemplates, filter), nil
}

func init() {
	providers.Register("ovh", &Client{})
}
