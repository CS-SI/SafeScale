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
	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/resource/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"
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
	// Application Key or project ID
	ApplicationKey string
	// //Consumer key
	// ConsumerKey string
	// Openstack identifier
	OpenstackID string
	// OpenStack password
	OpenstackPassword string
	// Name of the data center (GRA3, BHS3 ...)
	Region string
	// Project Name
	ProjectName string
}

// func parseOpenRC(openrc string) (*openstack.AuthOptions, error) {
// 	tokens := strings.Split(openrc, "export")
// }

//AuthenticatedClient returns an authenticated client
func AuthenticatedClient(opts AuthOptions) (*Client, error) {
	client := &Client{}
	osclt, err := openstack.AuthenticatedClient(
		openstack.AuthOptions{
			IdentityEndpoint: "https://auth.cloud.ovh.net/v2.0",
			//UserID:           opts.OpenstackID,
			Username:    opts.OpenstackID,
			Password:    opts.OpenstackPassword,
			TenantID:    opts.ApplicationKey,
			TenantName:  opts.ProjectName,
			Region:      opts.Region,
			AllowReauth: true,
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
			MetadataBucketName: api.BuildMetadataBucketName(opts.ApplicationKey),
		},
	)

	if err != nil {
		return nil, err
	}
	client.osclt = osclt

	return client, nil

}

// Ovh is the implementation of the ovh driver
type Ovh struct {
	AuthOpts           AuthenticationOptions
	MetadataBucketName string
	stack              *openstack.Stack
}

// Build build a new instance of Ovh using configuration parameters
func (p *Ovh) Build(params map[string]interface{}) (*api.Provider, error) {
	ApplicationKey, _ := params["ApplicationKey"].(string)
	OpenstackID, _ := params["OpenstackID"].(string)
	OpenstackPassword, _ := params["OpenstackPassword"].(string)
	Region, _ := params["Region"].(string)
	ProjectName, _ := params["ProjectName"].(string)

	newP := Ovh{
		AuthOpts: AuthenticationOptions{
			ApplicationKey:    ApplicationKey,
			OpenstackID:       OpenstackID,
			OpenstackPassword: OpenstackPassword,
			Region:            Region,
			ProjectName:       ProjectName,
		},
		CfgOpts: {},
	}
	newP.stack, err := ovh.New(newP.AuthOpts, newPCfgOpts)
	if err != nil {
		return nil, err
	}
	return &newP, nil
}

// GetCfgOpts return configuration parameters
func (p *Ovh) GetCfgOpts() (provider.Config, error) {
	return p.stack.GetCfgOpts()
}

// GetAuthOpts returns the auth options
func (p *Ovh) GetAuthOpts() (provider.Config, error) {
	return p.stack.GetAuthOpts()
}

func init() {
	provider.Register("ovh", &Ovh{})
}
