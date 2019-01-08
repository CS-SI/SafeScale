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

	"github.com/CS-SI/SafeScale/iaas"
	filters "github.com/CS-SI/SafeScale/iaas/filters/templates"
	"github.com/CS-SI/SafeScale/iaas/model"
	"github.com/CS-SI/SafeScale/iaas/model/enums/VolumeSpeed"
	"github.com/CS-SI/SafeScale/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/iaas/provider"
	"github.com/CS-SI/SafeScale/iaas/provider/api"
	"github.com/CS-SI/SafeScale/iaas/stack"
	"github.com/CS-SI/SafeScale/iaas/stack/openstack"
)

// externalNetwork name of ovh external network
const externalNetwork string = "Ext-Net"

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

// impl is the implementation of the OVH provider
type impl struct {
	*openstack.Stack
	ExternalNetworkID string
}

var (
	identityEndpoint = "https://auth.cloud.ovh.net/v2.0"
	externalNetwork  = "Ext-Net"
	dnsServers       = []string{"213.186.33.99", "1.1.1.1"}
)

// Build build a new instance of Ovh using configuration parameters
func (p *impl) Build(params map[string]interface{}) (api.Provider, error) {
	identityParams, _ := params["identity"].(map[string]interface{})
	computeParams, _ := params["compute"].(map[string]interface{})
	networkParams, _ := params["network"].(map[string]interface{})

	applicationKey, _ := identityParams["ApplicationKey"].(string)
	openstackID, _ := identityParams["OpenstackID"].(string)
	openstackPassword, _ := identityParams["OpenstackPassword"].(string)
	region, _ := computeParams["Region"].(string)
	projectName, _ := computeParams["ProjectName"].(string)

	authOptions := &stack.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         openstackID,
		Password:         openstackPassword,
		TenantID:         applicationKey,
		TenantName:       projectName,
		Region:           region,
		AllowReauth:      true,
	}

	metadataBucketName, err := objectstorage.BuildMetadataBucketName("openstack", region, applicationKey, projectName)
	if err != nil {
		return nil, err
	}

	cfgOptions := &stack.ConfigurationOptions{
		ProviderNetwork:           externalNetwork,
		UseFloatingIP:             false,
		UseLayer3Networking:       false,
		AutoHostNetworkInterfaces: false,
		DNSList:                   dnsServers,
		VolumeSpeeds: map[string]VolumeSpeed.Enum{
			"classic":    VolumeSpeed.COLD,
			"high-speed": VolumeSpeed.HDD,
		},
		MetadataBucketName: metadataBucketName,
	}

	stack, err := openstack.New(authOptions, cfgOptions)
	if err != nil {
		return nil, err
	}
	return &impl{Stack: stack}, nil
}

// GetCfgOpts return configuration parameters
func (p *impl) GetCfgOpts() (provider.Config, error) {
	return p.Stack.GetCfgOpts()
}

// GetAuthOpts returns the auth options
func (p *impl) GetAuthOpts() (provider.Config, error) {
	return p.Stack.GetAuthOpts()
}

// GetTemplate overload OpenStack GetTemplate method to add GPU configuration
func (p *impl) GetTemplate(id string) (*model.HostTemplate, error) {
	tpl, err := p.Stack.GetTemplate(id)
	if tpl != nil {
		addGPUCfg(tpl)
	}
	return tpl, err
}

func addGPUCfg(tpl *model.HostTemplate) {
	if cfg, ok := gpuMap[tpl.Name]; ok {
		tpl.GPUNumber = cfg.GPUNumber
		tpl.GPUType = cfg.GPUType
	}
}

// ListTemplates overload OpenStack ListTemplate method to filter wind and flex instance and add GPU configuration
func (p *impl) ListTemplates(all bool) ([]model.HostTemplate, error) {
	allTemplates, err := p.Stack.ListTemplates()
	if err != nil {
		return nil, err
	}
	if all {
		return allTemplates, nil
	}

	filter := filters.NewFilter(isWindowsTemplate).Not().And(filters.NewFilter(isFlexTemplate).Not())
	return filters.FilterTemplates(allTemplates, filter), nil
}

func isWindowsTemplate(t model.HostTemplate) bool {
	return strings.HasPrefix(strings.ToLower(t.Name), "win-")
}

func isFlexTemplate(t model.HostTemplate) bool {
	return strings.HasSuffix(strings.ToLower(t.Name), "flex")
}

// CreateNetwork is overloaded to handle specific OVH situation
func (p *impl) CreateNetwork(req model.NetworkRequest) (*model.Network, error) {
	// Special treatment for OVH : no dnsServers means __NO__ DNS servers, not default ones
	// The way to do so, accordingly to OVH support, is to set DNS servers to 0.0.0.0
	if len(req.DNSServers) == 0 {
		req.DNSServers = []string{"0.0.0.0"}
	}
	return p.Stack.CreateNetwork(req)
}

func init() {
	iaas.Register("ovh", &impl{})
}
