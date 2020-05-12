/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package outscale

import (
	"fmt"
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/outscale"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// OutscaleProvider safescale integration of outscale IaaS API
// see https://docs.outscale.com/api
type provider struct {
	outscale.Stack
}

func remap(s interface{}) map[string]interface{} {
	m, ok := s.(map[string]interface{})
	if !ok {
		return map[string]interface{}{}
	}
	return m
}

func get(m map[string]interface{}, key string, def ...string) string {
	v, ok := m[key]
	if !ok {
		if def != nil {
			return def[0]
		}
		return ""
	}
	return v.(string)
}
func getList(m map[string]interface{}, key string) []string {
	v, ok := m[key]
	if !ok {
		return []string{}
	}
	l, ok := v.([]interface{})
	if !ok {
		return []string{}
	}
	sl := make([]string, len(l))
	for _, i := range l {
		s, ok := i.(string)
		if !ok {
			return []string{}
		}
		sl = append(sl, s)
	}
	return sl
}

func volumeSpeed(s string) volumespeed.Enum {
	if s == "COLD" {
		return volumespeed.COLD
	}
	if s == "COLD" {
		return volumespeed.SSD
	}
	return volumespeed.HDD

}

func (p *provider) Build(opt map[string]interface{}) (api.Provider, error) {
	if p == nil {
		return nil, scerr.InvalidInstanceError()
	}
	identity := remap(opt["identity"])
	compute := remap(opt["compute"])
	metadata := remap(opt["metadata"])
	network := remap(opt["network"])
	objectstorage := remap(opt["objectstorage"])
	options := &outscale.ConfigurationOptions{
		Identity: outscale.Credentials{
			AccessKey: get(identity, "AccessKey"),
			SecretKey: get(identity, "SecretKey"),
		},
		Compute: outscale.ComputeConfiguration{
			URL:                     get(compute, "URL", "outscale.com/api/latest"),
			Service:                 get(compute, "Service", "api"),
			Region:                  get(compute, "Region"),
			Subregion:               get(compute, "Subregion"),
			DNSList:                 getList(compute, "DNSList"),
			DefaultTenancy:          get(compute, "DefaultTenancy", "default"),
			DefaultImage:            get(compute, "DefaultImage"),
			DefaultVolumeSpeed:      volumeSpeed(get(compute, "DefaultVolumeSpeed", "HDD")),
			OperatorUsername:        get(compute, "OperatorUsername", "safescale"),
			BlacklistImageRegexp:    regexp.MustCompile(get(compute, "BlacklistImageRegexp")),
			BlacklistTemplateRegexp: regexp.MustCompile(get(compute, "BlacklistTemplateRegexp")),
			WhitelistImageRegexp:    regexp.MustCompile(get(compute, "WhitelistImageRegexp")),
			WhitelistTemplateRegexp: regexp.MustCompile(get(compute, "WhitelistTemplateRegexp")),
		},
		Network: outscale.NetworConfiguration{
			VPCCIDR: get(network, "VPCCIDR", "192.168.0.0/16"),
			VPCID:   get(network, "VPCID"),
			VPCName: get(network, "VPCName", "safecale-net"),
		},
		ObjectStorage: outscale.StorageConfiguration{
			AccessKey: get(objectstorage, "AccessKey", get(identity, "AccessKey")),
			SecretKey: get(objectstorage, "SecretKey", get(identity, "SecretKey")),
			Endpoint:  get(objectstorage, "Endpoint", fmt.Sprintf("https://osu.%s.outscale.com", get(compute, "Region"))),
			Type:      get(objectstorage, "Type", "s3"),
		},
		Metadata: outscale.MetadataConfiguration{
			AccessKey: get(metadata, "AccessKey", get(objectstorage, "AccessKey", get(identity, "AccessKey"))),
			SecretKey: get(metadata, "SecretKey", get(objectstorage, "SecretKey", get(identity, "SecretKey"))),
			Endpoint:  get(metadata, "Endpoint", get(objectstorage, "Endpoint", fmt.Sprintf("https://osu.%s.outscale.com", get(compute, "Region")))),
			Type:      get(metadata, "Type", get(objectstorage, "Type", "s3")),
			Bucket:    get(metadata, "Bucket", "safescale"),
			CryptKey:  get(metadata, "CryptKey", "safescale"),
		},
	}

	stack, err := outscale.New(options)
	if err != nil {
		return nil, err
	}
	p.Stack = *stack
	return p, nil
}

// GetAuthenticationOptions returns authentication parameters
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {
	if p == nil {
		return nil, scerr.InvalidInstanceError()
	}
	m := providers.ConfigMap{}
	m.Set("AccessKey", p.Options.Identity.AccessKey)
	m.Set("SecretKey", p.Options.Identity.SecretKey)
	m.Set("Region", p.Options.Compute.Region)
	m.Set("Service", p.Options.Compute.Service)
	m.Set("URL", p.Options.Compute.URL)
	return m, nil
}

// GetConfigurationOptions returns configuration parameters
func (p *provider) GetConfigurationOptions() (providers.Config, error) {
	if p == nil {
		return nil, scerr.InvalidInstanceError()
	}
	// MetadataBucketName
	cfg := providers.ConfigMap{}
	//
	cfg.Set("DNSList", p.Options.Compute.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", true)
	cfg.Set("UseLayer3Networking", false)
	cfg.Set("DefaultImage", p.Options.Compute.DefaultImage)
	cfg.Set("MetadataBucketName", p.Options.Metadata.Bucket)
	cfg.Set("OperatorUsername", p.Options.Compute.OperatorUsername)
	cfg.Set("ProviderName", p.GetName())
	cfg.Set("BuildSubnetworks", false)
	return cfg, nil
}

// GetName returns the provider name
func (p *provider) GetName() string {
	return "outscale"
}

// GetTenantParameters returns the tenant parameters as-is
// TODO
func (p *provider) GetTenantParameters() map[string]interface{} {
	return nil
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{
		PublicVirtualIP:  false,
		PrivateVirtualIP: true,
		Layer3Networking: false,
	}
}

// TODO init when finished
func init() {
	iaas.Register("outscale", &provider{})
}
