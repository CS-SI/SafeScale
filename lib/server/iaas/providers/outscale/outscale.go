/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/outscale"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// provider is integration of outscale IaaS API
// see https://docs.outscale.com/api
type provider struct {
	api.Stack
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

// IsNull tells if the instance represents a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build ...
// Can be called from nil
func (p *provider) Build(opt map[string]interface{}) (_ providers.Provider, xerr fail.Error) {
	identity := remap(opt["identity"])
	compute := remap(opt["compute"])
	metadata := remap(opt["metadata"])
	network := remap(opt["network"])
	objstorage := remap(opt["objectstorage"])

	region := get(compute, "Region")
	if region == "" {
		return nil, fail.SyntaxError("field 'Region' in section 'compute' not found in tenant file", nil, nil)
	}
	if _, ok := metadata["Bucket"]; !ok {
		stackName := get(identity, "provider")
		userID := get(identity, "UserID")
		if userID == "" {
			return nil, fail.SyntaxError("field 'UserID' in section 'identity' not found in tenant file")
		}
		metadata["Bucket"], xerr = objectstorage.BuildMetadataBucketName(stackName, region, "", userID)
		if xerr != nil {
			return nil, xerr
		}
	}

	options := &outscale.ConfigurationOptions{
		Identity: outscale.Credentials{
			AccessKey: get(identity, "AccessKey"),
			SecretKey: get(identity, "SecretKey"),
		},
		Compute: outscale.ComputeConfiguration{
			URL:                     get(compute, "URL", "outscale.com/api/latest"),
			Service:                 get(compute, "Service", "api"),
			Region:                  region,
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
		Network: outscale.NetworkConfiguration{
			DefaultNetworkCIDR: get(network, "DefaultNetworkCIDR", get(network, "VPCCIDR")),
			//VPCID:              get(network, "VPCID"),
			DefaultNetworkName: get(network, "DefaultNetworkName", get(network, "VPCName")),
		},
		ObjectStorage: outscale.StorageConfiguration{
			AccessKey: get(objstorage, "AccessKey", get(identity, "AccessKey")),
			SecretKey: get(objstorage, "SecretKey", get(identity, "SecretKey")),
			Endpoint:  get(objstorage, "Endpoint", fmt.Sprintf("https://osu.%s.outscale.com", get(compute, "Region"))),
			Type:      get(objstorage, "Type", "s3"),
		},
		Metadata: outscale.MetadataConfiguration{
			AccessKey: get(metadata, "AccessKey", get(objstorage, "AccessKey", get(identity, "AccessKey"))),
			SecretKey: get(metadata, "SecretKey", get(objstorage, "SecretKey", get(identity, "SecretKey"))),
			Endpoint:  get(metadata, "Endpoint", get(objstorage, "Endpoint", fmt.Sprintf("https://osu.%s.outscale.com", get(compute, "Region")))),
			Type:      get(metadata, "Type", get(objstorage, "Type", "s3")),
			Bucket:    get(metadata, "Bucket", "0.safescale"),
			CryptKey:  get(metadata, "CryptKey", "safescale"),
		},
	}

	stack, err := outscale.New(options)
	if err != nil {
		return nil, fail.ToError(err)
	}
	p.Stack = stack
	return p, nil
}

// GetAuthenticationOptions returns authentication parameters
func (p provider) GetAuthenticationOptions() (providers.Config, fail.Error) {
	if p.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	opts := p.Stack.(api.ReservedForProviderUse).GetAuthenticationOptions()
	cfg := providers.ConfigMap{}
	cfg.Set("AccessKey", opts.AccessKeyID)
	cfg.Set("SecretKey", opts.SecretAccessKey)
	cfg.Set("Region", opts.Region)
	//cfg.Set("Service", opts.)
	cfg.Set("URL", opts.IdentityEndpoint)
	return cfg, nil
}

// GetConfigurationOptions returns configuration parameters
func (p provider) GetConfigurationOptions() (providers.Config, fail.Error) {
	if p.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	opts := p.Stack.(api.ReservedForProviderUse).GetConfigurationOptions()
	cfg := providers.ConfigMap{}
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", true)
	cfg.Set("UseLayer3Networking", false)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("ProviderName", p.GetName())
	cfg.Set("BuildSubnets", false)
	return cfg, nil
}

// GetName returns the provider name
func (p provider) GetName() string {
	return "outscale"
}

// GetTenantParameters returns the tenant parameters as-is
// TODO:
func (p provider) GetTenantParameters() map[string]interface{} {
	return nil
}

// GetCapabilities returns the capabilities of the provider
func (p provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{
		PublicVirtualIP: false,
		// TODO: not tested, corresponding code inside stack is commented
		// PrivateVirtualIP: true,
		PrivateVirtualIP: false,
		Layer3Networking: false,
	}
}

// ListImages ...
func (p provider) ListImages(all bool) ([]abstract.Image, fail.Error) {
	return p.Stack.(api.ReservedForProviderUse).ListImages()
}

// ListTemplates ...
func (p provider) ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error) {
	return p.Stack.(api.ReservedForProviderUse).ListTemplates()
}

// TODO: init when finished
func init() {
	iaas.Register("outscale", &provider{})
}
