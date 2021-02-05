/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/iaas/abstract/enums/volumespeed"
	"github.com/CS-SI/SafeScale/lib/server/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/lib/server/iaas/providers"
	apiprovider "github.com/CS-SI/SafeScale/lib/server/iaas/providers/api"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/outscale"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// OutscaleProvider safescale integration of outscale IaaS API
// see https://docs.outscale.com/api
type provider struct {
	outscale.Stack

	tenantParameters map[string]interface{}
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
	if s == "SSD" {
		return volumespeed.SSD
	}
	return volumespeed.HDD

}

func (p *provider) Build(opt map[string]interface{}) (apiprovider.Provider, error) {
	if p == nil {
		return nil, fail.InvalidInstanceError()
	}
	identity := remap(opt["identity"])
	compute := remap(opt["compute"])
	metadata := remap(opt["metadata"])
	network := remap(opt["network"])
	objstorage := remap(opt["objectstorage"])

	region := get(compute, "Region")
	if region == "" {
		return nil, fail.Errorf("'Region' parameter in section 'compute' of the tenant is mandatory", nil)
	}
	if _, ok := metadata["Bucket"]; !ok {
		stackName := get(identity, "provider")
		userID := get(identity, "UserID")
		if userID == "" {
			return nil, fail.Errorf("'UserID' parameter in section 'identity' of the tenant is mandatory", nil)
		}
		var err error
		metadata["Bucket"], err = objectstorage.BuildMetadataBucketName(stackName, region, "", userID)
		if err != nil {
			return nil, err
		}
	}

	providerName := "outscale"

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
			MaxLifetimeInHours:      get(compute, "MaxLifetimeInHours", "0"),
			BlacklistImageRegexp:    regexp.MustCompile(get(compute, "BlacklistImageRegexp")),
			BlacklistTemplateRegexp: regexp.MustCompile(get(compute, "BlacklistTemplateRegexp")),
			WhitelistImageRegexp:    regexp.MustCompile(get(compute, "WhitelistImageRegexp")),
			WhitelistTemplateRegexp: regexp.MustCompile(get(compute, "WhitelistTemplateRegexp")),
		},
		Network: outscale.NetworConfiguration{
			VPCCIDR: get(network, "VPCCIDR", "192.168.0.0/16"),
			VPCID:   get(network, "VPCID"),
			VPCName: get(network, "VPCName", "safecale-vpc"),
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
			Endpoint: get(
				metadata, "Endpoint",
				get(objstorage, "Endpoint", fmt.Sprintf("https://osu.%s.outscale.com", get(compute, "Region"))),
			),
			Type:     get(metadata, "Type", get(objstorage, "Type", "s3")),
			Bucket:   get(metadata, "Bucket", "0.safescale"),
			CryptKey: get(metadata, "CryptKey", "safescale"),
		},
	}

	stack, err := outscale.New(options)
	if err != nil {
		return nil, err
	}

	p.Stack = *stack
	p.tenantParameters = opt

	evalid := apiprovider.NewValidatedProvider(p, providerName)
	etrace := apiprovider.NewErrorTraceProvider(evalid, providerName)
	prov := apiprovider.NewLoggedProvider(etrace, providerName)

	return prov, nil
}

// GetAuthenticationOptions returns authentication parameters
func (p *provider) GetAuthenticationOptions() (providers.Config, error) {
	if p == nil {
		return nil, fail.InvalidInstanceError()
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
		return nil, fail.InvalidInstanceError()
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
	cfg.Set("MaxLifetimeInHours", p.Options.Compute.MaxLifetimeInHours)

	return cfg, nil
}

// GetName returns the provider name
func (p *provider) GetName() string {
	return "outscale"
}

// GetTenantParameters returns the tenant parameters as-is
func (p *provider) GetTenantParameters() map[string]interface{} {
	return p.tenantParameters
}

// GetCapabilities returns the capabilities of the provider
func (p *provider) GetCapabilities() providers.Capabilities {
	return providers.Capabilities{
		PublicVirtualIP:  false,
		PrivateVirtualIP: true,
		Layer3Networking: false,
	}
}

func init() {
	iaas.Register("outscale", &provider{})
}
