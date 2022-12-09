/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/outscale"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"
)

const (
	outscaleDefaultImage = "Ubuntu 20.04"
)

//goland:noinspection GoPreferNilSlice
var (
	dnsServers = []string{}
)

// provider is integration of outscale IaaS API
// see https://docs.outscale.com/api
type provider struct {
	api.Stack

	tenantParameters map[string]interface{}
	templatesWithGPU []string
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
		if len(def) > 0 {
			return def[0]
		}
		return ""
	}
	return v.(string)
}

func getNotEmpty(m map[string]interface{}, key string, def ...string) string {
	v, ok := m[key]
	if ok {
		val, _ := v.(string) // nolint
		if val != "" {
			return val
		}
		return def[0]
	}

	if len(def) > 0 {
		return def[0]
	}

	panic("this kind of getters is bad for struct population")
}

func volumeSpeed(s string) volumespeed.Enum {
	switch s {
	case "Cold":
		return volumespeed.Cold
	case "Ssd":
		return volumespeed.Ssd
	default:
		return volumespeed.Hdd
	}
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil || p.Stack == nil
}

// Build builds a new Client from configuration parameter
func (p *provider) Build(opt map[string]interface{}) (_ providers.Provider, ferr fail.Error) {
	identity := remap(opt["identity"])
	compute := remap(opt["compute"])
	metadata := remap(opt["metadata"])
	network := remap(opt["network"])
	objstorage := remap(opt["objectstorage"])
	tc := remap(opt["timings"])

	region := get(compute, "Region")
	if region == "" {
		return nil, fail.SyntaxError("keyword 'Region' in section 'compute' not found in tenant file", nil, nil)
	}
	if _, ok := metadata["Bucket"]; !ok {
		stackName := get(identity, "provider")
		userID := get(identity, "UserID")
		if userID == "" {
			return nil, fail.SyntaxError("keyword 'UserID' in section 'identity' not found in tenant file")
		}

		var xerr fail.Error
		metadata["Bucket"], xerr = objectstorage.BuildMetadataBucketName(stackName, region, "", userID)
		if xerr != nil {
			return nil, xerr
		}
	}

	customDNS := get(compute, "DNS")
	if customDNS != "" {
		if strings.Contains(customDNS, ",") {
			fragments := strings.Split(customDNS, ",")
			for _, fragment := range fragments {
				fragment = strings.TrimSpace(fragment)
				if valid.IsIP(fragment) {
					dnsServers = append(dnsServers, fragment)
				}
			}
		} else {
			fragment := strings.TrimSpace(customDNS)
			if valid.IsIP(fragment) {
				dnsServers = append(dnsServers, fragment)
			}
		}
	}

	isSafe, ok := compute["Safe"].(bool) // nolint
	if !ok {
		isSafe = true
	}

	logrus.WithContext(context.Background()).Infof("Setting safety to: %t", isSafe)

	var timings *temporal.MutableTimings
	s := &temporal.MutableTimings{}
	err := mapstructure.Decode(tc, &s)
	if err != nil {
		goto next
	}
	timings = s
next:

	options := &outscale.ConfigurationOptions{
		Identity: outscale.Credentials{
			AccessKey: get(identity, "AccessKey"),
			SecretKey: get(identity, "SecretKey"),
		},
		Compute: outscale.ComputeConfiguration{
			URL:                get(compute, "URL", fmt.Sprintf("https://api.%s.outscale.com/api/v1", region)),
			Service:            get(compute, "Service", "api"),
			Region:             region,
			Subregion:          get(compute, "Subregion"),
			DNSList:            dnsServers,
			DefaultTenancy:     get(compute, "DefaultTenancy", "default"),
			DefaultImage:       getNotEmpty(compute, "DefaultImage", outscaleDefaultImage),
			DefaultVolumeSpeed: volumeSpeed(get(compute, "DefaultVolumeSpeed", "Hdd")),
			OperatorUsername:   get(compute, "OperatorUsername", "safescale"),
			Safe:               isSafe,
		},
		Network: outscale.NetworkConfiguration{
			DefaultNetworkCIDR: get(network, "DefaultNetworkCIDR", get(network, "VPCCIDR")),
			DefaultNetworkName: get(network, "DefaultNetworkName", get(network, "VPCName")),
		},
		ObjectStorage: outscale.StorageConfiguration{
			AccessKey: get(objstorage, "AccessKey", get(identity, "AccessKey")),
			SecretKey: get(objstorage, "SecretKey", get(identity, "SecretKey")),
			Endpoint:  get(objstorage, "Endpoint", fmt.Sprintf("https://oos.%s.outscale.com", get(compute, "Region"))),
			Type:      get(objstorage, "Type", "s3"),
		},
		Metadata: outscale.MetadataConfiguration{
			AccessKey: get(metadata, "AccessKey", get(objstorage, "AccessKey", get(identity, "AccessKey"))),
			SecretKey: get(metadata, "SecretKey", get(objstorage, "SecretKey", get(identity, "SecretKey"))),
			Endpoint: get(
				metadata, "Endpoint",
				get(objstorage, "Endpoint", fmt.Sprintf("https://oos.%s.outscale.com", get(compute, "Region"))),
			),
			Type:     get(metadata, "Type", get(objstorage, "Type", "s3")),
			Bucket:   get(metadata, "Bucket", "0.safescale"),
			CryptKey: get(metadata, "CryptKey", "safescale"),
		},
		Timings: timings,
	}

	stack, err := outscale.New(options)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	// Note: if timings have to be tuned, update stack.MutableTimings

	wrapped := api.StackProxy{
		FullStack: stack,
		Name:      "outscale",
	}

	p.Stack = wrapped
	p.tenantParameters = opt

	wp := providers.ProviderProxy{
		Provider: p,
		Name:     wrapped.Name,
	}

	return wp, nil
}

// GetAuthenticationOptions returns authentication parameters
func (p provider) GetAuthenticationOptions(ctx context.Context) (providers.Config, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	opts, err := p.Stack.(api.ReservedForProviderUse).GetRawAuthenticationOptions(ctx)
	if err != nil {
		return nil, err
	}

	cfg := providers.ConfigMap{}
	cfg.Set("AccessKey", opts.AccessKeyID)
	cfg.Set("SecretKey", opts.SecretAccessKey)
	cfg.Set("Region", opts.Region)
	cfg.Set("AuthURL", opts.IdentityEndpoint)
	return cfg, nil
}

// GetConfigurationOptions returns configuration parameters
func (p provider) GetConfigurationOptions(ctx context.Context) (providers.Config, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	opts, err := p.Stack.(api.ReservedForProviderUse).GetRawConfigurationOptions(ctx)
	if err != nil {
		return nil, err
	}

	provName, xerr := p.GetName()
	if xerr != nil {
		return nil, xerr
	}

	cfg := providers.ConfigMap{}
	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("ProviderName", provName)
	cfg.Set("BuildSubnets", opts.BuildSubnets)
	cfg.Set("UseNATService", opts.UseNATService)
	cfg.Set("MaxLifeTimeInHours", opts.MaxLifeTime)
	cfg.Set("Safe", opts.Safe)

	return cfg, nil
}

// GetName returns the provider name
func (p provider) GetName() (string, fail.Error) {
	return "outscale", nil
}

// GetStack returns the stack object used by the provider
// Note: use with caution, last resort option
func (p provider) GetStack() (api.Stack, fail.Error) {
	return p.Stack, nil
}

// GetTenantParameters returns the tenant parameters as-is
func (p provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNil(p) {
		return map[string]interface{}{}, fail.InvalidInstanceError()
	}
	return p.tenantParameters, nil
}

// GetCapabilities returns the capabilities of the provider
func (p provider) GetCapabilities(context.Context) (providers.Capabilities, fail.Error) {
	return providers.Capabilities{
		PublicVirtualIP:  false,
		PrivateVirtualIP: false,
		Layer3Networking: false,
	}, nil
}

// ListImages ...
func (p provider) ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error) {
	return p.Stack.(api.ReservedForProviderUse).ListImages(ctx, all)
}

// ListTemplates ...
func (p provider) ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) {
	return p.Stack.(api.ReservedForProviderUse).ListTemplates(ctx, all)
}

// GetRegexpsOfTemplatesWithGPU returns a slice of regexps corresponding to templates with GPU
func (p provider) GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}

	var (
		out []*regexp.Regexp
	)

	for _, v := range p.templatesWithGPU {
		re, err := regexp.Compile(v)
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		out = append(out, re)
	}

	return out, nil
}

func init() {
	iaas.Register("outscale", &provider{})
}
