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

package ovhtf

import (
	"context"
	"embed"
	"regexp"
	"strconv"
	"strings"

	validation "github.com/go-ozzo/ozzo-validation/v4"
	"github.com/mitchellh/mapstructure"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/openstack"
	stackoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	providerName    = "ovhtf"
	ovhDefaultImage = "Ubuntu 20.04"
)

type gpuCfg struct {
	GPUNumber int
	GPUType   string
}

var gpuMap = map[string]gpuCfg{
	"g2-15": {
		GPUNumber: 1,
		GPUType:   "NVIDIA 1070",
	},
	"g2-30": {
		GPUNumber: 1,
		GPUType:   "NVIDIA 1070",
	},
	"g3-120": {
		GPUNumber: 3,
		GPUType:   "NVIDIA 1080 TI",
	},
	"g3-30": {
		GPUNumber: 1,
		GPUType:   "NVIDIA 1080 TI",
	},
}

var (
	identityEndpoint = "https://auth.cloud.ovh.net/v3"
	externalNetwork  = "Ext-Net"
	dnsServers       = []string{"213.186.33.99", "1.1.1.1"}
)

// provider is the provider implementation of the OVH provider
type provider struct {
	// stacks.Stack
	ExternalNetworkID string

	// go:embed snippets
	efs embed.FS // contains embedded files used by the provider for any purpose

	tenantParameters  map[string]interface{}
	authOptions       stackoptions.AuthenticationOptions
	configOptions     stackoptions.ConfigurationOptions
	configSnippetPath string // contains the path of the provider configuration configSnippetPath in efs
	tfWorkdir         string // contains the target work dir for terraform

}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil // || p.Stack == nil
}

// Build builds a new instance of Ovh using configuration parameters
// Can be called from nil
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	var validInput bool

	identityParams, _ := params["identity"].(map[string]interface{}) // nolint
	compute, _ := params["compute"].(map[string]interface{})         // nolint
	// networkParams, _ := params["network"].(map[string]interface{}) // nolint

	applicationKey, _ := identityParams["ApplicationKey"].(string)       // nolint
	openstackID, _ := identityParams["OpenstackID"].(string)             // nolint
	openstackPassword, _ := identityParams["OpenstackPassword"].(string) // nolint
	region, _ := compute["Region"].(string)                              // nolint
	zone, ok := compute["AvailabilityZone"].(string)
	if !ok {
		zone = "nova"
	}

	customDNS, _ := compute["DNS"].(string) // nolint
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

	projectName, validInput := compute["ProjectName"].(string)
	if !validInput {
		return nil, fail.NewError("Invalid input for 'ProjectName'")
	}

	var alternateAPIApplicationKey string
	var alternateAPIApplicationSecret string
	var alternateAPIConsumerKey string
	val1, ok1 := identityParams["AlternateApiApplicationKey"]
	val2, ok2 := identityParams["AlternateApiApplicationSecret"]
	val3, ok3 := identityParams["AlternateApiConsumerKey"]
	if ok1 && ok2 && ok3 {
		alternateAPIApplicationKey, validInput = val1.(string)
		if !validInput {
			return nil, fail.NewError("Invalid input for 'AlternateApiApplicationKey'")
		}
		alternateAPIApplicationSecret, validInput = val2.(string)
		if !validInput {
			return nil, fail.NewError("Invalid input for 'AlternateApiApplicationSecret'")
		}
		alternateAPIConsumerKey, validInput = val3.(string)
		if !validInput {
			return nil, fail.NewError("Invalid input for 'AlternateApiConsumerKey'")
		}
	}

	operatorUsername := abstract.DefaultUser
	if operatorUsernameIf, there := compute["OperatorUsername"]; there {
		operatorUsername, ok = operatorUsernameIf.(string)
		if !ok {
			return nil, fail.InconsistentError("'OperatorUsername' should be a string")
		}
		if operatorUsername == "" {
			logrus.WithContext(context.Background()).Warnf("OperatorUsername is empty ! Check your tenants.toml file ! Using 'safescale' user instead.")
			operatorUsername = abstract.DefaultUser
		}
	}

	defaultImage, ok := compute["DefaultImage"].(string)
	if !ok {
		defaultImage = ovhDefaultImage
	}

	maxLifeTime := 0
	if _, ok = compute["MaxLifetimeInHours"].(string); ok {
		maxLifeTime, _ = strconv.Atoi(compute["MaxLifetimeInHours"].(string))
	}

	authOptions := stackoptions.AuthenticationOptions{
		IdentityEndpoint: identityEndpoint,
		Username:         openstackID,
		Password:         openstackPassword,
		TenantID:         applicationKey,
		TenantName:       projectName,
		Region:           region,
		AvailabilityZone: zone,
		AllowReauth:      true,
		AK:               alternateAPIApplicationKey,
		AS:               alternateAPIApplicationSecret,
		CK:               alternateAPIConsumerKey,
	}

	err := validation.ValidateStruct(&authOptions,
		validation.Field(&authOptions.Region, validation.Required, validation.Match(regexp.MustCompile("^[-a-zA-Z0-9-_]+$"))),
		validation.Field(&authOptions.AvailabilityZone, validation.Required, validation.Match(regexp.MustCompile("^[-a-zA-Z0-9-_]+$"))),
	)
	if err != nil {
		return nil, fail.NewError("Structure validation failure: %v", err)
	}

	metadataBucketName, xerr := objectstorage.BuildMetadataBucketName(providerName, region, applicationKey, projectName)
	if xerr != nil {
		return nil, xerr
	}

	var timings *temporal.MutableTimings
	if tc, ok := params["timings"]; ok {
		if theRecoveredTiming, ok := tc.(map[string]interface{}); ok {
			s := &temporal.MutableTimings{}
			err := mapstructure.Decode(theRecoveredTiming, &s)
			if err != nil {
				goto next
			}
			timings = s
		}
	}
next:

	cfgOptions := stackoptions.ConfigurationOptions{
		ProviderNetwork:           externalNetwork,
		UseFloatingIP:             false,
		UseLayer3Networking:       false,
		AutoHostNetworkInterfaces: false,
		DNSList:                   dnsServers,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"classic":    volumespeed.Cold,
			"high-speed": volumespeed.Hdd,
		},
		MetadataBucket:           metadataBucketName,
		OperatorUsername:         operatorUsername,
		ProviderName:             providerName,
		DefaultSecurityGroupName: "default",
		DefaultImage:             defaultImage,
		MaxLifeTime:              maxLifeTime,
		Timings:                  timings,
	}

	serviceVersions := map[string]string{"volume": "v2"}

	stack, xerr := openstack.New(authOptions, nil, cfgOptions, serviceVersions)
	if xerr != nil {
		return nil, xerr
	}

	// Note: if timings have to be tuned, update stack.MutableTimings
	//
	// wrapped := stacks.Remediator{
	// 	FullStack: stack,
	// 	Name:      providerName,
	// }

	newP := &provider{
		// Stack:            wrapped,
		tenantParameters: params,
		authOptions:      authOptions,
		configOptions:    cfgOptions,
	}

	wp := providers.Remediator{
		Provider: newP,
		Name:     wrapped.Name,
	}

	return wp, nil
}

// GetAuthenticationOptions returns the auth options
func (p *provider) GetAuthenticationOptions(ctx context.Context) (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}
	if valid.IsNull(p) {
		return cfg, fail.InvalidInstanceError()
	}

	opts, err := p.Stack.(stacks.ReservedForProviderUse).GetRawAuthenticationOptions(ctx)
	if err != nil {
		return nil, err
	}
	cfg.Set("TenantName", opts.TenantName)
	cfg.Set("TenantID", opts.TenantID)
	cfg.Set("DomainName", opts.DomainName)
	cfg.Set("Login", opts.Username)
	cfg.Set("Password", opts.Password)
	cfg.Set("AuthURL", opts.IdentityEndpoint)
	cfg.Set("Region", opts.Region)
	cfg.Set("AlternateApiApplicationKey", opts.AK)
	cfg.Set("AlternateApiApplicationSecret", opts.AS)
	cfg.Set("AlternateApiConsumerKey", opts.CK)
	return cfg, nil
}

// GetConfigurationOptions return configuration parameters
func (p *provider) GetConfigurationOptions(ctx context.Context) (providers.Config, fail.Error) {
	cfg := providers.ConfigMap{}
	if valid.IsNull(p) {
		return cfg, fail.InvalidInstanceError()
	}

	opts, err := p.Stack.(stacks.ReservedForProviderUse).GetRawConfigurationOptions(ctx)
	if err != nil {
		return nil, err
	}

	cfg.Set("DNSList", opts.DNSList)
	cfg.Set("AutoHostNetworkInterfaces", opts.AutoHostNetworkInterfaces)
	cfg.Set("UseLayer3Networking", opts.UseLayer3Networking)
	cfg.Set("DefaultImage", opts.DefaultImage)
	cfg.Set("MetadataBucketName", opts.MetadataBucket)
	cfg.Set("OperatorUsername", opts.OperatorUsername)
	cfg.Set("ProviderName", providerName)
	cfg.Set("UseNATService", opts.UseNATService)
	cfg.Set("MaxLifeTimeInHours", opts.MaxLifeTime)

	return cfg, nil
}

// GetName returns the name of the driver
func (p *provider) GetName() (string, fail.Error) {
	if valid.IsNull(p) {
		return "", fail.InvalidInstanceError()
	}

	return providerName, nil
}

// GetStack returns the stack object used by the provider
// Note: use with caution, last resort option
func (p provider) GetStack() (stacks.Stack, fail.Error) {
	return p.Stack, nil
}

func (p provider) GetTenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNil(p) {
		return map[string]interface{}{}, fail.InvalidInstanceError()
	}
	return p.tenantParameters, nil
}

// GetCapabilities returns the capabilities of the provider
func (p provider) GetCapabilities(context.Context) (providers.Capabilities, fail.Error) {
	return providers.Capabilities{
		PrivateVirtualIP: true,
	}, nil
}

func (p provider) EmbeddedFS() embed.FS {
	return p.efs
}

func (p provider) Snippet() string {
	return p.configSnippetPath
}

func init() {
	iaas.Register(providerName, &provider{})
}
