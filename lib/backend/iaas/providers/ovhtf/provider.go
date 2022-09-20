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
	stackoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/terraformer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	providerName      = "ovhtf"
	ovhDefaultImage   = "Ubuntu 20.04"
	configSnippetPath = "snippets/provider_ovh.tf.template"
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
	capabilities = providers.Capabilities{
		UseTerraformer:   true,
		PrivateVirtualIP: true,
	}

	terraformProviders = []terraformer.RequiredProvider{
		{
			Source:  "",
			Version: "",
		},
		{
			Source:  "",
			Version: "",
		},
	}

	identityEndpoint = "https://auth.cloud.ovh.net/v3"
	externalNetwork  = "Ext-Net"
	dnsServers       = []string{"213.186.33.99", "1.1.1.1"}

	//go:embed snippets
	snippets embed.FS // contains embedded files used by the provider for any purpose
)

// provider is the provider implementation of the OVH provider
type provider struct {
	// stacks.Stack
	summoner          terraformer.Summoner
	ExternalNetworkID string

	// FIXME: move these fields in a provider Core?
	authOptions   stackoptions.Authentication
	configOptions stackoptions.Configuration

	tenantParameters map[string]interface{}
	*temporal.MutableTimings
}

func (p provider) GetStackName() (string, fail.Error) {
	return "terraformer", nil
}

// IsNull returns true if the instance is considered as a null value
func (p *provider) IsNull() bool {
	return p == nil // || p.Stack == nil
}

// BuildWithTerraformer needs to be called when terraformer is used
func (p *provider) BuildWithTerraformer(params map[string]any, config terraformer.Configuration) (providers.Provider, fail.Error) {
	out, xerr := (&provider{}).build(params)
	if xerr != nil {
		return nil, xerr
	}

	// Initialize a terraformer Summoner to handle resources
	out.summoner, xerr = terraformer.NewSummoner(out, config)
	if xerr != nil {
		return nil, xerr
	}

	return remediatize(out), nil
}

// Build builds a new instance of Ovh using configuration parameters
// Can be called from nil
func (p *provider) Build(params map[string]interface{}) (providers.Provider, fail.Error) {
	root, xerr := p.build(params)
	if xerr != nil {
		return nil, xerr
	}

	return remediatize(root), nil
}

// remediatize wraps a provider inside a providers.Remediator to filter potential panics
func remediatize(provider *provider) providers.Provider {
	out := providers.Remediator{
		Provider: provider,
		Name:     provider.Name(),
	}
	return out
}

// build constructs a new instance of provider accordingly parameterized
func (p *provider) build(params map[string]any) (*provider, fail.Error) {
	var validInput bool

	identityParams, _ := params["identity"].(map[string]any) // nolint
	compute, _ := params["compute"].(map[string]any)         // nolint
	// networkParams, _ := params["network"].(map[string]any) // nolint
	specificParams, _ := params["specific"].(map[string]any)
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

	var (
		alternateAPIApplicationKey    string
		alternateAPIApplicationSecret string
		alternateAPIConsumerKey       string
	)
	val1, ok1 := specificParams["AlternateApiApplicationKey"]
	val2, ok2 := specificParams["AlternateApiApplicationSecret"]
	val3, ok3 := specificParams["AlternateApiConsumerKey"]
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

	authOptions := stackoptions.Authentication{
		IdentityEndpoint: identityEndpoint,
		Username:         openstackID,
		Password:         openstackPassword,
		TenantID:         applicationKey,
		TenantName:       projectName,
		Region:           region,
		AvailabilityZone: zone,
		AllowReauth:      true,
		// AK:               alternateAPIApplicationKey,
		// AS:               alternateAPIApplicationSecret,
		// CK:               alternateAPIConsumerKey,
		Specific: OVHAPI{
			ApplicationKey:    alternateAPIApplicationKey,
			ApplicationSecret: alternateAPIApplicationSecret,
			ConsumerKey:       alternateAPIConsumerKey,
		},
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
	cfgOptions := stackoptions.Configuration{
		ProviderNetwork:           externalNetwork,
		UseFloatingIP:             false,
		UseLayer3Networking:       false,
		AutoHostNetworkInterfaces: false,
		DNSServers:                dnsServers,
		VolumeSpeeds: map[string]volumespeed.Enum{
			"classic":    volumespeed.Cold,
			"high-speed": volumespeed.Hdd,
		},
		MetadataBucketName:       metadataBucketName,
		OperatorUsername:         operatorUsername,
		ProviderName:             providerName,
		DefaultSecurityGroupName: "default",
		DefaultImage:             defaultImage,
		MaxLifeTime:              maxLifeTime,
		Timings:                  timings,
	}

	// serviceVersions := map[string]string{"volume": "v2"}

	// stack, xerr := openstack.New(authOptions, nil, cfgOptions, serviceVersions)
	// if xerr != nil {
	// 	return nil, xerr
	// }

	// Note: if timings have to be tuned, update stack.MutableTimings
	//
	// wrapped := stacks.Remediator{
	// 	Stack: stack,
	// 	Name:      providerName,
	// }

	out := &provider{
		// Stack:            wrapped,
		tenantParameters: params,
		authOptions:      authOptions,
		configOptions:    cfgOptions,
	}
	return out, nil
}

// Name returns the name of the driver
func (p provider) Name() string {
	return providerName
}

// GetName is an alias to Name() (compatibility with legacy drivers)
func (p provider) GetName() (string, fail.Error) {
	return p.Name(), nil
}

// GetStack returns the stack object used by the provider
// Note: use with caution, last resort option
func (p provider) GetStack() (stacks.Stack, fail.Error) {
	return nil, nil //p.Stack, nil
}

func (p provider) TenantParameters() (map[string]interface{}, fail.Error) {
	if valid.IsNil(p) {
		return map[string]interface{}{}, fail.InvalidInstanceError()
	}
	return p.tenantParameters, nil
}

// Capabilities returns the capabilities of the provider
func (p provider) Capabilities() providers.Capabilities {
	return capabilities
}

func (p provider) EmbeddedFS() embed.FS {
	return snippets
}

func (p provider) Snippet() string {
	return configSnippetPath
}

func (p provider) Terraformer() terraformer.Summoner {
	return p.summoner
}

func (p *provider) AuthenticationOptions() (stackoptions.Authentication, fail.Error) {
	if valid.IsNull(p) {
		return stackoptions.Authentication{}, fail.InvalidInstanceError()
	}

	return p.authOptions, nil
}

func (p *provider) ConfigurationOptions() (stackoptions.Configuration, fail.Error) {
	if valid.IsNull(p) {
		return stackoptions.Configuration{}, fail.InvalidInstanceError()
	}

	p.configOptions.ProviderName = providerName
	return p.configOptions, nil
}

// Timings returns the instance containing current timeout settings
func (p *provider) Timings() (temporal.Timings, fail.Error) {
	if valid.IsNull(p) {
		return temporal.NewTimings(), fail.InvalidInstanceError()
	}

	if p.MutableTimings == nil {
		p.MutableTimings = temporal.NewTimings()
	}
	return p.MutableTimings, nil
}

func (p *provider) UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	return fail.NotImplementedError()
}

func (p *provider) DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	return fail.NotImplementedError()
}

func init() {
	profile := providers.NewProfile(
		capabilities,
		func() providers.Provider { return &provider{} },
		terraformProviders,
	)
	iaas.Register(providerName, profile)
}
