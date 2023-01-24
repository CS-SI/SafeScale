/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package outscale // Package outscale contains stack implementation for Outscale

import (
	"context"
	"fmt"
	"time"

	"github.com/outscale/osc-sdk-go/osc"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/volumespeed"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Credentials outscale credentials
type Credentials struct {
	AccessKey string
	SecretKey string
}

// ComputeConfiguration outscale compute configuration
type ComputeConfiguration struct {
	URL                string
	Region             string
	Subregion          string
	Service            string
	DefaultImage       string
	DefaultVolumeSpeed volumespeed.Enum
	DefaultTenancy     string
	DNSList            []string
	OperatorUsername   string
	Safe               bool
}

// NetworkConfiguration Outscale network configuration
type NetworkConfiguration struct {
	DefaultNetworkName string
	DefaultNetworkCIDR string
}

// StorageConfiguration Outscale storage configuration
type StorageConfiguration struct {
	Type      string
	Endpoint  string
	AccessKey string
	SecretKey string
}

// MetadataConfiguration metadata storage configuration
type MetadataConfiguration struct {
	Type      string
	Endpoint  string
	AccessKey string
	SecretKey string
	Bucket    string
	CryptKey  string
}

// ConfigurationOptions outscale stack configuration options
type ConfigurationOptions struct {
	Identity      Credentials           `json:"identity,omitempty"`
	Compute       ComputeConfiguration  `json:"compute,omitempty"`
	Network       NetworkConfiguration  `json:"network,omitempty"`
	ObjectStorage StorageConfiguration  `json:"objectstorage,omitempty"`
	Metadata      MetadataConfiguration `json:"metadata,omitempty"`
	Timings       *temporal.MutableTimings
}

// stack implements Outscale IaaS API
type stack struct {
	Options              ConfigurationOptions
	client               *osc.APIClient
	auth                 context.Context
	CPUPerformanceMap    map[int]float32
	VolumeSpeedsMap      map[string]volumespeed.Enum
	configurationOptions *iaasoptions.Configuration
	deviceNames          []string
	templates            []*abstract.HostTemplate
	vpc                  *abstract.Network

	*temporal.MutableTimings
}

// NullStack returns a null value of the stack
func NullStack() *stack { // nolint
	return &stack{}
}

// GetStackName returns the name of the stack
func (instance *stack) GetStackName() (string, fail.Error) {
	return "outscale", nil
}

// New creates a new stack
func New(options *ConfigurationOptions) (_ *stack, ferr fail.Error) { // nolint
	if options == nil {
		return nil, fail.InvalidParameterCannotBeNilError("options")
	}

	tracer := debug.NewTracer(context.Background(), tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()

	config := osc.NewConfiguration()
	config.BasePath = options.Compute.URL
	config.Scheme = "https"
	client := osc.NewAPIClient(config)
	auth := context.WithValue(context.Background(), osc.ContextAWSv4, osc.AWSv4{
		AccessKey: options.Identity.AccessKey,
		SecretKey: options.Identity.SecretKey,
	})
	volumeSpeeds := map[string]volumespeed.Enum{
		"standard": volumespeed.Cold,
		"gp2":      volumespeed.Hdd,
		"io1":      volumespeed.Ssd,
	}
	s := stack{
		Options:         *options,
		client:          client,
		VolumeSpeedsMap: volumeSpeeds,
		CPUPerformanceMap: map[int]float32{
			1: 3.0,
			2: 2.5,
			3: 2.0,
		},
		deviceNames: deviceNames(),
		configurationOptions: &iaasoptions.Configuration{
			ProviderNetwork:           "",
			DNSServers:                options.Compute.DNSList,
			UseFloatingIP:             true,
			UseLayer3Networking:       false,
			UseNATService:             false,
			ProviderName:              "outscale",
			BuildSubnets:              false,
			AutoHostNetworkInterfaces: false,
			VolumeSpeeds:              volumeSpeeds,
			DefaultImage:              options.Compute.DefaultImage,
			MetadataBucketName:        options.Metadata.Bucket,
			OperatorUsername:          options.Compute.OperatorUsername,
			// BlacklistImageRegexp:      options.Compute.BlacklistImageRegexp,
			// BlacklistTemplateRegexp:   options.Compute.BlacklistTemplateRegexp,
			// WhitelistImageRegexp:      options.Compute.WhitelistImageRegexp,
			// WhitelistTemplateRegexp:   options.Compute.WhitelistTemplateRegexp,
			Timings: options.Timings,
		},
		auth: auth,
	}
	s.buildTemplateList()

	// Note: If timeouts and/or delays have to be adjusted, do it here in stack.timeouts and/or stack.delays
	if options.Timings != nil {
		s.MutableTimings = options.Timings
		_ = s.MutableTimings.Update(temporal.NewTimings())
	} else {
		// outscale needs more time
		s.MutableTimings = temporal.NewTimings() // take default timings, but...
	}

	// change a few things
	s.MutableTimings.HostOperation = temporal.MaxTimeout(20*time.Minute, s.MutableTimings.HostOperation)
	s.MutableTimings.HostCreation = temporal.MaxTimeout(20*time.Minute, s.MutableTimings.HostCreation)
	s.MutableTimings.SSHConnection = temporal.MaxTimeout(20*time.Minute, s.MutableTimings.SSHConnection)
	s.MutableTimings.Operation = temporal.MaxTimeout(20*time.Minute, s.MutableTimings.Operation)

	return &s, s.initDefaultNetwork(context.Background()) // FIXME: Verify this
}

// IsNull tells if the instance is a null value of stack
func (s *stack) IsNull() bool {
	return s == nil || s.client == nil
}

// initDefaultNetwork() initializes the instance of the Network/VPC if one is defined in tenant
func (s *stack) initDefaultNetwork(ctx context.Context) fail.Error {
	if s.vpc == nil && s.Options.Network.DefaultNetworkName != "" {
		an, xerr := s.InspectNetworkByName(ctx, s.Options.Network.DefaultNetworkName)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// VPC not found, create it
				if s.Options.Network.DefaultNetworkCIDR == "" {
					s.Options.Network.DefaultNetworkCIDR = stacks.DefaultNetworkCIDR
				}
				req := abstract.NetworkRequest{
					Name: s.Options.Network.DefaultNetworkName,
					CIDR: s.Options.Network.DefaultNetworkCIDR,
				}
				an, xerr = s.CreateNetwork(ctx, req)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to initialize default Network '%s'", s.Options.Network.DefaultNetworkName)
				}
			default:
				return xerr
			}
		}

		s.vpc = an
	}
	return nil
}

func deviceNames() []string {
	var deviceNames []string
	for i := int('d') - int('a'); i <= int('z')-int('a'); i++ {
		deviceNames = append(deviceNames, fmt.Sprintf("xvd%s", string('a'+rune(i))))
	}
	return deviceNames
}

// ListRegions list available regions
func (instance *stack) ListRegions(ctx context.Context) (_ []string, ferr fail.Error) {
	if valid.IsNil(instance) {
		return []string{}, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, _, err := instance.client.RegionApi.ReadRegions(instance.auth, nil)
	if err != nil {
		return []string{}, normalizeError(err)
	}

	var regions []string
	for _, r := range resp.Regions {
		regions = append(regions, r.RegionName)
	}

	return regions, nil
}

// ListAvailabilityZones returns availability zone in a set
func (instance *stack) ListAvailabilityZones(ctx context.Context) (az map[string]bool, ferr fail.Error) {
	emptyMap := make(map[string]bool)
	if valid.IsNil(instance) {
		return emptyMap, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stacks.outscale")).WithStopwatch().Entering()
	defer tracer.Exiting()

	resp, _, err := instance.client.SubregionApi.ReadSubregions(instance.auth, nil)
	if err != nil {
		return emptyMap, normalizeError(err)
	}

	az = make(map[string]bool, len(resp.Subregions))
	for _, r := range resp.Subregions {
		az[r.SubregionName] = true
	}
	return az, nil
}

// Timings returns the instance containing current timeout settings
func (s *stack) Timings() (temporal.Timings, fail.Error) {
	if s == nil {
		return temporal.NewTimings(), fail.InvalidInstanceError()
	}
	if s.MutableTimings == nil {
		s.MutableTimings = temporal.NewTimings()
	}
	return s.MutableTimings, nil
}

func (s *stack) UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	_, xerr := s.rpcCreateTags(ctx, id, lmap)
	return xerr
}

func (s *stack) DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error {
	if s == nil {
		return fail.InvalidInstanceError()
	}

	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	report := make(map[string]string)
	for _, k := range keys {
		report[k] = ""
	}

	xerr := s.rpcDeleteTags(ctx, id, report)
	return xerr
}
