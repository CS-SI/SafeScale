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

package terraformer // Package terraform contains the implemenation of a stack using terraform to request providers

import (
	"golang.org/x/net/context"

	stackoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// stack contains the needs to operate on stack OpenStack
type stack struct {
	// ComputeClient  *gophercloud.ServiceClient
	// NetworkClient  *gophercloud.ServiceClient
	// VolumeClient   *gophercloud.ServiceClient
	// IdentityClient *gophercloud.ServiceClient
	// Driver         *gophercloud.ProviderClient

	authOpts stackoptions.Authentication
	cfgOpts  stackoptions.Configuration

	// DefaultSecurityGroupName is the name of the default security groups
	DefaultSecurityGroupName string
	// // // DefaultSecurityGroupDescription contains a description for the default security groups
	// // DefaultSecurityGroupDescription string
	// // // SecurityGroup is an instance of the default security group
	// SecurityGroup     *abstract.SecurityGroup
	// ProviderNetworkID string

	// // versions contains the last version supported for each service
	// versions map[string]string

	// selectedAvailabilityZone contains the last selected availability zone chosen
	selectedAvailabilityZone string

	*temporal.MutableTimings
}

// NullStack returns a null value of the stack
func NullStack() *stack { // nolint
	return &stack{}
}

// New authenticates and returns a stack pointer
func New(auth stackoptions.Authentication, cfg stackoptions.Configuration) (*stack, fail.Error) { // nolint
	ctx := context.Background()
	_ = ctx

	if auth.DomainName == "" && auth.DomainID == "" {
		auth.DomainName = "Default"
	}

	return nil, fail.NotImplementedError()

	/*
		if cfg.DefaultSecurityGroupName == "" {
			cfg.DefaultSecurityGroupName = defaultSecurityGroupName
		}

		s := &stack{
			DefaultSecurityGroupName: cfg.DefaultSecurityGroupName,

			authOpts: auth,
			cfgOpts:  cfg,
		}

		// Get provider network ID from network service
		if cfg.ProviderNetwork != "" {
			xerr = stacks.RetryableRemoteCall(ctx,
				func() error {
					var innerErr error
					s.ProviderNetworkID, innerErr = getIDFromName(s.NetworkClient, cfg.ProviderNetwork)
					return innerErr
				},
				NormalizeError,
			)
			if xerr != nil {
				return nil, xerr
			}
		}

		// TODO: should be moved on iaas.factory.go to apply on all providers (if the provider proposes AZ)
		validAvailabilityZones, xerr := s.ListAvailabilityZones(ctx)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
				debug.IgnoreError(xerr)
			default:
				return nil, xerr
			}
		} else if len(validAvailabilityZones) != 0 {
			var validZones []string
			zoneIsValidInput := false
			for az, valid := range validAvailabilityZones {
				if valid {
					if az == auth.AvailabilityZone {
						zoneIsValidInput = true
					}
					validZones = append(validZones, `'`+az+`'`)
				}
			}
			if !zoneIsValidInput {
				return nil, fail.InvalidRequestError("invalid Availability zone '%s', valid zones are %s", auth.AvailabilityZone, strings.Join(validZones, ","))
			}
		}

		// Note: If timeouts and/or delays have to be adjusted, do it here in stack.timeouts and/or stack.delays
		if cfg.Timings != nil {
			s.MutableTimings = cfg.Timings
			_ = s.MutableTimings.Update(temporal.NewTimings())
		} else {
			s.MutableTimings = temporal.NewTimings()
		}

		return s, nil
	*/
}

// IsNull ...
func (s *stack) IsNull() bool {
	return s == nil // || s.Driver == nil
}

// GetStackName returns the name of the stack
func (s stack) GetStackName() (string, fail.Error) {
	return "terraform", nil
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
