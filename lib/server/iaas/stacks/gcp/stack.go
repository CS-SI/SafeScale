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

package gcp

import (
	"context"
	"encoding/json"

	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
)

// stack ...
type stack struct {
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
	GcpConfig   *stacks.GCPConfiguration

	ComputeService *compute.Service

	selfLinkPrefix string

	*temporal.MutableTimings
}

// NullStack is not exposed through API, is needed essentially by tests
func NullStack() *stack { // nolint
	return &stack{}
}

func (s *stack) IsNull() bool {
	return s == nil || s.ComputeService == nil
}

// GetStackName returns the name of the stack
func (s stack) GetStackName() (string, fail.Error) {
	return "gcp", nil
}

// GetRawConfigurationOptions ...
func (s stack) GetRawConfigurationOptions() (stacks.ConfigurationOptions, fail.Error) {
	if valid.IsNil(s) || s.Config == nil {
		return stacks.ConfigurationOptions{}, nil
	}
	return *s.Config, nil
}

// GetRawAuthenticationOptions ...
func (s stack) GetRawAuthenticationOptions() (stacks.AuthenticationOptions, fail.Error) {
	if valid.IsNil(s) || s.AuthOptions == nil {
		return stacks.AuthenticationOptions{}, nil
	}
	return *s.AuthOptions, nil
}

// New Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.GCPConfiguration, cfg stacks.ConfigurationOptions) (*stack, fail.Error) { // nolint
	gcpStack := &stack{
		Config:      &cfg,
		AuthOptions: &auth,
		GcpConfig:   &localCfg,
	}

	d1, err := json.MarshalIndent(localCfg, "", "  ")
	if err != nil {
		return &stack{}, fail.ConvertError(err)
	}

	cred, err := google.CredentialsFromJSON(context.Background(), d1, iam.CloudPlatformScope)
	if err != nil {
		return &stack{}, fail.ConvertError(err)
	}

	gcpStack.ComputeService, err = compute.NewService(context.Background(), option.WithTokenSource(cred.TokenSource))
	if err != nil {
		return &stack{}, fail.ConvertError(err)
	}

	gcpStack.selfLinkPrefix = `https://www.googleapis.com/compute/v1/projects/` + localCfg.ProjectID
	// gcpStack.searchPrefix = `.*/projects/` + localCfg.ProjectID + `/global`

	gcpStack.MutableTimings = temporal.NewTimings()
	// Note: If timeouts and/or delays have to be adjusted, do it here in stack.timeouts and/or stack.delays

	return gcpStack, nil
}

// Timings returns the instance containing current timing (timeouts, delays) settings
func (s *stack) Timings() (temporal.Timings, fail.Error) {
	if s == nil {
		return temporal.NewTimings(), fail.InvalidInstanceError()
	}
	if s.MutableTimings == nil {
		s.MutableTimings = temporal.NewTimings()
	}
	return s.MutableTimings, nil
}
