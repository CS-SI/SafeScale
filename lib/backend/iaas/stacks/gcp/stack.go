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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
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
func (s stack) GetRawConfigurationOptions(context.Context) (stacks.ConfigurationOptions, fail.Error) {
	if valid.IsNil(s) || s.Config == nil {
		return stacks.ConfigurationOptions{}, fail.InvalidInstanceError()
	}
	return *s.Config, nil
}

// GetRawAuthenticationOptions ...
func (s stack) GetRawAuthenticationOptions(context.Context) (stacks.AuthenticationOptions, fail.Error) {
	if valid.IsNil(s) || s.AuthOptions == nil {
		return stacks.AuthenticationOptions{}, fail.InvalidInstanceError()
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

	// Note: If timeouts and/or delays have to be adjusted, do it here in stack.timeouts and/or stack.delays
	if cfg.Timings != nil {
		gcpStack.MutableTimings = cfg.Timings
		_ = gcpStack.MutableTimings.Update(temporal.NewTimings())
	} else {
		gcpStack.MutableTimings = temporal.NewTimings()
	}

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

func (s *stack) UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	xerr := s.rpcCreateTags(ctx, id, lmap)
	if xerr != nil {
		return xerr
	}

	xerr = s.rpcCreateLabels(ctx, id, lmap)
	return xerr
}

func (s *stack) DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error {
	if kind != abstract.HostResource {
		return fail.NotImplementedError("Tagging resources other than hosts not implemented yet")
	}

	xerr := s.rpcRemoveTagsFromInstance(ctx, id, keys)
	if xerr != nil {
		return xerr
	}

	xerr = s.rpcRemoveLabels(ctx, id, keys)
	if xerr != nil {
		return xerr
	}

	return nil
}
