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

package gcp

import (
	"context"
	"encoding/json"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// stack ...
type stack struct {
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
	GcpConfig   *stacks.GCPConfiguration

	ComputeService *compute.Service

	selfLinkPrefix string
}

// NullStack is not exposed through API, is needed essentially by testss
func NullStack() *stack {
	return &stack{}
}

func (s *stack) IsNull() bool {
	return s == nil || s.ComputeService == nil
}

// GetConfigurationOptions ...
func (s stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	if s.IsNull() || s.Config == nil {
		return stacks.ConfigurationOptions{}
	}
	return *s.Config
}

// GetAuthenticationOptions ...
func (s stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	if s.IsNull() || s.AuthOptions == nil {
		return stacks.AuthenticationOptions{}
	}
	return *s.AuthOptions
}

// New Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.GCPConfiguration, cfg stacks.ConfigurationOptions) (*stack, fail.Error) {
	gcpStack := &stack{
		Config:      &cfg,
		AuthOptions: &auth,
		GcpConfig:   &localCfg,
	}

	d1, err := json.MarshalIndent(localCfg, "", "  ")
	if err != nil {
		return &stack{}, fail.ToError(err)
	}

	cred, err := google.CredentialsFromJSON(context.Background(), d1, iam.CloudPlatformScope)
	if err != nil {
		return &stack{}, fail.ToError(err)
	}

	gcpStack.ComputeService, err = compute.NewService(context.Background(), option.WithTokenSource(cred.TokenSource))
	if err != nil {
		return &stack{}, fail.ToError(err)
	}

	gcpStack.selfLinkPrefix = `https://www.googleapis.com/compute/v1/projects/` + localCfg.ProjectID
	// gcpStack.searchPrefix = `.*/projects/` + localCfg.ProjectID + `/global`

	return gcpStack, nil
}
