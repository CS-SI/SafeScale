// +build ignore
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
 *
 */

package vclouddirector

import (
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"net/url"

	"github.com/CS-SI/SafeScale/lib/utils/fail"

	"github.com/vmware/go-vcloud-director/govcd"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
)

type stack struct {
	EbrcService *govcd.VCDClient
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
}

// IsNull tells if the instance corresponds to null value
func (s *stack) IsNull() bool {
	return s == nil || s.EbrcService == nil
}

// GetConfigurationOptions ...
func (s stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	if s.IsNull() {
		return stacks.ConfigurationOptions{}
	}
	return *s.Config
}

// GetAuthenticationOptions ...
func (s stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	if s.IsNull() {
		return stacks.AuthenticationOptions{}
	}
	return *s.AuthOptions
}

// NullStacks returns a null value of the stack
func NullStack() *stack {
	return &stack{}
}

// New creates and initializes a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.VCloudConfigurationOptions, cfg stacks.ConfigurationOptions) (api.Stack, fail.Error) {
	stack := &stack{
		Config:      &cfg,
		AuthOptions: &auth,
	}

	u, err := url.ParseRequestURI(auth.IdentityEndpoint)
	if err != nil {
		return nil, fail.NewError("unable to pass url")
	}

	vcdclient := govcd.NewVCDClient(*u, localCfg.Insecure)
	err = vcdclient.Authenticate(auth.Username, auth.Password, auth.ProjectName)
	if err != nil {
		return nil, fail.Wrap(normalizeError(err), "Unable to authenticate")
	}
	stack.EbrcService = vcdclient

	return stack, nil
}
