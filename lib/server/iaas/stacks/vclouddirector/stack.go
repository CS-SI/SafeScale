// +build ignore
/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"net/url"

	"github.com/vmware/go-vcloud-director/govcd"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
)

type Stack struct {
	EbrcService *govcd.VCDClient
	Config      *stacks.ConfigurationOptions
	AuthOptions *stacks.AuthenticationOptions
}

func (s *Stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return *s.Config
}

func (s *Stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return *s.AuthOptions
}

// Build Create and initialize a ClientAPI
func New(auth stacks.AuthenticationOptions, localCfg stacks.VCloudConfigurationOptions, cfg stacks.ConfigurationOptions) (*Stack, fail.Error) {
	stack := &Stack{
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
