/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package huaweicloud

import (
	"github.com/CS-SI/SafeScale/iaas/providers"
	"github.com/CS-SI/SafeScale/iaas/stacks"
)

// GetAuthOpts returns the auth options
func (s *Stack) GetAuthOpts() (providers.Config, error) {
	cfg := providers.ConfigMap{}

	cfg.Set("DomainName", s.authOpts.DomainName)
	cfg.Set("Login", s.authOpts.Username)
	cfg.Set("Password", s.authOpts.Password)
	cfg.Set("AuthUrl", s.authOpts.IdentityEndpoint)
	cfg.Set("Region", s.authOpts.Region)
	cfg.Set("VPCName", s.authOpts.VPCName)

	return cfg, nil
}

// GetConfigurationOptions ...
func (s *Stack) GetConfigurationOptions() stacks.ConfigurationOptions {
	return s.cfgOpts
}

// GetAuthenticationOptions ...
func (s *Stack) GetAuthenticationOptions() stacks.AuthenticationOptions {
	return s.authOpts
}
