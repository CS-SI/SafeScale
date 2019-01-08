/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/iaas/provider"
)

// GetAuthOpts returns the auth options
func (s *Stack) GetAuthOpts() (provider.Config, error) {
	cfg := provider.ConfigMap{}

	cfg.Set("DomainName", s.AuthOpts.DomainName)
	cfg.Set("Login", s.AuthOpts.Username)
	cfg.Set("Password", s.AuthOpts.Password)
	cfg.Set("AuthUrl", s.AuthOpts.IdentityEndpoint)
	cfg.Set("Region", s.AuthOpts.Region)
	cfg.Set("VPCName", s.AuthOpts.VPCName)

	return cfg, nil
}

// GetCfgOpts return configuration parameters
func (s *Stack) GetCfgOpts() (provider.Config, error) {
	return s.osclt.GetCfgOpts()
}
