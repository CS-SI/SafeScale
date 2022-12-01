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

package huaweicloud

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// // GetAuthOpts returns the auth options
// func (s stack) GetAuthOpts() (providers.Config, error) {
// 	cfg := providers.ConfigMap{}
//
// 	cfg.Set("DomainName", s.authOpts.DomainName)
// 	cfg.Set("Login", s.authOpts.Username)
// 	cfg.Set("Password", s.authOpts.Password)
// 	cfg.Set("AuthURL", s.authOpts.IdentityEndpoint)
// 	cfg.Set("Region", s.authOpts.Region)
//
// 	return cfg, nil
// }

// ConfigurationOptions ...
func (instance *stack) ConfigurationOptions() (iaasoptions.Configuration, fail.Error) {
	return instance.cfgOpts, nil
}

// AuthenticationOptions ...
func (instance *stack) AuthenticationOptions() (iaasoptions.Authentication, fail.Error) {
	return instance.authOpts, nil
}
