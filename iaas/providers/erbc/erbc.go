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
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or provideried.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package erbc

import (
	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/providers"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/iaas/stacks"
)

// provider is the providerementation of the Erbc provider
type provider struct {
	stacks.Stack
}

// New creates a new instance of erbc provider
func New() providers.Provider {
	return &provider{}
}

// Build build a new Client from configuration parameter
func (p *provider) Build(params map[string]interface{}) (providers.Provider, error) {
	panic("Not Implemented")
}

// GetAuthOpts returns the auth options
func (p *provider) GetAuthOpts() (providers.Config, error) {
	panic("Not Implemented")
}

// GetCfgOpts return configuration parameters
func (p *provider) GetCfgOpts() (providers.Config, error) {
	panic("Not Implemented")
}

// ListTemplates ...
// Value of all has no impact on the result
func (p *provider) ListTemplates(all bool) ([]resources.HostTemplate, error) {
	panic("Not Implemented")
}

// ListImages ...
// Value of all has no impact on the result
func (p *provider) ListImages(all bool) ([]resources.Image, error) {
	panic("Not Implemented")
}

// GetName returns the providerName
func (p *provider) GetName() string {
	return "erbc"
}

func init() {
	iaas.Register("erbc", &provider{})
}
