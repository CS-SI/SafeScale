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
 */

package providers

import (
	"regexp"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_providerapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/iaas/providers Provider

// Provider is the interface to cloud stack
// It has to recall Stack api, to serve as Provider AND as Stack
type Provider interface {
	Build(map[string]interface{}) (Provider, fail.Error)

	api.Stack

	// ListImages lists available OS images
	ListImages(all bool) ([]abstract.Image, fail.Error)

	// ListTemplates lists available host templates
	// IPAddress templates are sorted using Dominant Resource Fairness Algorithm
	ListTemplates(all bool) ([]abstract.HostTemplate, fail.Error)

	// GetAuthenticationOptions returns authentication options as a Config
	GetAuthenticationOptions() (Config, fail.Error)

	// GetConfigurationOptions returns configuration options as a Config
	GetConfigurationOptions() (Config, fail.Error)

	// GetName returns the provider name
	GetName() string

	GetRegexpsOfTemplatesWithGPU() []*regexp.Regexp

	// GetCapabilities returns the capabilities of the provider
	GetCapabilities() Capabilities

	// GetTenantParameters returns the tenant parameters as read
	GetTenantParameters() map[string]interface{}
}
