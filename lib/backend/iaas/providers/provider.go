/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"regexp"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -o mocks/mock_provider.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers.Provider

// Provider is the interface to cloud stack
// It has to recall Stack api, to serve as Provider AND as Stack
type Provider interface {
	api.Stack

	// Build builds a new Client from configuration parameter and can be called from nil
	Build(map[string]interface{}) (Provider, fail.Error)

	// ListImages lists available OS images, all bool is unused here but used at upper levels to filter using whitelists and blacklists
	ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error)

	// ListTemplates lists available host templates, all bool is unused here but used at upper levels to filter using whitelists and blacklists, Host templates are sorted using Dominant Resource Fairness Algorithm
	ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error)

	// GetAuthenticationOptions returns authentication options as a Config
	GetAuthenticationOptions(ctx context.Context) (Config, fail.Error)

	// GetConfigurationOptions returns configuration options as a Config
	GetConfigurationOptions(ctx context.Context) (Config, fail.Error)

	GetName() (string, fail.Error)     // GetName returns the tenant name
	GetStack() (api.Stack, fail.Error) // Returns the stack object used by the provider. Use with caution

	GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error)

	// GetCapabilities returns the capabilities of the provider
	GetCapabilities(ctx context.Context) (Capabilities, fail.Error)

	// GetTenantParameters returns the tenant parameters as read
	GetTenantParameters() (map[string]interface{}, fail.Error)
}
