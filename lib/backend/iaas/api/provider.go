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

package iaasapi

import (
	"context"
	"regexp"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
)

//go:generate minimock -o mocks/mock_provider.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api.Provider

// Provider is the interface to cloud stack
// It has to recall Stack api, to serve as Provider AND as Stack
type Provider interface {
	Stack

	// Build builds a new Client from configuration parameter and can be called from nil
	Build(params map[string]interface{}, opts options.Options) (Provider, fail.Error)

	// ListImages lists available OS images, all bool is unused here but used at upper levels to filter using whitelists and blacklists
	ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error)

	// ListTemplates lists available host templates, all bool is unused here but used at upper levels to filter using whitelists and blacklists, Host templates are sorted using Dominant Resource Fairness Algorithm
	ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error)

	// AuthenticationOptions returns authentication options
	AuthenticationOptions() (iaasoptions.Authentication, fail.Error)

	// ConfigurationOptions returns configuration options
	ConfigurationOptions() (iaasoptions.Configuration, fail.Error)

	GetName() (string, fail.Error) // GetName returns the tenant name
	GetStack() (Stack, fail.Error) // Returns the stack object used by the Provider. Use with caution

	GetRegexpsOfTemplatesWithGPU() ([]*regexp.Regexp, fail.Error)

	// Capabilities returns the capabilities of the Provider
	Capabilities() Capabilities

	// TenantParameters returns the tenant parameters as read
	TenantParameters() (map[string]interface{}, fail.Error)

	// HasDefaultNetwork tells if the stack has a default network (defined in tenant settings)
	HasDefaultNetwork() (bool, fail.Error)
	// DefaultNetwork returns the abstract.Network used as default Network
	DefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error)
}

//go:generate minimock -o mocks/mock_provider.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers.StackReservedForProviderUse

// StackReservedForProviderUse is an interface about the methods only available to providers internally
type StackReservedForProviderUse interface {
	ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error)           // list available OS images
	ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) // list available host templates
	ConfigurationOptions() (iaasoptions.Configuration, fail.Error)                      // Return a read-only struct containing configuration options
	AuthenticationOptions() (iaasoptions.Authentication, fail.Error)                    // Return a read-only struct containing authentication options
	HasDefaultNetwork() (bool, fail.Error)                                              // return true if the stack as a default network set (coming from tenants file)
	DefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error)                 // return the *abstract.Network corresponding to the default network
}
