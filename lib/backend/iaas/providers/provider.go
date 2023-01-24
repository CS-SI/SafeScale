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

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

type (
	// StackReservedForProviderUse is an interface about the methods only available to providers internally
	StackReservedForProviderUse interface {
		ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error)           // list available OS images
		ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error) // list available host templates
		ConfigurationOptions() (iaasoptions.Configuration, fail.Error)                      // Return a read-only struct containing configuration options
		AuthenticationOptions() (iaasoptions.Authentication, fail.Error)                    // Return a read-only struct containing authentication options
		HasDefaultNetwork() (bool, fail.Error)                                              // return true if the stack as a default network set (coming from tenants file)
		DefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error)                 // return the *abstract.Network corresponding to the default network
	}

	ReservedForTerraformerUse interface {
		// TerraformRenderer(iaasapi.Provider) (terraformerapi.Terraformer, fail.Error)
		ConsolidateNetworkSnippet(*abstract.Network) fail.Error
		ConsolidateSubnetSnippet(*abstract.Subnet) fail.Error
		ConsolidateSecurityGroupSnippet(*abstract.SecurityGroup) fail.Error
		// ConsolidateLabelSnippet(*abstract.Label)
		ConsolidateHostSnippet(*abstract.HostCore) fail.Error
		ConsolidateVolumeSnippet(*abstract.Volume) fail.Error
	}
)
