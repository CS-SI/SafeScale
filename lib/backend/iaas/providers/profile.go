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

package providers

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/terraformer"
)

// Profile contains Provider profile
type Profile struct {
	capabilities       Capabilities                   // contains capabilities of the provider
	metrics            *Metrics                       // contains the metric of the provider, all instances combined
	referenceInstance  func() Provider                // contains a reference provider from which we can call Build
	terraformProviders []terraformer.RequiredProvider // contains the provider(s) to require in terraform HCL
}

func NewProfile(caps Capabilities, referenceInstance func() Provider, terraformProviders []terraformer.RequiredProvider) *Profile {
	out := &Profile{
		capabilities:       caps,
		metrics:            NewMetrics(),
		referenceInstance:  referenceInstance,
		terraformProviders: terraformProviders,
	}
	return out
}

// IsNull tells if the instance corresponds to a zero-value
func (p Profile) IsNull() bool {
	return p.referenceInstance == nil
}

// Capabilities returns the capabilities of the provider
func (p Profile) Capabilities() Capabilities {
	return p.capabilities
}

// Metrics returns the global metrics of a Provider (accumulating the metrics of instances)
func (p Profile) Metrics() Metrics {
	return *p.metrics
}

func (p Profile) TerraformProviders() []terraformer.RequiredProvider {
	return p.terraformProviders
}

func (p Profile) ReferenceInstance() Provider {
	return p.referenceInstance()
}
