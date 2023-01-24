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
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
)

// Profile contains Provider profile
type Profile struct {
	capabilities       iaasapi.Capabilities             // contains capabilities of the provider
	metrics            *Metrics                         // contains the metric of the provider, all instances combined
	referenceInstance  func() iaasapi.Provider          // contains a reference provider from which we can call Build
	terraformProviders terraformerapi.RequiredProviders // contains the provider(s) to require in terraform HCL
}

func NewProfile(caps iaasapi.Capabilities, referenceInstance func() iaasapi.Provider, terraformProviders map[string]terraformerapi.RequiredProvider) *Profile {
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
func (p Profile) Capabilities() iaasapi.Capabilities {
	return p.capabilities
}

// Metrics returns the global metrics of a Provider (accumulating the metrics of instances)
func (p Profile) Metrics() Metrics {
	return *p.metrics
}

func (p Profile) TerraformProviders() terraformerapi.RequiredProviders {
	return p.terraformProviders
}

func (p Profile) ReferenceInstance() iaasapi.Provider {
	return p.referenceInstance()
}
