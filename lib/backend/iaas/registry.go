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

package iaas

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var (
	providerProfiles = map[string]*providers.Profile{}
)

// RegisterProviderProfile a service referenced by the provider name. Ex: "ovh", ovh.newCore()
// This function should be called by the init function of each provider to be registered in SafeScale
func RegisterProviderProfile(name string, profile *providers.Profile) {
	// if already registered, leave
	if _, ok := providerProfiles[name]; ok {
		return
	}

	providerProfiles[name] = profile
}

// FindProviderProfile returns a Profile corresponding to provider name passed as parameter
func FindProviderProfile(providerName string) (*providers.Profile, fail.Error) {
	if providerName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("providerName")
	}

	p, ok := providerProfiles[providerName]
	if !ok {
		return nil, fail.NotFoundError("failed to find a Profile for Provider '%s'", providerName)
	}

	return p, nil
}
