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

package iaasoptions

import (
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api/terraformer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

type (
	Build struct {
		TenantName               string
		TerraformerConfiguration terraformerapi.Configuration
	}
)

// Load is a dummy implementation to satisfy options.Options interface
func (o Build) Load(key string) (any, fail.Error) {
	return nil, nil
}

// Store ...
func (o Build) Store(key string, value any) (any, fail.Error) {
	return nil, nil
}

// BuildWithTenant allows to define the tenant to use
func BuildWithTenant(name string) options.Mutator {
	return func(o options.Options) fail.Error {
		if name == "" {
			return fail.InvalidParameterCannotBeEmptyStringError("name")
		}

		return options.Add(o, "TenantName", name)
	}
}

// BuildWithTerraformer allows to indicate what terraformer.Configuration has to be used
func BuildWithTerraformer(config terraformerapi.Configuration) options.Mutator {
	return func(o options.Options) fail.Error {
		if valid.IsNull(config) {
			return fail.InvalidParameterError("config", "must be a valid 'terraformer.Configuration' in WithTerraformer()")
		}

		return options.Add(o, "TerraformerConfiguration", config)
	}
}
