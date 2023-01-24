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

package iaasoptions

import (
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	BuildOptionTenantName               = "tenant_name"
	BuildOptionTerraformerConfiguration = "terraformer_conf"
)

// WithTerraformer allows to indicate what terraformer.Configuration has to be used
func WithTerraformer(config terraformerapi.Configuration) options.Option {
	return func(o options.Options) fail.Error {
		if valid.IsNull(config) {
			return fail.InvalidParameterError("config", "must be a valid 'terraformer.Configuration' in WithTerraformer()")
		}

		return options.Add(o, BuildOptionTerraformerConfiguration, config)
	}
}
