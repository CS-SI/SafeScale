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

package terraformer

import (
	"reflect"

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/api"
	iaasoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	OptionScope = iaasoptions.OptionScope

	ConfigOptionRelease           = "release"
	ConfigOptionWorkDir           = "workdir"
	ConfigOptionExecPath          = "execpath"
	ConfigOptionPluginDir         = "plugindir"
	ConfigOptionConsulServer      = "consul_server"
	ConfigOptionConsulPrefix      = "consukl_prefix" // should contains "safescale/terraformstate/{Scope.Organization}/{Scope.Project}/{Scope.Tenant}
	ConfigOptionRequiredProviders = "required_providers"
)

// WithScope allows to define the tenant to use
func WithScope(scope scopeapi.Scope) options.Option {
	return func(o options.Options) fail.Error {
		if valid.IsNull(scope) {
			return fail.InvalidParameterError("scope", "cannot be null value of '%s'", reflect.TypeOf(scope).String())
		}

		xerr := options.Add(o, OptionScope, scope)
		if xerr != nil {
			return xerr
		}

		return nil
	}
}
