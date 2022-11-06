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

package host

import (
	"context"

	scopeapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/scope/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// List returns a list of available hosts
func List(ctx context.Context, scope scopeapi.Scope, all bool) (abstract.HostList, fail.Error) {
	var nullList abstract.HostList
	if ctx == nil {
		return nullList, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNull(scope) {
		return nullList, fail.InvalidParameterCannotBeNilError("scope")
	}

	if all {
		return scope.Service().ListHosts(ctx, all)
	}

	hostSvc, xerr := New(scope)
	if xerr != nil {
		return nullList, xerr
	}

	hosts := nullList
	xerr = hostSvc.Browse(ctx, func(hc *abstract.HostCore) fail.Error {
		hf := converters.HostCoreToHostFull(*hc)
		hosts = append(hosts, hf)
		return nil
	})
	return hosts, xerr
}

// New creates an instance of resources.Host
func New(scope scopeapi.Scope) (_ resources.Host, err fail.Error) {
	return operations.NewHost(scope)
}

// Load loads the metadata of host and returns an instance of resources.Host
func Load(ctx context.Context, scope scopeapi.Scope, ref string) (_ resources.Host, err fail.Error) {
	return operations.LoadHost(ctx, scope, ref)
}
