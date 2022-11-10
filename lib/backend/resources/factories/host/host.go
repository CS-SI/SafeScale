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

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a list of available hosts
func List(ctx context.Context, all bool) (abstract.HostList, fail.Error) {
	var nullList abstract.HostList
	if ctx == nil {
		return nullList, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if all {
		myjob, xerr := jobapi.FromContext(ctx)
		if xerr != nil {
			return nil, xerr
		}

		return myjob.Service().ListHosts(ctx, all)
	}

	hostSvc, xerr := New(ctx)
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
func New(ctx context.Context) (_ resources.Host, err fail.Error) {
	return operations.NewHost(ctx)
}

// Load loads the metadata of host and returns an instance of resources.Host
func Load(ctx context.Context, ref string) (_ resources.Host, err fail.Error) {
	return operations.LoadHost(ctx, ref)
}
