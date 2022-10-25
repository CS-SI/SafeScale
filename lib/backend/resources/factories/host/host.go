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

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a list of available hosts
func List(ctx context.Context, svc iaas.Service, all bool) (abstract.HostList, fail.Error) {
	var nullList abstract.HostList
	if ctx == nil {
		return nullList, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if svc == nil {
		return nullList, fail.InvalidParameterCannotBeNilError("svc")
	}

	if all {
		return svc.ListHosts(ctx, all)
	}

	hostSvc, xerr := New(svc)
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

func Wipe(ctx context.Context, svc iaas.Service, all bool) fail.Error {
	hol, xerr := List(ctx, svc, all)
	if xerr != nil {
		return xerr
	}

	for _, host := range hol {
		hid, err := host.GetID()
		if err != nil {
			continue
		}

		xerr = svc.DeleteHost(ctx, hid)
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// New creates an instance of resources.Host
func New(svc iaas.Service) (_ resources.Host, err fail.Error) {
	return operations.NewHost(svc)
}

// Load loads the metadata of host and returns an instance of resources.Host
func Load(ctx context.Context, svc iaas.Service, ref string) (_ resources.Host, err fail.Error) {
	return operations.LoadHost(ctx, svc, ref)
}
