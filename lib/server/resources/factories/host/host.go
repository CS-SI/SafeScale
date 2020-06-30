/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ErrorList returns a list of available hosts
func List(task concurrency.Task, svc iaas.Service, all bool) (abstract.HostList, fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	// FIXME: get code from HostListener

	if all {
		return svc.ListHosts(all)
	}

	objh, err := New(svc)
	if err != nil {
		return nil, err
	}
	hosts := abstract.HostList{}
	err = objh.Browse(task, func(hc *abstract.HostCore) fail.Error {
		hf := converters.HostCoreToHostFull(*hc)
		hosts = append(hosts, hf)
		return nil
	})
	return hosts, err
}

// New creates an instance of resources.Host
func New(svc iaas.Service) (_ resources.Host, err fail.Error) {
	if svc == nil {
		return nil, fail.InvalidInstanceError()
	}
	host, err := operations.NewHost(svc)
	if err != nil {
		return nil, err
	}
	return host, nil
}

// Load loads the metadata of host and returns an instance of resources.Host
func Load(task concurrency.Task, svc iaas.Service, ref string) (_ resources.Host, err fail.Error) {
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if svc == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	// FIXME: tracer...

	return operations.LoadHost(task, svc, ref)
}
