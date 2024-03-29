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

package host

import (
	"context"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"

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

	isTerraform := false
	pn, xerr := svc.GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	if all && !isTerraform {
		theList, err := svc.ListHosts(ctx, all)
		if err != nil {
			return theList, err
		}

		var newList abstract.HostList
		for _, v := range theList {
			hID, err := v.GetID()
			if err != nil {
				continue
			}

			_, xerr := svc.InspectHost(ctx, hID)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					logrus.WithContext(ctx).Debugf("Metadata only instance: %s", litter.Sdump(v))
					continue
				default:
					logrus.WithContext(ctx).Debugf("problem browsing: %v", xerr)
					continue
				}
			}

			newList = append(newList, v)
		}
		return newList, nil
	}

	hostSvc, xerr := New(svc, isTerraform)
	if xerr != nil {
		return nullList, xerr
	}

	hosts := nullList
	if !isTerraform {
		xerr = hostSvc.Browse(ctx, func(hc *abstract.HostCore) fail.Error {
			hf := converters.HostCoreToHostFull(*hc)

			hID, err := hf.GetID()
			if err != nil {
				return nil
			}

			_, xerr = svc.InspectHost(ctx, hID)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					logrus.WithContext(ctx).Debugf("Metadata only instance: %s", litter.Sdump(hf))
					return nil
				default:
					logrus.WithContext(ctx).Debugf("problem browsing: %v", xerr)
					return nil
				}
			}

			hosts = append(hosts, hf)
			return nil
		})
	} else { // using closures was another mistake, a closure assumes knowledge of the implementation, which is not the case here
		aho, xerr := operations.LoadTerraformHosts(ctx, svc)
		if xerr != nil {
			return nil, xerr
		}

		for _, v := range aho {
			ahf := abstract.NewHostFull()
			ac := ahf.Core
			ac.Name = v.GetName()
			ac.ID, _ = v.GetID()

			// FIXME: Add creation date
			hosts = append(hosts, ahf)
		}
	}

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
func New(svc iaas.Service, terraform bool) (_ resources.Host, err fail.Error) {
	if terraform {
		return operations.NewTerraformHost(svc)
	}
	return operations.NewHost(svc)
}

// Load loads the metadata of host and returns an instance of resources.Host
func Load(ctx context.Context, svc iaas.Service, ref string, terraform bool) (_ resources.Host, err fail.Error) {
	if terraform {
		return operations.LoadTerraformHost(ctx, svc, ref)
	}
	return operations.LoadHost(ctx, svc, ref)
}
