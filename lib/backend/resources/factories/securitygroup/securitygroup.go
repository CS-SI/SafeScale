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

package securitygroup

import (
	"context"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/network"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a list of available security groups
func List(ctx context.Context, networkRef string, all bool) ([]*abstract.SecurityGroup, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if all {
		myjob, xerr := jobapi.FromContext(ctx)
		if xerr != nil {
			return nil, xerr
		}

		return myjob.Service().ListSecurityGroups(ctx, "")
	}

	var networkID string
	if networkRef != "" {
		networkInstance, xerr := networkfactory.Load(ctx, networkRef)
		if xerr != nil {
			return nil, xerr
		}

		var err error
		networkID, err = networkInstance.GetID()
		if err != nil {
			return nil, fail.Wrap(err)
		}
	}

	sgInstance, xerr := New(ctx)
	if xerr != nil {
		return nil, xerr
	}

	var (
		list     []*abstract.SecurityGroup
		callback func(asg *abstract.SecurityGroup) fail.Error
	)
	if networkID == "" {
		callback = func(asg *abstract.SecurityGroup) fail.Error {
			list = append(list, asg)
			return nil
		}
	} else {
		callback = func(asg *abstract.SecurityGroup) fail.Error {
			if networkID == asg.Network {
				list = append(list, asg)
			}
			return nil
		}
	}
	xerr = sgInstance.Browse(ctx, callback)
	return list, xerr
}

// New creates an instance of *SecurityGroup
func New(ctx context.Context) (_ *resources.SecurityGroup, ferr fail.Error) {
	return resources.NewSecurityGroup(ctx)
}

// Load loads the metadata of Security Group a,d returns an instance of *SecurityGroup
func Load(ctx context.Context, ref string) (_ *resources.SecurityGroup, ferr fail.Error) {
	return resources.LoadSecurityGroup(ctx, ref)
}
