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

package securitygroup

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// List returns a list of available security groups
func List(ctx context.Context, svc iaas.Service, all bool) ([]*abstract.SecurityGroup, fail.Error) {
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	if all {
		return svc.ListSecurityGroups(ctx, "")
	}

	sgInstance, xerr := New(svc)
	if xerr != nil {
		return nil, xerr
	}

	var list []*abstract.SecurityGroup
	xerr = sgInstance.Browse(ctx, func(asg *abstract.SecurityGroup) fail.Error {
		list = append(list, asg)
		return nil
	})
	return list, xerr
}

// New creates an instance of resources.SecurityGroup
func New(svc iaas.Service) (_ resources.SecurityGroup, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	sgInstance, xerr := operations.NewSecurityGroup(svc)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance, nil
}

// Load loads the metadata of Security Group a,d returns an instance of resources.SecurityGroup
func Load(ctx context.Context, svc iaas.Service, ref string) (_ resources.SecurityGroup, ferr fail.Error) {
	return operations.LoadSecurityGroup(ctx, svc, ref)
}
