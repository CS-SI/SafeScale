/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// List returns a list of available security groups
func List(task concurrency.Task, svc iaas.Service, all bool) ([]*abstract.SecurityGroup, fail.Error) {
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if svc.IsNull() {
		return nil, fail.InvalidParameterError("svc", "cannot be null value of 'iaas.Service'")
	}

	if all {
		return svc.ListSecurityGroups("")
	}

	rsg, err := New(svc)
	if err != nil {
		return nil, err
	}
	var list []*abstract.SecurityGroup
	err = rsg.Browse(task, func(asg *abstract.SecurityGroup) fail.Error {
		list = append(list, asg)
		return nil
	})
	return list, err
}

// New creates an instance of resources.SecurityGroup
func New(svc iaas.Service) (_ resources.SecurityGroup, xerr fail.Error) {
	if svc.IsNull() {
		return nil, fail.InvalidParameterError("svc", "cannot be null value of 'iaas.Service'")
	}

	rsg, xerr := operations.NewSecurityGroup(svc)
	if xerr != nil {
		return nil, xerr
	}
	return rsg, nil
}

// Load loads the metadata of Security Group a,d returns an instance of resources.SecurityGroup
func Load(task concurrency.Task, svc iaas.Service, ref string) (_ resources.SecurityGroup, xerr fail.Error) {
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if svc.IsNull() {
		return nil, fail.InvalidParameterError("svc", "cannot be null value of 'iaas.Service'")
	}
	if ref == "" {
		return nil, fail.InvalidParameterError("ref", "cannot be empty string")
	}

	// FIXME: tracer...

	return operations.LoadSecurityGroup(task, svc, ref)
}
