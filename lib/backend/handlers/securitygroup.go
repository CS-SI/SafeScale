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

package handlers

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/securitygroup"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.SecurityGroupHandler -o mocks/mock_securitygroup.go

// SecurityGroupHandler exposes interface of handler of Security Group requests
type SecurityGroupHandler interface {
	AddRule(sgRef string, rule *abstract.SecurityGroupRule) (resources.SecurityGroup, fail.Error)
	Bonds(sgRef string, kind string) ([]*propertiesv1.SecurityGroupBond, []*propertiesv1.SecurityGroupBond, fail.Error)
	Clear(sgRef string) fail.Error
	Create(networkRef string, sgName string, description string, rules abstract.SecurityGroupRules) (resources.SecurityGroup, fail.Error)
	Delete(sgRef string, force bool) fail.Error
	DeleteRule(sgRef string, rule *abstract.SecurityGroupRule) (resources.SecurityGroup, fail.Error)
	Inspect(sgRef string) (resources.SecurityGroup, fail.Error)
	List(all bool) ([]*abstract.SecurityGroup, fail.Error)
	Reset(sgRef string) fail.Error
}

type securityGroupHandler struct {
	job backend.Job
}

// NewSecurityGroupHandler returns an instance of SecurityGroupHandler
func NewSecurityGroupHandler(job backend.Job) SecurityGroupHandler {
	return &securityGroupHandler{job}
}

// List lists hosts managed by SafeScale only, or all hosts.
func (handler *securityGroupHandler) List(all bool) (_ []*abstract.SecurityGroup, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	return securitygroupfactory.List(handler.job.Context(), handler.job.Service(), all)
}

// Create creates a new Security Group
func (handler *securityGroupHandler) Create(networkRef, sgName, description string, rules abstract.SecurityGroupRules) (_ resources.SecurityGroup, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if networkRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("networkRef")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	networkInstance, xerr := networkfactory.Load(handler.job.Context(), handler.job.Service(), networkRef, isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	sgInstance, xerr := securitygroupfactory.New(handler.job.Service(), isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	nid, err := networkInstance.GetID()
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	xerr = sgInstance.Create(handler.job.Context(), nid, sgName, description, rules)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance, nil
}

// Clear calls the clear method to remove all rules from a security group
func (handler *securityGroupHandler) Clear(sgRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	return sgInstance.Clear(handler.job.Context())
}

// Reset clears the rules of a security group and reads the ones stored in metadata
func (handler *securityGroupHandler) Reset(sgRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	return sgInstance.Reset(handler.job.Context())
}

// Inspect a host
func (handler *securityGroupHandler) Inspect(sgRef string) (_ resources.SecurityGroup, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	return securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
}

// Delete a host
func (handler *securityGroupHandler) Delete(sgRef string, force bool) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return xerr
	}
	isTerraform = pn == "terraform"

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
	if xerr != nil {
		return xerr
	}

	return sgInstance.Delete(handler.job.Context(), force)
}

// AddRule creates a new rule and add it to an existing security group
func (handler *securityGroupHandler) AddRule(sgRef string, rule *abstract.SecurityGroupRule) (_ resources.SecurityGroup, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if sgRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}
	if rule == nil {
		return nil, fail.InvalidParameterCannotBeNilError("rule")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	xerr = sgInstance.AddRule(handler.job.Context(), rule)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance, nil
}

// DeleteRule deletes a rule identified by id from a security group
func (handler *securityGroupHandler) DeleteRule(sgRef string, rule *abstract.SecurityGroupRule) (_ resources.SecurityGroup, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if sgRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}
	if rule == nil {
		return nil, fail.InvalidParameterCannotBeNilError("rule")
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, xerr
	}
	isTerraform = pn == "terraform"

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
	if xerr != nil {
		return nil, xerr
	}

	xerr = sgInstance.DeleteRule(handler.job.Context(), rule)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance, nil
}

// Bonds lists the resources bound to the Security Group
func (handler *securityGroupHandler) Bonds(sgRef string, kind string) (_ []*propertiesv1.SecurityGroupBond, _ []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, nil, fail.InvalidInstanceError()
	}
	if sgRef == "" {
		return nil, nil, fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	loweredKind := strings.ToLower(kind)
	switch loweredKind {
	case "":
		loweredKind = "all"
	case "all", "host", "hosts", "network", "networks":
		// continue
	default:
		return nil, nil, fail.InvalidRequestError("invalid value '%s' in field 'Kind'", kind)
	}

	isTerraform := false
	pn, xerr := handler.job.Service().GetType()
	if xerr != nil {
		return nil, nil, xerr
	}
	isTerraform = pn == "terraform"

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef, isTerraform)
	if xerr != nil {
		return nil, nil, xerr
	}

	var (
		hostBonds, subnetBonds []*propertiesv1.SecurityGroupBond
	)
	switch loweredKind {
	case "all", "host", "hosts":
		hostBonds, xerr = sgInstance.GetBoundHosts(handler.job.Context())
		if xerr != nil {
			return nil, nil, xerr
		}
	}
	switch loweredKind {
	case "all", "subnet", "subnets", "network", "networks":
		subnetBonds, xerr = sgInstance.GetBoundSubnets(handler.job.Context())
		if xerr != nil {
			return nil, nil, xerr
		}
	}

	return hostBonds, subnetBonds, nil
}
