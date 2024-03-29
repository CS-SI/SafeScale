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

package listeners

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"strings"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	securitygroupfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/securitygroup"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// SecurityGroupListener security-group service server grpc
type SecurityGroupListener struct {
	protocol.UnimplementedSecurityGroupServiceServer
}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *SecurityGroupListener) List(inctx context.Context, in *protocol.SecurityGroupListRequest) (_ *protocol.SecurityGroupListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list security groups")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	job, err := PrepareJob(inctx, "", "/securitygroups/list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()

	handler := handlers.NewSecurityGroupHandler(job)
	list, xerr := handler.List(all)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.SecurityGroupListResponse{}
	out.SecurityGroups = make([]*protocol.SecurityGroupResponse, len(list))
	for k, v := range list {
		out.SecurityGroups[k] = converters.SecurityGroupFromAbstractToProtocol(*v)
	}
	return out, nil
}

// Create creates a new Security Group
func (s *SecurityGroupListener) Create(inctx context.Context, in *protocol.SecurityGroupCreateRequest) (_ *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot create security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	name := in.GetName()
	networkRef, _ := srvutils.GetReference(in.GetNetwork())
	job, xerr := PrepareJob(inctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/network/%s/securitygroup/%s/create", networkRef, name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()

	rules, xerr := converters.SecurityGroupRulesFromProtocolToAbstract(in.GetRules())
	if xerr != nil {
		return nil, xerr
	}

	handler := handlers.NewSecurityGroupHandler(job)
	sgInstance, xerr := handler.Create(networkRef, name, in.GetDescription(), rules)
	if xerr != nil {
		return nil, xerr
	}

	logrus.WithContext(ctx).Infof("Security Group '%s' successfully created", name)
	return sgInstance.ToProtocol(ctx)
}

// Clear calls the clear method to remove all rules from a security group
func (s *SecurityGroupListener) Clear(inctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot clear Security Group")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}

	// FIXME: networkRef is missing to locate security group if name is provided
	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/securitygroup/%s/clear", ref))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()

	handler := handlers.NewSecurityGroupHandler(job)
	xerr = handler.Clear(ref)
	if xerr != nil {
		return empty, xerr
	}

	logrus.WithContext(ctx).Infof("Security Group '%s' successfully cleared", ref)
	return empty, nil
}

// Reset clears the rules of a security group and readds the ones stored in metadata
func (s *SecurityGroupListener) Reset(inctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot reset Security Group")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/securitygroup/%s/reset", ref))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()

	handler := handlers.NewSecurityGroupHandler(job)
	xerr = handler.Reset(ref)
	if xerr != nil {
		return empty, xerr
	}

	logrus.WithContext(ctx).Infof("Security Group %s successfully cleared", refLabel)
	return empty, nil
}

// Inspect a host
func (s *SecurityGroupListener) Inspect(inctx context.Context, in *protocol.Reference) (_ *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	// FIXME: networkRef missing if security group is provided by name
	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/securitygroup/%s/inspect", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()

	handler := handlers.NewSecurityGroupHandler(job)
	sgInstance, xerr := handler.Inspect(ref)
	if xerr != nil {
		return nil, xerr
	}

	return sgInstance.ToProtocol(ctx)
}

// Delete a host
func (s *SecurityGroupListener) Delete(inctx context.Context, in *protocol.SecurityGroupDeleteRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete Security Group")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}

	// FIXME: networkRef missing if security group is provided by name
	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id given as reference")
	}

	job, xerr := PrepareJob(inctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/securitygroup/%s/delete", sgRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()

	handler := handlers.NewSecurityGroupHandler(job)
	xerr = handler.Delete(sgRef, in.GetForce())
	if xerr != nil {
		return empty, xerr
	}

	logrus.WithContext(ctx).Infof("Security Group %s successfully deleted.", sgRefLabel)
	return empty, nil
}

// AddRule creates a new rule and add it to an existing security group
func (s *SecurityGroupListener) AddRule(inctx context.Context, in *protocol.SecurityGroupRuleRequest) (sgr *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot add rule to security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.Group)
	if sgRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	rule, xerr := converters.SecurityGroupRuleFromProtocolToAbstract(in.Rule)
	if xerr != nil {
		return nil, xerr
	}

	rule.Network = in.ResourceGroup.String()

	job, xerr := PrepareJob(inctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/securitygroup/%s/rule/add", sgRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()

	handler := handlers.NewSecurityGroupHandler(job)
	sgInstance, xerr := handler.AddRule(sgRef, rule)
	if xerr != nil {
		return nil, xerr
	}

	logrus.WithContext(ctx).Infof("Rule successfully added to security group %s", sgRefLabel)
	return sgInstance.ToProtocol(ctx)
}

// DeleteRule deletes a rule identified by id from a security group
func (s *SecurityGroupListener) DeleteRule(inctx context.Context, in *protocol.SecurityGroupRuleDeleteRequest) (_ *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete rule from security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	ref, refLabel := srvutils.GetReference(in.GetGroup())
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	rule, xerr := converters.SecurityGroupRuleFromProtocolToAbstract(in.GetRule())
	if xerr != nil {
		return nil, xerr
	}

	job, err := PrepareJob(inctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/securitygroup/%s/rule/delete", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()

	handler := handlers.NewSecurityGroupHandler(job)
	sgInstance, xerr := handler.DeleteRule(ref, rule)
	if xerr != nil {
		return nil, xerr
	}

	logrus.WithContext(ctx).Infof("Rule successfully added to security group %s", refLabel)
	return sgInstance.ToProtocol(ctx)
}

// Bonds lists the resources bound to the Security Group
func (s *SecurityGroupListener) Bonds(inctx context.Context, in *protocol.SecurityGroupBondsRequest) (_ *protocol.SecurityGroupBondsResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list bonds of Security Group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	ref, _ := srvutils.GetReference(in.GetTarget())
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	loweredKind := strings.ToLower(in.GetKind())
	switch loweredKind {
	case "":
		loweredKind = "all"
	case "all", "host", "hosts", "network", "networks":
		// continue
	default:
		return nil, fail.InvalidRequestError("invalid value '%s' in field 'Kind'", in.GetKind())
	}

	job, err := PrepareJob(inctx, in.GetTarget().GetTenantId(), fmt.Sprintf("/securitygroup/%s/bonds/list", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()

	sgInstance, xerr := securitygroupfactory.Load(ctx, job.Service(), ref, false)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.SecurityGroupBondsResponse{}
	switch loweredKind {
	case "all", "host", "hosts":
		bonds, xerr := sgInstance.GetBoundHosts(ctx)
		if xerr != nil {
			return nil, xerr
		}

		out.Hosts = converters.SliceOfSecurityGroupBondFromPropertyToProtocol(bonds)
	}
	switch loweredKind {
	case "all", "subnet", "subnets", "network", "networks":
		bonds, xerr := sgInstance.GetBoundSubnets(ctx)
		if xerr != nil {
			return nil, xerr
		}

		out.Subnets = converters.SliceOfSecurityGroupBondFromPropertyToProtocol(bonds)
	}

	return out, nil
}
