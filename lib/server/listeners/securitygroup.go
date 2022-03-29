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

package listeners

import (
	"context"
	"fmt"
	"strings"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	networkfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/securitygroup"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v21/lib/server/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

// SecurityGroupListener security-group service server grpc
type SecurityGroupListener struct {
	protocol.UnimplementedSecurityGroupServiceServer
}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *SecurityGroupListener) List(ctx context.Context, in *protocol.SecurityGroupListRequest) (_ *protocol.SecurityGroupListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list security groups")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	job, err := PrepareJob(ctx, "", "/securitygroups/list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	task := job.Task()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.security-group"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	list, xerr := securitygroupfactory.List(task.Context(), job.Service(), all)
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
func (s *SecurityGroupListener) Create(ctx context.Context, in *protocol.SecurityGroupCreateRequest) (_ *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	name := in.GetName()
	networkRef, _ := srvutils.GetReference(in.GetNetwork())
	job, err := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/network/%s/securitygroup/%s/create", networkRef, name))
	if err != nil {
		return nil, err
	}
	defer job.Close()
	svc := job.Service()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	networkInstance, xerr := networkfactory.Load(job.Context(), svc, networkRef)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := networkInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	rules, xerr := converters.SecurityGroupRulesFromProtocolToAbstract(in.Rules)
	if xerr != nil {
		return nil, xerr
	}

	sgInstance, xerr := securitygroupfactory.New(svc)
	if xerr != nil {
		return nil, xerr
	}

	xerr = sgInstance.Create(job.Context(), networkInstance.GetID(), name, in.Description, rules)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	return sgInstance.ToProtocol()
}

// Clear calls the clear method to remove all rules from a security group
func (s *SecurityGroupListener) Clear(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot clear Security Group")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	// FIXME: networkRef is missing to locate security group if name is provided
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/securitygroup/%s/clear", ref))
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	xerr = sgInstance.Clear(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Security Group '%s' successfully cleared", ref)
	return empty, nil
}

// Reset clears the rules of a security group and readds the ones stored in metadata
func (s *SecurityGroupListener) Reset(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot reset Security Group")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/securitygroup/%s/reset", ref))
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return empty, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	xerr = sgInstance.Reset(job.Context())
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Security Group %s successfully cleared", refLabel)
	return empty, nil
}

// Inspect a host
func (s *SecurityGroupListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	// FIXME: networkRef missing if security group is provided by name
	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/securitygroup/%s/inspect", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	return sgInstance.ToProtocol()
}

// Delete a host
func (s *SecurityGroupListener) Delete(ctx context.Context, in *protocol.SecurityGroupDeleteRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete Security Group")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	// FIXME: networkRef missing if security group is provided by name
	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/securitygroup/%s/delete", sgRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "(%s)", sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), sgRef)
	if xerr != nil {
		return empty, xerr
	}

	xerr = sgInstance.Delete(job.Context(), in.GetForce())
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Security Group %s successfully deleted.", sgRefLabel)
	return empty, nil
}

// AddRule creates a new rule and add it to an eisting security group
func (s *SecurityGroupListener) AddRule(ctx context.Context, in *protocol.SecurityGroupRuleRequest) (sgr *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot add rule to security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.Group)
	if sgRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	rule, xerr := converters.SecurityGroupRuleFromProtocolToAbstract(in.Rule)
	if xerr != nil {
		return nil, xerr
	}

	job, err := PrepareJob(ctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/securitygroup/%s/rule/add", sgRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "(%s)", sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), sgRef)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	xerr = sgInstance.AddRule(job.Context(), rule)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Rule successfully added to security group %s", sgRefLabel)
	return sgInstance.ToProtocol()
}

// DeleteRule deletes a rule identified by id from a security group
func (s *SecurityGroupListener) DeleteRule(ctx context.Context, in *protocol.SecurityGroupRuleDeleteRequest) (_ *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete rule from security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ref, refLabel := srvutils.GetReference(in.GetGroup())
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	rule, xerr := converters.SecurityGroupRuleFromProtocolToAbstract(in.GetRule())
	if xerr != nil {
		return nil, xerr
	}

	job, err := PrepareJob(ctx, in.GetGroup().GetTenantId(), fmt.Sprintf("/securitygroup/%s/rule/delete", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "(%s, %v)", refLabel, rule).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	xerr = sgInstance.DeleteRule(job.Context(), rule)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Rule successfully added to security group %s", refLabel)
	return sgInstance.ToProtocol()
}

// Sanitize checks if provider-side rules are coherent with registered ones in metadata
func (s *SecurityGroupListener) Sanitize(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot sanitize security group")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/securitygroup/%s/sanitize", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()
	// task := job.Task()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return empty, fail.NotImplementedError("not yet implemented")
}

// Bonds lists the resources bound to the Security Group
func (s *SecurityGroupListener) Bonds(ctx context.Context, in *protocol.SecurityGroupBondsRequest) (_ *protocol.SecurityGroupBondsResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list bonds of Security Group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ref, refLabel := srvutils.GetReference(in.GetTarget())
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

	job, err := PrepareJob(ctx, in.GetTarget().GetTenantId(), fmt.Sprintf("/securitygroup/%s/bonds/list", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sgInstance, xerr := securitygroupfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := sgInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	out := &protocol.SecurityGroupBondsResponse{}
	switch loweredKind {
	case "all", "host", "hosts":
		bonds, xerr := sgInstance.GetBoundHosts(job.Context())
		if xerr != nil {
			return nil, xerr
		}

		out.Hosts = converters.SliceOfSecurityGroupBondFromPropertyToProtocol(bonds)
	}
	switch loweredKind {
	case "all", "subnet", "subnets", "network", "networks":
		bonds, xerr := sgInstance.GetBoundSubnets(job.Context())
		if xerr != nil {
			return nil, xerr
		}

		out.Subnets = converters.SliceOfSecurityGroupBondFromPropertyToProtocol(bonds)
	}

	return out, nil
}
