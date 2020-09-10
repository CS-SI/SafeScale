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

package listeners

import (
	"context"

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	securitygroupfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/securitygroup"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// SecurityGroupListener security-group service server grpc
type SecurityGroupListener struct{}

// List lists hosts managed by SafeScale only, or all hosts.
func (s *SecurityGroupListener) List(ctx context.Context, in *protocol.SecurityGroupListRequest) (sgl *protocol.SecurityGroupListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list security groups")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, "", "security-group list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.security-group"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rsg, xerr := securitygroupfactory.New(job.GetService())
	if xerr != nil {
		return nil, xerr
	}

	sgl = nil
	xerr = rsg.Browse(task, func(asg *abstract.SecurityGroup) fail.Error {
		sgl.List = append(sgl.List, converters.SecurityGroupFromAbstractToProtocol(*asg))
		return nil
	})
	return sgl, xerr
}

// Create creates a new host
func (s *SecurityGroupListener) Create(ctx context.Context, in *protocol.SecurityGroupRequest) (_ *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, "", "security-group create")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	name := in.GetName()
	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.security-group"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rsg, xerr := securitygroupfactory.New(job.GetService())
	if xerr != nil {
		return nil, xerr
	}
	rules, xerr := converters.SecurityGroupRulesFromProtocolToAbstract(in.Rules)
	if xerr != nil {
		return nil, xerr
	}
	xerr = rsg.Create(task, name, in.Description, rules)
	if xerr != nil {
		return nil, xerr
	}

	return rsg.ToProtocol(task)
}

// Clear calls the clear method to remove all rules from a security group
func (s *SecurityGroupListener) Clear(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot clear security group")

	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.TenantId, "security-group clear")
	if err != nil {
		return empty, err
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rsg, xerr := securitygroupfactory.New(job.GetService())
	if xerr != nil {
		return empty, xerr
	}
	xerr = rsg.Clear(task)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Security Group '%s' successfully cleared", ref)
	return empty, nil
}

// Reset clears the rules of a security group and readds the ones stored in metadata
func (s *SecurityGroupListener) Reset(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot reset security group")

	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, "", "security-group reset")
	if err != nil {
		return empty, err
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rsg, xerr := securitygroupfactory.Load(task, job.GetService(), ref)
	if xerr != nil {
		return empty, xerr
	}
	xerr = rsg.Reset(task)
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Security Group %s successfully cleared", refLabel)
	return empty, nil
}

// Inspect an host
func (s *SecurityGroupListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.SecurityGroupResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect security group")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.TenantId, "security-group inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rsg, xerr := securitygroupfactory.Load(task, job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}
	return rsg.ToProtocol(task)
}

// Delete an host
func (s *SecurityGroupListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete security-group")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.TenantId, "security-group delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rsg, xerr := securitygroupfactory.Load(task, job.GetService(), ref)
	if xerr != nil {
		return empty, xerr
	}
	xerr = rsg.Delete(task)
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Security Group %s successfully deleted.", refLabel)
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
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in.Group)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	rule, xerr := converters.SecurityGroupRuleFromProtocolToAbstract(in.Rule)
	if xerr != nil {
		return nil, xerr
	}

	job, err := PrepareJob(ctx, "", "security-group add-rule")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rsg, xerr := securitygroupfactory.Load(task, job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}

	xerr = rsg.AddRule(task, rule)
	if xerr != nil {
		return nil, xerr
	}
	tracer.Trace("Rule successfully added to security group %s", refLabel)
	return rsg.ToProtocol(task)
}

// Sanitize checks if provider-side rules are coherent with registered ones in metadata
func (s *SecurityGroupListener) Sanitize(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	empty = &googleprotobuf.Empty{}
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot sanitize security group")

	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "security-group sanitize")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.security-group"), "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rsg, xerr := securitygroupfactory.Load(task, job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}

	xerr = rsg.CheckConsistency(task)
	if xerr != nil {
		return nil, xerr
	}
	tracer.Trace("Security Group %s is in sync with metadata %s")
	return empty, nil
}
