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
	"fmt"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/securitygroup"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// safescale network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw-net1)
// safescale network list
// safescale network delete net1
// safescale network inspect net1

// NetworkListener network service server grpc
type NetworkListener struct{}

// Create a new network
func (s *NetworkListener) Create(ctx context.Context, in *protocol.NetworkDefinition) (_ *protocol.Network, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create network")

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

	networkName := in.GetName()
	if networkName == "" {
		return nil, fail.InvalidRequestError("network name cannot be empty string")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("network create '%s'", networkName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, true, "('%s')", networkName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	var (
		sizing    *abstract.HostSizingRequirements
		gwImageID string
		gwName    string
	)
	if in.Gateway != nil {
		if in.Gateway.SizingAsString != "" {
			sizing, _, xerr = converters.HostSizingRequirementsFromStringToAbstract(in.Gateway.SizingAsString)
			if xerr != nil {
				return nil, xerr
			}
		} else if in.Gateway.Sizing != nil {
			sizing = converters.HostSizingRequirementsFromProtocolToAbstract(in.Gateway.Sizing)
		}
	}
	if sizing == nil {
		sizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}
	sizing.Image = in.Gateway.GetImageId()

	handler := handlers.NewNetworkHandler(job)
	network, xerr := handler.Create(
		networkName,
		in.GetCidr(),
		ipversion.IPv4,
		*sizing,
		gwImageID,
		gwName,
		in.FailOver,
		in.KeepOnFailure,
		in.Domain,
	)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Network '%s' successfuly created.", networkName)
	return network.ToProtocol(task)
}

// List existing networks
func (s *NetworkListener) List(ctx context.Context, in *protocol.NetworkListRequest) (_ *protocol.NetworkList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list networks")

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

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "network list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewNetworkHandler(job)
	networks, err := handler.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	// Build response mapping abstract.Network to protocol.Network
	var pbnetworks []*protocol.Network
	for _, network := range networks {
		pbnetworks = append(pbnetworks, converters.NetworkFromAbstractToProtocol(network))
	}
	rv := &protocol.NetworkList{Networks: pbnetworks}
	return rv, nil
}

// Inspect returns infos on a network
func (s *NetworkListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.Network, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect network")

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

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "network inspect")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, true, "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	network, xerr := networkfactory.Load(task, job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}
	return network.ToProtocol(task)
}

// Delete a network
func (s *NetworkListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete network")

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
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "delete network")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), true, "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	handler := handlers.NewNetworkHandler(job)
	_, xerr = job.GetTask().Run(
		func(_ concurrency.Task, _ concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
			return nil, handler.Delete(ref)
		},
		nil,
	)
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Network %s successfully deleted.", refLabel)
	return empty, nil
}

// BindSecurityGroup attaches a Security Group to a hostnetwork
func (s *NetworkListener) BindSecurityGroup(ctx context.Context, in *protocol.SecurityGroupBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host SSH information")

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

	if ok, err := govalidator.ValidateStruct(in); err == nil && !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetTarget())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Network")
	}
	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetGroup().GetTenantId(), "network bind-security-group")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.network"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rn, xerr := networkfactory.Load(task, svc, networkRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rn.BindSecurityGroup(task, sg, in.GetEnable()); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// UnbindSecurityGroup detaches a Security Group from a network
func (s *NetworkListener) UnbindSecurityGroup(ctx context.Context, in *protocol.SecurityGroupBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host SSH information")

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
	if err == nil && !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetTarget())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Network")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetGroup().GetTenantId(), "network unbind-security-group")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.network"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rn, xerr := networkfactory.Load(task, svc, networkRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rn.UnbindSecurityGroup(task, sg); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// EnableSecurityGroup applies the rules of a bound security group on a network
func (s *NetworkListener) EnableSecurityGroup(ctx context.Context, in *protocol.SecurityGroupBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get host SSH information")

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

	if ok, err := govalidator.ValidateStruct(in); err == nil && !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetTarget())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Network")
	}
	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetGroup().GetTenantId(), "network security-group enable")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.network"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rn, xerr := networkfactory.Load(task, svc, networkRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rn.EnableSecurityGroup(task, sg); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// DisableSecurityGroup detaches a Security Group from a network
func (s *NetworkListener) DisableSecurityGroup(ctx context.Context, in *protocol.SecurityGroupBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot disable security group on network")

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
	if err == nil && !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetTarget())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Network")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetGroup().GetTenantId(), "network security-group disable")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.network"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rn, xerr := networkfactory.Load(task, svc, networkRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rn.DisableSecurityGroup(task, sg); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// ListSecurityGroups applies a Security Group already attached (if not already applied)
func (s *NetworkListener) ListSecurityGroups(ctx context.Context, in *protocol.SecurityGroupBondsRequest) (_ *protocol.SecurityGroupBondsResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	//defer fail.OnExitWrapError(&err, "cannot list security groups bound to network")

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
	if err == nil && !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetTarget())
	if networkRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference of Network")
	}

	job, xerr := PrepareJob(ctx, in.GetTarget().GetTenantId(), "network security-group list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.network"), "(%s)", networkRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rn, xerr := networkfactory.Load(task, svc, networkRef)
	if xerr != nil {
		return nil, xerr
	}
	bonds, xerr := rn.ListSecurityGroups(task, in.GetKind())
	if xerr != nil {
		return nil, xerr
	}
	resp := converters.SecurityGroupBondsFromPropertyToProtocol(bonds, "networks")
	return resp, nil
}
