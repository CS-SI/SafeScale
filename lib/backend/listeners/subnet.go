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

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// safescale network subnet create --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" net1 subnet-1 (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw-net1)
// safescale network subnet list
// safescale network subnet delete net1 subnet-1
// safescale network subnet inspect net1 subnet-1

// SubnetListener subnet service server gRPC
type SubnetListener struct {
	protocol.UnimplementedSubnetServiceServer
}

// VPL: workaround to make SafeScale compile with recent gRPC changes, before understanding the scope of these changes

// Create a new subnet
func (s *SubnetListener) Create(inctx context.Context, in *protocol.SubnetCreateRequest) (_ *protocol.Subnet, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitLogError(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot create Subnet")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkLabel := srvutils.GetReference(in.GetNetwork())
	if networkRef == "" {
		return nil, fail.InvalidParameterError("in.Network", "must contain an ID or a Name")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), fmt.Sprintf("/subnet/%s/create", networkRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.subnet"), "(%s, '%s')", networkLabel, in.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	var sizing *abstract.HostSizingRequirements
	if in.GetGateway() != nil {
		if in.GetGateway().SizingAsString != "" {
			sizing, _, xerr = converters.HostSizingRequirementsFromStringToAbstract(in.GetGateway().GetSizingAsString())
			if xerr != nil {
				return nil, xerr
			}
		} else if in.GetGateway().GetSizing() != nil {
			sizing = converters.HostSizingRequirementsFromProtocolToAbstract(in.GetGateway().GetSizing())
		}
	}
	if sizing == nil {
		sizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}
	sizing.Image = in.GetGateway().GetImageId()

	req := abstract.SubnetRequest{
		Name:           in.GetName(),
		CIDR:           in.GetCidr(),
		Domain:         in.GetDomain(),
		HA:             in.GetFailOver(),
		DefaultSSHPort: in.GetGateway().GetSshPort(),
		KeepOnFailure:  in.GetKeepOnFailure(),
	}

	handler := handlers.NewSubnetHandler(job)
	subnetInstance, xerr := handler.Create(networkRef, req, "", *sizing)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Subnet '%s' successfully created.", req.Name)
	return subnetInstance.ToProtocol(ctx)
}

// List existing networks
func (s *SubnetListener) List(inctx context.Context, in *protocol.SubnetListRequest) (_ *protocol.SubnetList, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitLogError(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot list Subnets")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	if networkRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference for Network")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), "/subnets/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.subnet"), "(%s, %v)", networkRefLabel, in.All).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	handler := handlers.NewSubnetHandler(job)
	list, xerr := handler.List(networkRef, in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	// Build response mapping abstract.Networking to protocol.Networking
	var pbList []*protocol.Subnet
	for _, subnet := range list {
		pbList = append(pbList, converters.SubnetFromAbstractToProtocol(subnet))
	}
	resp := &protocol.SubnetList{Subnets: pbList}
	return resp, nil
}

// Inspect returns infos on a subnet
func (s *SubnetListener) Inspect(inctx context.Context, in *protocol.SubnetInspectRequest) (_ *protocol.Subnet, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitLogError(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect Subnet")
	defer fail.OnPanic(&err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), fmt.Sprintf("/network/%s/subnetInstance/%s/inspect", networkRef, subnetRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.subnetInstance"), "(%s, %s)", networkRefLabel, subnetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewSubnetHandler(job)
	subnetInstance, xerr := handler.Inspect(networkRef, subnetRef)
	if xerr != nil {
		return nil, xerr
	}

	return subnetInstance.ToProtocol(ctx)
}

// Delete a/many subnet/s
func (s *SubnetListener) Delete(inctx context.Context, in *protocol.SubnetDeleteRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitLogError(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete Subnet")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), fmt.Sprintf("/network/%s/subnet/%s/delete", networkRef, subnetRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, true, "(%s, %s)", networkRefLabel, subnetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewSubnetHandler(job)
	xerr = handler.Delete(networkRef, subnetRef, in.GetForce())
	if xerr != nil {
		return empty, xerr
	}

	logrus.Infof("Subnet %s successfully deleted.", subnetRefLabel)
	return empty, nil
}

// BindSecurityGroup attaches a Security Group to a hostnetwork
func (s *SubnetListener) BindSecurityGroup(inctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitLogError(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot bind Security Group to Subnet")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), fmt.Sprintf("/network/%s/subnet/%s/securitygroup/%s/bind", networkRef, subnetRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.subnet"), "(%s, %s, %s)", networkRefLabel, subnetRef, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	var enable resources.SecurityGroupActivation
	switch in.GetState() {
	case protocol.SecurityGroupState_SGS_DISABLED:
		enable = resources.SecurityGroupDisable
	default:
		enable = resources.SecurityGroupEnable
	}

	handler := handlers.NewSubnetHandler(job)
	return empty, handler.BindSecurityGroup(networkRef, subnetRef, sgRef, enable)
}

// UnbindSecurityGroup detaches a Security Group from a subnet
func (s *SubnetListener) UnbindSecurityGroup(inctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitLogError(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot unbind Security Group from Subnet")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), fmt.Sprintf("/network/%s/subnet/%s/securitygroup/%s/unbind", networkRef, subnetRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.subnet"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewSubnetHandler(job)
	return empty, handler.UnbindSecurityGroup(networkRef, subnetRef, sgRef)
}

// EnableSecurityGroup applies the rules of a bound security group on a network
func (s *SubnetListener) EnableSecurityGroup(inctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitLogError(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot enable Security Group of Subnet")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), fmt.Sprintf("/network/%s/subnet/%s/securitygroup/%s/enable", networkRef, subnetRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.subnet"), "(%s, %s, %s)", networkRefLabel, subnetRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewSubnetHandler(job)
	return empty, handler.EnableSecurityGroup(networkRef, subnetRef, sgRef)
}

// DisableSecurityGroup detaches a Security Group from a subnet
func (s *SubnetListener) DisableSecurityGroup(inctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitLogError(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot disable Security Group of Subnet")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), fmt.Sprintf("/network/%s/subnet/%s/securitygroup/%s/disable", networkRef, subnetRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.subnet"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewSubnetHandler(job)
	return empty, handler.DisableSecurityGroup(networkRef, subnetRef, sgRef)
}

// ListSecurityGroups lists the Security Group bound to subnet
func (s *SubnetListener) ListSecurityGroups(inctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (_ *protocol.SecurityGroupBondsResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitLogError(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list Security Groups bound to Subnet")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := prepareJob(inctx, in.GetNetwork(), fmt.Sprintf("network/%s/subnet/%s/securitygroups/list", networkRef, subnetRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.subnet"), "(%s)", networkRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	state := securitygroupstate.Enum(in.GetState())

	handler := handlers.NewSubnetHandler(job)
	bonds, xerr := handler.ListSecurityGroups(networkRef, subnetRef, state)
	if xerr != nil {
		return nil, xerr
	}

	resp := converters.SecurityGroupBondsFromPropertyToProtocol(bonds, "subnets")
	return resp, nil
}
