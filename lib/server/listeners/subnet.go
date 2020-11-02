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

package listeners

import (
	"context"
	"fmt"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	subnetfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/securitygroup"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// safescale network subnet create --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" net1 subnet-1 (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw-net1)
// safescale network subnet list
// safescale network subnet delete net1 subnet-1
// safescale network subnet inspect net1 subnet-1

// SubnetListener subnet service server gRPC
type SubnetListener struct{}

// Create a new subnet
func (s *SubnetListener) Create(ctx context.Context, in *protocol.SubnetCreateRequest) (_ *protocol.Subnet, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot create Subnet")

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

	networkRef, networkLabel := srvutils.GetReference(in.GetNetwork())
	if networkRef == "" {
		return nil, fail.InvalidRequestError("network name cannot be empty string")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("subnet create '%s'", networkRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.subnet"), "(%s, '%s')", networkLabel, in.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	var (
		sizing *abstract.HostSizingRequirements
		gwName string
	)
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
		NetworkID:     networkRef,
		Name:          in.GetName(),
		CIDR:          in.GetCidr(),
		Domain:        in.GetDomain(),
		HA:            in.GetFailOver(),
		KeepOnFailure: in.GetKeepOnFailure(),
	}
	rs, xerr := subnetfactory.New(svc)
	if xerr != nil {
		return nil, xerr
	}
	if xerr = rs.Create(task, req, gwName, sizing); xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Subnet '%s' successfully created.", req.Name)
	return rs.ToProtocol(task)
}

// List existing networks
func (s *SubnetListener) List(ctx context.Context, in *protocol.SubnetListRequest) (_ *protocol.SubnetList, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot list Subnets")

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

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "network list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.subnet"), "(%v, %v)", in.Network, in.All).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	var (
		an        *abstract.Network
		networkID string
	)
	if svc.HasDefaultNetwork() {
		if an, xerr = svc.GetDefaultNetwork(); xerr != nil {
			return nil, xerr
		}
	}
	networkRef, _ := srvutils.GetReference(in.Network)
	if networkRef == "" || (an != nil && an.Name == networkRef) {
		networkID = an.ID
	} else {
		rn, xerr := networkfactory.Load(task, svc, networkRef)
		if xerr != nil {
			return nil, xerr
		}
		networkID = rn.GetID()
	}
	list, xerr := subnetfactory.List(task, svc, networkID, in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	// Build response mapping abstract.Networking to protocol.Networking
	var pbList []*protocol.Subnet
	for _, subnet := range list {
		//if networkID == "" || subnet.Networking == networkID {
		pbList = append(pbList, converters.SubnetFromAbstractToProtocol(subnet))
		//}
	}
	resp := &protocol.SubnetList{Subnets: pbList}
	return resp, nil
}

// Inspect returns infos on a subnet
func (s *SubnetListener) Inspect(ctx context.Context, in *protocol.SubnetInspectRequest) (_ *protocol.Subnet, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect Subnet")
	defer fail.OnPanic(&err)

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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "network subnet inspect")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.subnet"), "(%s, %s)", networkRefLabel, subnetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	subnet, xerr := subnetfactory.Load(task, job.GetService(), networkRef, subnetRef)
	if xerr != nil {
		return nil, xerr
	}
	return subnet.ToProtocol(task)
}

// Delete a/many subnet/s
func (s *SubnetListener) Delete(ctx context.Context, in *protocol.SubnetInspectRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot delete Subnet")

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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "network subnet delete")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(task, true, "(%s, %s)", networkRefLabel, subnetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	var rs resources.Subnet
	if rs, xerr = subnetfactory.Load(task, svc, networkRef, subnetRef); xerr == nil {
		xerr = rs.Delete(task)
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a Subnet not found as a successful deletion
		default:
			return empty, fail.Wrap(xerr, "failed to delete Subnet '%s' in Network '%s'", subnetRef, networkRef)
		}
	}

	logrus.Infof("Subnet %s successfully deleted.", subnetRefLabel)
	return empty, nil
}

// BindSecurityGroup attaches a Security Group to a hostnetwork
func (s *SubnetListener) BindSecurityGroup(ctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot bind Security Group to Subnet")

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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "network subnet security group bind")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.subnet"), "(%s, %s, %s)", networkRefLabel, subnetRef, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rs, xerr := subnetfactory.Load(task, svc, networkRef, subnetRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}

	var enable resources.SecurityGroupActivation
	switch in.GetState() {
	case protocol.SecurityGroupState_SGS_DISABLED:
		enable = resources.SecurityGroupDisable
	default:
		enable = resources.SecurityGroupEnable
	}

	if xerr = rs.BindSecurityGroup(task, sg, enable); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// UnbindSecurityGroup detaches a Security Group from a subnet
func (s *SubnetListener) UnbindSecurityGroup(ctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot unbind Security Group from Subnet")

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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Networking")
	}

	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "network subnet security group unbind")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.subnet"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}

	if rs, xerr := subnetfactory.Load(task, svc, networkRef, subnetRef); xerr == nil {
		xerr = rs.UnbindSecurityGroup(task, sg)
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If Subnet does not exist, try to see if there is metadata in Security Group to clean up
			xerr = sg.UnbindFromSubnetByReference(task, subnetRef)
		default:
			return empty, xerr
		}
	}
	return empty, nil
}

// EnableSecurityGroup applies the rules of a bound security group on a network
func (s *SubnetListener) EnableSecurityGroup(ctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot enable Security Group of Subnet")

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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "network subnet security group enable")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.subnet"), "(%s, %s, %s)", networkRefLabel, subnetRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rs, xerr := subnetfactory.Load(task, svc, networkRef, subnetRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rs.EnableSecurityGroup(task, sg); xerr != nil {
		return empty, xerr
	}

	return empty, nil
}

// DisableSecurityGroup detaches a Security Group from a subnet
func (s *SubnetListener) DisableSecurityGroup(ctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot disable Security Group of Subnet")

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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "network subnet security group disable")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.subnet"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rs, xerr := subnetfactory.Load(task, svc, networkRef, subnetRef)
	if xerr != nil {
		return empty, xerr
	}
	sg, xerr := securitygroupfactory.Load(task, svc, sgRef)
	if xerr != nil {
		return empty, xerr
	}
	if xerr = rs.DisableSecurityGroup(task, sg); xerr != nil {
		return empty, xerr
	}
	return empty, nil
}

// ListSecurityGroups lists the Security Group bound to subnet
func (s *SubnetListener) ListSecurityGroups(ctx context.Context, in *protocol.SecurityGroupSubnetBindRequest) (_ *protocol.SecurityGroupBondsResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err)
	defer fail.OnExitWrapError(&err, "cannot list Security Groups bound to Subnet")

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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "network subnet security group list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.subnet"), "(%s)", networkRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	state := securitygroupstate.Enum(in.GetState())

	rs, xerr := subnetfactory.Load(task, svc, networkRef, subnetRef)
	if xerr != nil {
		return nil, xerr
	}
	bonds, xerr := rs.ListSecurityGroups(task, state)
	if xerr != nil {
		return nil, xerr
	}
	resp := converters.SecurityGroupBondsFromPropertyToProtocol(bonds, "subnets")
	return resp, nil
}
