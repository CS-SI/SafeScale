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

	netretry "github.com/CS-SI/SafeScale/v21/lib/utils/net"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupstate"
	subnetfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/securitygroup"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v21/lib/server/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
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

	networkRef, networkLabel := srvutils.GetReference(in.GetNetwork())
	if networkRef == "" {
		return nil, fail.InvalidParameterError("in.Network", "must contain an ID or a Name")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/subnet/%s/create", networkRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.subnet"), "(%s, '%s')", networkLabel, in.GetName()).WithStopwatch().Entering()
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

	networkInstance, xerr := networkfactory.Load(job.Service(), networkRef)
	if xerr != nil {
		return nil, xerr
	}

	defer networkInstance.Released()

	subnetInstance, xerr := subnetfactory.New(job.Service())
	if xerr != nil {
		return nil, xerr
	}

	// If there is conflict with docker quit
	cidr := in.GetCidr()
	thisCidr := netretry.CIDRString(cidr)
	conflict, err := thisCidr.IntersectsWith("172.17.0.0/16")
	if err != nil {
		return nil, err
	}
	if conflict {
		return nil, fail.InvalidRequestError("cidr %s intersects with default docker network %s", cidr, "172.17.0.0/16")
	}

	req := abstract.SubnetRequest{
		NetworkID:      networkInstance.GetID(),
		Name:           in.GetName(),
		CIDR:           in.GetCidr(),
		Domain:         in.GetDomain(),
		HA:             in.GetFailOver(),
		DefaultSSHPort: in.GetGateway().GetSshPort(),
		KeepOnFailure:  in.GetKeepOnFailure(),
	}

	xerr = subnetInstance.Create(job.Context(), req, gwName, sizing)
	if xerr != nil {
		return nil, xerr
	}

	defer subnetInstance.Released()

	xerr = networkInstance.AdoptSubnet(job.Context(), subnetInstance)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Subnet '%s' successfully created.", req.Name)
	return subnetInstance.ToProtocol()
}

// List existing networks
func (s *SubnetListener) List(ctx context.Context, in *protocol.SubnetListRequest) (_ *protocol.SubnetList, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(&ferr)
	defer fail.OnExitLogError(&ferr)
	defer fail.OnExitWrapError(&ferr, "cannot list Subnets")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), "/subnets/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.subnet"), "(%v, %v)", in.Network, in.All).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

	var networkID string
	networkRef, _ := srvutils.GetReference(in.Network)
	if networkRef == "" {
		withDefaultNetwork, err := job.Service().HasDefaultNetwork()
		if err != nil {
			return nil, err
		}
		if withDefaultNetwork {
			an, xerr := job.Service().GetDefaultNetwork()
			if xerr != nil {
				return nil, xerr
			}
			networkID = an.ID
		}
	} else {
		networkInstance, xerr := networkfactory.Load(job.Service(), networkRef)
		if xerr != nil {
			return nil, xerr
		}

		networkID = networkInstance.GetID()
		networkInstance.Released()
	}
	list, xerr := subnetfactory.List(job.Context(), job.Service(), networkID, in.GetAll())
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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())
	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/network/%s/subnetInstance/%s/inspect", networkRef, subnetRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.subnetInstance"), "(%s, %s)", networkRefLabel, subnetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	subnetInstance, xerr := subnetfactory.Load(job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return nil, xerr
	}

	defer subnetInstance.Released()

	return subnetInstance.ToProtocol()
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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/network/%s/subnet/%s/delete", networkRef, subnetRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), true, "(%s, %s)", networkRefLabel, subnetRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	var (
		networkInstance resources.Network
		subnetInstance  resources.Subnet
		subnetID        string
	)
	subnetInstance, xerr = subnetfactory.Load(job.Service(), networkRef, subnetRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a Subnet not found as a job done
			debug.IgnoreError(xerr)
			return empty, nil
		default:
			return empty, fail.Wrap(xerr, "failed to delete Subnet '%s' in Network '%s'", subnetRef, networkRef)
		}
	}
	clean := true
	subnetID = subnetInstance.GetID()
	networkInstance, xerr = subnetInstance.InspectNetwork()
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a Subnet not found as a successful deletion
			debug.IgnoreError(xerr)
			clean = false
		default:
			return empty, fail.Wrap(xerr, "failed to delete Subnet '%s' in Network '%s'", subnetRef, networkRef)
		}
	}
	if clean {
		xerr = subnetInstance.Delete(job.Context())
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// consider a Subnet not found as a job done
				debug.IgnoreError(xerr)
			default:
				return empty, fail.Wrap(xerr, "failed to delete Subnet '%s' in Network '%s'", subnetRef, networkRef)
			}
		}
	}

	if networkInstance != nil {
		defer networkInstance.Released()

		xerr = networkInstance.AbandonSubnet(job.Context(), subnetID)
		if xerr != nil {
			return empty, xerr
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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/network/%s/subnet/%s/securitygroup/%s/bind", networkRef, subnetRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.subnet"), "(%s, %s, %s)", networkRefLabel, subnetRef, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	subnetInstance, xerr := subnetfactory.Load(job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return empty, xerr
	}

	defer subnetInstance.Released()

	sgInstance, xerr := securitygroupfactory.Load(job.Service(), sgRef)
	if xerr != nil {
		return empty, xerr
	}

	defer sgInstance.Released()

	var enable resources.SecurityGroupActivation
	switch in.GetState() {
	case protocol.SecurityGroupState_SGS_DISABLED:
		enable = resources.SecurityGroupDisable
	default:
		enable = resources.SecurityGroupEnable
	}

	xerr = subnetInstance.BindSecurityGroup(job.Context(), sgInstance, enable)
	if xerr != nil {
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

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/network/%s/subnet/%s/securitygroup/%s/unbind", networkRef, subnetRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.subnet"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	var sgInstance resources.SecurityGroup
	sgInstance, xerr = securitygroupfactory.Load(job.Service(), sgRef)
	if xerr != nil {
		return empty, xerr
	}

	defer sgInstance.Released()

	var subnetInstance resources.Subnet
	subnetInstance, xerr = subnetfactory.Load(job.Service(), networkRef, subnetRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If Subnet does not exist, try to see if there is metadata in Security Group to clean up
			xerr = sgInstance.UnbindFromSubnetByReference(job.Context(), subnetRef)
			if xerr != nil {
				return empty, xerr
			}
		default:
			return empty, xerr
		}
	}

	defer subnetInstance.Released()
	xerr = subnetInstance.UnbindSecurityGroup(job.Context(), sgInstance)
	if xerr != nil {
		return empty, xerr
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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, subnetRefLabel := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/network/%s/subnet/%s/securitygroup/%s/enable", networkRef, subnetRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.subnet"), "(%s, %s, %s)", networkRefLabel, subnetRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	subnetInstance, xerr := subnetfactory.Load(job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return empty, xerr
	}

	defer subnetInstance.Released()

	sgInstance, xerr := securitygroupfactory.Load(job.Service(), sgRef)
	if xerr != nil {
		return empty, xerr
	}

	defer sgInstance.Released()

	xerr = subnetInstance.EnableSecurityGroup(job.Context(), sgInstance)
	if xerr != nil {
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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	sgRef, sgRefLabel := srvutils.GetReference(in.GetGroup())
	if sgRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference of Security Group")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("/network/%s/subnet/%s/securitygroup/%s/disable", networkRef, subnetRef, sgRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.subnet"), "(%s, %s)", networkRefLabel, sgRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	subnetInstance, xerr := subnetfactory.Load(job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return empty, xerr
	}

	defer subnetInstance.Released()

	sgInstance, xerr := securitygroupfactory.Load(job.Service(), sgRef)
	if xerr != nil {
		return empty, xerr
	}

	defer sgInstance.Released()

	xerr = subnetInstance.DisableSecurityGroup(job.Context(), sgInstance)
	if xerr != nil {
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

	networkRef, networkRefLabel := srvutils.GetReference(in.GetNetwork())

	subnetRef, _ := srvutils.GetReference(in.GetSubnet())
	if subnetRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference for Subnet")
	}

	job, xerr := PrepareJob(ctx, in.GetNetwork().GetTenantId(), fmt.Sprintf("network/%s/subnet/%s/securitygroups/list", networkRef, subnetRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.subnet"), "(%s)", networkRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	state := securitygroupstate.Enum(in.GetState())

	subnetInstance, xerr := subnetfactory.Load(job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return nil, xerr
	}

	defer subnetInstance.Released()

	bonds, xerr := subnetInstance.ListSecurityGroups(job.Context(), state)
	if xerr != nil {
		return nil, xerr
	}

	resp := converters.SecurityGroupBondsFromPropertyToProtocol(bonds, "subnets")
	return resp, nil
}
