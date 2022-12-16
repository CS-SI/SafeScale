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

	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/utils"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
)

const (
	defaultCIDR = "192.168.0.0/23"
)

// NetworkListener network service server grpc
type NetworkListener struct {
	protocol.UnimplementedNetworkServiceServer
}

// Create a new network
func (s *NetworkListener) Create(inctx context.Context, in *protocol.NetworkCreateRequest) (_ *protocol.Network, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitLogError(inctx, &ferr, "cannot create network")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkName := in.GetName()
	if networkName == "" {
		return nil, fail.InvalidRequestError("network name cannot be empty string")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/network/%s/create", networkName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, true, "('%s')", networkName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	cidr := in.GetCidr()
	if cidr == "" {
		cidr = defaultCIDR
	}

	// If there is conflict with docker quit
	thisCidr := netretry.CIDRString(cidr)
	conflict, err := thisCidr.IntersectsWith("172.17.0.0/16")
	if err != nil {
		return nil, err
	}
	if conflict {
		return nil, fail.InvalidRequestError("cidr %s intersects with default docker network %s", cidr, "172.17.0.0/16")
	}

	networkReq := abstract.NetworkRequest{
		Name:          networkName,
		CIDR:          cidr,
		DNSServers:    in.GetDnsServers(),
		KeepOnFailure: in.GetKeepOnFailure(),
	}
	var (
		subnetReq *abstract.SubnetRequest
		gwSizing  *abstract.HostSizingRequirements
	)
	if !in.GetNoSubnet() {
		if in.GetGateway() != nil {
			if in.GetGateway().SizingAsString != "" {
				gwSizing, _, xerr = converters.HostSizingRequirementsFromStringToAbstract(in.GetGateway().GetSizingAsString())
				if xerr != nil {
					return nil, xerr
				}
			} else if in.GetGateway().GetSizing() != nil {
				gwSizing = converters.HostSizingRequirementsFromProtocolToAbstract(in.GetGateway().GetSizing())
			}
		}

		subnetReq = &abstract.SubnetRequest{
			Name:           networkName,
			KeepOnFailure:  in.GetKeepOnFailure(),
			DefaultSSHPort: in.GetGateway().GetSshPort(),
			ImageRef:       in.GetGateway().GetImageId(),
		}
	}

	handler := handlers.NewNetworkHandler(job)
	networkInstance, xerr := handler.Create(networkReq, subnetReq, in.GetGateway().Name, gwSizing)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Network '%s' successfully created.", networkName)
	return networkInstance.ToProtocol(ctx)
}

// List existing networks
func (s *NetworkListener) List(inctx context.Context, in *protocol.NetworkListRequest) (_ *protocol.NetworkList, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list networks")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), "/networks/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.network")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewNetworkHandler(job)
	list, xerr := handler.List(in.GetAll())
	if xerr != nil {
		return nil, xerr
	}

	// Build response mapping abstract.Network to protocol.Network
	var pbnetworks []*protocol.Network
	for _, v := range list {
		pbnetworks = append(pbnetworks, converters.NetworkFromAbstractToProtocol(v))
	}
	rv := &protocol.NetworkList{Networks: pbnetworks}
	return rv, nil
}

// Inspect returns infos on a network
func (s *NetworkListener) Inspect(inctx context.Context, in *protocol.Reference) (_ *protocol.Network, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect network")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterError("inctx", "cannot be nil")
	}

	networkRef, networkRefLabel := srvutils.GetReference(in)
	if networkRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(inctx, in.GetTenantId(), fmt.Sprintf("/network/%s/inspect", networkRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("listeners.network")*/, "(%s)", networkRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewNetworkHandler(job)
	networkInstance, xerr := handler.Inspect(networkRef)
	if xerr != nil {
		return nil, xerr
	}

	return networkInstance.ToProtocol(ctx)
}

// Delete a network
func (s *NetworkListener) Delete(inctx context.Context, in *protocol.NetworkDeleteRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete network")

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

	networkRef, networkRefLabel := srvutils.GetReference(in.Network)
	if networkRef == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference")
	}

	force := in.GetForce()
	if force {
		logrus.Tracef("forcing network deletion")
	}

	job, xerr := PrepareJob(inctx, in.Network.GetTenantId(), fmt.Sprintf("/network/%s/delete", networkRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, true /*tracing.ShouldTrace("listeners.network")*/, "(%s)", networkRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewNetworkHandler(job)
	return empty, handler.Delete(networkRef, in.GetForce())
}
