/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"net"

	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/asaskevich/govalidator"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	subnetfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/lib/utils/net"
)

const (
	defaultCIDR = "192.168.0.0/23"
)

// NetworkListener network service server grpc
type NetworkListener struct{}

// Create a new network
func (s *NetworkListener) Create(ctx context.Context, in *protocol.NetworkCreateRequest) (_ *protocol.Network, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitLogError(&err, "cannot create network")

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
	svc := job.GetService()

	tracer := debug.NewTracer(task, true, "('%s')", networkName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	cidr := in.GetCidr()
	if cidr == "" {
		cidr = defaultCIDR
	}

	req := abstract.NetworkRequest{
		Name:          in.GetName(),
		CIDR:          cidr,
		DNSServers:    in.GetDnsServers(),
		KeepOnFailure: in.GetKeepOnFailure(),
	}
	rn, xerr := networkfactory.New(svc)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = rn.Create(task, req); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if err != nil && !in.GetKeepOnFailure() {
			defer task.DisarmAbortSignal()()

			if derr := rn.Delete(task); derr != nil {
				_ = fail.ToError(err).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network '%s'", in.GetName()))
			}
		}
	}()

	if !in.GetNoSubnet() {
		_, networkNet, _ := net.ParseCIDR(cidr)
		subnetNet, xerr := netretry.FirstIncludedSubnet(*networkNet, 1)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to derive the CIDR of the Subnet from Network CIDR '%s'", in.GetCidr())
		}

		logrus.Debugf("Creating default Subnet of Network '%s' with CIDR '%s'", req.Name, subnetNet.String())

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

		rs, xerr := subnetfactory.New(svc)
		if xerr != nil {
			return nil, xerr
		}
		req := abstract.SubnetRequest{
			NetworkID:      rn.GetID(),
			Name:           in.GetName(),
			CIDR:           subnetNet.String(),
			KeepOnFailure:  in.GetKeepOnFailure(),
			DefaultSSHPort: in.GetGateway().GetSshPort(),
		}
		xerr = rs.Create(task, req, in.GetGateway().GetName(), sizing)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to create subnet '%s'", req.Name)
		}
	}

	tracer.Trace("Network '%s' successfully created.", networkName)
	return rn.ToProtocol(task)
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
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "network list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(task, true /*tracing.ShouldTrace("listeners.network")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	var list []*abstract.Network
	if in.GetAll() {
		list, xerr = svc.ListNetworks()
	} else {
		list, xerr = networkfactory.List(task, svc)
	}
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

	tracer := debug.NewTracer(task, true /*tracing.ShouldTrace("listeners.network")*/, "(%s)", refLabel).WithStopwatch().Entering()
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
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(task, true /*tracing.ShouldTrace("listeners.network")*/, "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rn, xerr := networkfactory.Load(task, svc, ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			an, xerr := svc.InspectNetworkByName(ref)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					an, xerr = svc.InspectNetwork(ref)
				default:
					return empty, xerr
				}
			}
			if xerr != nil {
				switch xerr.(type) { //nolint
				case *fail.ErrNotFound:
					return empty, fail.NotFoundError("failed to find Network %s", refLabel)
				}
				return empty, xerr
			}

			if cfg, xerr := svc.GetConfigurationOptions(); xerr == nil {
				if name, found := cfg.Get("DefaultNetworkName"); found && name.(string) == an.Name {
					return empty, fail.InvalidRequestError("cannot delete default Network %s because its existence is not controlled by SafeScale", refLabel)
				}
			}
			return empty, fail.InvalidRequestError("%s is not managed by SafeScale", refLabel)
		default:
			return empty, xerr
		}
	}
	if xerr = rn.Delete(task); xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Network %s successfully deleted.", refLabel)
	return empty, nil
}
