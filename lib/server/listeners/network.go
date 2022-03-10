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
	"net"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/network"
	subnetfactory "github.com/CS-SI/SafeScale/v21/lib/server/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/v21/lib/server/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v21/lib/utils/net"
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
func (s *NetworkListener) Create(ctx context.Context, in *protocol.NetworkCreateRequest) (_ *protocol.Network, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(&ferr)
	defer fail.OnExitLogError(&ferr, "cannot create network")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	networkName := in.GetName()
	if networkName == "" {
		return nil, fail.InvalidRequestError("network name cannot be empty string")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/network/%s/create", networkName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	svc := job.Service()

	tracer := debug.NewTracer(job.Task(), true, "('%s')", networkName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage())

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

	req := abstract.NetworkRequest{
		Name:          in.GetName(),
		CIDR:          cidr,
		DNSServers:    in.GetDnsServers(),
		KeepOnFailure: in.GetKeepOnFailure(),
	}
	networkInstance, xerr := networkfactory.New(svc)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = networkInstance.Create(job.Context(), req); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if ferr != nil && !in.GetKeepOnFailure() {
			// VPL: using context.Background() instead of job.Context() disables the cancellation
			// defer job.Task().DisarmAbortSignal()()
			if dferr := networkInstance.Delete(context.Background()); dferr != nil {
				casted := fail.ConvertError(ferr)
				_ = casted.AddConsequence(fail.Wrap(dferr, "cleaning up on failure, failed to delete Network '%s'", in.GetName()))
				ferr = casted
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

		subnetInstance, xerr := subnetfactory.New(svc)
		if xerr != nil {
			return nil, xerr
		}

		req := abstract.SubnetRequest{
			NetworkID:      networkInstance.GetID(),
			Name:           in.GetName(),
			CIDR:           subnetNet.String(),
			KeepOnFailure:  in.GetKeepOnFailure(),
			DefaultSSHPort: in.GetGateway().GetSshPort(),
			ImageRef:       in.GetGateway().GetImageId(),
		}
		xerr = subnetInstance.Create(job.Context(), req, in.GetGateway().GetName(), sizing)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to create subnet '%s'", req.Name)
		}

		err := subnetInstance.Released()
		if err != nil {
			return nil, fail.Wrap(err)
		}
	}

	err := networkInstance.Released()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	tracer.Trace("Network '%s' successfully created.", networkName)
	return networkInstance.ToProtocol()
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

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "/networks/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	svc := job.Service()

	tracer := debug.NewTracer(job.Task(), true /*tracing.ShouldTrace("listeners.network")*/).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	var list []*abstract.Network
	if in.GetAll() {
		list, xerr = svc.ListNetworks()
	} else {
		list, xerr = networkfactory.List(job.Context(), svc)
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

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/network/%s/inspect", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), true /*tracing.ShouldTrace("listeners.networkInstance")*/, "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	networkInstance, xerr := networkfactory.Load(job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		issue := networkInstance.Released()
		if issue != nil {
			logrus.Warn(issue)
		}
	}()

	return networkInstance.ToProtocol()
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

	ref, refLabel := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("neither name nor id given as reference")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/network/%s/delete", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	svc := job.Service()

	tracer := debug.NewTracer(job.Task(), true /*tracing.ShouldTrace("listeners.network")*/, "(%s)", refLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	networkInstance, xerr := networkfactory.Load(svc, ref)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			abstractNetwork, xerr := svc.InspectNetworkByName(ref)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					abstractNetwork, xerr = svc.InspectNetwork(ref)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return empty, fail.NotFoundError("failed to find Network %s", refLabel)
						default:
							return empty, xerr
						}
					}
				default:
					return empty, xerr
				}
			}

			cfg, cerr := svc.GetConfigurationOptions()
			if cerr != nil {
				return empty, cerr
			}

			if name, found := cfg.Get("DefaultNetworkName"); found && name.(string) == abstractNetwork.Name {
				return empty, fail.InvalidRequestError("cannot delete default Network %s because its existence is not controlled by SafeScale", refLabel)
			}

			return empty, fail.InvalidRequestError("%s is not managed by SafeScale", refLabel)
		default:
			return empty, xerr
		}
	}

	xerr = networkInstance.Delete(job.Context())
	if xerr != nil {
		return empty, xerr
	}

	tracer.Trace("Network %s successfully deleted.", refLabel)
	return empty, nil
}
