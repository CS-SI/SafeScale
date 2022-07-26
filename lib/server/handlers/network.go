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

package handlers

import (
	"context"
	"net"

	"github.com/CS-SI/SafeScale/v22/lib/server"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/network"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/sirupsen/logrus"
)

const (
	defaultCIDR = "192.168.0.0/23"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/server/handlers.NetworkHandler -o mocks/mock_network.go

// NetworkHandler exposes Network handling methods
type NetworkHandler interface {
	Create(networkReq abstract.NetworkRequest, subnetReq *abstract.SubnetRequest, gwName string, gwSizing *abstract.HostSizingRequirements) (resources.Network, fail.Error)
	Delete(networkRef string, force bool) fail.Error
	Inspect(networkRef string) (resources.Network, fail.Error)
	List(all bool) ([]*abstract.Network, fail.Error)
}

// networkHandler is one implementation of NetworkHandler interface
type networkHandler struct {
	job server.Job
}

// NewNetworkHandler returns an instance of *networkHandler that satisfies interface NetworkHandler
func NewNetworkHandler(job server.Job) NetworkHandler {
	return &networkHandler{job}
}

// Create a new network
func (handler *networkHandler) Create(networkReq abstract.NetworkRequest, subnetReq *abstract.SubnetRequest, gwName string, gwSizing *abstract.HostSizingRequirements) (_ resources.Network, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	defer fail.OnExitLogError(handler.job.Context(), &ferr, "cannot create network")

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if networkReq.Name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("networkReq.Name")
	}

	tracer := debug.NewTracer(handler.job.Context(), true, "('%s')", networkReq.Name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	if networkReq.CIDR == "" {
		networkReq.CIDR = defaultCIDR
	}

	// If there is conflict with docker quit
	thisCidr := netretry.CIDRString(networkReq.CIDR)
	conflict, err := thisCidr.IntersectsWith("172.17.0.0/16")
	if err != nil {
		return nil, fail.Wrap(err)
	}
	if conflict {
		return nil, fail.InvalidRequestError("requested CIDR '%s' intersects with default docker network '%s'", "172.17.0.0/16")
	}

	networkInstance, xerr := networkfactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}

	xerr = networkInstance.Create(handler.job.Context(), networkReq)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !networkReq.KeepOnFailure {
			if derr := networkInstance.Delete(context.Background()); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Network '%s'", networkReq.Name))
			}
		}
	}()

	if subnetReq != nil {
		_, networkNet, _ := net.ParseCIDR(networkReq.CIDR)
		subnetNet, xerr := netretry.FirstIncludedSubnet(*networkNet, 1)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to derive the CIDR of the Subnet from Network CIDR '%s'", networkReq.CIDR)
		}

		logrus.WithContext(handler.job.Context()).Debugf("Creating default Subnet of Network '%s' with CIDR '%s'", networkReq.Name, subnetNet.String())

		if gwSizing == nil {
			gwSizing = &abstract.HostSizingRequirements{MinGPU: -1}
		}

		subnetInstance, xerr := subnetfactory.New(handler.job.Service())
		if xerr != nil {
			return nil, xerr
		}

		subnetReq.NetworkID, err = networkInstance.GetID()
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		subnetReq.Name = networkReq.Name
		subnetReq.CIDR = subnetNet.String()
		subnetReq.KeepOnFailure = networkReq.KeepOnFailure
		xerr = subnetInstance.Create(handler.job.Context(), *subnetReq, gwName, gwSizing)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to create subnet '%s'", networkReq.Name)
		}
	}

	return networkInstance, nil
}

// List existing networks
func (handler *networkHandler) List(all bool) (_ []*abstract.Network, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.network"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	if all {
		return handler.job.Service().ListNetworks(handler.job.Context())
	}

	return networkfactory.List(handler.job.Context(), handler.job.Service())
}

// Inspect returns infos on a network
func (handler *networkHandler) Inspect(networkRef string) (_ resources.Network, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)
	defer fail.OnExitWrapError(handler.job.Context(), &ferr, "cannot inspect network")

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if networkRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("networkRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.network"), "('%s')", networkRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	return networkfactory.Load(handler.job.Context(), handler.job.Service(), networkRef)
}

// Delete a network
func (handler *networkHandler) Delete(networkRef string, force bool) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if networkRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("networkRef")
	}

	if force {
		logrus.Tracef("forcing network deletion")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.network"), "('%s')", networkRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	networkInstance, xerr := networkfactory.Load(handler.job.Context(), handler.job.Service(), networkRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			abstractNetwork, xerr := handler.job.Service().InspectNetworkByName(handler.job.Context(), networkRef)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					abstractNetwork, xerr = handler.job.Service().InspectNetwork(handler.job.Context(), networkRef)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return fail.NotFoundError("failed to find Network '%s'", networkRef)
						default:
							return xerr
						}
					}
				default:
					return xerr
				}
			}

			cfg, cerr := handler.job.Service().GetConfigurationOptions(handler.job.Context())
			if cerr != nil {
				return cerr
			}

			name, found := cfg.Get("DefaultNetworkName")
			if found && name.(string) == abstractNetwork.Name {
				return fail.InvalidRequestError("cannot delete default Network '%s' because its existence is not controlled by SafeScale", networkRef)
			}

			return fail.InvalidRequestError("network '%s' is not managed by SafeScale", networkRef)
		default:
			return xerr
		}
	}

	return networkInstance.Delete(handler.job.Context())
}
