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
	"reflect"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/network"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/sirupsen/logrus"
)

const (
	defaultCIDR = "192.168.0.0/23"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.NetworkHandler -o mocks/mock_network.go

// NetworkHandler exposes Network handling methods
type NetworkHandler interface {
	Create(networkReq abstract.NetworkRequest, subnetReq *abstract.SubnetRequest, gwName string, gwSizing *abstract.HostSizingRequirements) (resources.Network, fail.Error)
	Delete(networkRef string, force bool) fail.Error
	Inspect(networkRef string) (resources.Network, fail.Error)
	List(all bool) ([]*abstract.Network, fail.Error)
}

// networkHandler is one implementation of NetworkHandler interface
type networkHandler struct {
	job jobapi.Job
}

// NewNetworkHandler returns an instance of *networkHandler that satisfies interface NetworkHandler
func NewNetworkHandler(ctx context.Context) (NetworkHandler, fail.Error) {
	value := ctx.Value(jobapi.KeyForJobInContext)
	if value == nil {
		return nil, fail.InvalidRequestError("failed to get the job inside the context")
	}

	job, ok := value.(jobapi.Job)
	if !ok {
		return nil, fail.InconsistentError("failed to cast value (%s) to 'jobapi.Job'", reflect.TypeOf(value).String())
	}

	return &networkHandler{job}, nil
}

// Create a new network
func (handler *networkHandler) Create(networkReq abstract.NetworkRequest, subnetReq *abstract.SubnetRequest, gwName string, gwSizing *abstract.HostSizingRequirements) (_ resources.Network, ferr fail.Error) {
	ctx := handler.job.Context()
	defer func() {
		if ferr != nil {
			ferr.WithContext(ctx)
		}
	}()
	defer fail.OnPanic(&ferr)
	defer fail.OnExitLogError(ctx, &ferr, "cannot create network")

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if networkReq.Name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("networkReq.Name")
	}

	tracer := debug.NewTracer(ctx, true, "('%s')", networkReq.Name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

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

	networkInstance, xerr := networkfactory.New(ctx)
	if xerr != nil {
		return nil, xerr
	}

	xerr = networkInstance.Create(ctx, networkReq)
	if xerr != nil {
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && networkReq.CleanOnFailure() {
			derr := networkInstance.Delete(jobapi.NewContextPropagatingJob(ctx))
			if derr != nil {
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

		logrus.WithContext(ctx).Debugf("Creating default Subnet of Network '%s' with CIDR '%s'", networkReq.Name, subnetNet.String())

		if gwSizing == nil {
			gwSizing = &abstract.HostSizingRequirements{MinGPU: -1}
		}

		subnetInstance, xerr := subnetfactory.New(ctx)
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
		xerr = subnetInstance.Create(ctx, *subnetReq, gwName, gwSizing, nil)
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

	return networkfactory.List(handler.job.Context())
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

	return networkfactory.Load(handler.job.Context(), networkRef)
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

	ctx := handler.job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("handlers.network"), "('%s')", networkRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage())

	networkInstance, xerr := networkfactory.Load(ctx, networkRef)
	if xerr != nil {
		var abstractNetwork *abstract.Network
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// FIXME: InspectNetworkByName is not yet implemented in ovhtf
			// abstractNetwork, xerr := svc.InspectNetworkByName(ctx, networkRef)
			// if xerr != nil {
			// 	switch xerr.(type) {
			// 	case *fail.ErrNotFound:
			abstractNetwork, xerr = handler.job.Service().InspectNetwork(ctx, networkRef)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					return fail.NotFoundError("failed to find Network '%s'", networkRef)
				default:
					return xerr
				}
			}
			//	default:
			//		return xerr
			//	}
			// }

			cfg, cerr := handler.job.Service().ConfigurationOptions()
			if cerr != nil {
				return cerr
			}

			if cfg.DefaultNetworkName == abstractNetwork.Name {
				return fail.InvalidRequestError("cannot delete default Network '%s' because its existence is not controlled by SafeScale", networkRef)
			}

			return fail.InvalidRequestError("network '%s' is not managed by SafeScale", networkRef)
		default:
			return xerr
		}
	}

	return networkInstance.Delete(ctx)
}
