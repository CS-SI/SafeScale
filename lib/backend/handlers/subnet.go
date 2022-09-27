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

	"github.com/CS-SI/SafeScale/v22/lib/backend/common/job"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	networkfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/network"
	securitygroupfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/securitygroup"
	subnetfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/subnet"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.SubnetHandler -o mocks/mock_subnet.go

type SubnetHandler interface {
	BindSecurityGroup(networkRef string, subnetRef string, sgRef string, enable resources.SecurityGroupActivation) fail.Error
	Create(networkRef string, req abstract.SubnetRequest, gwName string, sizing abstract.HostSizingRequirements) (resources.Subnet, fail.Error)
	Delete(networkRef string, subnetRef string, force bool) fail.Error
	DisableSecurityGroup(networkRef string, subnetRef string, sgRef string) fail.Error
	EnableSecurityGroup(networkRef string, subnetRef string, sgRef string) fail.Error
	Inspect(networkRef string, subnetRef string) (resources.Subnet, fail.Error)
	List(networkRef string, all bool) ([]*abstract.Subnet, fail.Error)
	ListSecurityGroups(networkRef string, subnetRef string, state securitygroupstate.Enum) ([]*propertiesv1.SecurityGroupBond, fail.Error)
	UnbindSecurityGroup(networkRef, subnetRef, sgRef string) fail.Error
}

// SubnetHandler ...
type subnetHandler struct {
	job job.Job
}

func NewSubnetHandler(job job.Job) SubnetHandler {
	return &subnetHandler{job}
}

// Create a new subnet
func (handler *subnetHandler) Create(networkRef string, req abstract.SubnetRequest, gwName string, sizing abstract.HostSizingRequirements) (_ resources.Subnet, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if valid.IsNil(req) {
		return nil, fail.InvalidParameterError("in", "cannot be null value of 'abstract.SubnetRequest'")
	}
	if networkRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("networkRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.subnet"), "('%s')", networkRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	thisCidr := netretry.CIDRString(req.CIDR)
	conflict, err := thisCidr.IntersectsWith("172.17.0.0/16")
	if err != nil {
		return nil, fail.Wrap(err)
	}
	if conflict {
		return nil, fail.InvalidRequestError("cidr %s intersects with default docker network %s", req.CIDR, "172.17.0.0/16")
	}

	networkInstance, xerr := networkfactory.Load(handler.job.Context(), handler.job.Service(), networkRef)
	if xerr != nil {
		return nil, xerr
	}

	req.NetworkID, err = networkInstance.GetID()
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	subnetInstance, xerr := subnetfactory.New(handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}

	xerr = subnetInstance.Create(handler.job.Context(), req, gwName, &sizing)
	if xerr != nil {
		return nil, xerr
	}

	xerr = networkInstance.AdoptSubnet(handler.job.Context(), subnetInstance)
	if xerr != nil {
		return nil, xerr
	}

	tracer.Trace("Subnet '%s' successfully created.", req.Name)
	return subnetInstance, nil
}

// List existing networks
func (handler *subnetHandler) List(networkRef string, all bool) (_ []*abstract.Subnet, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.subnet"), "(%v, %v)", networkRef, all).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	var networkID string
	svc := handler.job.Service()
	if networkRef == "" {
		withDefaultNetwork, xerr := svc.HasDefaultNetwork()
		if xerr != nil {
			return nil, xerr
		}

		if withDefaultNetwork {
			an, xerr := svc.DefaultNetwork(handler.job.Context())
			if xerr != nil {
				return nil, xerr
			}

			networkID = an.ID
		}
	} else {
		networkInstance, xerr := networkfactory.Load(handler.job.Context(), handler.job.Service(), networkRef)
		if xerr != nil {
			return nil, xerr
		}

		_, err := networkInstance.GetID()
		if err != nil {
			return nil, fail.ConvertError(err)
		}
	}

	return subnetfactory.List(handler.job.Context(), handler.job.Service(), networkID, all)
}

// Inspect returns infos on a subnet
func (handler *subnetHandler) Inspect(networkRef, subnetRef string) (_ resources.Subnet, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if networkRef == "" && subnetRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("networkRef+subnetRef")
	}
	if subnetRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("subnetRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.subnet"), "'%s', '%s')", networkRef, subnetRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	return subnetfactory.Load(handler.job.Context(), handler.job.Service(), networkRef, subnetRef)
}

// Delete a/many subnet/s
func (handler *subnetHandler) Delete(networkRef, subnetRef string, force bool) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if networkRef == "" && subnetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("networkRef+subnetRef")
	}
	if subnetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("subnetRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), true, "('%s', '%s')", networkRef, subnetRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	newCtx := context.WithValue(handler.job.Context(), "force", force) // nolint

	var (
		networkInstance resources.Network
		subnetInstance  resources.Subnet
	)
	subnetInstance, xerr := subnetfactory.Load(handler.job.Context(), handler.job.Service(), networkRef, subnetRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a Subnet not found as a job done
			debug.IgnoreError(xerr)
			return nil
		default:
			return fail.Wrap(xerr, "failed to delete Subnet '%s' in Network '%s'", subnetRef, networkRef)
		}
	}

	clean := true
	subnetID, err := subnetInstance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	networkInstance, xerr = subnetInstance.InspectNetwork(handler.job.Context())
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// consider a Subnet not found as a successful deletion
			debug.IgnoreError(xerr)
			clean = false
		default:
			return fail.Wrap(xerr, "failed to delete Subnet '%s' in Network '%s'", subnetRef, networkRef)
		}
	}
	if clean {
		xerr = subnetInstance.Delete(newCtx)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// consider a Subnet not found as a job done
				debug.IgnoreError(xerr)
			default:
				return fail.Wrap(xerr, "failed to delete Subnet '%s' in Network '%s'", subnetRef, networkRef)
			}
		}
	}

	if networkInstance != nil {
		xerr = networkInstance.AbandonSubnet(newCtx, subnetID)
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// BindSecurityGroup attaches a Security Group to a Subnet
func (handler *subnetHandler) BindSecurityGroup(networkRef, subnetRef, sgRef string, enable resources.SecurityGroupActivation) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if networkRef == "" && subnetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("networkRef+subnetRef")
	}
	if subnetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("subnetRef")
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}
	if enable != resources.SecurityGroupDisable && enable != resources.SecurityGroupEnable {
		return fail.InvalidParameterError("enable", "must be either 'resources.SecurityGroupEnable' or 'resources.SecurityGroupDisable'")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.subnet"), "('%s', '%s', '%s')", networkRef, subnetRef, sgRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	subnetInstance, xerr := subnetfactory.Load(handler.job.Context(), handler.job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef)
	if xerr != nil {
		return xerr
	}

	return subnetInstance.BindSecurityGroup(handler.job.Context(), sgInstance, enable)
}

// UnbindSecurityGroup detaches a Security Group from a subnet
func (handler *subnetHandler) UnbindSecurityGroup(networkRef, subnetRef, sgRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if subnetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("subnetRef")
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.subnet"), "('%s', '%s', '%s')", networkRef, subnetRef, sgRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef)
	if xerr != nil {
		return xerr
	}

	subnetInstance, xerr := subnetfactory.Load(handler.job.Context(), handler.job.Service(), networkRef, subnetRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// If Subnet does not exist, try to see if there is metadata in Security Group to clean up
			xerr = sgInstance.UnbindFromSubnetByReference(handler.job.Context(), subnetRef)
			if xerr != nil {
				return xerr
			}
		default:
			return xerr
		}
	}

	return subnetInstance.UnbindSecurityGroup(handler.job.Context(), sgInstance)
}

// EnableSecurityGroup applies the rules of a bound security group on a network
func (handler *subnetHandler) EnableSecurityGroup(networkRef, subnetRef, sgRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if subnetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("subnetRef")
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.subnet"), "('%s', '%s', '%s')", networkRef, subnetRef, sgRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	subnetInstance, xerr := subnetfactory.Load(handler.job.Context(), handler.job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef)
	if xerr != nil {
		return xerr
	}

	xerr = subnetInstance.EnableSecurityGroup(handler.job.Context(), sgInstance)
	if xerr != nil {
		return xerr
	}

	return nil
}

// DisableSecurityGroup detaches a Security Group from a subnet
func (handler *subnetHandler) DisableSecurityGroup(networkRef, subnetRef, sgRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if subnetRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("subnetRef")
	}
	if sgRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("sgRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.subnet"), "('%s', '%s', '%s')", networkRef, subnetRef, sgRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	subnetInstance, xerr := subnetfactory.Load(handler.job.Context(), handler.job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return xerr
	}

	sgInstance, xerr := securitygroupfactory.Load(handler.job.Context(), handler.job.Service(), sgRef)
	if xerr != nil {
		return xerr
	}

	xerr = subnetInstance.DisableSecurityGroup(handler.job.Context(), sgInstance)
	if xerr != nil {
		return xerr
	}

	return nil
}

// ListSecurityGroups lists the Security Group bound to subnet
func (handler *subnetHandler) ListSecurityGroups(networkRef, subnetRef string, state securitygroupstate.Enum) (_ []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if networkRef == "" && subnetRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("networkRef+subnetRef")
	}
	if subnetRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("subnetRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.subnet"), "('%s', '%s')", networkRef, subnetRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	subnetInstance, xerr := subnetfactory.Load(handler.job.Context(), handler.job.Service(), networkRef, subnetRef)
	if xerr != nil {
		return nil, xerr
	}

	return subnetInstance.ListSecurityGroups(handler.job.Context(), state)
}
