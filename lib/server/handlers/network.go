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

package handlers

import (
    "github.com/CS-SI/SafeScale/lib/server"
    "github.com/CS-SI/SafeScale/lib/server/resources"
    "github.com/CS-SI/SafeScale/lib/server/resources/abstract"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
    networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
    "github.com/CS-SI/SafeScale/lib/utils/debug"
    "github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers NetworkHandler

// NetworkHandler defines API to manage networks
type NetworkHandler interface {
    Create(string, string, ipversion.Enum, abstract.HostSizingRequirements, string, string, bool, bool, string) (resources.Network, fail.Error)
    List(bool) ([]*abstract.Network, fail.Error)
    Inspect(string) (resources.Network, fail.Error)
    Delete(string) fail.Error
}

// FIXME: Technical debt Input verification

// networkHandler an implementation of NetworkAPI
type networkHandler struct {
    job server.Job
    // ipVersion ipversion.Enum
}

// NewNetworkHandler Creates new Network service
func NewNetworkHandler(job server.Job) NetworkHandler {
    return &networkHandler{job: job}
}

// Create creates a network
func (handler *networkHandler) Create(
    name string, cidr string, ipVersion ipversion.Enum,
    sizing abstract.HostSizingRequirements, theos string, gwname string,
    failover bool, keepOnFailure bool, domain string,
) (network resources.Network, xerr fail.Error) {

    if handler == nil {
        return nil, fail.InvalidInstanceError()
    }
    if handler.job == nil {
        return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
    }
    if name == "" {
        return nil, fail.InvalidParameterError("name", "cannot be empty string")
    }
    if failover && gwname != "" {
        return nil, fail.InvalidParameterError("gwname", "cannot be set if failover is set")
    }

    task := handler.job.GetTask()
    tracer := debug.NewTracer(
        task,
        tracing.ShouldTrace("handlers.network"),
        "('%s', '%s', %s, <sizing>, '%s', '%s', %v)", name, cidr, ipVersion.String(), theos, gwname, failover,
    ).WithStopwatch().Entering()
    defer tracer.Exiting()
    // VPL: coding rule "propagate or log error": here propagate
    // defer fail.OnExitLogError(&err, tracer.TraceMessage())
    defer fail.OnPanic(&xerr)

    objn, xerr := networkfactory.New(handler.job.GetService())
    if xerr != nil {
        return nil, xerr
    }
    req := abstract.NetworkRequest{
        Name:          name,
        IPVersion:     ipVersion,
        CIDR:          cidr,
        HA:            failover,
        KeepOnFailure: keepOnFailure,
        Domain:        domain,
    }
    xerr = objn.Create(task, req, gwname, &sizing)
    if xerr != nil {
        return nil, xerr
    }
    return objn, nil
}

// ErrorList returns the network list
func (handler *networkHandler) List(all bool) (netList []*abstract.Network, xerr fail.Error) {
    if handler == nil {
        return nil, fail.InvalidInstanceError()
    }
    if handler.job == nil {
        return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
    }

    task := handler.job.GetTask()
    tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.network"), "(%v)", all).WithStopwatch().Entering()
    defer tracer.Exiting()
    // defer fail.OnExitLogError(&err, tracer.TraceMessage())
    defer fail.OnPanic(&xerr)

    objn, xerr := networkfactory.New(handler.job.GetService())
    if xerr != nil {
        return nil, xerr
    }

    xerr = objn.Browse(task, func(rn *abstract.Network) fail.Error {
        netList = append(netList, rn)
        return nil
    })
    return netList, xerr
}

// Inspect returns the network identified by ref, ref can be the name or the id
func (handler *networkHandler) Inspect(ref string) (network resources.Network, xerr fail.Error) {
    if handler == nil {
        return nil, fail.InvalidInstanceError()
    }
    if handler.job == nil {
        return nil, fail.InvalidInstanceContentError("handler.job", "cannot be nil")
    }
    if ref == "" {
        return nil, fail.InvalidParameterError("ref", "cannot be empty string")
    }

    task := handler.job.GetTask()
    tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.network"), "('%s')", ref).WithStopwatch().Entering()
    defer tracer.Exiting()
    // defer fail.OnExitLogError(&err, tracer.TraceMessage())
    defer fail.OnPanic(&xerr)

    return networkfactory.Load(task, handler.job.GetService(), ref)
}

// Delete deletes network referenced by ref
func (handler *networkHandler) Delete(ref string) (xerr fail.Error) {
    if handler == nil {
        return fail.InvalidInstanceError()
    }
    if handler.job == nil {
        return fail.InvalidInstanceContentError("handler.job", "cannot be nil")
    }
    if ref == "" {
        return fail.InvalidParameterError("ref", "cannot be empty string")
    }

    task := handler.job.GetTask()
    tracer := debug.NewTracer(task, tracing.ShouldTrace("handlers.network"), "('%s')", ref).WithStopwatch().Entering()
    defer tracer.Exiting()
    // defer fail.OnExitLogError(&err, tracer.TraceMessage())
    defer fail.OnPanic(&xerr)

    objn, xerr := networkfactory.Load(task, handler.job.GetService(), ref)
    if xerr != nil {
        return xerr
    }
    return objn.Delete(task)
}
