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
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers NetworkHandler

// NetworkHandler defines API to manage networks
type NetworkHandler interface {
	Create(string, string, ipversion.Enum, abstract.HostSizingRequirements, string, string, bool, bool) (resources.Network, error)
	List(bool) ([]*abstract.Network, error)
	Inspect(string) (resources.Network, error)
	Delete(string) error
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
	failover bool, keepOnFailure bool,
) (network resources.Network, err error) {

	if handler == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentReport("handler.job", "cannot be nil")
	}
	if name == "" {
		return nil, fail.InvalidParameterReport("name", "cannot be empty string")
	}
	if failover && gwname != "" {
		return nil, fail.InvalidParameterReport("gwname", "cannot be set if failover is set")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(
		task,
		debug.ShouldTrace("handlers.network"),
		"('%s', '%s', %s, <sizing>, '%s', '%s', %v)", name, cidr, ipVersion.String(), theos, gwname, failover,
	).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	// defer fail.OnExitLogError(tracer.TraceMessage(""), &err)
	defer fail.OnPanic(&err)

	objn, err := networkfactory.New(handler.job.SafeGetService())
	if err != nil {
		return nil, err
	}
	req := abstract.NetworkRequest{
		Name:          name,
		IPVersion:     ipVersion,
		CIDR:          cidr,
		HA:            failover,
		KeepOnFailure: keepOnFailure,
	}
	err = objn.Create(task, req, gwname, &sizing)
	if err != nil {
		return nil, err
	}
	return objn, nil
}

// ErrorList returns the network list
func (handler *networkHandler) List(all bool) (netList []*abstract.Network, err error) {
	if handler == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentReport("handler.job", "cannot be nil")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.network"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	// defer fail.OnExitLogError(tracer.TraceMessage(""), &err)
	defer fail.OnPanic(&err)

	objn, err := networkfactory.New(handler.job.SafeGetService())
	if err != nil {
		return nil, err
	}

	err = objn.Browse(task, func(rn *abstract.Network) error {
		netList = append(netList, rn)
		return nil
	})
	return netList, err
}

// Inspect returns the network identified by ref, ref can be the name or the id
func (handler *networkHandler) Inspect(ref string) (network resources.Network, err error) {
	if handler == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if handler.job == nil {
		return nil, fail.InvalidInstanceContentReport("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, fail.InvalidParameterReport("ref", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.network"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	// defer fail.OnExitLogError(tracer.TraceMessage(""), &err)
	defer fail.OnPanic(&err)

	return networkfactory.Load(task, handler.job.SafeGetService(), ref)
}

// Delete deletes network referenced by ref
func (handler *networkHandler) Delete(ref string) (err error) {
	if handler == nil {
		return fail.InvalidInstanceReport()
	}
	if handler.job == nil {
		return fail.InvalidInstanceContentReport("handler.job", "cannot be nil")
	}
	if ref == "" {
		return fail.InvalidParameterReport("ref", "cannot be empty string")
	}

	task := handler.job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("handlers.network"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	// defer fail.OnExitLogError(tracer.TraceMessage(""), &err)
	defer fail.OnPanic(&err)

	objn, err := networkfactory.Load(task, handler.job.SafeGetService(), ref)
	if err != nil {
		return err
	}
	return objn.Delete(task)
}
