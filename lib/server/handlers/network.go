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
	"fmt"

	"github.com/CS-SI/SafeScale/lib/server"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

//go:generate mockgen -destination=../mocks/mock_networkapi.go -package=mocks github.com/CS-SI/SafeScale/lib/server/handlers NetworkAPI

// TODO At service level, we need to log before returning, because it's the last chance to track the real issue in server side

// NetworkHandler defines API to manage networks
type NetworkHandler interface {
	Create(string, string, ipversion.Enum, resources.SizingRequirements, string, string, bool) (*resources.Network, error)
	List(bool) ([]*resources.Network, error)
	Inspect(string) (*resources.Network, error)
	Delete(string) error
}

// FIXME ROBUSTNESS All functions MUST propagate context
// FIXME Technical debt Input verification

// networkHandler an implementation of NetworkAPI
type networkHandler struct {
	job       server.Job
	ipVersion ipversion.Enum
}

// NewNetworkHandler Creates new Network service
func NewNetworkHandler(job server.Job) NetworkHandler {
	return &networkHandler{job: job}
}

// Create creates a network
func (handler *networkHandler) Create(
	name string, cidr string, ipVersion ipversion.Enum,
	sizing abstract.SizingRequirements, theos string, gwname string,
	failover bool,
) (network resources.Network, err error) {

	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if name == "" {
		return nil, scerr.InvalidParameterError("name", "cannot be empty string")
	}
	if failover && gwname != "" {
		return nil, scerr.InvalidParameterError("gwname", "cannot be set if failover is set")
	}

	task := handler.task.Job()
	tracer := concurrency.NewTracer(
		task,
		fmt.Sprintf("('%s', '%s', %s, <sizing>, '%s', '%s', %v)", name, cidr, ipVersion.String(), theos, gwname, failover),
		true,
	).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objn, err := networkfactory.New(handler.service)
	if err != nil {
		return nil, err
	}
	req := abstract.NetworkRequest{
		Name:      name,
		IPVersion: ipVersion,
		CIDR:      cidr,
	}
	err = objn.Create(task, req, gwname, &sizing)
	if err != nil {
		return nil, err
	}
	return objn, nil
}

// List returns the network list
func (handler *networkHandler) List(all bool) (netList []*abstract.Network, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%v)", all), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	objn, err := networkfactory.New(handler.service)
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
func (handler *NetworkHandler) Inspect(ref string) (network resources.Network, err error) {
	if handler == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	return networkfactory.Load(task, handler.service, ref)
}

// Delete deletes network referenced by ref
func (handler *networkHandler) Delete(ref string) (err error) {
	if handler == nil {
		return scerr.InvalidInstanceError()
	}
	if handler.job == nil {
		return nil, scerr.InvalidInstanceContentError("handler.job", "cannot be nil")
	}
	if ref == "" {
		return nil, scerr.InvalidParameterError("ref", "cannot be empty string")
	}

	task := handler.job.Task()
	tracer := concurrency.NewTracer(task, fmt.Sprintf("('%s')", ref), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	objn, err := networkfactory.Load(task, handler.service, ref)
	if err == nil {
		err = objn.Delete(task)
	}
	return err
}
