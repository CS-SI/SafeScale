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

package listeners

import (
	"context"
	"fmt"

	"github.com/asaskevich/govalidator"
	google_protobuf "github.com/golang/protobuf/ptypes/empty"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	networkfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/network"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// safescale network create net1 --cidr="192.145.0.0/16" --cpu=2 --ram=7 --disk=100 --os="Ubuntu 16.04" (par défault "192.168.0.0/24", on crée une gateway sur chaque réseau: gw-net1)
// safescale network list
// safescale network delete net1
// safescale network inspect net1

// NetworkListener network service server grpc
type NetworkListener struct{}

// Create a new network
func (s *NetworkListener) Create(ctx context.Context, in *protocol.NetworkDefinition) (_ *protocol.Network, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot create network").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	networkName := in.GetName()
	if networkName == "" {
		return nil, scerr.InvalidRequestError("network name cannot be empty string")
	}

	job, err := PrepareJob(ctx, "", fmt.Sprintf("network create '%s'", networkName))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, true, "('%s')", networkName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	var (
		sizing    *abstract.HostSizingRequirements
		gwImageID string
		gwName    string
	)
	if in.Gateway != nil {
		if in.Gateway.SizingAsString != "" {
			sizing, _, err = converters.HostSizingRequirementsFromStringToAbstract(in.Gateway.SizingAsString)
			if err != nil {
				return nil, err
			}
		} else if in.Gateway.Sizing != nil {
			sizing = converters.HostSizingRequirementsFromProtocolToAbstract(*in.Gateway.Sizing)
		}
	}
	if sizing == nil {
		sizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}
	sizing.Image = in.Gateway.GetImageId()

	handler := handlers.NewNetworkHandler(job)
	r, err := task.Run(
		func(_ concurrency.Task, _ concurrency.TaskParameters) (concurrency.TaskResult, error) {
			return handler.Create(
				networkName,
				in.GetCidr(),
				ipversion.IPv4,
				*sizing,
				gwImageID,
				gwName,
				in.FailOver,
			)
		},
		nil,
	)
	if err != nil {
		return nil, err
	}
	network := r.(resources.Network)

	tracer.Trace("Network '%s' successfuly created.", networkName)
	return network.ToProtocol(task)
}

// List existing networks
func (s *NetworkListener) List(ctx context.Context, in *protocol.NetworkListRequest) (_ *protocol.NetworkList, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot list networks").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	job, err := PrepareJob(ctx, "", "network list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewNetworkHandler(job)
	networks, err := handler.List(in.GetAll())
	if err != nil {
		return nil, err
	}

	// Build response mapping abstract.Network to protocol.Network
	var pbnetworks []*protocol.Network
	for _, network := range networks {
		pbnetworks = append(pbnetworks, converters.NetworkFromAbstractToProtocol(network))
	}
	rv := &protocol.NetworkList{Networks: pbnetworks}
	return rv, nil
}

// Inspect returns infos on a network
func (s *NetworkListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.Network, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot inspect network").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if in == nil {
		return nil, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
		}
	}

	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, scerr.InvalidRequestError("neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, "", "network inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, true, "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	network, err := networkfactory.Load(task, job.SafeGetService(), ref)
	if err != nil {
		return nil, err
	}
	return network.ToProtocol(task)
}

// Delete a network
func (s *NetworkListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer func() {
		if err != nil {
			err = scerr.Wrap(err, "cannot delete network").ToGRPCStatus()
		}
	}()

	empty = &google_protobuf.Empty{}
	if s == nil {
		return empty, scerr.InvalidInstanceError()
	}
	if in == nil {
		return empty, scerr.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, scerr.InvalidParameterError("ctx", "cannot be nil")
	}

	ok, err := govalidator.ValidateStruct(in)
	if err == nil {
		if !ok {
			logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
		}
	}

	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, scerr.InvalidRequestError("cannot delete network: neither name nor id given as reference")
	}

	job, err := PrepareJob(ctx, "", "delete network")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), true, "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	handler := handlers.NewNetworkHandler(job)
	_, err = job.SafeGetTask().Run(
		func(_ concurrency.Task, _ concurrency.TaskParameters) (concurrency.TaskResult, error) {
			return nil, handler.Delete(ref)
		},
		nil,
	)
	if err != nil {
		return empty, err
	}

	tracer.Trace("Network '%s' successfully deleted.", ref)
	return empty, nil
}
