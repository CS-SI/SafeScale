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
	"reflect"

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/handlers"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// ClusterListener host service server grpc
type ClusterListener struct{}

// ErrorList lists clusters
func (s *ClusterListener) List(ctx context.Context, in *protocol.HostListRequest) (hl *protocol.HostList, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot list clusters").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, "", "cluster list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	all := in.GetAll()
	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.cluster"), "(%v)", all).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	hosts, err := handler.List(all)
	if lerr != nil {
		return nil, lerr
	}

	// build response mapping abstract.Host to protocol.Host
	var pbhost []*protocol.Host
	for _, host := range hosts {
		pbhost = append(pbhost, converters.HostFullFromAbstractToProtocol(host))
	}
	rv := &protocol.HostList{Hosts: pbhost}
	return rv, nil
}

// Create creates a new cluster
func (s *ClusterListener) Create(ctx context.Context, in *protocol.ClusterCreateRequest) (_ *protocol.ClusterResponse, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot create cluster").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, "", "cluster create")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	name := in.GetName()
	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("listeners.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	var sizing *abstract.HostSizingRequirements
	if in.SizingAsString != "" {
		sizing, _, err = converters.HostSizingRequirementsFromStringToAbstract(in.SizingAsString)
		if err != nil {
			return nil, err
		}
	} else if in.Sizing != nil {
		sizing = converters.HostSizingRequirementsFromProtocolToAbstract(*in.Sizing)
	}
	if sizing == nil {
		sizing = &abstract.HostSizingRequirements{MinGPU: -1}
	}
	sizing.Image = in.GetImageId()

	hostReq := abstract.HostRequest{
		ResourceName:  name,
		PublicIP:      in.GetPublic(),
		KeepOnFailure: in.GetKeepOnFailure(),
	}
	err = network.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		networkCore, ok := clonable.(*abstract.Network)
		if !ok {
			return fail.InconsistentReport("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		hostReq.Networks = []*abstract.Network{networkCore}
		return nil
	})

	handler := handlers.NewHostHandler(job)
	host, err := handler.Create(hostReq, *sizing, in.Force)
	if err != nil {
		return nil, err
	}
	// logrus.Infof("Host '%s' created", name)
	r, err := host.ToProtocol(task)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Status returns the status of a cluster
func (s *ClusterListener) Status(ctx context.Context, in *protocol.Reference) (ht *protocol.ClusterStateResponse, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot get cluster status").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}

	job, lerr := PrepareJob(ctx, "", "cluster state")
	if lerr != nil {
		return nil, lerr
	}
	defer job.Close()

	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &lerr)

	handler := handlers.NewHostHandler(job)
	host, lerr := handler.Inspect(ref)
	if lerr != nil {
		return nil, lerr
	}
	r, err := converters.HostStatusFromAbstractToProtocol(host.SafeGetName(), host.SafeGetState(task))
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Inspect a cluster
func (s *ClusterListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.ClusterResponse, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot inspect cluster").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "cluster inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.SafeGetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("listeners.host"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	host, err := handler.Inspect(ref)
	if err != nil {
		return nil, err
	}
	r, err := host.ToProtocol(task)
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Start ...
func (s *ClusterListener) Start(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot start cluster").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceReport()
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidParameterReport("ref", "cannot be empty string")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, "", "cluster start")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Start(ref)
	if err != nil {
		return empty, err
	}

	tracer.Trace("Host '%s' successfully started", ref)
	return empty, nil
}

// Stop shutdowns a entire cluster (including the gateways)
func (s *ClusterListener) Stop(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot stop cluster").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceReport()
	}
	if in == nil {
		return empty, fail.InvalidParameterReport("in", "can't be nil")
	}
	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return empty, fail.InvalidRequestReport("cluster name is missing")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, err := PrepareJob(ctx, "", "host stop")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.host"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Stop(ref)
	if err != nil {
		return empty, err
	}

	tracer.Trace("Cluster '%s' stopped successfully.", clusterName)
	return empty, nil
}

// Delete a cluster
func (s *ClusterListener) Delete(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot delete cluster").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceReport()
	}
	if in == nil {
		return empty, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return empty, fail.InvalidRequestReport("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "cluster delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return empty, err
	}
	tracer.Trace("Cluster '%s' successfully deleted.", ref)
	return empty, nil
}

// Expand adds node(s) to a cluster
func (s *ClusterListener) Expand(ctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot expand cluster").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "host delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.host"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return nil, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return nil, nil
}

// Shrink removes node(s) from a cluster
func (s *ClusterListener) Shrink(ctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot shrink cluster").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "host delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return nil, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return nil, nil
}

// ListNodes lists node(s) of a cluster
func (s *ClusterListener) ListNodes(ctx context.Context, in *protocol.Reference) (_ *protocol.ClusterNodeListResponse, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot list cluster nodes").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "cluster node list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return nil, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return nil, nil
}

// InspectNode inspects a node of the cluster
func (s *ClusterListener) InspectNode(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.HostDefinition, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot inspect cluster node").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestReport("neither name nor id of node is provided")
	}

	job, err := PrepareJob(ctx, "", "host delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.host"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return nil, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return nil, nil
}

// DeleteNode removes node(s) from a cluster
func (s *ClusterListener) DeleteNode(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empty, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot delete cluster node").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceReport()
	}
	if in == nil {
		return empty, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost()) // If NodeRef is empty string, asks to delete the last added node

	job, err := PrepareJob(ctx, "", "cluster node delete")
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.host"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return empty, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return empty, nil
}

// StopNode stops a node of the cluster
func (s *ClusterListener) StopNode(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empty, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot stop cluster node").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceReport()
	}
	if in == nil {
		return empty, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "neither name nor id of node is provided")
	}

	job, err := PrepareJob(ctx, "", "cluster node stop")
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.host"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return empty, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return empty, nil
}

// StartNode starts a stopped node of the cluster
func (s *ClusterListener) StartNode(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empt, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot start cluster node").ToGRPCStatus()
		}
	}()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceReport()
	}
	if in == nil {
		return empty, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestReport("neither name nor id of node is provided")
	}

	job, err := PrepareJob(ctx, "", "cluster node start")
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.cluster"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return empty, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return empty, nil
}

// StateNode returns the state of a node of the cluster
func (s *ClusterListener) StateNode(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.HostState, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot get cluster node state").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestReport("neither name nor id of node is provided")
	}

	job, err := PrepareJob(ctx, "", "cluster node state")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.host"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return nil, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return nil, nil
}

// ListMasters returns the list of masters of the cluster
func (s *ClusterListener) ListMasters(ctx context.Context, in *protocol.Reference) (_ *protocol.ClusterNodeListResponse, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot list masters").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "cluster master list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// InspectMaster returns the information about a master of the cluster
func (s *ClusterListener) InspectMaster(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.ClusterNodeListResponse, oerr error) {
	var err fail.Report
	defer func() {
		if err != nil {
			oerr = fail.Wrap(err, "cannot inspect cluster master").ToGRPCStatus()
		}
	}()

	if s == nil {
		return nil, fail.InvalidInstanceReport()
	}
	if in == nil {
		return nil, fail.InvalidParameterReport("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterReport("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestReport("cluster name is missing")
	}
	masterRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestReport("neither name nor id of master is provided")
	}

	job, err := PrepareJob(ctx, "", "cluster master inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.SafeGetTask(), debug.ShouldTrace("listeners.cluster"), "('%s', '%s')", clusterName, masterRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(tracer.TraceMessage(""), &err)

	handler := handlers.NewHostHandler(job)
	err = handler.Delete(ref)
	if err != nil {
		return nil, err
	}
	tracer.Trace("Host '%s' successfully deleted.", ref)
	return nil, nil
}
