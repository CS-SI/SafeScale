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

	"github.com/asaskevich/govalidator"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/lib/protocol"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// ClusterListener host service server grpc
type ClusterListener struct{}

// ErrorList lists clusters
func (s *ClusterListener) List(ctx context.Context, in *googleprotobuf.Empty) (hl *protocol.ClusterListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list clusters")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, "", "cluster list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.cluster")).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// Create creates a new cluster
func (s *ClusterListener) Create(ctx context.Context, in *protocol.ClusterCreateRequest) (_ *protocol.ClusterResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, "", "cluster create")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	name := in.GetName()
	task := job.GetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("listeners.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// Status returns the status of a cluster
func (s *ClusterListener) State(ctx context.Context, in *protocol.Reference) (ht *protocol.ClusterStateResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get cluster status")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, "", "cluster state")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	task := job.GetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// Inspect a cluster
func (s *ClusterListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.ClusterResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "cluster inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.GetTask()
	tracer := concurrency.NewTracer(task, debug.ShouldTrace("listeners.host"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// Start ...
func (s *ClusterListener) Start(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot start cluster")
	// defer func() {
	// 	if err != nil {
	// 		err = fail.Wrap(err, "cannot start cluster").ToGRPCStatus()
	// 	}
	// }()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	ref := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidParameterError("ref", "cannot be empty string")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, "", "cluster start")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return empty, fail.NotImplementedError()
}

// Stop shutdowns a entire cluster (including the gateways)
func (s *ClusterListener) Stop(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError("cannot stop cluster", &err)
	// defer func() {
	// 	if err != nil {
	// 		err = fail.Wrap(err, "cannot stop cluster").ToGRPCStatus()
	// 	}
	// }()

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterError("in", "can't be nil")
	}
	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, "", "host stop")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.host"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return empty, fail.NotImplementedError()
}

// Delete a cluster
func (s *ClusterListener) Delete(ctx context.Context, in *protocol.ClusterDeleteRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete cluster")

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

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}
	clusterName := in.GetName()
	if clusterName == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := PrepareJob(ctx, "", "cluster delete")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return empty, fail.NotImplementedError()
}

// Expand adds node(s) to a cluster
func (s *ClusterListener) Expand(ctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError("cannot expand cluster", &err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "host delete")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.host"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// Shrink removes node(s) from a cluster
func (s *ClusterListener) Shrink(ctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot shrink cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := PrepareJob(ctx, "", "host delete")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// ListNodes lists node(s) of a cluster
func (s *ClusterListener) ListNodes(ctx context.Context, in *protocol.Reference) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list cluster nodes")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "cluster node list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// InspectNode inspects a node of the cluster
func (s *ClusterListener) InspectNode(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect cluster node")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(ctx, "", "host delete")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.host"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// DeleteNode removes node(s) from a cluster
func (s *ClusterListener) DeleteNode(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete cluster node")

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

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost()) // If NodeRef is empty string, asks to delete the last added node

	job, err := PrepareJob(ctx, "", "cluster node delete")
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.host"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return empty, fail.NotImplementedError()
}

// StopNode stops a node of the cluster
func (s *ClusterListener) StopNode(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot stop cluster node")

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

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(ctx, "", "cluster node stop")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.host"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return empty, fail.NotImplementedError()
}

// StartNode starts a stopped node of the cluster
func (s *ClusterListener) StartNode(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot start cluster node")

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

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(ctx, "", "cluster node start")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.cluster"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return empty, fail.NotImplementedError()
}

// StateNode returns the state of a node of the cluster
func (s *ClusterListener) StateNode(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.ClusterStateResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get cluster node state")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, err := PrepareJob(ctx, "", "cluster node state")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.host"), "('%s', '%s')", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// ListMasters returns the list of masters of the cluster
func (s *ClusterListener) ListMasters(ctx context.Context, in *protocol.Reference) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list masters")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME Generate json tags in protobuf
	}

	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "cluster master list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// FindAvailableMaster determines the first master available master (ie the one that responds on ssh request)
func (s *ClusterListener) FindAvailableMaster(ctx context.Context, in *protocol.Reference) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list masters")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, "", "cluster master list")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// InspectMaster returns the information about a master of the cluster
func (s *ClusterListener) InspectMaster(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect cluster master")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterError("in", "cannot be nil")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterError("ctx", "cannot be nil")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of master is provided")
	}

	job, err := PrepareJob(ctx, "", "cluster master inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := concurrency.NewTracer(job.GetTask(), debug.ShouldTrace("listeners.cluster"), "('%s', '%s')", clusterName, masterRef).WithStopwatch().Entering()
	defer tracer.OnExitTrace()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}
