/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	clusterfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/cluster"
	hostfactory "github.com/CS-SI/SafeScale/lib/server/resources/factories/host"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv3 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v3"
	srvutils "github.com/CS-SI/SafeScale/lib/server/utils"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
)

// ClusterListener host service server grpc
type ClusterListener struct{}

// List lists clusters
func (s *ClusterListener) List(ctx context.Context, in *protocol.Reference) (hl *protocol.ClusterListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list clusters")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "cluster list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	list, xerr := clusterfactory.List(task.GetContext(), job.GetService())
	if xerr != nil {
		return nil, xerr
	}
	return converters.ClusterListFromAbstractToProtocol(list), nil
}

// Create creates a new cluster
func (s *ClusterListener) Create(ctx context.Context, in *protocol.ClusterCreateRequest) (_ *protocol.ClusterResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot create cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "cluster create")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	name := in.GetName()
	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.New(job.GetService())
	if xerr != nil {
		return nil, xerr
	}

	req, xerr := converters.ClusterRequestFromProtocolToAbstract(in)
	if xerr != nil {
		return nil, xerr
	}

	xerr = rc.Create(task.GetContext(), req)
	if xerr != nil {
		return nil, xerr
	}

	return rc.ToProtocol()
}

// State returns the status of a cluster
func (s *ClusterListener) State(ctx context.Context, in *protocol.Reference) (ht *protocol.ClusterStateResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get cluster status")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "cluster state")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}

	st, xerr := rc.GetState()
	if xerr != nil {
		return nil, xerr
	}
	return converters.ClusterStateFromAbstractToProtocol(st), nil
}

// Inspect a cluster
func (s *ClusterListener) Inspect(ctx context.Context, in *protocol.Reference) (_ *protocol.ClusterResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "cluster inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	task := job.GetTask()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}

	return rc.ToProtocol()
}

// Start ...
func (s *ClusterListener) Start(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot start cluster")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "cluster start")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}

	return empty, rc.Start(task.GetContext())
}

// Stop shutdowns a entire cluster (including the gateways)
func (s *ClusterListener) Stop(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError("cannot stop cluster", &err)

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "cluster stop")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}
	return empty, rc.Stop(task.GetContext())
}

// Delete a cluster
func (s *ClusterListener) Delete(ctx context.Context, in *protocol.ClusterDeleteRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete Cluster")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}
	ref := in.GetName()
	if ref == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "cluster delete")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(job.GetService(), ref)
	if xerr != nil {
		return nil, xerr
	}

	return empty, rc.Delete(task.GetContext(), in.GetForce())
}

// Expand adds node(s) to a cluster
func (s *ClusterListener) Expand(ctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError("cannot expand cluster", &err)

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	ref := in.GetName()
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "cluster expand")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sizing, _, err := converters.HostSizingRequirementsFromStringToAbstract(in.GetNodeSizing())
	if err != nil {
		return nil, err
	}

	if sizing.Image == "" {
		sizing.Image = in.GetImageId()
	}

	rc, xerr := clusterfactory.Load(job.GetService(), in.GetName())
	if xerr != nil {
		return nil, xerr
	}

	resp, xerr := rc.AddNodes(task.GetContext(), uint(in.Count), *sizing)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterNodeListResponse{}
	out.Nodes = make([]*protocol.Host, 0, len(resp))
	for _, v := range resp {
		h, xerr := v.ToProtocol()
		if xerr != nil {
			return nil, xerr
		}

		out.Nodes = append(out.Nodes, h)
	}
	return out, nil
}

// Shrink removes node(s) from a cluster
func (s *ClusterListener) Shrink(ctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot shrink cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "host delete")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(svc, in.GetName())
	if xerr != nil {
		return nil, xerr
	}

	count := uint(in.GetCount())
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "must be greater than 0")
	}

	removedNodes, xerr := instance.Shrink(task.GetContext(), count)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterNodeListResponse{}
	out.Nodes = fromClusterNodes(removedNodes)
	return out, nil
}

func fromClusterNodes(in []*propertiesv3.ClusterNode) []*protocol.Host {
	out := make([]*protocol.Host, 0, len(in))
	for _, v := range in {
		out = append(out, converters.ClusterNodeFromPropertyToProtocol(*v))
	}
	return out
}

// ListNodes lists node(s) of a cluster
func (s *ClusterListener) ListNodes(ctx context.Context, in *protocol.Reference) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list cluster nodes")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "cluster node list")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(job.GetService(), in.GetName())
	if xerr != nil {
		return nil, xerr
	}

	list, xerr := rc.ListNodes(task.GetContext())
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterNodeListResponse{}
	out.Nodes = make([]*protocol.Host, 0, len(list))
	for _, v := range list {
		item := &protocol.Host{
			Id:   v.ID,
			Name: v.Name,
		}
		out.Nodes = append(out.Nodes, item)
	}
	return out, nil
}

// InspectNode inspects a node of the cluster
func (s *ClusterListener) InspectNode(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect cluster node")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), "cluster node inspect")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return nil, fail.NotImplementedError()
}

// DeleteNode removes node(s) from a cluster
func (s *ClusterListener) DeleteNode(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot delete Cluster Node")

	empty = &googleprotobuf.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost()) // If NodeRef is empty string, asks to delete the last added node

	job, err := PrepareJob(ctx, in.GetHost().GetTenantId(), "cluster node delete")
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	_ = nodeRef // VPL: waiting for code...
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
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, status.Errorf(codes.FailedPrecondition, "neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), "cluster node stop")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
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
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), "cluster node start")
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
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
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, err := PrepareJob(ctx, in.GetHost().GetTenantId(), "cluster node state")
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.GetTask(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
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
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName, _ := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "cluster master list")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(job.GetService(), clusterName)
	if xerr != nil {
		return nil, xerr
	}

	list, xerr := rc.ListMasters(task.GetContext())
	if xerr != nil {
		return nil, xerr
	}
	out, xerr := converters.IndexedListOfClusterNodesFromResourceToProtocol(list)
	if xerr != nil {
		return nil, xerr
	}
	return out, nil
}

// FindAvailableMaster determines the first master available master (ie the one that responds on ssh request)
func (s *ClusterListener) FindAvailableMaster(ctx context.Context, in *protocol.Reference) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot list masters")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName, _ := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), "cluster master list")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.GetTask()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(job.GetService(), clusterName)
	if xerr != nil {
		return nil, xerr
	}
	master, xerr := rc.FindAvailableMaster(task.GetContext())
	if xerr != nil {
		return nil, xerr
	}
	out, xerr := master.ToProtocol()
	if xerr != nil {
		return nil, xerr
	}
	return out, nil
}

// InspectMaster returns the information about a master of the cluster
func (s *ClusterListener) InspectMaster(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot inspect cluster master")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	if ok, err := govalidator.ValidateStruct(in); err != nil || !ok {
		logrus.Warnf("Structure validation failure: %v", in) // FIXME: Generate json tags in protobuf
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of master is provided")
	}

	job, err := PrepareJob(ctx, in.GetHost().GetTenantId(), "cluster master inspect")
	if err != nil {
		return nil, err
	}
	defer job.Close()
	task := job.GetTask()
	svc := job.GetService()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(svc, clusterName)
	if xerr != nil {
		return nil, xerr
	}

	var masterID string
	xerr = rc.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, v := range nodesV3.Masters {
				if node, found := nodesV3.ByNumericalID[v]; found {
					if node.ID == masterRef || node.Name == masterRef {
						masterID = node.ID
						break
					}
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}
	if masterID == "" {
		return nil, fail.NotFoundError("failed to find a master '%s' in cluster '%s'", masterRefLabel, clusterName)
	}

	master, xerr := hostfactory.Load(svc, masterID)
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := master.ToProtocol()
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}
