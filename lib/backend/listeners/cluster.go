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

package listeners

import (
	"context"
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	srvutils "github.com/CS-SI/SafeScale/v22/lib/backend/common"
	"github.com/CS-SI/SafeScale/v22/lib/backend/handlers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ClusterListener host service server grpc
type ClusterListener struct {
	protocol.UnimplementedClusterServiceServer
}

// List lists clusters
func (s *ClusterListener) List(inctx context.Context, in *protocol.Reference) (hl *protocol.ClusterListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list clusters")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	job, xerr := prepareJob(inctx, in, "/clusters/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	list, xerr := handler.List()
	if xerr != nil {
		return nil, xerr
	}

	return converters.ClusterListFromAbstractToProtocol(list), nil
}

// Create creates a new cluster
func (s *ClusterListener) Create(inctx context.Context, in *protocol.ClusterCreateRequest) (_ *protocol.ClusterResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot create cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	name := in.GetName()
	job, xerr := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/create", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	req, xerr := converters.ClusterRequestFromProtocolToAbstract(in)
	if xerr != nil {
		return nil, xerr
	}

	handler := handlers.NewClusterHandler(job)
	instance, xerr := handler.Create(*req)
	if xerr != nil {
		return nil, xerr
	}

	return instance.ToProtocol(ctx)
}

// State returns the status of a cluster
func (s *ClusterListener) State(inctx context.Context, in *protocol.Reference) (ht *protocol.ClusterStateResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot get cluster status")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/state", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	st, xerr := handler.State(ref)
	if xerr != nil {
		return nil, xerr
	}

	return converters.ClusterStateFromAbstractToProtocol(st), nil
}

// Inspect a cluster
func (s *ClusterListener) Inspect(inctx context.Context, in *protocol.Reference) (_ *protocol.ClusterResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/inspect", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	instance, xerr := handler.Inspect(ref)
	if xerr != nil {
		return nil, xerr
	}

	return instance.ToProtocol(ctx)
}

// Start ...
func (s *ClusterListener) Start(inctx context.Context, in *protocol.Reference) (empty *emptypb.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot start cluster")

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}

	job, xerr := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/start", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	return empty, handler.Start(ref)
}

// Stop shutdowns an entire cluster (including the gateways)
func (s *ClusterListener) Stop(inctx context.Context, in *protocol.Reference) (empty *emptypb.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot stop cluster")

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/stop", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	return empty, handler.Start(ref)
}

// Delete a cluster
func (s *ClusterListener) Delete(inctx context.Context, in *protocol.ClusterDeleteRequest) (empty *emptypb.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete Cluster")

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	ref := in.GetName()
	if ref == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/delete", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	return empty, handler.Delete(ref, in.GetForce())
}

// Expand adds node(s) to a cluster
func (s *ClusterListener) Expand(inctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &ferr)
	defer fail.OnExitWrapError(inctx, &ferr, "cannot expand cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	ref := in.GetName()
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/expand", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	sizing, _, err := converters.HostSizingRequirementsFromStringToAbstract(in.GetNodeSizing())
	if err != nil {
		return nil, err
	}

	if sizing.Image == "" {
		sizing.Image = in.GetImageId()
	}

	handler := handlers.NewClusterHandler(job)
	resp, xerr := handler.Expand(ref, *sizing, uint(in.Count), operations.ExtractFeatureParameters(in.GetParameters()), in.GetKeepOnFailure())
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterNodeListResponse{}
	out.Nodes = make([]*protocol.Host, 0, len(resp))
	for _, v := range resp {
		h, xerr := v.ToProtocol(ctx)
		if xerr != nil {
			return nil, xerr
		}

		out.Nodes = append(out.Nodes, h)
	}
	return out, nil
}

// Shrink removes node(s) from a cluster
func (s *ClusterListener) Shrink(inctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot shrink cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/shrink", clusterName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	count := uint(in.GetCount())
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "must be greater than 0")
	}

	handler := handlers.NewClusterHandler(job)
	removedNodes, xerr := handler.Shrink(clusterName, count)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterNodeListResponse{}
	out.Nodes = fromClusterNodes(removedNodes)
	return out, nil
}

func fromClusterNodes(in []*propertiesv3.ClusterNode) []*protocol.Host {
	out := make([]*protocol.Host, len(in))
	for k, v := range in {
		out[k] = converters.ClusterNodeFromPropertyToProtocol(*v)
	}
	return out
}

// ListNodes lists node(s) of a cluster
func (s *ClusterListener) ListNodes(inctx context.Context, in *protocol.Reference) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list cluster nodes")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/nodes/list", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)

	list, xerr := handler.ListNodes(ref)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterNodeListResponse{}
	out.Nodes = make([]*protocol.Host, 0, len(list))
	for _, v := range list {
		out.Nodes = append(out.Nodes, &protocol.Host{
			Id:   v.ID,
			Name: v.Name,
		})
	}
	return out, nil
}

// InspectNode inspects a node of the cluster
func (s *ClusterListener) InspectNode(inctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect cluster node")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/node/%s/inspect", clusterName, nodeRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	hostInstance, xerr := handler.InspectNode(clusterName, nodeRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, fail.NotFoundError("failed to find node %s in cluster '%s'", nodeRefLabel, clusterName)
		default:
			return nil, xerr
		}
	}

	return hostInstance.ToProtocol(ctx)
}

// DeleteNode removes node(s) from a cluster
func (s *ClusterListener) DeleteNode(inctx context.Context, in *protocol.ClusterNodeRequest) (empty *emptypb.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot delete Cluster Node")

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost()) // If NodeRef is empty string, asks to delete the last added node

	job, err := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/node/%s/delete", clusterName, nodeRef))
	if err != nil {
		return empty, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	xerr := handler.DeleteNode(clusterName, nodeRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return empty, fail.NotFoundError("failed to find a node %s in cluster '%s'", nodeRefLabel, clusterName)
		default:
			return empty, xerr
		}
	}

	return empty, nil
}

// StopNode stops a node of the cluster
func (s *ClusterListener) StopNode(inctx context.Context, in *protocol.ClusterNodeRequest) (empty *emptypb.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot stop cluster node")

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id of node is provided")
	}

	job, xerr := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/node/%s/stop", clusterName, nodeRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	xerr = handler.StopNode(clusterName, nodeRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return empty, fail.NotFoundError("failed to find node %s in Cluster '%s'", nodeRefLabel, clusterName)
		default:
			return empty, xerr
		}
	}

	return empty, nil
}

// StartNode starts a stopped node of the cluster
func (s *ClusterListener) StartNode(inctx context.Context, in *protocol.ClusterNodeRequest) (empty *emptypb.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot start cluster node")

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/node/%s/start", clusterName, nodeRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	xerr = handler.StartNode(clusterName, nodeRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return empty, fail.NotFoundError("failed to find a node %s in Cluster '%s'", nodeRefLabel, clusterName)
		default:
			return empty, xerr
		}
	}

	return empty, nil
}

// StateNode returns the state of a node of the cluster
func (s *ClusterListener) StateNode(inctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.HostStatus, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot get cluster node state")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, err := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/node/%s/state", clusterName, nodeRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	state, xerr := handler.StateNode(clusterName, nodeRef)
	out := converters.HostStatusFromAbstractToProtocol(nodeRef, state)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return out, fail.NotFoundError("failed to find a node %s in Cluster '%s'", nodeRefLabel, clusterName)
		default:
			return out, xerr
		}
	}

	return out, nil
}

// ListMasters returns the list of masters of the cluster
func (s *ClusterListener) ListMasters(inctx context.Context, in *protocol.Reference) (_ *protocol.ClusterNodeListResponse, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot list masters")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	clusterName, _ := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/masters/list", clusterName))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	list, xerr := handler.ListMasters(clusterName)
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
func (s *ClusterListener) FindAvailableMaster(inctx context.Context, in *protocol.Reference) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot find available master")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	clusterName, _ := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := prepareJob(inctx, in, fmt.Sprintf("/cluster/%s/master/available", clusterName))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	master, xerr := handler.FindAvailableMaster(clusterName)
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := master.ToProtocol(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}

// InspectMaster returns the information about a master of the cluster
func (s *ClusterListener) InspectMaster(inctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.Host, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot inspect cluster master")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of master is provided")
	}

	job, err := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/master/%s/inspect", clusterName, masterRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	master, xerr := handler.InspectMaster(clusterName, masterRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, fail.NotFoundError("failed to find a master %s in Cluster '%s'", masterRefLabel, clusterName)
		default:
			return nil, xerr
		}
	}

	out, xerr := master.ToProtocol(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}

// StopMaster stops a master of the Cluster
func (s *ClusterListener) StopMaster(inctx context.Context, in *protocol.ClusterNodeRequest) (empty *emptypb.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot stop Cluster master")

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id of node is provided")
	}

	job, xerr := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/master/%s/stop", clusterName, masterRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	xerr = handler.StopMaster(clusterName, masterRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return empty, fail.NotFoundError("failed to find a master %s in Cluster '%s'", masterRefLabel, clusterName)
		default:
			return empty, xerr
		}
	}

	return empty, nil
}

// StartMaster starts a stopped master of the Cluster
func (s *ClusterListener) StartMaster(inctx context.Context, in *protocol.ClusterNodeRequest) (empty *emptypb.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot start Cluster master")

	empty = &emptypb.Empty{}
	if s == nil {
		return empty, fail.InvalidInstanceError()
	}
	if in == nil {
		return empty, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return empty, fail.InvalidParameterCannotBeNilError("inctx")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/master/%s/start", clusterName, masterRef))
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	xerr = handler.StartMaster(clusterName, masterRef)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return empty, fail.NotFoundError("failed to find a master %s in Cluster '%s'", masterRefLabel, clusterName)
		default:
			return empty, xerr
		}
	}

	return empty, nil
}

// StateMaster returns the state of a master of the Cluster
func (s *ClusterListener) StateMaster(inctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.HostStatus, err error) {
	defer fail.OnExitConvertToGRPCStatus(inctx, &err)
	defer fail.OnExitWrapError(inctx, &err, "cannot get Cluster master state")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, err := prepareJob(inctx, in.GetHost(), fmt.Sprintf("/cluster/%s/node/%s/state", clusterName, masterRef))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	ctx := job.Context()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &err, tracer.TraceMessage())

	handler := handlers.NewClusterHandler(job)
	state, xerr := handler.StateMaster(clusterName, masterRef)
	out := converters.HostStatusFromAbstractToProtocol(masterRef, state)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return out, fail.NotFoundError("failed to find a master %s in Cluster '%s'", masterRefLabel, clusterName)
		default:
			return out, xerr
		}
	}

	return out, nil
}
