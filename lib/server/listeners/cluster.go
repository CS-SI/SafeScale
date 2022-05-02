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

	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations"
	googleprotobuf "github.com/golang/protobuf/ptypes/empty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	clusterfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/cluster"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/server/resources/factories/host"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/operations/converters"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v3"
	srvutils "github.com/CS-SI/SafeScale/v22/lib/server/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// ClusterListener host service server grpc
type ClusterListener struct {
	protocol.UnimplementedClusterServiceServer
}

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

	job, xerr := PrepareJob(ctx, in.GetTenantId(), "/clusters/list")
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	list, xerr := clusterfactory.List(job.Context(), job.Service())
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

	name := in.GetName()
	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/create", name))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.New(job.Context(), job.Service())
	if xerr != nil {
		return nil, xerr
	}

	req, xerr := converters.ClusterRequestFromProtocolToAbstract(in)
	if xerr != nil {
		return nil, xerr
	}

	if req.Tenant == "" {
		req.Tenant = job.Tenant()
	}

	xerr = instance.Create(job.Context(), *req)
	if xerr != nil {
		return nil, xerr
	}

	return instance.ToProtocol(job.Context())
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

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/state", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	st, xerr := instance.GetState(job.Context())
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

	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/inspect", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	return instance.ToProtocol(job.Context())
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

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/start", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	return empty, instance.Start(job.Context())
}

// Stop shutdowns an entire cluster (including the gateways)
func (s *ClusterListener) Stop(ctx context.Context, in *protocol.Reference) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot stop cluster")

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

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/stop", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}

	return empty, instance.Stop(job.Context())
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

	ref := in.GetName()
	if ref == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/delete", ref))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), ref)
	if xerr != nil {
		return nil, xerr
	}
	// Note: no .Released, the instance will be deleted

	return empty, instance.Delete(job.Context(), in.GetForce())
}

// Expand adds node(s) to a cluster
func (s *ClusterListener) Expand(ctx context.Context, in *protocol.ClusterResizeRequest) (_ *protocol.ClusterNodeListResponse, ferr error) {
	defer fail.OnExitConvertToGRPCStatus(&ferr)
	defer fail.OnExitWrapError(&ferr, "cannot expand cluster")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}

	ref := in.GetName()
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/expand", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.host"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	sizing, _, err := converters.HostSizingRequirementsFromStringToAbstract(in.GetNodeSizing())
	if err != nil {
		return nil, err
	}

	if sizing.Image == "" {
		sizing.Image = in.GetImageId()
	}

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), in.GetName())
	if xerr != nil {
		return nil, xerr
	}

	// Instructs adding nodes
	resp, xerr := instance.AddNodes(job.Context(), uint(in.Count), *sizing, operations.ExtractFeatureParameters(in.GetParameters()), in.GetKeepOnFailure())
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterNodeListResponse{}
	out.Nodes = make([]*protocol.Host, 0, len(resp))
	for _, v := range resp {
		h, xerr := v.ToProtocol(job.Context())
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

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, xerr := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/shrink", clusterName))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), in.GetName())
	if xerr != nil {
		return nil, xerr
	}

	count := uint(in.GetCount())
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "must be greater than 0")
	}

	removedNodes, xerr := instance.Shrink(job.Context(), count)
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

	ref, _ := srvutils.GetReference(in)
	if ref == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/nodes/list", ref))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", ref).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), in.GetName())
	if xerr != nil {
		return nil, xerr
	}

	list, xerr := instance.ListNodes(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterNodeListResponse{}
	out.Nodes = make([]*protocol.Host, 0, len(list))
	for _, v := range list {
		out.Nodes = append(
			out.Nodes, &protocol.Host{
				Id:   v.ID,
				Name: v.Name,
			},
		)
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

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/node/%s/inspect", clusterName, nodeRef))
	if xerr != nil {
		return nil, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	svc := job.Service()
	clusterInstance, xerr := clusterfactory.Load(job.Context(), svc, in.GetName())
	if xerr != nil {
		return nil, xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return nil, fail.NotFoundError("failed to find node %s in Cluster", nodeRefLabel)
	}

	hostInstance, xerr := hostfactory.Load(job.Context(), svc, id)
	if xerr != nil {
		return nil, xerr
	}

	return hostInstance.ToProtocol(job.Context())
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

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost()) // If NodeRef is empty string, asks to delete the last added node

	job, err := PrepareJob(
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/node/%s/delete", clusterName, nodeRef),
	)
	if err != nil {
		return empty, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return empty, xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return nil, fail.NotFoundError("failed to find node %s in Cluster", nodeRefLabel)
	}

	xerr = clusterInstance.DeleteSpecificNode(job.Context(), id, "")
	return empty, xerr
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

	clusterName := in.GetName()
	if clusterName == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/node/%s/stop", clusterName, nodeRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	jobCtx := job.Context()
	svc := job.Service()
	clusterInstance, xerr := clusterfactory.Load(jobCtx, svc, clusterName)
	if xerr != nil {
		return empty, xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(jobCtx)
	if xerr != nil {
		return empty, xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return empty, fail.NotFoundError("failed to find node %s in Cluster", nodeRefLabel)
	}

	hostInstance, xerr := hostfactory.Load(jobCtx, svc, id)
	if xerr != nil {
		return empty, xerr
	}

	return empty, hostInstance.Stop(jobCtx)
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

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/node/%s/start", clusterName, nodeRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return empty, xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(job.Context())
	if xerr != nil {
		return empty, xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return empty, fail.NotFoundError("failed to find node %s in Cluster", nodeRefLabel)
	}

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), id)
	if xerr != nil {
		return empty, xerr
	}

	xerr = hostInstance.Start(job.Context())
	return empty, xerr
}

// StateNode returns the state of a node of the cluster
func (s *ClusterListener) StateNode(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.HostStatus, err error) {
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

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	nodeRef, nodeRefLabel := srvutils.GetReference(in.GetHost())
	if nodeRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, err := PrepareJob(
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/node/%s/state", clusterName, nodeRef),
	)
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, nodeRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return nil, xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return nil, fail.NotFoundError("failed to find node %s in Cluster", nodeRefLabel)
	}

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), id)
	if xerr != nil {
		return nil, xerr
	}

	state, xerr := hostInstance.ForceGetState(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	return converters.HostStatusFromAbstractToProtocol(hostInstance.GetName(), state), nil
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

	clusterName, _ := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/masters/list", clusterName))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return nil, xerr
	}

	list, xerr := instance.ListMasters(job.Context())
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

	clusterName, _ := srvutils.GetReference(in)
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}

	job, err := PrepareJob(ctx, in.GetTenantId(), fmt.Sprintf("/cluster/%s/master/available", clusterName))
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s')", clusterName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return nil, xerr
	}

	master, xerr := instance.FindAvailableMaster(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := master.ToProtocol(job.Context())
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

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of master is provided")
	}

	job, err := PrepareJob(
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/master/%s/inspect", clusterName, masterRef),
	)
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return nil, xerr
	}

	masterList, xerr := instance.ListMasters(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	id := idOfClusterMember(masterList, masterRef)
	if id == "" {
		return nil, fail.NotFoundError("failed to find a master '%s' in cluster '%s'", masterRefLabel, clusterName)
	}

	master, xerr := hostfactory.Load(job.Context(), job.Service(), id)
	if xerr != nil {
		return nil, xerr
	}

	out, xerr := master.ToProtocol(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}

// StopMaster stops a master of the Cluster
func (s *ClusterListener) StopMaster(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot stop Cluster master")

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

	clusterName := in.GetName()
	if clusterName == "" {
		return empty, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return empty, status.Errorf(codes.FailedPrecondition, "neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/master/%s/stop", clusterName, masterRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return empty, xerr
	}

	masterList, xerr := clusterInstance.ListMasters(job.Context())
	if xerr != nil {
		return empty, xerr
	}

	id := idOfClusterMember(masterList, masterRef)
	if id == "" {
		return empty, fail.NotFoundError("failed to find master %s in Cluster '%s'", masterRefLabel, clusterName)
	}

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), id)
	if xerr != nil {
		return empty, xerr
	}

	xerr = hostInstance.Stop(job.Context())
	return empty, xerr
}

// StartMaster starts a stopped master of the Cluster
func (s *ClusterListener) StartMaster(ctx context.Context, in *protocol.ClusterNodeRequest) (empty *googleprotobuf.Empty, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot start Cluster master")

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

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, xerr := PrepareJob(
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/master/%s/start", clusterName, masterRef),
	)
	if xerr != nil {
		return empty, xerr
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return empty, xerr
	}

	masterList, xerr := clusterInstance.ListMasters(job.Context())
	if xerr != nil {
		return empty, xerr
	}

	id := idOfClusterMember(masterList, masterRef)
	if id == "" {
		return empty, fail.NotFoundError("failed to find master %s in Cluster '%s'", masterRefLabel, clusterName)
	}

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), id)
	if xerr != nil {
		return empty, xerr
	}

	xerr = hostInstance.Start(job.Context())
	return empty, xerr
}

// StateMaster returns the state of a master of the Cluster
func (s *ClusterListener) StateMaster(ctx context.Context, in *protocol.ClusterNodeRequest) (_ *protocol.HostStatus, err error) {
	defer fail.OnExitConvertToGRPCStatus(&err)
	defer fail.OnExitWrapError(&err, "cannot get Cluster master state")

	if s == nil {
		return nil, fail.InvalidInstanceError()
	}
	if in == nil {
		return nil, fail.InvalidParameterCannotBeNilError("in")
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	clusterName := in.GetName()
	if clusterName == "" {
		return nil, fail.InvalidRequestError("cluster name is missing")
	}
	masterRef, masterRefLabel := srvutils.GetReference(in.GetHost())
	if masterRef == "" {
		return nil, fail.InvalidRequestError("neither name nor id of node is provided")
	}

	job, err := PrepareJob(
		ctx, in.GetHost().GetTenantId(), fmt.Sprintf("/cluster/%s/node/%s/state", clusterName, masterRef),
	)
	if err != nil {
		return nil, err
	}
	defer job.Close()

	tracer := debug.NewTracer(job.Task(), tracing.ShouldTrace("listeners.cluster"), "('%s', %s)", clusterName, masterRefLabel).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&err, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(job.Context(), job.Service(), clusterName)
	if xerr != nil {
		return nil, xerr
	}

	masterList, xerr := clusterInstance.ListMasters(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	id := idOfClusterMember(masterList, masterRef)
	if id == "" {
		return nil, fail.NotFoundError("failed to find master %s in Cluster", masterRefLabel)
	}

	hostInstance, xerr := hostfactory.Load(job.Context(), job.Service(), id)
	if xerr != nil {
		return nil, xerr
	}

	state, xerr := hostInstance.ForceGetState(job.Context())
	if xerr != nil {
		return nil, xerr
	}

	return converters.HostStatusFromAbstractToProtocol(hostInstance.GetName(), state), nil
}

// idOfClusterMember returns the id of the member of the Cluster corresponding to 'ref', or "" if not found
func idOfClusterMember(list resources.IndexedListOfClusterNodes, ref string) string {
	var id string
	for _, v := range list {
		if v.ID == ref || v.Name == ref {
			id = v.ID
			break
		}
	}
	return id
}
