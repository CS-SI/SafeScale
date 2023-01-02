/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/v22/lib/backend"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	clusterfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/cluster"
	hostfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/host"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/handlers.ClusterHandler -o mocks/mock_cluster.go

// ClusterHandler defines interface to manipulate buckets
type ClusterHandler interface {
	List() ([]abstract.ClusterIdentity, fail.Error)
	Create(abstract.ClusterRequest) (resources.Cluster, fail.Error)
	State(string) (clusterstate.Enum, fail.Error)
	Inspect(string) (resources.Cluster, fail.Error)
	Start(string) fail.Error
	Stop(string) fail.Error
	Delete(string, bool) fail.Error
	Expand(string, abstract.HostSizingRequirements, uint, data.Map, bool) ([]resources.Host, fail.Error)
	Shrink(string, uint) ([]*propertiesv3.ClusterNode, fail.Error)
	ListNodes(string) (resources.IndexedListOfClusterNodes, fail.Error)
	InspectNode(string, string) (resources.Host, fail.Error)
	DeleteNode(string, string) fail.Error
	StopNode(string, string) fail.Error
	StartNode(string, string) fail.Error
	StateNode(string, string) (hoststate.Enum, fail.Error)
	ListMasters(string) (resources.IndexedListOfClusterNodes, fail.Error)
	FindAvailableMaster(string) (resources.Host, fail.Error)
	InspectMaster(string, string) (resources.Host, fail.Error)
	StopMaster(string, string) fail.Error
	StartMaster(string, string) fail.Error
	StateMaster(string, string) (hoststate.Enum, fail.Error)
}

// clusterHandler bucket service
type clusterHandler struct {
	job backend.Job
}

// NewClusterHandler creates a ClusterHandler
func NewClusterHandler(job backend.Job) ClusterHandler {
	return &clusterHandler{job: job}
}

// List lists clusters
func (handler *clusterHandler) List() (_ []abstract.ClusterIdentity, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	return clusterfactory.List(handler.job.Context(), handler.job.Service())
}

// Create creates a new cluster
// Note: returned resources.Cluster has to be .Released() by caller...
func (handler *clusterHandler) Create(req abstract.ClusterRequest) (_ resources.Cluster, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", req.Name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.New(handler.job.Context(), handler.job.Service())
	if xerr != nil {
		return nil, xerr
	}

	if req.Tenant == "" {
		req.Tenant = handler.job.Tenant()
	}

	xerr = instance.Create(handler.job.Context(), req)
	if xerr != nil {
		return nil, xerr
	}

	return instance, nil
}

// State returns the status of a cluster
func (handler *clusterHandler) State(name string) (_ clusterstate.Enum, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return clusterstate.Unknown, fail.InvalidInstanceError()
	}
	if name == "" {
		return clusterstate.Unknown, fail.InvalidParameterCannotBeEmptyStringError("name")
	}
	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return clusterstate.Unknown, xerr
	}

	st, xerr := instance.GetState(handler.job.Context())
	if xerr != nil {
		return clusterstate.Unknown, xerr
	}

	return st, nil
}

// Inspect a cluster
// Note: returned resources.Cluster has to be .Released() by caller...
func (handler *clusterHandler) Inspect(name string) (_ resources.Cluster, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	rc, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}

	exists, xerr := rc.Exists(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	if !exists {
		return nil, abstract.ResourceNotFoundError("cluster", name)
	}

	return rc, nil
}

// Start boots an entire cluster
func (handler *clusterHandler) Start(name string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return xerr
	}

	return instance.Start(handler.job.Context())
}

// Stop shutdowns an entire cluster (including the gateways)
func (handler *clusterHandler) Stop(name string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return xerr
	}

	return instance.Stop(handler.job.Context())
}

// Delete a cluster
func (handler *clusterHandler) Delete(name string, force bool) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return xerr
	}
	// Note: no .Released, the instance will be deleted

	return instance.Delete(handler.job.Context(), force)
}

// Expand adds node(s) to a cluster
// Note: returned []resources.host have to be .Released() by caller...
func (handler *clusterHandler) Expand(name string, sizing abstract.HostSizingRequirements, count uint, parameters data.Map, keepOnFailure bool) (_ []resources.Host, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}
	if count < 1 {
		return nil, fail.InvalidParameterError("count", "must be at least 1")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.host"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}

	// Instructs adding nodes
	return instance.AddNodes(handler.job.Context(), name, count, sizing, parameters, keepOnFailure)
}

// Shrink removes node(s) from a cluster
func (handler *clusterHandler) Shrink(name string, count uint) (_ []*propertiesv3.ClusterNode, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}
	if count < 1 {
		return nil, fail.InvalidParameterError("count", "must be at least 1")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}

	return instance.Shrink(handler.job.Context(), name, count)
}

// ListNodes lists node(s) of a cluster
func (handler *clusterHandler) ListNodes(name string) (_ resources.IndexedListOfClusterNodes, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}

	return instance.ListNodes(handler.job.Context())
}

// InspectNode inspects a node of the cluster
// Note: returned resources.Host has to be .Released() by caller...
func (handler *clusterHandler) InspectNode(clusterName, nodeRef string) (_ resources.Host, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	svc := handler.job.Service()
	clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), svc, clusterName)
	if xerr != nil {
		return nil, xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return nil, fail.NotFoundError()
	}

	return hostfactory.Load(handler.job.Context(), svc, id)
}

// DeleteNode removes node(s) from a cluster
func (handler *clusterHandler) DeleteNode(clusterName, nodeRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), clusterName)
	if xerr != nil {
		return xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(handler.job.Context())
	if xerr != nil {
		return xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return fail.NotFoundError()
	}

	return clusterInstance.DeleteSpecificNode(handler.job.Context(), id, "")
}

// StopNode stops a node of the cluster
func (handler *clusterHandler) StopNode(clusterName, nodeRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), clusterName)
	if xerr != nil {
		return xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(handler.job.Context())
	if xerr != nil {
		return xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return fail.NotFoundError()
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), id)
	if xerr != nil {
		return xerr
	}

	return hostInstance.Stop(handler.job.Context())
}

// StartNode starts a stopped node of the cluster
func (handler *clusterHandler) StartNode(clusterName, nodeRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), clusterName)
	if xerr != nil {
		return xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(handler.job.Context())
	if xerr != nil {
		return xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return fail.NotFoundError()
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), id)
	if xerr != nil {
		return xerr
	}

	return hostInstance.Start(handler.job.Context())
}

// StateNode returns the state of a node of the cluster
func (handler *clusterHandler) StateNode(clusterName, nodeRef string) (_ hoststate.Enum, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return hoststate.Unknown, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if nodeRef == "" {
		return hoststate.Unknown, fail.InvalidParameterCannotBeEmptyStringError("nodeRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, nodeRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), clusterName)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	nodeList, xerr := clusterInstance.ListNodes(handler.job.Context())
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	id := idOfClusterMember(nodeList, nodeRef)
	if id == "" {
		return hoststate.Unknown, fail.NotFoundError()
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), id)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	return hostInstance.ForceGetState(handler.job.Context())
}

// ListMasters returns the list of masters of the cluster
func (handler *clusterHandler) ListMasters(name string) (_ resources.IndexedListOfClusterNodes, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}

	return instance.ListMasters(handler.job.Context())
}

// FindAvailableMaster determines the first available master (ie the one that responds on ssh request)
// Note: returned resources.Host has to be .Released()...
func (handler *clusterHandler) FindAvailableMaster(name string) (_ resources.Host, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s')", name).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), name)
	if xerr != nil {
		return nil, xerr
	}

	return instance.FindAvailableMaster(handler.job.Context())
}

// InspectMaster returns the information about a master of the cluster
// Note: returned resources.Host has to be .Released() by caller...
func (handler *clusterHandler) InspectMaster(clusterName, masterRef string) (_ resources.Host, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return nil, fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if masterRef == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("masterRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, masterRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	instance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), clusterName)
	if xerr != nil {
		return nil, xerr
	}

	masterList, xerr := instance.ListMasters(handler.job.Context())
	if xerr != nil {
		return nil, xerr
	}

	id := idOfClusterMember(masterList, masterRef)
	if id == "" {
		return nil, fail.NotFoundError()
	}

	return hostfactory.Load(handler.job.Context(), handler.job.Service(), id)
}

// StopMaster stops a master of the Cluster
func (handler *clusterHandler) StopMaster(clusterName, masterRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if masterRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("masterRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, masterRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), clusterName)
	if xerr != nil {
		return xerr
	}

	masterList, xerr := clusterInstance.ListMasters(handler.job.Context())
	if xerr != nil {
		return xerr
	}

	id := idOfClusterMember(masterList, masterRef)
	if id == "" {
		return fail.NotFoundError()
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), id)
	if xerr != nil {
		return xerr
	}

	return hostInstance.Stop(handler.job.Context())
}

// StartMaster starts a stopped master of the Cluster
func (handler *clusterHandler) StartMaster(clusterName, masterRef string) (ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if masterRef == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("masterRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, masterRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), clusterName)
	if xerr != nil {
		return xerr
	}

	masterList, xerr := clusterInstance.ListMasters(handler.job.Context())
	if xerr != nil {
		return xerr
	}

	id := idOfClusterMember(masterList, masterRef)
	if id == "" {
		return fail.NotFoundError()
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), id)
	if xerr != nil {
		return xerr
	}

	return hostInstance.Start(handler.job.Context())
}

// StateMaster returns the state of a master of the Cluster
func (handler *clusterHandler) StateMaster(clusterName, masterRef string) (_ hoststate.Enum, ferr fail.Error) {
	defer func() {
		if ferr != nil {
			ferr.WithContext(handler.job.Context())
		}
	}()
	defer fail.OnPanic(&ferr)

	if handler == nil {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}
	if clusterName == "" {
		return hoststate.Unknown, fail.InvalidParameterCannotBeEmptyStringError("clusterName")
	}
	if masterRef == "" {
		return hoststate.Unknown, fail.InvalidParameterCannotBeEmptyStringError("masterRef")
	}

	tracer := debug.NewTracer(handler.job.Context(), tracing.ShouldTrace("handlers.cluster"), "('%s', %s)", clusterName, masterRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(handler.job.Context(), &ferr, tracer.TraceMessage())

	clusterInstance, xerr := clusterfactory.Load(handler.job.Context(), handler.job.Service(), clusterName)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	masterList, xerr := clusterInstance.ListMasters(handler.job.Context())
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	id := idOfClusterMember(masterList, masterRef)
	if id == "" {
		return hoststate.Unknown, fail.NotFoundError()
	}

	hostInstance, xerr := hostfactory.Load(handler.job.Context(), handler.job.Service(), id)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	return hostInstance.ForceGetState(handler.job.Context())
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
