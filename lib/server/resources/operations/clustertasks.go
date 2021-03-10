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

package operations

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	propertiesv3 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v3"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

func (instance *cluster) taskStartHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	id, ok := params.(string)
	if !ok || id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("params")
	}

	if xerr = instance.GetService().StartHost(id); xerr != nil {
		switch xerr.(type) { //nolint
		case *fail.ErrDuplicate: // A host already started is considered as a successful run
			return nil, nil
		}
	}
	return nil, xerr
}

func (instance *cluster) taskStopHost(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	id, ok := params.(string)
	if !ok || id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("params")
	}

	if xerr = instance.GetService().StopHost(id); xerr != nil {
		switch xerr.(type) { //nolint
		case *fail.ErrDuplicate: // A host already stopped is considered as a successful run
			return nil, nil
		}
	}
	return nil, xerr
}

type taskInstallGatewayParameters struct {
	Host resources.Host
}

// taskInstallGateway installs necessary components on one gateway
// This function is intended to be call as a goroutine
func (instance *cluster) taskInstallGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), params).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	p, ok := params.(taskInstallGatewayParameters)
	if !ok {
		return result, fail.InvalidParameterError("params", "must be a 'taskInstallGatewayParameters'")
	}
	if p.Host == nil {
		return result, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	hostLabel := p.Host.GetName()
	logrus.Debugf("[%s] starting installation...", hostLabel)

	if _, xerr = p.Host.WaitSSHReady(task.GetContext(), temporal.GetHostTimeout()); xerr != nil {
		return nil, xerr
	}

	// Installs docker and docker-compose on gateway
	if xerr = instance.installDocker(task.GetContext(), p.Host, hostLabel); xerr != nil {
		return nil, xerr
	}

	// Installs proxycache server on gateway (if not disabled)
	if xerr = instance.installProxyCacheServer(task.GetContext(), p.Host, hostLabel); xerr != nil {
		return nil, xerr
	}

	// Installs requirements as defined by cluster Flavor (if it exists)
	if xerr = instance.installNodeRequirements(task.GetContext(), clusternodetype.Gateway, p.Host, hostLabel); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] preparation successful", hostLabel)
	return nil, nil
}

type taskConfigureGatewayParameters struct {
	Host resources.Host
}

// taskConfigureGateway prepares one gateway
// This function is intended to be call as a goroutine
func (instance *cluster) taskConfigureGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// validate and convert parameters
	p, ok := params.(taskConfigureGatewayParameters)
	if !ok {
		return result, fail.InvalidParameterError("params", "must be a 'taskConfigureGatewayParameters'")
	}
	if p.Host == nil {
		return result, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	logrus.Debugf("[%s] starting configuration...", p.Host.GetName())

	if instance.makers.ConfigureGateway != nil {
		if xerr = instance.makers.ConfigureGateway(instance); xerr != nil {
			return nil, xerr
		}
	}

	logrus.Debugf("[%s] configuration successful in [%s].", p.Host.GetName(), tracer.Stopwatch().String())
	return nil, nil
}

type taskCreateMastersParameters struct {
	count         uint
	mastersDef    abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateMasters creates masters
// This function is intended to be call as a goroutine
func (instance *cluster) taskCreateMasters(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Convert and validate parameters
	p, ok := params.(taskCreateMastersParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreteMastersParameters'")
	}
	if p.count < 1 {
		return nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
	}

	clusterName := instance.GetName()

	if p.count == 0 {
		logrus.Debugf("[cluster %s] no masters to create.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] creating %d master%s...", clusterName, p.count, strprocess.Plural(p.count))

	var subtasks []concurrency.Task
	timeout := temporal.GetContextTimeout() + time.Duration(p.count)*time.Minute
	var i uint
	for ; i < p.count; i++ {
		subtask, xerr := task.StartInSubtask(instance.taskCreateMaster, taskCreateMasterParameters{
			index:         i + 1,
			masterDef:     p.mastersDef,
			timeout:       timeout,
			keepOnFailure: p.keepOnFailure,
		})
		if xerr != nil {
			return nil, xerr
		}
		subtasks = append(subtasks, subtask)
	}
	var errs []string
	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		msg := strings.Join(errs, "\n")
		return nil, fail.NewError("[cluster %s] failed to create master(s): %s", clusterName, msg)
	}

	logrus.Debugf("[cluster %s] masters creation successful.", clusterName)
	return nil, nil
}

type taskCreateMasterParameters struct {
	index         uint
	masterDef     abstract.HostSizingRequirements
	timeout       time.Duration
	keepOnFailure bool
}

// taskCreateMaster creates one master
// This function is intended to be call as a goroutine
func (instance *cluster) taskCreateMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Convert and validate parameters
	p, ok := params.(taskCreateMasterParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreateMasterParameters'")
	}

	if p.index < 1 {
		return nil, fail.InvalidParameterError("params.index", "must be an integer greater than 0")
	}

	hostLabel := fmt.Sprintf("master #%d", p.index)
	logrus.Debugf("[%s] starting master Host creation...", hostLabel)

	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, xerr = instance.buildHostname("master", clusternodetype.Master)
	if xerr != nil {
		return nil, xerr
	}

	// First creates master in metadata, to keep track of its tried creation, in case of failure
	var nodeIdx uint
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nodesV3.GlobalLastIndex++
			nodeIdx = nodesV3.GlobalLastIndex

			node := &propertiesv3.ClusterNode{
				NumericalID: nodeIdx,
				Name:        hostReq.ResourceName,
			}
			nodesV3.ByNumericalID[nodeIdx] = node
			return nil
		})
	})
	if xerr != nil {
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	// Starting from here, if exiting with error, remove entry from master nodes of the metadata
	defer func() {
		if xerr != nil && !p.keepOnFailure {
			// // Disable abort signal during the clean up
			// defer task.DisarmAbortSignal()()

			derr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					delete(nodesV3.ByNumericalID, nodeIdx)
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove master from Cluster metadata", actionFromError(xerr)))
			}
		}
	}()

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	netCfg, xerr := instance.GetNetworkConfig()
	if xerr != nil {
		return nil, xerr
	}

	subnet, xerr := LoadSubnet(instance.GetService(), "", netCfg.SubnetID)
	if xerr != nil {
		return nil, xerr
	}

	// Create the Host
	xerr = subnet.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		hostReq.Subnets = []*abstract.Subnet{as}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	if hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP(); xerr != nil {
		return nil, xerr
	}

	hostReq.PublicIP = false
	hostReq.KeepOnFailure = p.keepOnFailure

	rh, xerr := NewHost(instance.GetService())
	if xerr != nil {
		return nil, xerr
	}

	if _, xerr = rh.Create(task.GetContext(), hostReq, p.masterDef); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !p.keepOnFailure {
			// // Disable abort signal during the clean up
			// defer task.DisarmAbortSignal()()

			if derr := rh.Delete(context.Background()); derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			node := nodesV3.ByNumericalID[nodeIdx]
			node.ID = rh.GetID()

			// Recover public IP of the master if it exists
			node.PublicIP, innerXErr = rh.GetPublicIP()
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// No public IP, this can happen; continue
				default:
					return innerXErr
				}
			}

			// Recover the private IP of the master that MUST exist
			node.PrivateIP, innerXErr = rh.GetPrivateIP()
			if innerXErr != nil {
				return innerXErr
			}

			// Updates property
			nodesV3.Masters = append(nodesV3.Masters, nodeIdx)
			nodesV3.MasterByName[node.Name] = node.NumericalID
			nodesV3.MasterByID[node.ID] = node.NumericalID

			return nil
		})
	})
	if xerr != nil {
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	hostLabel = fmt.Sprintf("master #%d (%s)", p.index, rh.GetName())

	if xerr = instance.installProxyCacheClient(task.GetContext(), rh, hostLabel); xerr != nil {
		return nil, xerr
	}

	if xerr = instance.installNodeRequirements(task.GetContext(), clusternodetype.Master, rh, hostLabel); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] Host creation successful.", hostLabel)
	return rh, nil
}

// taskConfigureMasters configure masters
// This function is intended to be call as a goroutine
func (instance *cluster) taskConfigureMasters(task concurrency.Task, _ concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	logrus.Debugf("[cluster %s] Configuring masters...", instance.GetName())
	started := time.Now()

	// var subtasks []concurrency.Task
	masters, xerr := instance.unsafeListMasters()
	if xerr != nil {
		return nil, xerr
	}
	if len(masters) == 0 {
		return nil, nil
	}

	tg, xerr := concurrency.NewTaskGroupWithParent(task)
	if xerr != nil {
		return nil, xerr
	}

	var errors []error
	for i, master := range masters {
		if master.ID == "" {
			continue
		}

		host, xerr := LoadHost(instance.GetService(), master.ID)
		if xerr != nil {
			logrus.Warnf("failed to get metadata of Host: %s", xerr.Error())
			errors = append(errors, xerr)
			continue
		}
		defer func(hostInstance resources.Host) {
			hostInstance.Released()
		}(host)

		_, xerr = tg.Start(instance.taskConfigureMaster, taskConfigureMasterParameters{
			Index: i + 1,
			Host:  host,
		})
		if xerr != nil {
			errors = append(errors, xerr)
		}
		// subtasks = append(subtasks, subtask)
	}

	// for _, s := range subtasks {
	// 	_, state := s.Wait()
	// 	if state != nil {
	// 		errors = append(errors, state)
	// 	}
	// }
	// if len(errors) > 0 {
	// 	return nil, fail.NewErrorList(errors)
	// }
	if _, xerr = tg.Wait(); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[cluster %s] Masters configuration successful in [%s].", instance.GetName(), temporal.FormatDuration(time.Since(started)))
	return nil, nil
}

type taskConfigureMasterParameters struct {
	Index uint
	Host  resources.Host
}

// taskConfigureMaster configures one master
// This function is intended to be call as a goroutine
func (instance *cluster) taskConfigureMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Convert and validate params
	p, ok := params.(taskConfigureMasterParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskConfigureMasterParameters'")
	}

	if p.Index < 1 {
		return nil, fail.InvalidParameterError("params.indexindex", "cannot be an integer less than 1")
	}
	if p.Host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	started := time.Now()

	hostLabel := fmt.Sprintf("master #%d (%s)", p.Index, p.Host.GetName())
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// install docker feature (including docker-compose)
	if xerr = instance.installDocker(task.GetContext(), p.Host, hostLabel); xerr != nil {
		return nil, xerr
	}

	// Configure master for flavour
	if instance.makers.ConfigureMaster != nil {
		if xerr = instance.makers.ConfigureMaster(instance, p.Index, p.Host); xerr != nil {
			return nil, fail.Wrap(xerr, "failed to configure master '%s'", p.Host.GetName())
		}

		logrus.Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
		return nil, nil
	}

	// Not finding a callback isn't an error, so return nil in this case
	return nil, nil
}

type taskCreateNodesParameters struct {
	count         uint
	public        bool
	nodesDef      abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateNodes creates nodes
// This function is intended to be call as a goroutine
func (instance *cluster) taskCreateNodes(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Convert then validate params
	p, ok := params.(taskCreateNodesParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreateNodesParameters'")
	}

	if p.count < 1 {
		return nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d, %v)", p.count, p.public).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	clusterName := instance.GetName()

	if p.count == 0 {
		logrus.Debugf("[cluster %s] no nodes to create.", clusterName)
		return nil, nil
	}
	logrus.Debugf("[cluster %s] creating %d node%s...", clusterName, p.count, strprocess.Plural(p.count))

	timeout := temporal.GetContextTimeout() + time.Duration(p.count)*time.Minute
	var subtasks []concurrency.Task
	for i := uint(1); i <= p.count; i++ {
		subtask, xerr := task.StartInSubtask(instance.taskCreateNode, taskCreateNodeParameters{
			index:         i,
			nodeDef:       p.nodesDef,
			timeout:       timeout,
			keepOnFailure: p.keepOnFailure,
		})
		if xerr != nil {
			return nil, xerr
		}

		subtasks = append(subtasks, subtask)
	}

	var errs []error
	for _, s := range subtasks {
		if _, state := s.Wait(); state != nil {
			errs = append(errs, state)
		}
	}
	if len(errs) > 0 {
		return nil, fail.NewErrorList(errs)
	}

	logrus.Debugf("[cluster %s] %d node%s creation successful.", clusterName, p.count, strprocess.Plural(p.count))
	return nil, nil
}

type taskCreateNodeParameters struct {
	index         uint
	nodeDef       abstract.HostSizingRequirements
	timeout       time.Duration // Not used currently
	keepOnFailure bool
}

// taskCreateNode creates a node in the Cluster
// This function is intended to be call as a goroutine
func (instance *cluster) taskCreateNode(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Convert then validate parameters
	p, ok := params.(taskCreateNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}

	if p.index < 1 {
		return nil, fail.InvalidParameterError("params.indexindex", "cannot be an integer less than 1")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d)", p.index).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	hostLabel := fmt.Sprintf("node #%d", p.index)
	logrus.Debugf("[%s] starting Host creation...", hostLabel)

	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, xerr = instance.buildHostname("node", clusternodetype.Node)
	if xerr != nil {
		return nil, xerr
	}

	// First creates node in metadata, to keep track of its tried creation, in case of failure
	var nodeIdx uint
	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nodesV3.GlobalLastIndex++
			nodeIdx = nodesV3.GlobalLastIndex
			node := &propertiesv3.ClusterNode{
				NumericalID: nodeIdx,
				Name:        hostReq.ResourceName,
			}
			nodesV3.ByNumericalID[nodeIdx] = node
			return nil
		})
	})
	if xerr != nil {
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	// Starting from here, if exiting with error, remove entry from master nodes of the metadata
	defer func() {
		if xerr != nil && !p.keepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			derr := instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					delete(nodesV3.ByNumericalID, nodeIdx)
					return nil
				})
			})
			if derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove master from Cluster metadata", actionFromError(xerr)))
			}
		}
	}()

	netCfg, xerr := instance.GetNetworkConfig()
	if xerr != nil {
		return nil, xerr
	}

	subnet, xerr := LoadSubnet(instance.GetService(), "", netCfg.SubnetID)
	if xerr != nil {
		return nil, xerr
	}

	// Create the rh
	xerr = subnet.Inspect(func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		as, ok := clonable.(*abstract.Subnet)
		if !ok {
			return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		hostReq.Subnets = []*abstract.Subnet{as}
		return nil
	})
	if xerr != nil {
		return nil, xerr
	}

	if hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP(); xerr != nil {
		return nil, xerr
	}

	hostReq.PublicIP = false
	hostReq.KeepOnFailure = p.keepOnFailure

	rh, xerr := NewHost(instance.GetService())
	if xerr != nil {
		return nil, xerr
	}

	if _, xerr = rh.Create(task.GetContext(), hostReq, p.nodeDef); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !p.keepOnFailure {
			// // Disable abort signal during the clean up
			// defer task.DisarmAbortSignal()()

			if derr := rh.Delete(context.Background()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Host '%s'", actionFromError(xerr), rh.GetName()))
			}
		}
	}()

	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			node := nodesV3.ByNumericalID[nodeIdx]
			node.ID = rh.GetID()
			node.PublicIP, innerXErr = rh.GetPublicIP()
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// No public IP, this can happen; continue
				default:
					return innerXErr
				}
			}

			if node.PrivateIP, innerXErr = rh.GetPrivateIP(); innerXErr != nil {
				return innerXErr
			}

			nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
			nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
			nodesV3.PrivateNodeByID[node.ID] = node.NumericalID

			return nil
			//
			// nodesV3.GlobalLastIndex++
			//
			// pubIP, innerXErr := rh.GetPublicIP(task)
			// if innerXErr != nil {
			// 	switch innerXErr.(type) {
			// 	case *fail.ErrNotFound:
			// 		// No public IP, this can happen; continue
			// 	default:
			// 		return innerXErr
			// 	}
			// }
			//
			// privIP, innerXErr := rh.GetPrivateIP(task)
			// if innerXErr != nil {
			// 	return innerXErr
			// }
			//
			// node = &propertiesv3.ClusterNode{
			// 	ID:          rh.GetID(),
			// 	NumericalID: nodesV3.GlobalLastIndex,
			// 	Name:        rh.GetName(),
			// 	PrivateIP:   privIP,
			// 	PublicIP:    pubIP,
			// }
			// nodesV3.ByNumericalID[node.NumericalID] = node
			// nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
			// nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
			// nodesV3.PrivateNodeByID[node.ID] = node.NumericalID
			// return nil
		})
	})
	if xerr != nil {
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	hostLabel = fmt.Sprintf("node #%d (%s)", p.index, rh.GetName())

	if xerr = instance.installProxyCacheClient(task.GetContext(), rh, hostLabel); xerr != nil {
		return nil, xerr
	}

	if xerr = instance.installNodeRequirements(task.GetContext(), clusternodetype.Node, rh, hostLabel); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] Host creation successful.", hostLabel)
	return rh, nil
}

// taskConfigureNodes configures nodes
// This function is intended to be call as a goroutine
func (instance *cluster) taskConfigureNodes(task concurrency.Task, _ concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	clusterName := instance.GetName()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	list, err := instance.unsafeListNodes()
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		logrus.Debugf("[cluster %s] no nodes to configure.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] configuring nodes...", clusterName)

	var (
		// i    uint
		errs []error
	)

	svc := instance.GetService()
	tg, xerr := concurrency.NewTaskGroupWithParent(task)
	if xerr != nil {
		return nil, xerr
	}

	// var subtasks []concurrency.Task
	for i, node := range list {
		if node.ID == "" {
			continue
		}

		host, xerr := LoadHost(svc, node.ID)
		if xerr != nil {
			errs = append(errs, fail.Wrap(xerr, "failed to get metadata of Host '%s'", node.Name))
			continue
		}
		defer func(hostInstance resources.Host) {
			hostInstance.Released()
		}(host)

		// subtask, xerr := task.StartInSubtask(instance.taskConfigureNode, taskConfigureNodeParameters{
		_, xerr = task.StartInSubtask(instance.taskConfigureNode, taskConfigureNodeParameters{
			Index: i + 1,
			Host:  host,
		})
		if xerr != nil {
			return nil, xerr
		}

		// subtasks = append(subtasks, subtask)
	}

	// for _, s := range subtasks {
	// 	if _, xerr := s.Wait(); xerr != nil {
	// 		errs = append(errs, xerr)
	// 	}
	// }
	if len(errs) > 0 {
		return nil, fail.NewErrorList(errs)
	}
	if _, xerr = tg.Wait(); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[cluster %s] nodes configuration successful.", clusterName)
	return nil, nil
}

type taskConfigureNodeParameters struct {
	Index uint
	Host  resources.Host
}

// taskConfigureNode configure one node
// This function is intended to be call as a goroutine
func (instance *cluster) taskConfigureNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Convert and validate params
	p, ok := params.(taskConfigureNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskConfigureNodeParameters'")
	}
	if p.Index < 1 {
		return nil, fail.InvalidParameterError("params.indexindex", "cannot be an integer less than 1")
	}
	if p.Host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d, %s)", p.Index, p.Host.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	hostLabel := fmt.Sprintf("node #%d (%s)", p.Index, p.Host.GetName())
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// Docker and docker-compose installation is mandatory on all nodes
	if xerr = instance.installDocker(task.GetContext(), p.Host, hostLabel); xerr != nil {
		return nil, xerr
	}

	// Now configures node specifically for cluster flavor
	if instance.makers.ConfigureNode == nil {
		return nil, nil
	}
	if xerr = instance.makers.ConfigureNode(instance, p.Index, p.Host); xerr != nil {
		logrus.Error(xerr.Error())
		return nil, xerr
	}
	logrus.Debugf("[%s] configuration successful.", hostLabel)
	return nil, nil
}

type taskDeleteNodeOnFailureParameters struct {
	node *propertiesv3.ClusterNode
}

// taskDeleteNodeOnFailure deletes a host
func (instance *cluster) taskDeleteNodeOnFailure(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Convert and validate params
	node := params.(taskDeleteNodeOnFailureParameters).node
	// if rh.isNull() {
	// 	return nil, fail.InvalidParameterError("params", "must be a valid '*host'")
	// }

	prefix := "Cleaning up on failure, "
	hostName := node.Name
	logrus.Debugf(prefix + fmt.Sprintf("deleting Host '%s'", hostName))

	rh, xerr := LoadHost(instance.GetService(), node.ID)
	if xerr != nil {
		return nil, xerr
	}

	if xerr := rh.Delete(context.Background()); xerr != nil {
		logrus.Errorf(prefix + fmt.Sprintf("failed to delete Host '%s'", hostName))
		return nil, xerr
	}

	logrus.Debugf(prefix + fmt.Sprintf("successfully deleted Host '%s'", hostName))
	return nil, nil
}

type taskDeleteNodeParameters struct {
	node   *propertiesv3.ClusterNode
	master *host
}

func (instance *cluster) taskDeleteNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Convert and validate params
	p, ok := params.(taskDeleteNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeParameters'")
	}
	if p.node == nil {
		return nil, fail.InvalidParameterError("params.node", "cannot be nil")
	}

	defer func() {
		if xerr != nil {
			xerr = fail.Wrap(xerr, "failed to delete Node '%s'", p.node.Name)
		}
	}()

	logrus.Debugf("Deleting Node '%s'", p.node.Name)
	if xerr := instance.deleteNode(task.GetContext(), p.node, p.master); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("Successfully deleted Node '%s'", p.node.Name)
	return nil, nil
}

func (instance *cluster) taskDeleteMaster(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	// Convert and validate params
	p, ok := params.(taskDeleteNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskDeleteNodeParameters'")
	}
	if p.node == nil {
		return nil, fail.InvalidParameterError("params.node", "cannot be nil")
	}

	var host resources.Host
	if p.node.ID != "" { //nolint
		host, xerr = LoadHost(instance.GetService(), p.node.ID)
	} else if p.node.Name != "" {
		host, xerr = LoadHost(instance.GetService(), p.node.Name)
	} else {
		return nil, fail.InvalidParameterError("p.node", "must have a non-empty string in either field ID or Name")
	}
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("Deleting Master '%s'", p.node.Name)
	if xerr := instance.deleteMaster(task.GetContext(), host); xerr != nil {
		logrus.Errorf("Failed to delete Master '%s'", p.node.Name)
		return nil, xerr
	}

	logrus.Debugf("Successfully deleted Master '%s'", p.node.Name)
	return nil, nil
}

type taskDeleteHostOnFailureParameters struct {
	host resources.Host
}

// taskDeleteHostOnFailure deletes a host
func (instance *cluster) taskDeleteHostOnFailure(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	// Convert and validate params
	hostInstance := params.(taskDeleteHostOnFailureParameters).host
	// if rh.isNull() {
	// 	return nil, fail.InvalidParameterError("params", "must be a valid '*host'")
	// }

	prefix := "Cleaning up on failure, "
	hostName := hostInstance.GetName()
	logrus.Debugf(prefix + fmt.Sprintf("deleting Host '%s'", hostName))

	if xerr := hostInstance.Delete(context.Background()); xerr != nil {
		logrus.Errorf(prefix + fmt.Sprintf("failed to delete Host '%s'", hostName))
		return nil, xerr
	}

	logrus.Debugf(prefix + fmt.Sprintf("successfully deleted Host '%s'", hostName))
	return nil, nil
}
