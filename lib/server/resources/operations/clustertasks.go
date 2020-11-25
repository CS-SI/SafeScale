/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (c *cluster) taskStartHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	// FIXME: validate params
	return nil, c.service.StartHost(params.(string))
}

func (c *cluster) taskStopHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	if c == nil {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	// FIXME: validate params
	return nil, c.service.StopHost(params.(string))
}

// taskInstallGateway installs necessary components on one gateway
// This function is intended to be call as a goroutine
func (c *cluster) taskInstallGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), params).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	gateway, ok := params.(resources.Host)
	if !ok {
		return result, fail.InvalidParameterError("params", "must contain a 'resources.Host'")
	}
	if gateway == nil {
		return result, fail.InvalidParameterError("params", "cannot be nil")
	}

	hostLabel := gateway.GetName()
	logrus.Debugf("[%s] starting installation...", hostLabel)

	if _, xerr = gateway.WaitSSHReady(task, temporal.GetHostTimeout()); xerr != nil {
		return nil, xerr
	}

	// Installs docker and docker-compose on gateway
	if xerr = c.installDocker(task, gateway, hostLabel); xerr != nil {
		return nil, xerr
	}

	// Installs proxycache server on gateway (if not disabled)
	if xerr = c.installProxyCacheServer(task, gateway, hostLabel); xerr != nil {
		return nil, xerr
	}

	// Installs requirements as defined by cluster Flavor (if it exists)
	if xerr = c.installNodeRequirements(task, clusternodetype.Gateway, gateway, hostLabel); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] preparation successful", hostLabel)
	return nil, nil
}

// taskConfigureGateway prepares one gateway
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	// validate and convert parameters
	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}
	gw, ok := params.(*protocol.Host)
	if !ok {
		return result, fail.InvalidParameterError("params", "must contain a *protocol.Host")
	}
	if gw == nil {
		return result, fail.InvalidParameterError("params", "cannot be nil")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	logrus.Debugf("[%s] starting configuration...", gw.Name)

	if c.makers.ConfigureGateway != nil {
		if xerr = c.makers.ConfigureGateway(task, c); xerr != nil {
			return nil, xerr
		}
	}

	logrus.Debugf("[%s] configuration successful in [%s].", gw.Name, tracer.Stopwatch().String())
	return nil, nil
}

// taskCreateMasters creates masters
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateMasters(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("params", "is not a data.Map")
	}
	var (
		count  uint
		def    abstract.HostSizingRequirements
		nokeep bool
	)
	if count, ok = p["count"].(uint); !ok {
		return nil, fail.InvalidParameterError("params[count]", "is missing or is not an unsigned integer")
	}
	if count < 1 {
		return nil, fail.InvalidParameterError("params[count]", "cannot be an integer less than 1")
	}
	if _, ok = p["masterDef"]; !ok {
		return nil, fail.InvalidParameterError("params[masterDef]", "is missing")
	}
	if def, ok = p["masterDef"].(abstract.HostSizingRequirements); !ok {
		return nil, fail.InvalidParameterError("params[masterDef]", "is not an 'abstract.HostSizingRequirements'")
	}
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	clusterName := c.GetName()

	if count == 0 {
		logrus.Debugf("[cluster %s] no masters to create.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] creating %d master%s...", clusterName, count, strprocess.Plural(count))

	var subtasks []concurrency.Task
	timeout := temporal.GetContextTimeout() + time.Duration(count)*time.Minute
	var i uint
	for ; i < count; i++ {
		subtask, xerr := task.StartInSubtask(c.taskCreateMaster, data.Map{
			"index":     i + 1,
			"masterDef": def,
			"timeout":   timeout,
			"nokeep":    nokeep,
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

// taskCreateMaster creates one master
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())
	defer fail.OnPanic(&xerr)

	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}

	var (
		anon  interface{}
		index uint
		def   abstract.HostSizingRequirements
		// timeout time.Duration
		nokeep bool
	)
	if anon, ok = p["index"]; !ok {
		return nil, fail.InvalidParameterError("params['index']", "is missing or is not an unsigned integer")
	}
	if index, ok = anon.(uint); !ok || index < 1 {
		return nil, fail.InvalidParameterError("params['index']", "must be an interger greater than 0")
	}
	if anon, ok = p["masterDef"]; !ok {
		return nil, fail.InvalidParameterError("params['masterDef']", "is missing")
	}
	if def, ok = anon.(abstract.HostSizingRequirements); !ok {
		return nil, fail.InvalidParameterError("params['masterDef']", "is not an 'abstract.HostSizingRequirements'")
	}
	// if anon, ok = p["timeout"]; !ok {
	// 	timeout = 0
	// } else {
	// 	if timeout = anon.(time.Duration); !ok {
	// 		return nil, fail.InvalidParameterError("params[timeout]", "is not a time.Duration")
	// 	}
	// }
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	hostLabel := fmt.Sprintf("master #%d", index)
	logrus.Debugf("[%s] starting objh resource creation...", hostLabel)

	netCfg, xerr := c.GetNetworkConfig(task)
	if xerr != nil {
		return nil, xerr
	}
	subnet, xerr := LoadSubnet(task, c.service, "", netCfg.NetworkID)
	if xerr != nil {
		return nil, xerr
	}

	hostReq := abstract.HostRequest{}
	xerr = subnet.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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

	if hostReq.ResourceName, xerr = c.buildHostname(task, "master", clusternodetype.Master); xerr != nil {
		return nil, xerr
	}
	hostReq.DefaultRouteIP = netCfg.DefaultRouteIP
	hostReq.PublicIP = false
	// hostReq.ImageID = def.Image

	objh, xerr := NewHost(c.service)
	if xerr != nil {
		return nil, xerr
	}
	if _, xerr = objh.Create(task, hostReq, def); xerr != nil {
		return nil, xerr
	}

	// Updates cluster metadata to keep track of created objh, before testing if an error occurred during the creation
	xerr = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// References new node in cluster
		return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
			nodesV2 := clonable.(*propertiesv2.ClusterNodes)
			nodesV2.GlobalLastIndex++
			pubIP, innerErr := objh.GetPublicIP(task)
			if innerErr != nil {
				return innerErr
			}
			privIP, innerErr := objh.GetPrivateIP(task)
			if innerErr != nil {
				return innerErr
			}
			node := &propertiesv2.ClusterNode{
				ID:          objh.GetID(),
				NumericalID: nodesV2.GlobalLastIndex,
				Name:        objh.GetName(),
				PrivateIP:   privIP,
				PublicIP:    pubIP,
			}
			nodesV2.Masters = append(nodesV2.Masters, node)
			return nil
		})
	})
	if xerr != nil {
		if nokeep {
			derr := objh.Delete(task)
			if derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
		return nil, fail.Wrap(xerr, "[%s] objh resource creation failed")
	}

	hostLabel = fmt.Sprintf("%s (%s)", hostLabel, objh.GetName())
	logrus.Debugf("[%s] objh resource creation successful", hostLabel)

	if xerr = c.installProxyCacheClient(task, objh, hostLabel); xerr != nil {
		return nil, xerr
	}

	// Installs cluster-level system requirements...
	if xerr = c.installNodeRequirements(task, clusternodetype.Master, objh, hostLabel); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] objh resource creation successful.", hostLabel)
	return nil, nil
}

// taskConfigureMasters configure masters
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureMasters(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	list, xerr := c.ListMasterIDs(task)
	if xerr != nil {
		return nil, xerr
	}
	if len(list) == 0 {
		return nil, nil
	}

	logrus.Debugf("[cluster %s] Configuring masters...", c.GetName())
	started := time.Now()

	var subtasks []concurrency.Task
	masters, xerr := c.ListMasterIDs(task)
	if xerr != nil {
		return nil, xerr
	}

	var errors []error

	for i, hostID := range masters {
		host, xerr := LoadHost(task, c.GetService(), hostID)
		if xerr != nil {
			logrus.Warnf("failed to get metadata of host: %s", xerr.Error())
			errors = append(errors, xerr)
			continue
		}
		subtask, xerr := task.StartInSubtask(c.taskConfigureMaster, data.Map{
			"index": i + 1,
			"host":  host,
		})
		if xerr != nil {
			errors = append(errors, xerr)
		}
		subtasks = append(subtasks, subtask)
	}

	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errors = append(errors, state)
		}
	}
	if len(errors) > 0 {
		return nil, fail.NewErrorList(errors)
	}

	logrus.Debugf("[cluster %s] Masters configuration successful in [%s].", c.GetName(), temporal.FormatDuration(time.Since(started)))
	return nil, nil
}

// taskConfigureMaster configures one master
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	// Convert and validate params
	p, ok := params.(data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}

	if p == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}
	var (
		index uint
		host  resources.Host
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, fail.InvalidParameterError("params[index]", "is missing")
	}
	if index < 1 {
		return nil, fail.InvalidParameterError("params[index]", "cannot be an integer less than 1")
	}
	if _, ok = p["host"]; !ok {
		return nil, fail.InvalidParameterError("params[host]", "is missing")
	}
	if host, ok = p["host"].(resources.Host); !ok {
		return nil, fail.InvalidParameterError("params[host]", "must be a 'resources.Host'")
	}
	if host == nil {
		return nil, fail.InvalidParameterError("params[host]", "cannot be nil")
	}

	started := time.Now()

	hostLabel := fmt.Sprintf("master #%d (%s)", index, host.GetName())
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// install docker feature (including docker-compose)
	if xerr = c.installDocker(task, host, hostLabel); xerr != nil {
		return nil, xerr
	}

	if c.makers.ConfigureNode != nil {
		if xerr = c.makers.ConfigureMaster(task, c, index, host); xerr != nil {
			return nil, xerr
		}
		logrus.Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
		return nil, nil
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil, nil
}

// taskCreateNodes creates nodes
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateNodes(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}

	// Convert then validate params
	p, ok := params.(data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("params", "is not a data.Map")
	}
	var (
		count  uint
		public bool
		def    abstract.HostSizingRequirements
		nokeep bool
	)
	if count, ok = p["count"].(uint); !ok {
		count = 1
	}
	if count < 1 {
		return nil, fail.InvalidParameterError("params[count]", "cannot be an integer less than 1")
	}
	if public, ok = p["public"].(bool); !ok {
		public = false
	}
	if _, ok = p["nodeDef"]; !ok {
		return nil, fail.InvalidParameterError("param[nodeDef]", "is missing")
	}
	if def, ok = p["nodeDef"].(abstract.HostSizingRequirements); !ok {
		return nil, fail.InvalidParameterError("param[nodeDef]", "is not an 'abstract.HostSizingRequirements'")
	}
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d, %v)", count, public).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	clusterName := c.GetName()

	if count == 0 {
		logrus.Debugf("[cluster %s] no nodes to create.", clusterName)
		return nil, nil
	}
	logrus.Debugf("[cluster %s] creating %d node%s...", clusterName, count, strprocess.Plural(count))

	timeout := temporal.GetContextTimeout() + time.Duration(count)*time.Minute
	var subtasks []concurrency.Task
	for i := uint(1); i <= count; i++ {
		subtask, xerr := task.StartInSubtask(c.taskCreateNode, data.Map{
			"index":   i,
			"type":    clusternodetype.Node,
			"nodeDef": def,
			"timeout": timeout,
			"nokeep":  nokeep,
		})
		if xerr != nil {
			return nil, xerr
		}
		subtasks = append(subtasks, subtask)
	}

	var errs []error
	for _, s := range subtasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state)
		}
	}
	if len(errs) > 0 {
		return nil, fail.NewErrorList(errs)
	}

	logrus.Debugf("[cluster %s] %d node%s creation successful.", clusterName, count, strprocess.Plural(count))
	return nil, nil
}

// taskCreateNode creates a Node in the Cluster
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateNode(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Convert then validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}
	if p == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}
	var (
		index uint
		def   abstract.HostSizingRequirements
		// timeout time.Duration
		nokeep bool
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, fail.InvalidParameterError("params[index]", "cannot be an integer less than 1")
	}
	if def, ok = p["nodeDef"].(abstract.HostSizingRequirements); !ok {
		return nil, fail.InvalidParameterError("params[def]", "is missing or is not a *propertiesv2.HostEffectiveSizing")
	}
	// if timeout, ok = p["timeout"].(time.Duration); !ok {
	// 	return nil, fail.InvalidParameterError("params[timeout]", "is missing ir is not a time.Duration")
	// }
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d)", index).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	hostLabel := fmt.Sprintf("node #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, xerr := c.GetNetworkConfig(task)
	if xerr != nil {
		return nil, xerr
	}
	subnet, xerr := LoadSubnet(task, c.service, "", netCfg.NetworkID)
	if xerr != nil {
		return nil, xerr
	}

	// Create the host
	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, xerr = c.buildHostname(task, "node", clusternodetype.Node)
	if xerr != nil {
		return nil, xerr
	}

	xerr = subnet.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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

	if hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP(task); xerr != nil {
		return nil, xerr
	}

	hostReq.PublicIP = false
	// hostReq.ImageID = def.Image

	// if timeout < temporal.GetLongOperationTimeout() {
	// 	timeout = temporal.GetLongOperationTimeout()
	// }

	host, xerr := NewHost(c.GetService())
	if xerr != nil {
		return nil, xerr
	}
	if _, xerr = host.Create(task, hostReq, def); xerr != nil {
		return nil, xerr
	}
	if host != nil {
		return nil, fail.InconsistentError("host.Create() reported a success but host is nil")
	}

	defer func() {
		if xerr != nil {
			if derr := host.Delete(task); derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	var node *propertiesv2.ClusterNode
	xerr = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) fail.Error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			// Registers the new Agent in the swarmCluster struct
			nodesV2.GlobalLastIndex++
			pubIP, innerErr := host.GetPublicIP(task)
			if innerErr != nil {
				return innerErr
			}
			privIP, innerErr := host.GetPrivateIP(task)
			if innerErr != nil {
				return innerErr
			}
			node = &propertiesv2.ClusterNode{
				ID:          host.GetID(),
				NumericalID: nodesV2.GlobalLastIndex,
				Name:        host.GetName(),
				PrivateIP:   privIP,
				PublicIP:    pubIP,
			}
			nodesV2.PrivateNodes = append(nodesV2.PrivateNodes, node)
			return nil
		})
	})
	if xerr != nil {
		if nokeep {
			if derr := host.Delete(task); derr != nil {
				_ = xerr.AddConsequence(derr)
			}
		}
		return nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)
	}

	hostLabel = fmt.Sprintf("node #%d (%s)", index, host.GetName())
	logrus.Debugf("[%s] host resource creation successful.", hostLabel)

	if xerr = c.installProxyCacheClient(task, host, hostLabel); xerr != nil {
		return nil, xerr
	}

	if xerr = c.installNodeRequirements(task, clusternodetype.Node, host, hostLabel); xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return host, nil
}

// taskConfigureNodes configures nodes
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureNodes(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	// FIXME: validate parameters

	clusterName := c.GetName()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	list, err := c.ListNodeIDs(task)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		logrus.Debugf("[cluster %s] no nodes to configure.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] configuring nodes...", clusterName)

	var (
		host   resources.Host
		i      uint
		hostID string
		errs   []error
	)

	svc := c.GetService()
	var subtasks []concurrency.Task
	for _, hostID = range list {
		i++
		if host, xerr = LoadHost(task, svc, hostID); xerr != nil {
			errs = append(errs, fail.Wrap(xerr, "failed to get metadata of host '%s'", hostID))
			continue
		}
		subtask, xerr := task.StartInSubtask(c.taskConfigureNode, data.Map{
			"index": i,
			"host":  host,
		})
		if xerr != nil {
			return nil, xerr
		}

		subtasks = append(subtasks, subtask)
	}

	for _, s := range subtasks {
		if _, xerr := s.Wait(); xerr != nil {
			errs = append(errs, xerr)
		}
	}
	if len(errs) > 0 {
		return nil, fail.NewErrorList(errs)
	}

	logrus.Debugf("[cluster %s] nodes configuration successful.", clusterName)
	return nil, nil
}

// taskConfigureNode configure one node
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, xerr fail.Error) {
	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a data.Map")
	}
	var (
		index uint
		host  resources.Host
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, fail.InvalidParameterError("params[index]", "is missing or is not an integer")
	}
	if index < 1 {
		return nil, fail.InvalidParameterError("params[index]", "cannot be an integer less than 1")
	}
	if host, ok = p["host"].(resources.Host); !ok {
		return nil, fail.InvalidParameterError("params[host]", "is missing or is not a 'resources.Host'")
	}
	if host == nil {
		return nil, fail.InvalidParameterError("params[host]", "cannot be nil")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.cluster"), "(%d, %s)", index, host.GetName()).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage())

	hostLabel := fmt.Sprintf("node #%d (%s)", index, host.GetName())
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// Docker and docker-compose installation is mandatory on all nodes
	if xerr = c.installDocker(task, host, hostLabel); xerr != nil {
		return nil, xerr
	}

	// Now configures node specifically for cluster flavor
	if c.makers.ConfigureNode == nil {
		return nil, nil
	}
	if xerr = c.makers.ConfigureNode(task, c, index, host); xerr != nil {
		logrus.Error(xerr.Error())
		return nil, xerr
	}
	logrus.Debugf("[%s] configuration successful.", hostLabel)
	return nil, nil
}

// taskDeleteHost deletes a host
func (c *cluster) taskDeleteHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, fail.Error) {
	if params == nil {
		return nil, fail.InvalidParameterError("params", "cannot be nil")
	}
	if host, ok := params.(resources.Host); ok {
		return nil, host.Delete(task)
	}
	return nil, fail.InvalidParameterError("params", "must be a 'resources.Host'")
}
