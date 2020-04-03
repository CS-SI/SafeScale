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
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (c *cluster) taskStartHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	//FIXME: validate params
	return nil, c.service.StartHost(params.(string))
}

func (c *cluster) taskStopHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	if c == nil {
		return nil, scerr.InvalidInstanceError()
	}
	if task == nil {
		return nil, scerr.InvalidParameterError("task", "cannot be nil")
	}

	//FIXME: validate params
	return nil, c.service.StopHost(params.(string))
}

// taskInstallGateway installs necessary components on one gateway
// This function is intended to be call as a goroutine
func (c *cluster) taskInstallGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(task, true, "(%v)", params).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	gateway, ok := params.(resources.Host)
	if !ok {
		return result, scerr.InvalidParameterError("params", "must contain a 'resources.Host'")
	}
	if gateway == nil {
		return result, scerr.InvalidParameterError("params", "cannot be nil")
	}

	hostLabel := gateway.SafeGetName()
	logrus.Debugf("[%s] starting installation...", hostLabel)

	_, err = gateway.WaitSSHReady(task, temporal.GetHostTimeout())
	if err != nil {
		return nil, err
	}

	// Installs docker and docker-compose on gateway
	err = c.installDocker(task, gateway, hostLabel)
	if err != nil {
		return nil, err
	}

	// Installs proxycache server on gateway (if not disabled)
	err = c.installProxyCacheServer(task, gateway, hostLabel)
	if err != nil {
		return nil, err
	}

	// Installs requirements as defined by cluster Flavor (if it exists)
	err = c.installNodeRequirements(task, clusternodetype.Gateway, gateway, hostLabel)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[%s] preparation successful", hostLabel)
	return nil, nil
}

// taskConfigureGateway prepares one gateway
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	// validate and convert parameters
	if params == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}
	gw, ok := params.(*protocol.Host)
	if !ok {
		return result, scerr.InvalidParameterError("params", "must contain a *protocol.Host")
	}
	if gw == nil {
		return result, scerr.InvalidParameterError("params", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, debug.IfTrace("cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Debugf("[%s] starting configuration...", gw.Name)

	if c.makers.ConfigureGateway != nil {
		err := c.makers.ConfigureGateway(task, c)
		if err != nil {
			return nil, err
		}
	}

	logrus.Debugf("[%s] configuration successful in [%s].", gw.Name, tracer.Stopwatch().String())
	return nil, nil
}

// taskCreateMasters creates masters
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateMasters(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(task, true, "(%v)", params).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	if params == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params", "is not a data.Map")
	}
	var (
		count  uint
		def    *protocol.HostDefinition
		nokeep bool
	)
	if count, ok = p["count"].(uint); !ok {
		return nil, scerr.InvalidParameterError("params[count]", "is missing or is not an unsigned integer")
	}
	if count < 1 {
		return nil, scerr.InvalidParameterError("params[count]", "cannot be an integer less than 1")
	}
	if _, ok = p["masterDef"]; !ok {
		return nil, scerr.InvalidParameterError("params[masterDef]", "is missing")
	}
	if def, ok = p["masterDef"].(*protocol.HostDefinition); !ok {
		return nil, scerr.InvalidParameterError("params[masterDef]", "is not a *protocol.HostDefinition")
	}
	if def == nil {
		return nil, scerr.InvalidParameterError("params[masterDef]", "cannot be nil")
	}
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	clusterName := c.SafeGetName()

	if count == 0 {
		logrus.Debugf("[cluster %s] no masters to create.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] creating %d master%s...", clusterName, count, strprocess.Plural(count))

	var subtasks []concurrency.Task
	timeout := temporal.GetContextTimeout() + time.Duration(count)*time.Minute
	var i uint
	for ; i < count; i++ {
		subtask, err := task.StartInSubtask(c.taskCreateMaster, data.Map{
			"index":     i + 1,
			"masterDef": def,
			"timeout":   timeout,
			"nokeep":    nokeep,
		})
		if err != nil {
			return nil, err
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
		return nil, scerr.NewError("[cluster %s] failed to create master(s): %s", clusterName, msg)
	}

	logrus.Debugf("[cluster %s] masters creation successful.", clusterName)
	return nil, nil
}

// taskCreateMaster creates one master
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(task, true, "(%v)", params).Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()
	defer scerr.OnPanic(&err)()

	if params == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}

	var (
		anon  interface{}
		index uint
		def   *abstract.HostSizingRequirements
		image string
		// timeout time.Duration
		nokeep bool
	)
	if anon, ok = p["index"]; !ok {
		return nil, scerr.InvalidParameterError("params['index']", "is missing or is not an unsigned integer")
	}
	if index, ok = anon.(uint); !ok || index < 1 {
		return nil, scerr.InvalidParameterError("params['index']", "must be an interger greater than 0")
	}
	if anon, ok = p["masterDef"]; !ok {
		return nil, scerr.InvalidParameterError("params['masterDef']", "is missing")
	}
	if def, ok = anon.(*abstract.HostSizingRequirements); !ok {
		return nil, scerr.InvalidParameterError("params['masterDef']", "is not a *abstract.HostSizingRequirements")
	}
	if def == nil {
		return nil, scerr.InvalidParameterError("params['masterDef']", "cannot be nil")
	}
	if anon, ok = p["image"]; !ok {
		return nil, scerr.InvalidParameterError("params['image']", "is missing")
	}
	if image, ok = anon.(string); !ok {
		return nil, scerr.InvalidParameterError("params['image']", "cannot be an empty string")
	}
	// if anon, ok = p["timeout"]; !ok {
	// 	timeout = 0
	// } else {
	// 	if timeout = anon.(time.Duration); !ok {
	// 		return nil, scerr.InvalidParameterError("params[timeout]", "is not a time.Duration")
	// 	}
	// }
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	hostLabel := fmt.Sprintf("master #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, err := c.GetNetworkConfig(task)
	if err != nil {
		return nil, err
	}
	network, err := LoadNetwork(task, c.service, netCfg.NetworkID)
	if err != nil {
		return nil, err
	}

	hostReq := abstract.HostRequest{}
	err = network.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		networkCore, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		hostReq.Networks = []*abstract.Network{networkCore}
		return nil
	})
	if err != nil {
		return nil, err
	}

	hostReq.ResourceName, err = c.buildHostname(task, "master", clusternodetype.Master)
	if err != nil {
		return nil, err
	}
	hostReq.DefaultRouteIP = netCfg.DefaultRouteIP
	hostReq.PublicIP = false
	hostReq.ImageID = image

	host, err := NewHost(c.service)
	if err != nil {
		return nil, err
	}
	err = host.Create(task, hostReq, *def)
	if err != nil {
		return nil, err
	}

	// Updates cluster metadata to keep track of created host, before testing if an error occurred during the creation
	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		// References new node in cluster
		return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2 := clonable.(*propertiesv2.ClusterNodes)
			nodesV2.GlobalLastIndex++
			pubIP, innerErr := host.GetPublicIP(task)
			if innerErr != nil {
				return innerErr
			}
			privIP, innerErr := host.GetPrivateIP(task)
			if innerErr != nil {
				return innerErr
			}
			node := &propertiesv2.ClusterNode{
				ID:          host.SafeGetID(),
				NumericalID: nodesV2.GlobalLastIndex,
				Name:        host.SafeGetName(),
				PrivateIP:   privIP,
				PublicIP:    pubIP,
			}
			nodesV2.Masters = append(nodesV2.Masters, node)
			return nil
		})
	})
	if err != nil && nokeep {
		derr := host.Delete(task)
		if derr != nil {
			err = scerr.AddConsequence(err, derr)
		}
		return nil, err
	}

	if err != nil {
		return nil, scerr.Wrap(err, "[%s] host resource creation failed")
	}
	hostLabel = fmt.Sprintf("%s (%s)", hostLabel, host.SafeGetName())
	logrus.Debugf("[%s] host resource creation successful", hostLabel)

	err = c.installProxyCacheClient(task, host, hostLabel)
	if err != nil {
		return nil, err
	}

	// Installs cluster-level system requirements...
	err = c.installNodeRequirements(task, clusternodetype.Master, host, hostLabel)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return nil, nil
}

// taskConfigureMasters configure masters
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureMasters(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	list, err := c.ListMasterIDs(task)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}

	logrus.Debugf("[cluster %s] Configuring masters...", c.SafeGetName())
	started := time.Now()

	var subtasks []concurrency.Task
	masters, err := c.ListMasterIDs(task)
	if err != nil {
		return nil, err
	}

	var errors []error

	for i, hostID := range masters {
		host, err := LoadHost(task, c.SafeGetService(), hostID)
		if err != nil {
			logrus.Warnf("failed to get metadata of host: %s", err.Error())
			errors = append(errors, err)
			continue
		}
		subtask, err := task.StartInSubtask(c.taskConfigureMaster, data.Map{
			"index": i + 1,
			"host":  host,
		})
		if err != nil {
			errors = append(errors, err)
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
		return nil, scerr.ErrListError(errors)
	}

	logrus.Debugf("[cluster %s] Masters configuration successful in [%s].", c.SafeGetName(), temporal.FormatDuration(time.Since(started)))
	return nil, nil
}

// taskConfigureMaster configures one master
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(task, true, "(%v)", params).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Convert and validate params
	p, ok := params.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}

	if p == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}
	var (
		index uint
		host  resources.Host
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, scerr.InvalidParameterError("params[index]", "is missing")
	}
	if index < 1 {
		return nil, scerr.InvalidParameterError("params[index]", "cannot be an integer less than 1")
	}
	if _, ok = p["host"]; !ok {
		return nil, scerr.InvalidParameterError("params[host]", "is missing")
	}
	if host, ok = p["host"].(resources.Host); !ok {
		return nil, scerr.InvalidParameterError("params[host]", "must be a 'resources.Host'")
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("params[host]", "cannot be nil")
	}

	started := time.Now()

	hostLabel := fmt.Sprintf("master #%d (%s)", index, host.SafeGetName())
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// install docker feature (including docker-compose)
	err = c.installDocker(task, host, hostLabel)
	if err != nil {
		return nil, err
	}

	if c.makers.ConfigureNode != nil {
		err = c.makers.ConfigureMaster(task, c, index, host)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
		return nil, nil
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil, nil
}

// taskCreateNodes creates nodes
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateNodes(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	if params == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}

	// Convert then validate params
	p, ok := params.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params", "is not a data.Map")
	}
	var (
		count  uint
		public bool
		def    *protocol.HostDefinition
		nokeep bool
	)
	if count, ok = p["count"].(uint); !ok {
		count = 1
	}
	if count < 1 {
		return nil, scerr.InvalidParameterError("params[count]", "cannot be an integer less than 1")
	}
	if public, ok = p["public"].(bool); !ok {
		public = false
	}
	if _, ok = p["nodeDef"]; !ok {
		return nil, scerr.InvalidParameterError("param[nodeDef]", "is missing")
	}
	if def, ok = p["nodeDef"].(*protocol.HostDefinition); !ok {
		return nil, scerr.InvalidParameterError("param[nodeDef]", "is not a *protocol.HostDefinition")
	}
	if def == nil {
		return nil, scerr.InvalidParameterError("param[nodeDef]", "cannot be nil")
	}
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	tracer := concurrency.NewTracer(task, true, "(%d, %v)", count, public).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	clusterName := c.SafeGetName()

	if count == 0 {
		logrus.Debugf("[cluster %s] no nodes to create.", clusterName)
		return nil, nil
	}
	logrus.Debugf("[cluster %s] creating %d node%s...", clusterName, count, strprocess.Plural(count))

	timeout := temporal.GetContextTimeout() + time.Duration(count)*time.Minute
	var subtasks []concurrency.Task
	for i := uint(1); i <= count; i++ {
		subtask, err := task.StartInSubtask(c.taskCreateNode, data.Map{
			"index":   i,
			"type":    clusternodetype.Node,
			"nodeDef": def,
			"timeout": timeout,
			"nokeep":  nokeep,
		})
		if err != nil {
			return nil, err
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
		return nil, scerr.ErrListError(errs)
	}

	logrus.Debugf("[cluster %s] %d node%s creation successful.", clusterName, count, strprocess.Plural(count))
	return nil, nil
}

// taskCreateNode creates a Node in the Cluster
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateNode(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	defer scerr.OnPanic(&err)()

	// Convert then validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}
	if p == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}
	var (
		index uint
		def   *abstract.HostSizingRequirements
		image string
		// timeout time.Duration
		nokeep bool
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, scerr.InvalidParameterError("params[index]", "cannot be an integer less than 1")
	}
	if def, ok = p["nodeDef"].(*abstract.HostSizingRequirements); !ok {
		return nil, scerr.InvalidParameterError("params[def]", "is missing or is not a *propertiesv2.HostEffectiveSizing")
	}
	if def == nil {
		return nil, scerr.InvalidParameterError("params[def]", "cannot be nil")
	}
	if image, ok = p["image"].(string); !ok {
		return nil, scerr.InvalidParameterError("params[image]", "cannot be an empty string")
	}
	// if timeout, ok = p["timeout"].(time.Duration); !ok {
	// 	return nil, scerr.InvalidParameterError("params[timeout]", "is missing ir is not a time.Duration")
	// }
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	tracer := concurrency.NewTracer(task, true, "(%d)", index).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := fmt.Sprintf("node #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, err := c.GetNetworkConfig(task)
	if err != nil {
		return nil, err
	}
	network, err := LoadNetwork(task, c.service, netCfg.NetworkID)
	if err != nil {
		return nil, err
	}

	// Create the host
	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, err = c.buildHostname(task, "node", clusternodetype.Node)
	if err != nil {
		return nil, err
	}
	err = network.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) error {
		networkCore, ok := clonable.(*abstract.Network)
		if !ok {
			return scerr.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		hostReq.Networks = []*abstract.Network{networkCore}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if hostReq.DefaultRouteIP, err = network.GetDefaultRouteIP(task); err != nil {
		return nil, err
	}
	hostReq.PublicIP = false
	hostReq.ImageID = image

	// if timeout < temporal.GetLongOperationTimeout() {
	// 	timeout = temporal.GetLongOperationTimeout()
	// }

	host, err := NewHost(c.SafeGetService())
	if err != nil {
		return nil, err
	}
	err = host.Create(task, hostReq, *def)
	if err != nil {
		return nil, err
	}
	if host != nil {
		return nil, scerr.InconsistentError("host.Create() reported a success but host is nil")
	}

	defer func() {
		if err != nil {
			derr := host.Delete(task)
			if derr != nil {
				err = scerr.AddConsequence(err, derr)
			}
		}
	}()

	var node *propertiesv2.ClusterNode
	err = c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Alter(task, clusterproperty.NodesV2, func(clonable data.Clonable) error {
			nodesV2, ok := clonable.(*propertiesv2.ClusterNodes)
			if !ok {
				return scerr.InconsistentError("'*propertiesv2.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
				ID:          host.SafeGetID(),
				NumericalID: nodesV2.GlobalLastIndex,
				Name:        host.SafeGetName(),
				PrivateIP:   privIP,
				PublicIP:    pubIP,
			}
			nodesV2.PrivateNodes = append(nodesV2.PrivateNodes, node)
			return nil
		})
	})
	if err != nil && nokeep {
		derr := host.Delete(task)
		if derr != nil {
			err = scerr.AddConsequence(err, derr)
		}
		return nil, err
	}
	if err != nil {
		return nil, scerr.Wrap(err, "[%s] creation failed", hostLabel)
	}
	hostLabel = fmt.Sprintf("node #%d (%s)", index, host.SafeGetName())
	logrus.Debugf("[%s] host resource creation successful.", hostLabel)

	err = c.installProxyCacheClient(task, host, hostLabel)
	if err != nil {
		return nil, err
	}

	err = c.installNodeRequirements(task, clusternodetype.Node, host, hostLabel)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return host, nil
}

// taskConfigureNodes configures nodes
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureNodes(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, err error) {
	// FIXME: validate parameters

	clusterName := c.SafeGetName()

	tracer := concurrency.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

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

	svc := c.SafeGetService()
	var subtasks []concurrency.Task
	for _, hostID = range list {
		i++
		host, err = LoadHost(task, svc, hostID)
		if err != nil {
			errs = append(errs, scerr.Wrap(err, "failed to get metadata of host '%s'", hostID))
			continue
		}
		subtask, err := task.StartInSubtask(c.taskConfigureNode, data.Map{
			"index": i,
			"host":  host,
		})
		if err != nil {
			return nil, err
		}
		subtasks = append(subtasks, subtask)
	}

	for _, s := range subtasks {
		_, err := s.Wait()
		if err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return nil, scerr.ErrListError(errs)
	}

	logrus.Debugf("[cluster %s] nodes configuration successful.", clusterName)
	return nil, nil
}

// taskConfigureNode configure one node
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureNode(task concurrency.Task, params concurrency.TaskParameters) (_ concurrency.TaskResult, err error) {
	if params == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}
	var (
		index uint
		host  resources.Host
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, scerr.InvalidParameterError("params[index]", "is missing or is not an integer")
	}
	if index < 1 {
		return nil, scerr.InvalidParameterError("params[index]", "cannot be an integer less than 1")
	}
	if host, ok = p["host"].(resources.Host); !ok {
		return nil, scerr.InvalidParameterError("params[host]", "is missing or is not a 'resources.Host'")
	}
	if host == nil {
		return nil, scerr.InvalidParameterError("params[host]", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, true, "(%d, %s)", index, host.SafeGetName()).WithStopwatch().Entering()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := fmt.Sprintf("node #%d (%s)", index, host.SafeGetName())
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// Docker and docker-compose installation is mandatory on all nodes
	err = c.installDocker(task, host, hostLabel)
	if err != nil {
		return nil, err
	}

	// Now configures node specifically for cluster flavor
	if c.makers.ConfigureNode == nil {
		return nil, nil
	}
	err = c.makers.ConfigureNode(task, c, index, host)
	if err != nil {
		logrus.Error(err.Error())
		return nil, err
	}
	logrus.Debugf("[%s] configuration successful.", hostLabel)
	return nil, nil
}

// taskDeleteHost deletes a host
func (c *cluster) taskDeleteHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	if params == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}
	if host, ok := params.(resources.Host); ok {
		return nil, host.Delete(task)
	}
	return nil, scerr.InvalidParameterError("params", "must be a 'resources.Host'")
}
