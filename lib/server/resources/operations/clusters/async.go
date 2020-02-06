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

package clusters

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

func (c *Cluster) taskStartHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	//FIXME: valid params
	return nil, c.service.StartHost(params.(string))
}

func (c *Cluster) taskStopHost(task concurrency.Task, params concurrency.TaskParameters) (concurrency.TaskResult, error) {
	//FIXME: validate params
	return nil, c.service.StopHost(params.(string))
}

// taskInstallGateway installs necessary components on one gateway
// This function is intended to be call as a goroutine
func (c *cluster) taskInstallGateway(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(t, fmt.Sprintf("(%v)", params), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	pbGateway, ok := params.(*protocol.Host)
	if !ok {
		return result, scerr.InvalidParameterError("params", "must contain a *protocol.Host")
	}
	if pbGateway == nil {
		return result, scerr.InvalidParameterError("params", "cannot be nil")
	}

	hostLabel := pbGateway.Name
	logrus.Debugf("[%s] starting installation...", hostLabel)

	sshCfg, err := client.New().Host.SSHConfig(pbGateway.Id)
	if err != nil {
		return nil, err
	}

	ctx, err := t.GetContext()
	if err != nil {
		return nil, err
	}

	_, err = sshCfg.WaitServerReady(task, "ready", temporal.GetHostTimeout())
	if err != nil {
		return nil, err
	}

	// Installs docker and docker-compose on gateway
	err = c.installDocker(task, pbGateway, hostLabel)
	if err != nil {
		return nil, err
	}

	// Installs proxycache server on gateway (if not disabled)
	err = c.installProxyCacheServer(task, pbGateway, hostLabel)
	if err != nil {
		return nil, err
	}

	// Installs requirements as defined by cluster Flavor (if it exists)
	err = c.installNodeRequirements(task, NodeType.Gateway, pbGateway, hostLabel)
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

	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%v)", params), concurrency.IsLogActive("Trace.Controller")).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	logrus.Debugf("[%s] starting configuration...", gw.Name)

	if c.makers.ConfigureGateway != nil {
		err := c.makers.ConfigureGateway(t, b)
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
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%v)", params), true).WithStopwatch().GoingIn()
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

	clusterName := b.cluster.GetIdentity(t).Name

	if count == 0 {
		logrus.Debugf("[cluster %s] no masters to create.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] creating %d master%s...", clusterName, count, utils.Plural(count))

	var subtasks []concurrency.Task
	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	var i uint
	for ; i < count; i++ {
		subtask, err := task.StartInSubTask(b.taskCreateMaster, data.Map{
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
		return nil, fmt.Errorf("[cluster %s] failed to create master(s): %s", clusterName, msg)
	}

	logrus.Debugf("[cluster %s] masters creation successful.", clusterName)
	return nil, nil
}

// taskCreateMaster creates one master
// This function is intended to be call as a goroutine
func (c *cluster) taskCreateMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%v)", params), true).GoingIn()
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
		index   uint
		def     *protocol.HostDefinition
		timeout time.Duration
		nokeep  bool
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, scerr.InvalidParameterError("params[index]", "is missing or is not an unsigned integer")
	}
	if index < 1 {
		return nil, scerr.InvalidParameterError("params[index]", "cannot be an integer less than 1")
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
	if _, ok := p["timeout"]; !ok {
		timeout = 0
	} else {
		if timeout = p["timeout"].(time.Duration); !ok {
			return nil, scerr.InvalidParameterError("params[timeout]", "is not a time.Duration")
		}
	}
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	hostLabel := fmt.Sprintf("master #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, err := c.NetworkConfig(t)
	if err != nil {
		return nil, err
	}

	hostDef := *def
	hostDef.Name, err = c.buildHostname(t, "master", NodeType.Master)
	if err != nil {
		return nil, err
	}

	hostDef.Network = netCfg.NetworkID
	hostDef.Public = false
	clientHost := client.New().Host
	pbHost, err := clientHost.Create(hostDef, timeout)
	if pbHost != nil {
		// Updates cluster metadata to keep track of created host, before testing if an error occurred during the creation
		mErr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
			// References new node in cluster
			return props.Alter(clusterproperty.NodesV2, func(clonable data.Clonable) error {
				nodesV2 := clonable.(*propertiesv2.ClusterNodes)
				nodesV2.GlobalLastIndex++
				node := &clusterpropsv2.Node{
					ID:          pbHost.Id,
					NumericalID: nodesV2.GlobalLastIndex,
					Name:        pbHost.Name,
					PrivateIP:   pbHost.PrivateIp,
					PublicIP:    pbHost.PublicIp,
				}
				nodesV2.Masters = append(nodesV2.Masters, node)
				return nil
			})
		})
		if mErr != nil && nokeep {
			derr := clientHost.Delete([]string{pbHost.Id}, temporal.GetLongOperationTimeout())
			if derr != nil {
				mErr = scerr.AddConsequence(mErr, derr)
			}
			return nil, mErr
		}
	}
	if err != nil {
		return nil, client.DecorateError(err, fmt.Sprintf("[%s] host resource creation failed: %s", hostLabel, err.Error()), false)
	}
	hostLabel = fmt.Sprintf("%s (%s)", hostLabel, pbHost.Name)
	logrus.Debugf("[%s] host resource creation successful", hostLabel)

	err = c.installProxyCacheClient(task, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	// Installs cluster-level system requirements...
	err = c.installNodeRequirements(task, NodeType.Master, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return nil, nil
}

// taskConfigureMasters configure masters
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureMasters(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	list, err := c.ListMasterIDs(task)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}

	logrus.Debugf("[cluster %s] Configuring masters...", c.Name())
	started := time.Now()

	clientHost := client.New().Host
	var subtasks []concurrency.Task
	masters, err := c.ListMasterIDs(t)
	if err != nil {
		return nil, err
	}

	var errors []error

	for i, hostID := range masters {
		host, err := clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			logrus.Warnf("failed to get metadata of host: %s", err.Error())
			errors = append(errors, err)
			continue
		}
		subtask, err := task.StartInSubTask(b.taskConfigureMaster, data.Map{
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

	logrus.Debugf("[cluster %s] Masters configuration successful in [%s].", b.cluster.Name, temporal.FormatDuration(time.Since(started)))
	return nil, nil
}

// taskConfigureMaster configures one master
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureMaster(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%v)", params), true).WithStopwatch().GoingIn()
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
		index  uint
		pbHost *protocol.Host
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
	if pbHost, ok = p["host"].(*protocol.Host); !ok {
		return nil, scerr.InvalidParameterError("params[host]", "is not a *protocol.Host")
	}
	if pbHost == nil {
		return nil, scerr.InvalidParameterError("params[host]", "cannot be nil")
	}

	started := time.Now()

	hostLabel := fmt.Sprintf("master #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// install docker feature (including docker-compose)
	err = c.installDocker(t, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	if c.makers.ConfigureNode != nil {
		return c.makers.ConfigureMaster(task, c, index, pbHost)
		if err != nil {
			return nil, err
		}
		logrus.Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
		return nil, nil
	}
	// Not finding a callback isn't an error, so return nil in this case
	return nil
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

	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%d, %v)", count, public), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	clusterName := c.Identity(task).Name

	if count == 0 {
		logrus.Debugf("[cluster %s] no nodes to create.", clusterName)
		return nil, nil
	}
	logrus.Debugf("[cluster %s] creating %d node%s...", clusterName, count, utils.Plural(count))

	timeout := timeoutCtxHost + time.Duration(count)*time.Minute
	var subTasks []concurrency.Task
	for i := uint(1); i <= count; i++ {
		subtask, err := task.StartInSubTask(b.taskCreateNode, data.Map{
			"index":   i,
			"type":    NodeType.Node,
			"nodeDef": def,
			"timeout": timeout,
			"nokeep":  nokeep,
		})
		if err != nil {
			return nil, err
		}
		subTasks = append(subTasks, subtask)
	}

	var errs []string
	for _, s := range subTasks {
		_, state := s.Wait()
		if state != nil {
			errs = append(errs, state.Error())
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "\n"))
	}

	logrus.Debugf("[cluster %s] %d node%s creation successful.", clusterName, count, utils.Plural(count))
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
		index   uint
		def     *protocol.HostDefinition
		timeout time.Duration
		nokeep  bool
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, scerr.InvalidParameterError("params[index]", "cannot be an integer less than 1")
	}
	if def, ok = p["nodeDef"].(*protocol.HostDefinition); !ok {
		return nil, scerr.InvalidParameterError("params[def]", "is missing or is not a *protocol.HostDefinition")
	}
	if def == nil {
		return nil, scerr.InvalidParameterError("params[def]", "cannot be nil")
	}
	if timeout, ok = p["timeout"].(time.Duration); !ok {
		return nil, scerr.InvalidParameterError("params[tiemeout]", "is missing ir is not a time.Duration")
	}
	if nokeep, ok = p["nokeep"].(bool); !ok {
		nokeep = true
	}

	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%d)", index), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := fmt.Sprintf("node #%d", index)
	logrus.Debugf("[%s] starting host resource creation...", hostLabel)

	netCfg, err := c.NetworkConfig(task)
	if err != nil {
		return nil, err
	}

	// Create the host
	hostDef := *def
	hostDef.Name, err = c.buildHostname(t, "node", NodeType.Node)
	if err != nil {
		return nil, err
	}
	hostDef.Network = netCfg.NetworkID
	if timeout < temporal.GetLongOperationTimeout() {
		timeout = temporal.GetLongOperationTimeout()
	}

	clientHost := client.New().Host
	var node *clusterpropsv2.Node
	pbHost, err := clientHost.Create(hostDef, timeout)
	if pbHost != nil {
		mErr := c.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
			return props.Alter(clusterproperty.NodesV2, func(v interface{}) error {
				// FIXME: validate cast
				nodesV2 := clonable.(*propertiesv2.ClusterNodes)
				// Registers the new Agent in the swarmCluster struct
				nodesV2.GlobalLastIndex++
				node = &clusterpropsv2.Node{
					ID:          pbHost.Id,
					NumericalID: nodesV2.GlobalLastIndex,
					Name:        pbHost.Name,
					PrivateIP:   pbHost.PrivateIp,
					PublicIP:    pbHost.PublicIp,
				}
				nodesV2.PrivateNodes = append(nodesV2.PrivateNodes, node)
				return nil
			})
		})
		if mErr != nil && nokeep {
			derr := clientHost.Delete([]string{pbHost.Id}, temporal.GetLongOperationTimeout())
			if derr != nil {
				mErr = scerr.AddConsequence(mErr, derr)
			}
			return nil, mErr
		}
	}
	if err != nil {
		return nil, client.DecorateError(err, fmt.Sprintf("[%s] creation failed: %s", hostLabel, err.Error()), true)
	}
	hostLabel = fmt.Sprintf("node #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] host resource creation successful.", hostLabel)

	err = c.installProxyCacheClient(t, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	err = c.installNodeRequirements(t, NodeType.Node, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[%s] host resource creation successful.", hostLabel)
	return pbHost.Name, nil
}

// taskConfigureNodes configures nodes
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureNodes(task concurrency.Task, params concurrency.TaskParameters) (task concurrency.TaskResult, err error) {
	clusterName := b.cluster.GetIdentity(task).Name

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	list, err := c.ListNodeIDs(t)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		logrus.Debugf("[cluster %s] no nodes to configure.", clusterName)
		return nil, nil
	}

	logrus.Debugf("[cluster %s] configuring nodes...", clusterName)

	var (
		pbHost *protocol.Host
		i      uint
		hostID string
		errs   []string
	)

	var subtasks []concurrency.Task
	clientHost := client.New().Host
	for _, hostID = range list {
		i++
		pbHost, err = clientHost.Inspect(hostID, temporal.GetExecutionTimeout())
		if err != nil {
			break
		}
		subtask, err := task.StartInSubTask(c.taskConfigureNode, data.Map{
			"index": i,
			"host":  pbHost,
		})
		if err != nil {
			return nil, err
		}
		subtasks = append(subtasks, subtask)
	}
	// Deals with the metadata read failure
	if err != nil {
		errs = append(errs, "failed to get metadata of host '%s': %s", hostID, err.Error())
	}

	for _, s := range subtasks {
		_, err := s.Wait()
		if err != nil {
			errs = append(errs, err.Error())
		}
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf(strings.Join(errs, "\n"))
	}

	logrus.Debugf("[cluster %s] nodes configuration successful.", clusterName)
	return nil, nil
}

// taskConfigureNode configure one node
// This function is intended to be call as a goroutine
func (c *cluster) taskConfigureNode(task concurrency.Task, params concurrency.TaskParameters) (result concurrency.TaskResult, err error) {
	if params == nil {
		return nil, scerr.InvalidParameterError("params", "cannot be nil")
	}

	// Convert and validate parameters
	p, ok := params.(data.Map)
	if !ok {
		return nil, scerr.InvalidParameterError("params", "must be a data.Map")
	}
	var (
		index  uint
		pbHost *protocol.Host
	)
	if index, ok = p["index"].(uint); !ok {
		return nil, scerr.InvalidParameterError("params[index]", "is missing or is not an integer")
	}
	if index < 1 {
		return nil, scerr.InvalidParameterError("params[index]", "cannot be an integer less than 1")
	}
	if pbHost, ok = p["host"].(*protocol.Host); !ok {
		return nil, scerr.InvalidParameterError("params[host]", "is missing or is not a *protocol.Host")
	}
	if pbHost == nil {
		return nil, scerr.InvalidParameterError("params[host]", "cannot be nil")
	}

	tracer := concurrency.NewTracer(task, fmt.Sprintf("(%d, %s)", index, pbHost.Name), true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	hostLabel := fmt.Sprintf("node #%d (%s)", index, pbHost.Name)
	logrus.Debugf("[%s] starting configuration...", hostLabel)

	// Docker and docker-compose installation is mandatory on all nodes
	err = c.installDocker(task, pbHost, hostLabel)
	if err != nil {
		return nil, err
	}

	// Now configures node specifically for cluster flavor
	if c.makers.ConfigureNode == nil {
		return nil, nil
	}
	r, err := c.makers.ConfigureNode(task, c, index, pbHost)
	if err != nil {
		logrus.Error(err.Error())
		return nil, err
	}
	logrus.Debugf("[%s] configuration successful.", hostLabel)
	return r, nil
}

// Installs reverseproxy
func (c *cluster) installReverseProxy(task concurrency.Task) (err error) {
	defer scerr.OnPanic(&err)()

	identity := c.Identity(task)
	clusterName := identity.Name

	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	disabled := false
	err = c.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) error {
			featuresv1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return scerr.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_, disabled = featuresV1.Disabled["reverseproxy"]
			return nil
		})
	})
	if err != nil {
		return err
	}
	if !disabled {
		logrus.Debugf("[cluster %s] adding feature 'edgeproxy4network'", clusterName)
		feat, err := features.NewEmbeddedFeature(task, "edgeproxy4network")
		if err != nil {
			return err
		}
		results, err := feat.Add(c, features.Variables{}, features.Settings{})
		if err != nil {
			return err
		}
		if !results.Successful() {
			msg := results.AllErrorMessages()
			return fmt.Errorf("[cluster %s] failed to add '%s' failed: %s", clusterName, feat.DisplayName(), msg)
		}
		logrus.Debugf("[cluster %s] feature '%s' added successfully", clusterName, feat.DisplayName())
	}
	return nil
}
