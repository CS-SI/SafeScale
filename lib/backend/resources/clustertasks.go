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

package resources

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// taskStartHost is the code called in a Task to start a Host
func (instance *Cluster) taskStartHost(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	id, ok := params.(string)
	if !ok || id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("params")
	}

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/start/host/%s", oldKey, id)) // nolint
	}

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()
			timings, xerr := svc.Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			xerr = svc.StartHost(ctx, id)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) { // nolint
				case *fail.ErrDuplicate: // A host already started is considered as a successful run
					logrus.WithContext(ctx).Tracef("host duplicated, start considered as a success")
					debug.IgnoreErrorWithContext(ctx, xerr)
					return result{nil, nil}, nil
				}
			}
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// -- refresh state of host --
			hostInstance, xerr := LoadHost(ctx, id)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			_, xerr = hostInstance.WaitSSHReady(ctx, timings.HostOperationTimeout())
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			_, xerr = hostInstance.ForceGetState(ctx)
			return result{nil, xerr}, xerr
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}

}

func (instance *Cluster) taskStopHost(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	id, ok := params.(string)
	if !ok || id == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("params")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()
			xerr := svc.StopHost(ctx, id, false)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) { // nolint
				case *fail.ErrDuplicate: // A host already stopped is considered as a successful run
					logrus.WithContext(ctx).Tracef("host duplicated, stopping considered as a success")
					debug.IgnoreErrorWithContext(ctx, xerr)
					return result{nil, nil}, nil
				default:
					return result{nil, xerr}, xerr
				}
			}

			// -- refresh state of host --
			hostInstance, xerr := LoadHost(ctx, id)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			_, xerr = hostInstance.ForceGetState(ctx)
			return result{nil, xerr}, xerr
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskConfigureGatewayParameters struct {
	Host *Host
}

// taskConfigureGateway prepares one gateway
func (instance *Cluster) taskConfigureGateway(inctx context.Context, params interface{}) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// validate and convert parameters
	p, ok := params.(taskConfigureGatewayParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskConfigureGatewayParameters'")
	}
	if p.Host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}

	hostLabel := p.Host.GetName()

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/configure/gateway/%s", oldKey, hostLabel)) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			logrus.WithContext(ctx).Debugf("starting configuration")

			makers := instance.localCache.makers
			if makers.ConfigureGateway != nil {
				xerr := makers.ConfigureGateway(instance)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{nil, xerr}, xerr
				}
			}

			logrus.WithContext(ctx).Debugf("[%s] configuration successful in [%s].", hostLabel, tracer.Stopwatch().String())
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}

}

type taskCreateMastersParameters struct {
	count         uint
	mastersDef    abstract.HostSizingRequirements
	keepOnFailure bool
}

// taskCreateMasters creates masters
func (instance *Cluster) taskCreateMasters(inctx context.Context, clusterTrx clusterTransaction, params any) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	p, err := lang.Cast[taskCreateMastersParameters](params)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	if p.count < 1 {
		xerr := fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
		return nil, xerr
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	if p.count == 0 {
		logrus.WithContext(ctx).Debugf("[Cluster %s] no masters to create.", instance.GetName())
		return nil, nil
	}

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			svc := instance.Service()
			timings, xerr := svc.Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("Creating %d master%s...", p.count, strprocess.Plural(p.count))

			timeout := time.Duration(p.count) * timings.HostCreationTimeout() // FIXME: OPP This became the timeout for the whole cluster creation....

			winSize := 8
			cfg, xerr := svc.ConfigurationOptions()
			if xerr == nil {
				winSize = cfg.ConcurrentMachineCreationLimit
			}

			var listMasters []StdResult
			masterChan := make(chan StdResult, p.count)

			err := runWindow(ctx, clusterTrx, p.count, uint(math.Min(float64(p.count), float64(winSize))), timeout, masterChan, instance.trxCreateMaster, trxCreateMasterParameters{
				masterDef:     p.mastersDef,
				timeout:       timings.HostCreationTimeout(),
				keepOnFailure: p.keepOnFailure,
			})
			if err != nil {
				close(masterChan)
				return result{nil, fail.Wrap(err)}, fail.Wrap(err)
			}

			close(masterChan)
			for v := range masterChan {
				if v.Err != nil {
					continue
				}
				if v.ToBeDeleted {
					if aho, ok := v.Content.(*Host); ok {
						xerr = aho.Delete(cleanupContextFrom(ctx))
						debug.IgnoreErrorWithContext(ctx, xerr)
						continue
					}
				}
				listMasters = append(listMasters, v)
			}

			logrus.WithContext(ctx).Debugf("Masters creation successful: %v", listMasters)
			return result{listMasters, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskConfigureMastersParameters struct {
	variables data.Map[string, any]
}

// taskConfigureMasters configure masters
func (instance *Cluster) taskConfigureMasters(inctx context.Context, clusterTrx clusterTransaction, params any) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	p, err := lang.Cast[taskConfigureMastersParameters](params)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	variables := p.variables

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			clusterName := instance.GetName()
			logrus.WithContext(ctx).Debugf("[Cluster %s] Configuring masters...", clusterName)

			masters, xerr := trxListMasters(ctx, clusterTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}
			if len(masters) == 0 {
				ar := result{nil, fail.NewError("[Cluster %s] master list cannot be empty.", clusterName)}
				return ar, ar.rErr
			}

			for _, master := range masters {
				if master.ID == "" {
					ar := result{nil, fail.InvalidParameterError("masters", "cannot contain items with empty ID")}
					return ar, ar.rErr
				}
			}

			tgm := new(errgroup.Group)
			for _, master := range masters {
				capturedMaster := master
				tgm.Go(func() error {
					host, xerr := LoadHost(ctx, capturedMaster.ID)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return nil
						default:
							return xerr
						}
					}

					_, xerr = instance.taskConfigureMaster(ctx, clusterTrx, taskConfigureMasterParameters{
						Host:      host,
						variables: variables,
					})
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return nil
						default:
							return xerr
						}
					}
					return nil
				})
			}

			xerr = fail.Wrap(tgm.Wait())
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] masters configuration successful", clusterName)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskConfigureMasterParameters struct {
	Host      *Host
	variables data.Map[string, any]
}

// taskConfigureMaster configures one master
func (instance *Cluster) taskConfigureMaster(inctx context.Context, clusterTrx clusterTransaction, params any) (_ any, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// Convert and validate params
	p, ok := params.(taskConfigureMasterParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskConfigureMasterParameters'")
	}
	if p.Host == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Host")
	}
	variables := p.variables

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/configure/master/%s", oldKey, p.Host.GetName())) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%v)", params).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			started := time.Now()

			logrus.WithContext(ctx).Debugf("starting configuration...")

			does, xerr := p.Host.Exists(ctx)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			if !does {
				return result{nil, nil}, nil
			}

			// install docker feature (including docker-compose)
			hostLabel := fmt.Sprintf("master (%s)", p.Host.GetName())
			xerr = instance.trxInstallDocker(ctx, clusterTrx, p.Host, hostLabel, variables)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Configure master for flavor
			makers := instance.localCache.makers
			if makers.ConfigureMaster != nil {
				xerr = makers.ConfigureMaster(instance, p.Host)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, fail.Wrap(xerr, "failed to configure master '%s'", p.Host.GetName())}
					return ar, ar.rErr
				}

				logrus.WithContext(ctx).Debugf("[%s] configuration successful in [%s].", hostLabel, temporal.FormatDuration(time.Since(started)))
				return result{nil, nil}, nil
			}

			// Not finding a callback isn't an error, so return nil in this case
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskCreateNodesParameters struct {
	count         uint
	public        bool
	nodesDef      abstract.HostSizingRequirements
	keepOnFailure bool
}

func drainChannel(dch chan struct{}) {
	for {
		end := false
		select {
		case <-dch:
		default:
			end = true
		}
		if end {
			break
		}
	}
	close(dch)
}

func runWindow(
	inctx context.Context,
	clusterTrx clusterTransaction,
	count uint,
	windowSize uint,
	timeout time.Duration,
	uat chan StdResult,
	runner func(context.Context, clusterTransaction, interface{}) (interface{}, fail.Error), data interface{},
) error {

	if windowSize > count {
		return errors.Errorf("window size cannot be greater than task size: %d, %d", count, windowSize)
	}

	if windowSize == count {
		if count >= 4 {
			windowSize -= 2
		}
	}

	window := make(chan struct{}, windowSize) // Sliding window of windowSize
	target := make(chan struct{}, count)
	done := make(chan struct{})

	treeCtx, cancel := context.WithCancel(inctx)
	defer cancel()

	finished := false
	for { // only 4 simultaneous creations
		select {
		case <-done:
			finished = true
		case <-treeCtx.Done():
			finished = true
		case window <- struct{}{}:
		}
		if finished {
			cancel()
			break
		}

		go func() {
			defer func() {
				<-window
			}()

			res, err := runner(treeCtx, clusterTrx, data)
			if err != nil {
				// log the error
				logrus.WithContext(treeCtx).Errorf("window runner failed with: %s", err)
				return
			}

			select {
			case <-done:
				uat <- StdResult{
					Content:     res,
					Err:         err,
					ToBeDeleted: true,
				}
				return
			case <-treeCtx.Done():
				uat <- StdResult{
					Content:     res,
					Err:         err,
					ToBeDeleted: true,
				}
				return
			default:
				uat <- StdResult{
					Content:     res,
					Err:         err,
					ToBeDeleted: false,
				}
			}

			select {
			case <-done:
				return
			case <-treeCtx.Done():
				return
			case target <- struct{}{}:
				if len(target) == int(count) {
					close(done)
					return
				}
				return
			default: // if it blocks because it's full, end of story
				close(done)
				return
			}
		}()
	}

	defer drainChannel(window)
	defer drainChannel(target)

	select {
	case <-done:
		return nil
	case <-inctx.Done():
		return errors.Errorf("Task was cancelled by parent: %s", inctx.Err())
	case <-treeCtx.Done():
		if len(uat) == int(count) {
			return nil
		}
		return errors.Errorf("Task was canceled when target is %d\n", len(target))
	}
}

type StdResult struct {
	Content     interface{}
	Err         error
	ToBeDeleted bool
}

// taskCreateNodes creates nodes
func (instance *Cluster) taskCreateNodes(inctx context.Context, clusterTrx clusterTransaction, params any) (_ any, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// Convert then validate params
	p, ok := params.(taskCreateNodesParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreateNodesParameters'")
	}
	if p.count < 1 {
		return nil, fail.InvalidParameterError("params.count", "cannot be an integer less than 1")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d, %v)", p.count, p.public).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			timings, xerr := instance.Service().Timings()
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("Creating %d node%s...", p.count, strprocess.Plural(p.count))

			timeout := time.Duration(p.count) * timings.HostCreationTimeout()

			winSize := 8
			svc := instance.Service()
			if cfg, xerr := svc.ConfigurationOptions(); xerr == nil {
				winSize = cfg.ConcurrentMachineCreationLimit
			}

			var listNodes []StdResult
			nodesChan := make(chan StdResult, p.count)

			err := runWindow(ctx, clusterTrx, p.count, uint(math.Min(float64(p.count), float64(winSize))), timeout, nodesChan, instance.taskCreateNode, taskCreateNodeParameters{
				nodeDef:       p.nodesDef,
				timeout:       timings.HostOperationTimeout(),
				keepOnFailure: p.keepOnFailure,
			})
			if err != nil {
				return result{nil, fail.Wrap(err)}, fail.Wrap(err)
			}

			close(nodesChan)
			for v := range nodesChan {
				if v.Err != nil {
					continue
				}
				if v.ToBeDeleted {
					_, xerr = instance.trxDeleteNodeWithCtx(ctx, clusterTrx, v.Content.(*propertiesv3.ClusterNode), nil)
					debug.IgnoreErrorWithContext(ctx, xerr)
					continue
				}
				listNodes = append(listNodes, v)
			}

			logrus.WithContext(ctx).Debugf("%d node%s creation successful.", p.count, strprocess.Plural(p.count))
			return result{listNodes, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskCreateNodeParameters struct {
	index         uint
	nodeDef       abstract.HostSizingRequirements
	timeout       time.Duration // Not used currently
	keepOnFailure bool
}

// taskCreateNode creates a node in the Cluster
func (instance *Cluster) taskCreateNode(inctx context.Context, clusterTrx clusterTransaction, params interface{}) (_ interface{}, _ fail.Error) {
	var xerr fail.Error
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// Convert then validate parameters
	p, ok := params.(taskCreateNodeParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskCreateNodeParameters'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	hostReq := abstract.HostRequest{}
	hostReq.ResourceName, xerr = instance.trxBuildHostname(ctx, clusterTrx, "node", clusternodetype.Node)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/create/node/%s", oldKey, hostReq.ResourceName)) // nolint
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%d)", p.index).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			sleepTime := <-instance.randomDelayCh
			time.Sleep(time.Duration(sleepTime) * time.Millisecond)

			// -- First creates node in metadata, to keep track of its tried creation, in case of failure --
			var nodeIdx uint
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
				nodesV3.GlobalLastIndex++
				nodeIdx = nodesV3.GlobalLastIndex
				node := &propertiesv3.ClusterNode{
					NumericalID: nodeIdx,
					Name:        hostReq.ResourceName,
				}
				nodesV3.ByNumericalID[nodeIdx] = node
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", fmt.Sprintf("node %s", hostReq.ResourceName))}
				return ar, ar.rErr
			}

			hostLabel := fmt.Sprintf("node %s", hostReq.ResourceName)

			// Starting from here, if exiting with error, remove entry from node of the metadata
			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure {
					derr := alterClusterMetadataProperty(cleanupContextFrom(ctx), clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) fail.Error {
						delete(nodesV3.ByNumericalID, nodeIdx)
						return nil
					})
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to remove node from Cluster metadata", ActionFromError(ferr)))
					}
				}
			}()

			netCfg, xerr := instance.GetNetworkConfig(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			subnet, xerr := LoadSubnet(ctx, "", netCfg.SubnetID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}

			subnetTrx, xerr := newSubnetTransaction(ctx, subnet)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.rErr
			}
			defer subnetTrx.TerminateFromError(ctx, &ferr)

			// -- Create the Host instance corresponding to the new node --
			xerr = inspectSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
				hostReq.Subnets = []*abstract.Subnet{as}
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{nil, xerr}, xerr
			}

			hostReq.DefaultRouteIP, xerr = subnet.GetDefaultRouteIP(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			hostReq.PublicIP = false
			hostReq.KeepOnFailure = p.keepOnFailure

			if p.nodeDef.Image != "" {
				hostReq.ImageID = p.nodeDef.Image
			}
			if p.nodeDef.Template != "" {
				hostReq.TemplateID = p.nodeDef.Template
			}

			hostInstance, xerr := NewHost(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !p.keepOnFailure && hostInstance != nil {
					derr := hostInstance.Delete(cleanupContextFrom(ctx))
					if derr != nil {
						switch derr.(type) {
						case *fail.ErrNotFound:
							// missing Host is considered as a successful deletion, continue
							debug.IgnoreErrorWithContext(ctx, derr)
						default:
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Host '%s'", ActionFromError(ferr), hostInstance.GetName()))
						}
					}
				}
			}()

			// here is the actual creation of the machine
			cluID, _ := instance.GetID()
			_, xerr = hostInstance.Create(ctx, hostReq, p.nodeDef, map[string]string{
				"type":      "node",
				"clusterID": cluID,
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf(tracer.TraceMessage("[%s] Host updating cluster metadata...", hostLabel))

			// -- update cluster metadata --
			var node *propertiesv3.ClusterNode
			xerr = alterClusterMetadataProperty(ctx, clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) (innerXErr fail.Error) {
				node = nodesV3.ByNumericalID[nodeIdx]
				var innerErr error
				node.ID, innerErr = hostInstance.GetID()
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				var inErr fail.Error
				node.PublicIP, inErr = hostInstance.GetPublicIP(ctx)
				if inErr != nil {
					switch inErr.(type) {
					case *fail.ErrNotFound:
						// No public IP, this can happen; continue
					default:
						return inErr
					}
				}

				if node.PrivateIP, inErr = hostInstance.GetPrivateIP(ctx); inErr != nil {
					return inErr
				}

				nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, node.NumericalID)
				nodesV3.PrivateNodeByName[node.Name] = node.NumericalID
				nodesV3.PrivateNodeByID[node.ID] = node.NumericalID

				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				ar := result{nil, fail.Wrap(xerr, "[%s] creation failed", hostLabel)}
				return ar, ar.rErr
			}

			// VPL: transaction rollback will do the job
			// // Starting from here, rollback on cluster metadata in case of failure
			// defer func() {
			// 	ferr = debug.InjectPlannedFail(ferr)
			// 	if ferr != nil && !p.keepOnFailure {
			// 		derr := alterClusterMetadataProperty(cleanupContextFrom(ctx), clusterTrx, clusterproperty.NodesV3, func(nodesV3 *propertiesv3.ClusterNodes) (innerXErr fail.Error) {
			// 			if found, indexInSlice := containsClusterNode(nodesV3.PrivateNodes, nodeIdx); found {
			// 				length := len(nodesV3.PrivateNodes)
			// 				if indexInSlice < length-1 {
			// 					nodesV3.PrivateNodes = append(nodesV3.PrivateNodes[:indexInSlice], nodesV3.PrivateNodes[indexInSlice+1:]...)
			// 				} else {
			// 					nodesV3.PrivateNodes = nodesV3.PrivateNodes[:indexInSlice]
			// 				}
			// 			}
			//
			// 			hid, err := hostInstance.GetID()
			// 			if err != nil {
			// 				return fail.Wrap(err)
			// 			}
			//
			// 			Delete(nodesV3.PrivateNodeByName, hostInstance.GetName())
			// 			Delete(nodesV3.PrivateNodeByID, hid)
			// 			return nil
			// 		})
			// 		if derr != nil {
			// 			_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to remove node '%s' from metadata of cluster '%s'", hostInstance.GetName(), instance.GetName()))
			// 		}
			// 	}
			// }()

			logrus.WithContext(ctx).Debugf(tracer.TraceMessage("[%s] Host installing node requirements...", hostLabel))

			xerr = instance.installNodeRequirements(ctx, clusterTrx, clusternodetype.Node, hostInstance, hostLabel)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[%s] Node creation successful.", hostLabel)
			return result{node, nil}, nil
		}() // nolint
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// trxConfigureNodes configures nodes
func (instance *Cluster) trxConfigureNodes(inctx context.Context, clusterTrx clusterTransaction, variables data.Map[string, any]) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.cluster")).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			list, err := instance.trxListNodes(ctx, clusterTrx)
			err = debug.InjectPlannedFail(err)
			if err != nil {
				return result{nil, err}, err
			}
			if len(list) == 0 {
				ar := result{nil, fail.NewError("[Cluster %s] node list cannot be empty.", instance.GetName())}
				return ar, ar.rErr
			}

			clusterName := instance.GetName()
			logrus.WithContext(ctx).Debugf("[Cluster %s] configuring nodes...", instance.GetName())

			for _, node := range list {
				if node.ID == "" {
					ar := result{nil, fail.InvalidParameterError("list", "cannot contain items with empty ID")}
					return ar, ar.rErr
				}
			}

			type cfgRes struct {
				who  string
				what interface{}
			}

			resCh := make(chan cfgRes, len(list))
			eg := new(errgroup.Group)
			for _, node := range list {
				capturedNode := node
				eg.Go(func() error {
					tr, xerr := instance.taskConfigureNode(ctx, clusterTrx, capturedNode, variables)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrNotFound:
							return nil
						default:
							return xerr
						}
					}

					resCh <- cfgRes{
						who:  capturedNode.ID,
						what: tr,
					}

					return nil
				})
			}
			xerr := fail.Wrap(eg.Wait())
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			tgMap := make(map[string]interface{})
			close(resCh)
			for v := range resCh {
				tgMap[v.who] = v.what
			}

			logrus.WithContext(ctx).Debugf("[Cluster %s] nodes configuration successful: %v", clusterName, tgMap)
			return result{tgMap, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// taskConfigureNode configure one node
func (instance *Cluster) taskConfigureNode(inctx context.Context, clusterTrx clusterTransaction, node *propertiesv3.ClusterNode, variables data.Map[string, any]) (_ any, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if node == nil {
		return nil, fail.InvalidParameterCannotBeNilError("params.Node")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.cluster"), "(%s)", node.Name).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			hostLabel := fmt.Sprintf("node (%s)", node.Name)
			logrus.WithContext(ctx).Debugf("[%s] starting configuration...", hostLabel)

			hostInstance, xerr := LoadHost(ctx, node.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					ar := result{nil, fail.Wrap(xerr, "failed to get metadata of node '%s'", node.Name)}
					return ar, ar.rErr
				}
			}

			does, xerr := hostInstance.Exists(ctx)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			if !does {
				return result{nil, nil}, nil
			}

			// Docker and docker-compose installation is mandatory on all nodes
			xerr = instance.trxInstallDocker(ctx, clusterTrx, hostInstance, hostLabel, variables)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return result{nil, xerr}, xerr
			}

			// Now configures node specifically for Cluster flavor
			makers := instance.localCache.makers
			if makers.ConfigureNode == nil {
				return result{nil, nil}, nil
			}

			xerr = makers.ConfigureNode(instance, hostInstance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				logrus.WithContext(ctx).Error(xerr.Error())
				return result{nil, xerr}, xerr
			}

			logrus.WithContext(ctx).Debugf("[%s] configuration successful.", hostLabel)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type machineID struct {
	ID   string
	Name string
}

type taskDeleteNodeOnFailureParameters struct {
	ID            string
	Name          string
	KeepOnFailure bool
	Timeout       time.Duration
}

// taskDeleteNodeOnFailure deletes a node when a failure occurred
func (instance *Cluster) taskDeleteNodeOnFailure(inctx context.Context, params taskDeleteNodeOnFailureParameters) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// Convert and validate params
	if params.ID == "" {
		return nil, fail.InvalidParameterError("ID", "must NOT be empty")
	}
	if params.KeepOnFailure {
		return nil, nil
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			hostInstance, xerr := LoadHost(ctx, params.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					_ = instance.Service().DeleteHost(ctx, params.ID)
					return result{nil, nil}, nil
				default:
					return result{nil, xerr}, xerr
				}
			}

			xerr = hostInstance.Delete(ctx)
			_ = instance.Service().DeleteHost(ctx, params.ID)
			if xerr != nil {
				return result{}, xerr
			}

			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-time.After(params.Timeout):
		cancel()
		<-chRes
		return nil, fail.TimeoutError(fmt.Errorf("timeout trying to Delete node on failure"), params.Timeout)
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

func (instance *Cluster) trxDeleteNodeWithCtx(inctx context.Context, clusterTrx clusterTransaction, node *propertiesv3.ClusterNode, master *Host) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if node == nil {
		return nil, fail.InvalidParameterCannotBeNilError("node")
	}
	if node.NumericalID == 0 {
		return nil, fail.InvalidParameterError("node.NumericalID", "cannot be 0")
	}
	if node.ID == "" && node.Name == "" {
		return nil, fail.InvalidParameterError("node.ID|node.Name", "ID or Name must be set")
	}
	if node.Name == "" {
		node.Name = node.ID
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/Delete/node/%s", oldKey, node.Name)) // nolint
	}

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// FIXME: This is another mitigation....
			trueNodeID := node.ID

			logrus.WithContext(ctx).Debugf("Deleting Node...")
			xerr := instance.trxDeleteNode(ctx, clusterTrx, node, master)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					return result{nil, xerr}, xerr
				}
			}

			// kill zombies (instances without metadata)
			_ = instance.Service().DeleteHost(ctx, trueNodeID)

			logrus.WithContext(ctx).Debugf("Successfully deleted Node '%s'", node.Name)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// trxDeleteMaster deletes one master
func (instance *Cluster) trxDeleteMaster(inctx context.Context, clusterTrx clusterTransaction, node *propertiesv3.ClusterNode) (_ interface{}, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if node == nil {
		return nil, fail.InvalidParameterCannotBeNilError("node")
	}
	if node.ID == "" && node.Name == "" {
		return nil, fail.InvalidParameterError("node.ID|node.Name", "ID or Name must be set")
	}
	nodeRef := node.Name
	if nodeRef == "" {
		nodeRef = node.ID
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	if oldKey := ctx.Value("ID"); oldKey != nil {
		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/Delete/master/%s", oldKey, nodeRef)) // nolint
	}

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			logrus.WithContext(ctx).Debugf("Deleting Master %s", nodeRef)
			trueMasterID := node.ID
			xerr := instance.deleteMaster(ctx, clusterTrx, trueMasterID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					return result{nil, xerr}, xerr
				}
			}

			// kill zombies (instances without metadata)
			svc := instance.Service()
			_ = svc.DeleteHost(ctx, trueMasterID)

			logrus.WithContext(ctx).Debugf("Successfully deleted Master '%s'", node.Name)
			return result{nil, nil}, nil
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

type taskUpdateClusterInventoryMasterParameters struct {
	ctx           context.Context
	master        *Host
	inventoryData string
}

// taskUpdateClusterInventoryMaster task to update a Host (master) ansible inventory
func (instance *Cluster) taskUpdateClusterInventoryMaster(inctx context.Context, params any) (_ any, _ fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	// Convert and validate params
	casted, ok := params.(taskUpdateClusterInventoryMasterParameters)
	if !ok {
		return nil, fail.InvalidParameterError("params", "must be a 'taskUpdateClusterInventoryMasterParameters'")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  interface{}
		rErr fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			xerr := instance.updateClusterInventoryMaster(ctx, casted)
			return result{nil, xerr}, xerr
		}()
		chRes <- gres
	}()

	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return nil, fail.Wrap(inctx.Err())
	}
}

// updateClusterInventoryMaster updates a Host (master) ansible inventory
func (instance *Cluster) updateClusterInventoryMaster(inctx context.Context, param taskUpdateClusterInventoryMasterParameters) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer fail.OnPanic(&ferr)
		defer close(chRes)

		timings, xerr := instance.Service().Timings()
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		master := param.master
		inventoryData := param.inventoryData
		does, xerr := master.Exists(ctx)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}
		if !does {
			chRes <- result{nil}
			return
		}

		rfcItem := Item{
			Remote:       fmt.Sprintf("%s/%s", utils.TempFolder, "ansible-inventory.py"),
			RemoteOwner:  "cladm:cladm",
			RemoteRights: "ou+rx-w,g+rwx",
		}

		target := fmt.Sprintf("%s/ansible/inventory/", utils.EtcFolder)
		commands := []string{
			fmt.Sprintf("[ -f %s_inventory.py ] && sudo rm -f %s_inventory.py || exit 0", target, target),
			fmt.Sprintf("sudo mkdir -p %s && sudo mv %s %s_inventory.py", target, rfcItem.Remote, target),
			fmt.Sprintf("sudo chown cladm:root %s_inventory.py", target),
			fmt.Sprintf("ansible-inventory -i %s_inventory.py --list", target),
			fmt.Sprintf("[ -f %sinventory.py ] && sudo rm -f %sinventory.py  || exit 0", target, target),
			fmt.Sprintf("sudo mv %s_inventory.py %sinventory.py", target, target),
		}
		prerr := fmt.Sprintf("[Cluster %s, master %s] Ansible inventory update: ", instance.GetName(), master.GetName())
		errmsg := []string{
			fmt.Sprintf("%sfail to clean up temporaries", prerr),
			fmt.Sprintf("%sfail to move uploaded inventory", prerr),
			fmt.Sprintf("%sfail to update rights of uploaded inventory", prerr),
			fmt.Sprintf("%sfail to test/run uploaded inventory", prerr),
			fmt.Sprintf("%sfail to remove previous inventory", prerr),
			fmt.Sprintf("%sfail to move uploaded inventory to final destination", prerr),
		}

		// Remove possible junks
		cmd := fmt.Sprintf("[ -f %s ] && sudo rm -f %s || exit 0", rfcItem.Remote, rfcItem.Remote)
		connTimeout := timings.ConnectionTimeout()
		delay := timings.NormalDelay()
		retcode, stdout, stderr, xerr := master.Run(ctx, cmd, outputs.COLLECT, connTimeout, delay)
		if xerr != nil {
			chRes <- result{fail.Wrap(xerr, "%sfail to clean previous temporaries", prerr)}
			return
		}
		if retcode != 0 {
			xerr := fail.NewError("%sfail to clean previous temporaries", prerr)
			xerr.Annotate("cmd", cmd)
			xerr.Annotate("stdout", stdout)
			xerr.Annotate("stderr", stderr)
			xerr.Annotate("retcode", retcode)
			chRes <- result{xerr}
			return
		}

		// Upload new inventory
		xerr = rfcItem.UploadString(ctx, inventoryData, master)
		if xerr != nil {
			chRes <- result{fail.Wrap(xerr, "%supload fail", prerr)}
			return
		}

		// Run update commands
		for a, acmd := range commands {
			i, cmd := a, acmd
			retcode, stdout, stderr, xerr = master.Run(ctx, cmd, outputs.COLLECT, connTimeout, delay)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{fail.Wrap(xerr, errmsg[i])}
				return
			}
			if retcode != 0 {
				xerr := fail.NewError(errmsg[i])
				xerr.Annotate("cmd", cmd)
				xerr.Annotate("stdout", stdout)
				xerr.Annotate("stderr", stderr)
				xerr.Annotate("retcode", retcode)
				chRes <- result{xerr}
				return
			}
		}

		chRes <- result{nil}
	}()

	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.Wrap(ctx.Err())
	case <-inctx.Done():
		cancel()
		<-chRes
		return fail.Wrap(inctx.Err())
	}
}
