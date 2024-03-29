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

package operations

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/consts"
	"math"
	mrand "math/rand"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/callstack"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sanity-io/litter"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clustercomplexity"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusternodetype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/clusterflavors"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/clusterflavors/boh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/clusterflavors/k8s"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	propertiesv3 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v3"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/template"

	_ "github.com/sony/gobreaker"
)

const (
	clusterKind        = "cluster"
	clustersFolderName = "clusters" // path to use to reach ClassicCluster Definitions/Metadata
)

// ClassicCluster is the implementation of resources.Cluster interface
type ClassicCluster struct {
	*MetadataCore

	gateways []string
	masters  []string
	nodes    []string

	masterIPs data.IndexedListOfStrings
	nodeIPs   data.IndexedListOfStrings

	state clusterstate.Enum

	cluID *abstract.ClusterIdentity

	randomDelayTask func()
	randomDelayCh   <-chan int
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *ClassicCluster) Exists(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	// begin by inspecting all hosts...
	svc := instance.Service()

	gws, xerr := instance.trueListGateways(ctx)
	if xerr != nil {
		return false, xerr
	}

	mids := instance.masters

	nids := instance.nodes

	failures := make(chan string, len(mids)+len(nids)+len(gws))
	rg := new(errgroup.Group)

	for _, agw := range gws {
		agw := agw
		rg.Go(func() error {
			rh, xerr := LoadHost(ctx, svc, agw.Core.ID)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					failures <- agw.Core.ID
					return nil
				default:
					return xerr
				}
			}

			exists, xerr := rh.Exists(ctx)
			if xerr != nil {
				return xerr
			}

			if !exists {
				failures <- agw.Core.ID
			}
			return nil
		})
	}

	for _, mid := range mids {
		mid := mid
		rg.Go(func() error {
			rh, xerr := LoadHost(ctx, svc, mid)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					failures <- mid
					return nil
				default:
					return xerr
				}
			}

			exists, xerr := rh.Exists(ctx)
			if xerr != nil {
				return xerr
			}

			if !exists {
				failures <- mid
			}

			return nil
		})
	}

	for _, nid := range nids {
		nid := nid
		rg.Go(func() error {
			rh, xerr := LoadHost(ctx, svc, nid)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					failures <- nid
					return nil
				default:
					return xerr
				}
			}

			exists, xerr := rh.Exists(ctx)
			if xerr != nil {
				return xerr
			}

			if !exists {
				failures <- nid
			}

			return nil
		})
	}

	err := rg.Wait()
	if err != nil {
		close(failures)
		return false, fail.ConvertError(err)
	}

	close(failures)
	if len(failures) > 0 {
		return false, nil
	}
	return true, nil
}

// StartRandomDelayGenerator starts a Task to generate random delays, read from instance.randomDelayCh
func (instance *ClassicCluster) startRandomDelayGenerator(ctx context.Context, min, max int) fail.Error {
	chint := make(chan int)
	mrand.Seed(time.Now().UnixNano())

	instance.randomDelayTask = func() {
		defer close(chint)
		if min == max {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					chint <- min
				}
			}
		} else {
			value := max - min
			for {
				select {
				case <-ctx.Done():
					return
				default:
					chint <- mrand.Intn(value) + min // nolint
				}
			}
		}
	}
	go instance.randomDelayTask()

	instance.randomDelayCh = chint
	return nil
}

// onClusterCacheMiss is called when cluster cache does not contain an instance of cluster 'name'
func onClusterCacheMiss(inctx context.Context, svc iaas.Service, name string) (data.Identifiable, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  resources.Cluster
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ resources.Cluster, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			clusterInstanceRaw, xerr := NewCluster(ctx, svc)
			if xerr != nil {
				return nil, xerr
			}

			clusterInstance, ok := clusterInstanceRaw.(*ClassicCluster)
			if !ok {
				return nil, fail.InvalidParameterError("clusterInstanceRaw", "should have been a *ClassicCluster")
			}

			if xerr = clusterInstance.Read(ctx, name); xerr != nil {
				return nil, xerr
			}

			shi, err := clusterInstance.MetadataCore.shielded.UnWrap()
			if err != nil {
				return nil, fail.ConvertError(err)
			}

			aclu, ok := shi.(*abstract.ClusterIdentity)
			if !ok {
				return nil, fail.NewError("bad cast")
			}
			clusterInstance.cluID = aclu

			aclupro, err := clusterInstance.MetadataCore.properties.UnWrap()
			if err != nil {
				return nil, fail.ConvertError(err)
			}

			flavor, xerr := clusterInstance.GetFlavor(ctx)
			if xerr != nil {
				return nil, xerr
			}

			xerr = clusterInstance.bootstrap(flavor)
			if xerr != nil {
				return nil, xerr
			}

			if val, ok := aclupro[clusterproperty.NetworkV3]; !ok {
				return nil, fail.NewError("corrupted metadata")
			} else {
				if val == nil {
					return nil, fail.NewError("corrupted metadata")
				}
			}

			nev, err := aclupro[clusterproperty.NetworkV3].UnWrap()
			if err != nil {
				return nil, fail.ConvertError(err)
			}

			gottanev, ok := nev.(*propertiesv3.ClusterNetwork)
			if !ok {
				return nil, fail.NewError("bad cast")
			}

			clusterInstance.gateways = append(clusterInstance.gateways, gottanev.GatewayID)
			if gottanev.SecondaryGatewayID != "" {
				clusterInstance.gateways = append(clusterInstance.gateways, gottanev.SecondaryGatewayID)
			}

			if val, ok := aclupro[clusterproperty.NodesV3]; !ok {
				return nil, fail.NewError("corrupted metadata")
			} else {
				if val == nil {
					return nil, fail.NewError("corrupted metadata")
				}
			}

			foo, err := aclupro[clusterproperty.NodesV3].UnWrap()
			if err != nil {
				return nil, fail.ConvertError(err)
			}

			gotta, ok := foo.(*propertiesv3.ClusterNodes)
			if !ok {
				return nil, fail.NewError("bad cast")
			}

			for k := range gotta.PrivateNodeByID {
				clusterInstance.nodes = append(clusterInstance.nodes, k)
			}
			for k := range gotta.MasterByID {
				clusterInstance.masters = append(clusterInstance.masters, k)
			}

			if val, ok := aclupro[clusterproperty.StateV1]; !ok {
				return nil, fail.NewError("corrupted metadata")
			} else {
				if val == nil {
					return nil, fail.NewError("corrupted metadata")
				}
			}

			asta, err := aclupro[clusterproperty.StateV1].UnWrap()
			if err != nil {
				return nil, fail.ConvertError(err)
			}

			gurb, ok := asta.(*propertiesv1.ClusterState)
			if !ok {
				return nil, fail.NewError("bad cast")
			}

			clusterInstance.state = gurb.State

			for k, v := range gotta.ByNumericalID {
				if strings.Contains(v.Name, "node") {
					clusterInstance.nodeIPs[k] = v.PrivateIP
				}
				if strings.Contains(v.Name, "master") {
					clusterInstance.masterIPs[k] = v.PrivateIP
				}
			}

			xerr = clusterInstance.updateCachedInformation(ctx)
			if xerr != nil {
				return nil, xerr
			}

			return clusterInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// updateCachedInformation updates information cached in the instance
func (instance *ClassicCluster) updateCachedInformation(inctx context.Context) fail.Error {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		var xerr fail.Error
		if len(instance.masterIPs) == 0 {
			instance.masterIPs, xerr = instance.newunsafeListMasterIPs(ctx) // also updates instance.masters
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
		}

		if len(instance.nodeIPs) == 0 {
			instance.nodeIPs, xerr = instance.newunsafeListNodeIPs(ctx) // also updates instance.nodes
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
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
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

// IsNull tells if the instance should be considered as a null value
func (instance *ClassicCluster) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

// carry ...
func (instance *ClassicCluster) carry(inctx context.Context, clonable data.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) {
		if instance.MetadataCore.IsTaken() {
			return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
		}
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	xerr := instance.MetadataCore.Carry(ctx, clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Create creates the necessary infrastructure of the ClassicCluster
func (instance *ClassicCluster) Create(inctx context.Context, req abstract.ClusterRequest) fail.Error {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gerr := func() (ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			if !valid.IsNil(instance.MetadataCore) {
				if instance.MetadataCore.IsTaken() {
					return fail.InconsistentError("already carrying information")
				}
			}
			if ctx == nil {
				return fail.InvalidParameterCannotBeNilError("ctx")
			}

			res, xerr := instance.taskCreateCluster(ctx, req)
			if xerr != nil {
				return xerr
			}

			logrus.WithContext(ctx).Tracef("ClassicCluster creation finished with: %s", litter.Sdump(res))

			xerr = instance.regenerateClusterInventory(ctx)
			if xerr != nil {
				return xerr
			}

			return nil
		}()
		chRes <- result{gerr}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

func (instance *ClassicCluster) Sdump(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	dumped, xerr := instance.MetadataCore.Sdump(ctx)
	if xerr != nil {
		return "", xerr
	}
	return dumped, nil
}

// Deserialize reads json code and recreates ClassicCluster metadata
func (instance *ClassicCluster) Deserialize(_ context.Context, buf []byte) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	if len(buf) == 0 {
		return fail.InvalidParameterError("buf", "cannot be empty []byte")
	}

	err := json.Unmarshal(buf, instance) // nolint
	return fail.ConvertError(err)
}

// bootstrap (re)connects controller with the appropriate Makers
func (instance *ClassicCluster) bootstrap(flavor clusterflavor.Enum) (ferr fail.Error) {
	switch flavor {
	case clusterflavor.BOH:
	case clusterflavor.K8S:
	default:
		return fail.InvalidParameterError("unknown ClassicCluster Flavor '%d'", flavor)
	}
	return nil
}

func (instance *ClassicCluster) getMaker(inctx context.Context) (clusterflavors.Makers, fail.Error) {
	fla, xerr := instance.unsafeGetFlavor(inctx)
	if xerr != nil {
		return clusterflavors.Makers{}, xerr
	}

	switch fla {
	case clusterflavor.BOH:
		return boh.Makers, nil
	case clusterflavor.K8S:
		return k8s.Makers, nil
	default:
		return clusterflavors.Makers{}, fail.InvalidParameterError("unknown ClassicCluster Flavor '%d'", fla)
	}
}

// Browse walks through ClassicCluster MetadataFolder and executes a callback for each entry
// FIXME: adds a ClassicCluster status check to prevent operations on removed clusters
func (instance *ClassicCluster) Browse(inctx context.Context, callback func(*abstract.ClusterIdentity) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	return instance.MetadataCore.BrowseFolder(ctx, func(buf []byte) fail.Error {
		aci := abstract.NewClusterIdentity()
		xerr := aci.Deserialize(buf)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		return callback(aci)
	})
}

// GetIdentity returns the identity of the ClassicCluster
func (instance *ClassicCluster) GetIdentity(ctx context.Context) (clusterIdentity abstract.ClusterIdentity, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return abstract.ClusterIdentity{}, fail.InvalidInstanceError()
	}

	return instance.unsafeGetIdentity(ctx)
}

// GetFlavor returns the flavor of the ClassicCluster
func (instance *ClassicCluster) GetFlavor(ctx context.Context) (flavor clusterflavor.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	return instance.unsafeGetFlavor(ctx)
}

// GetComplexity returns the complexity of the ClassicCluster
func (instance *ClassicCluster) GetComplexity(ctx context.Context) (_ clustercomplexity.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return 0, fail.InvalidInstanceError()
	}

	return instance.unsafeGetComplexity(ctx)
}

// GetAdminPassword returns the password of the ClassicCluster admin account
// satisfies interface ClassicCluster.Controller
func (instance *ClassicCluster) GetAdminPassword(_ context.Context) (adminPassword string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	return instance.cluID.AdminPassword, nil
}

// GetKeyPair returns the key pair used in the ClassicCluster
func (instance *ClassicCluster) GetKeyPair(_ context.Context) (keyPair *abstract.KeyPair, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	return instance.cluID.Keypair, nil
}

// GetNetworkConfig returns subnet configuration of the ClassicCluster
func (instance *ClassicCluster) GetNetworkConfig(ctx context.Context) (config *propertiesv3.ClusterNetwork, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(
			clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
				networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
				if !ok {
					return fail.InconsistentError(
						"'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}
				config = networkV3
				return nil
			},
		)
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if config == nil {
		return nil, fail.InconsistentError("config should NOT be nil")
	}

	return config, nil
}

// Start starts the ClassicCluster
func (instance *ClassicCluster) Start(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	// If the ClassicCluster is in state Stopping or Stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = instance.unsafeGetState(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	switch prevState {
	case clusterstate.Removed:
		return fail.NotAvailableError("ClassicCluster is being removed")
	case clusterstate.Stopping:
		return nil
	case clusterstate.Starting:
		// If the ClassicCluster is in state Starting, wait for it to finish its start procedure
		xerr = retry.WhileUnsuccessful(
			func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				state, innerErr := instance.unsafeGetState(ctx)
				if innerErr != nil {
					return innerErr
				}

				if state == clusterstate.Nominal || state == clusterstate.Degraded {
					return nil
				}

				return fail.NewError("current state of ClassicCluster is '%s'", state.String())
			},
			timings.NormalDelay(),
			timings.ExecutionTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry:
				return fail.Wrap(fail.Cause(xerr), "stopping retries")
			case *retry.ErrTimeout:
				return fail.Wrap(fail.Cause(xerr), "timeout")
			default:
				return xerr
			}
		}
		return nil
	case clusterstate.Stopped, clusterstate.Degraded:
		// continue
	default:
		return fail.NotAvailableError("failed to start ClassicCluster because of it's current state: %s", prevState.String())
	}

	// First mark ClassicCluster to be in state Starting
	xerr = instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			stateV1.State = clusterstate.Starting
			instance.state = clusterstate.Starting
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return xerr
	}

	var (
		nodes                         []string
		masters                       []string
		gatewayID, secondaryGatewayID string
	)

	// Then start it and mark it as NOMINAL on success
	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			masters = make([]string, 0, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
				if node, found := nodesV3.ByNumericalID[v]; found {
					masters = append(masters, node.ID)
				}
			}
			nodes = make([]string, 0, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if node, found := nodesV3.ByNumericalID[v]; found {
					nodes = append(nodes, node.ID)
				}
			}

			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to get list of hosts")
		}

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
			}

			gatewayID = networkV3.GatewayID
			secondaryGatewayID = networkV3.SecondaryGatewayID
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Mark ClassicCluster as state Starting
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			stateV1.State = clusterstate.Starting
			instance.state = clusterstate.Starting
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return xerr
	}

	runGroup := new(errgroup.Group)

	runGroup.Go(func() error {
		_, err := instance.taskStartHost(ctx, gatewayID)
		return err
	})

	if secondaryGatewayID != "" {
		runGroup.Go(func() error {
			_, err := instance.taskStartHost(ctx, secondaryGatewayID)
			return err
		})
	}

	// Start masters
	for _, n := range masters {
		n := n
		runGroup.Go(func() error {
			_, err := instance.taskStartHost(ctx, n)
			return err
		})
	}

	// Start nodes
	for _, n := range nodes {
		n := n
		runGroup.Go(func() error {
			_, err := instance.taskStartHost(ctx, n)
			return err
		})
	}

	xerr = fail.ConvertError(runGroup.Wait())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		_ = instance.changeStatusTo(ctx, clusterstate.Degraded)
		return xerr
	}

	xerr = instance.changeStatusTo(ctx, clusterstate.Nominal)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return xerr
	}
	return nil
}

// Stop stops the ClassicCluster
func (instance *ClassicCluster) Stop(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	// If the ClassicCluster is stopped, do nothing
	var prevState clusterstate.Enum
	prevState, xerr = instance.unsafeGetState(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	switch prevState {
	case clusterstate.Removed:
		return fail.NotAvailableError("ClassicCluster is being removed")
	case clusterstate.Stopped:
		return nil
	case clusterstate.Stopping:
		xerr = retry.WhileUnsuccessful(
			func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				state, innerErr := instance.unsafeGetState(ctx)
				if innerErr != nil {
					return innerErr
				}

				if state == clusterstate.Removed {
					return retry.StopRetryError(fail.NotAvailableError("ClassicCluster is being removed"))
				}

				if state != clusterstate.Stopped {
					return fail.NotAvailableError("current state of ClassicCluster is '%s'", state.String())
				}

				return nil
			},
			timings.NormalDelay(),
			timings.ExecutionTimeout(),
		)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrTimeout:
				return fail.Wrap(xerr.Cause(), "timeout")
			case *retry.ErrStopRetry:
				return fail.Wrap(xerr.Cause(), "stopping retries")
			default:
				return xerr
			}
		}
		return nil
	case clusterstate.Nominal, clusterstate.Degraded, clusterstate.Starting:
		// continue
	default:
		// If the ClassicCluster is not in state Nominal, Starting or Degraded, forbid to stop
		return fail.NotAvailableError("failed to stop ClassicCluster because of it's current state: %s", prevState.String())
	}

	// First mark ClassicCluster to be in state Stopping
	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			stateV1.State = clusterstate.Stopping
			instance.state = clusterstate.Stopping
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return xerr
	}

	// Then stop it and mark it as STOPPED on success
	return instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		var (
			nodes                         []string
			masters                       []string
			gatewayID, secondaryGatewayID string
		)
		innerXErr := props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
			}

			masters = make([]string, 0, len(nodesV3.Masters))
			for _, v := range nodesV3.Masters {
				if node, found := nodesV3.ByNumericalID[v]; found {
					masters = append(masters, node.ID)
				}
			}
			nodes = make([]string, 0, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if node, found := nodesV3.ByNumericalID[v]; found {
					nodes = append(nodes, node.ID)
				}
			}
			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to get list of hosts")
		}

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			gatewayID = networkV3.GatewayID
			secondaryGatewayID = networkV3.SecondaryGatewayID
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Stop nodes
		egStopHosts := new(errgroup.Group)

		for _, n := range nodes {
			n := n
			egStopHosts.Go(func() error {
				_, err := instance.taskStopHost(ctx, n)
				return err
			})
		}
		// Stop masters
		for _, n := range masters {
			n := n
			egStopHosts.Go(func() error {
				_, err := instance.taskStopHost(ctx, n)
				return err
			})
		}
		// Stop gateway(s)
		egStopHosts.Go(func() error {
			_, err := instance.taskStopHost(ctx, gatewayID)
			return err
		})

		if secondaryGatewayID != "" {
			egStopHosts.Go(func() error {
				_, err := instance.taskStopHost(ctx, secondaryGatewayID)
				return err
			})
		}

		innerXErr = fail.ConvertError(egStopHosts.Wait())
		if innerXErr != nil {
			return innerXErr
		}

		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			stateV1.State = clusterstate.Stopped
			instance.state = clusterstate.Stopped
			return nil
		})
	})
}

// GetState returns the current state of the ClassicCluster
// Uses the "maker" ForceGetState
func (instance *ClassicCluster) GetState(ctx context.Context) (state clusterstate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	state = clusterstate.Unknown
	if valid.IsNil(instance) {
		return state, fail.InvalidInstanceError()
	}

	return instance.unsafeGetState(ctx)
}

// AddNodes adds several nodes
func (instance *ClassicCluster) AddNodes(ctx context.Context, cluName string, count uint, def abstract.HostSizingRequirements, parameters data.Map, keepOnFailure bool) (_ []resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "must be an int > 0")
	}

	defer func() {
		// drop the cache when we are done expanding the cluster
		if ka, err := instance.Service().GetCache(context.Background()); err == nil {
			if ka != nil {
				_ = ka.Clear(context.Background())
			}
		}
	}()

	parameters, err := data.FromMap(parameters)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	var disabled map[string]struct{}
	xerr = instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			disabled = featuresV1.Disabled
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	var (
		hostImage             string
		nodeDefaultDefinition *propertiesv2.HostSizingRequirements
	)
	xerr = instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(clusterproperty.DefaultsV3) {
			return props.Inspect(clusterproperty.DefaultsV3, func(clonable data.Clonable) fail.Error {
				defaultsV3, ok := clonable.(*propertiesv3.ClusterDefaults)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				nodeDefaultDefinition = &defaultsV3.NodeSizing
				hostImage = defaultsV3.Image

				// merge FeatureParameters in parameters, the latter keeping precedence over the former
				efe, serr := ExtractFeatureParameters(defaultsV3.FeatureParameters)
				if serr != nil {
					return fail.ConvertError(serr)
				}
				for k, v := range efe {
					if _, ok := parameters[k]; !ok {
						parameters[k] = v
					}
				}

				return nil
			})
		}

		// ClassicCluster may have been created before ClusterDefaultV3, so still support this context
		return props.Inspect(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
			defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nodeDefaultDefinition = &defaultsV2.NodeSizing
			hostImage = defaultsV2.Image
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	nodeDef := complementHostDefinition(def, *nodeDefaultDefinition)
	if def.Image != "" {
		hostImage = def.Image
	}

	if hostImage == "" {
		hostImage = consts.DEFAULTOS
	}

	svc := instance.Service()
	_, nodeDef.Image, xerr = determineImageID(ctx, svc, hostImage)
	if xerr != nil {
		return nil, xerr
	}

	var (
		nodes []*propertiesv3.ClusterNode
	)

	timings, xerr := svc.Timings()
	if xerr != nil {
		return nil, xerr
	}

	tcount := uint(math.Max(float64(count), 4))
	timeout := time.Duration(tcount) * timings.HostCreationTimeout() // More than enough

	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	winSize := 8
	st, xerr := instance.Service().GetProviderName()
	if xerr != nil {
		return nil, xerr
	}
	if st != "ovh" {
		winSize = int((8 * count) / 10)
		if winSize < 8 {
			winSize = 8
		}
	}
	if cfg, xerr := svc.GetConfigurationOptions(ctx); xerr == nil {
		if aval, ok := cfg.Get("ConcurrentMachineCreationLimit"); ok {
			if val, ok := aval.(int); ok {
				winSize = val
			}
		}
	}

	ctx, ca := context.WithTimeout(ctx, timeout)
	defer ca()

	// for OVH, we have to ignore the errors and keep trying until we have 'count'
	nodesChan := make(chan StdResult, 4*count)
	err = runWindow(ctx, count, uint(math.Min(float64(count), float64(winSize))), nodesChan, instance.taskCreateNode, taskCreateNodeParameters{
		nodeDef:       nodeDef,
		timeout:       timings.HostCreationTimeout(),
		keepOnFailure: keepOnFailure,
		clusterName:   cluName,
		request: abstract.ClusterRequest{
			DisabledDefaultFeatures: disabled,
		},
	})
	if err != nil {
		close(nodesChan)
		return nil, fail.ConvertError(err)
	}

	close(nodesChan)
	for v := range nodesChan {
		if v.Err != nil {
			continue
		}
		if v.ToBeDeleted {
			crucial, ok := v.Content.(*propertiesv3.ClusterNode)
			if !ok {
				continue
			}

			_, xerr = instance.taskDeleteNodeWithCtx(cleanupContextFrom(ctx), taskDeleteNodeParameters{node: v.Content.(*propertiesv3.ClusterNode), clusterName: cluName})
			debug.IgnoreError2(ctx, xerr)

			xerr = svc.DeleteHost(cleanupContextFrom(ctx), crucial.ID)
			debug.IgnoreError2(ctx, xerr)
			continue
		}
		nodes = append(nodes, v.Content.(*propertiesv3.ClusterNode))
		instance.nodes = append(instance.nodes, v.Content.(*propertiesv3.ClusterNode).ID)
	}

	// Starting from here, if exiting with error, delete created nodes if allowed (cf. keepOnFailure)
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil && !keepOnFailure && len(nodes) > 0 {
			egDeletion := new(errgroup.Group)

			for _, v := range nodes {
				v := v
				egDeletion.Go(func() error {
					_, err := instance.taskDeleteNodeWithCtx(cleanupContextFrom(ctx), taskDeleteNodeParameters{node: v, clusterName: cluName})
					return err
				})
			}
			derr := fail.ConvertError(egDeletion.Wait())
			derr = debug.InjectPlannedFail(derr)
			if derr != nil {
				_ = ferr.AddConsequence(derr)
			}
		}
	}()

	// configure what has to be done ClassicCluster-wide
	makers, xerr := instance.getMaker(ctx)
	if xerr != nil {
		return nil, xerr
	}
	if makers.ConfigureCluster != nil {
		xerr = makers.ConfigureCluster(ctx, instance, parameters, true)
		if xerr != nil {
			return nil, xerr
		}
	}
	incrementExpVar("cluster.cache.hit")

	// Now configure new nodes
	xerr = instance.configureNodesFromList(ctx, cluName, nodes, parameters)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// At last join nodes to ClassicCluster
	xerr = instance.joinNodesFromList(ctx, nodes)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	hosts := make([]resources.Host, 0, len(nodes))
	for _, v := range nodes {
		hostInstance, xerr := LoadHost(ctx, svc, v.ID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, xerr
		}
		hosts = append(hosts, hostInstance)
	}

	xerr = instance.regenerateClusterInventory(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return hosts, nil
}

// complementHostDefinition complements req with default values if needed
func complementHostDefinition(req abstract.HostSizingRequirements, def propertiesv2.HostSizingRequirements) abstract.HostSizingRequirements {
	if def.MinCores > 0 && req.MinCores == 0 {
		req.MinCores = def.MinCores
	}
	if def.MaxCores > 0 && req.MaxCores == 0 {
		req.MaxCores = def.MaxCores
	}
	if def.MinRAMSize > 0.0 && req.MinRAMSize == 0.0 {
		req.MinRAMSize = def.MinRAMSize
	}
	if def.MaxRAMSize > 0.0 && req.MaxRAMSize == 0.0 {
		req.MaxRAMSize = def.MaxRAMSize
	}
	if def.MinDiskSize > 0 && req.MinDiskSize == 0 {
		req.MinDiskSize = def.MinDiskSize
	}
	if req.MinGPU <= 0 && def.MinGPU > 0 {
		req.MinGPU = def.MinGPU
	}
	if req.MinCPUFreq == 0 && def.MinCPUFreq > 0 {
		req.MinCPUFreq = def.MinCPUFreq
	}
	if req.MinCores <= 0 {
		req.MinCores = 2
	}
	if req.MaxCores <= 0 {
		req.MaxCores = 4
	}
	if req.MinRAMSize <= 0.0 {
		req.MinRAMSize = 7.0
	}
	if req.MaxRAMSize <= 0.0 {
		req.MaxRAMSize = 16.0
	}
	if req.MinDiskSize <= 0 {
		req.MinDiskSize = 50
	}

	return req
}

// DeleteSpecificNode deletes a node identified by its ID
func (instance *ClassicCluster) DeleteSpecificNode(ctx context.Context, hostID string, selectedMasterID string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if hostID = strings.TrimSpace(hostID); hostID == "" {
		return fail.InvalidParameterError("hostID", "cannot be empty string")
	}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var selectedMaster resources.Host
	if selectedMasterID != "" {
		selectedMaster, xerr = LoadHost(ctx, instance.Service(), selectedMasterID)
	} else {
		selectedMaster, xerr = instance.unsafeFindAvailableMaster(ctx)
	}
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	var node *propertiesv3.ClusterNode
	xerr = instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
			}

			numericalID, ok := nodesV3.PrivateNodeByID[hostID]
			if !ok {
				return fail.NotFoundError("failed to find a node identified by %s", hostID)
			}

			node, ok = nodesV3.ByNumericalID[numericalID]
			if !ok {
				return fail.NotFoundError("failed to find a node identified by %s", hostID)
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return xerr
	}

	xerr = instance.deleteNode(cleanupContextFrom(ctx), node, selectedMaster.(*Host))
	if xerr != nil {
		return xerr
	}

	xerr = instance.regenerateClusterInventory(ctx)
	if xerr != nil {
		return xerr
	}

	return nil
}

// ListMasters lists the node instances corresponding to masters (if there is such masters in the flavor...)
func (instance *ClassicCluster) ListMasters(ctx context.Context) (list resources.IndexedListOfClusterNodes, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	lim, xerr := instance.unsafeListMasters(ctx)
	return lim, xerr
}

// FindAvailableMaster returns ID of the first master available to execute order
// satisfies interface ClassicCluster.ClassicCluster.Controller
func (instance *ClassicCluster) FindAvailableMaster(ctx context.Context) (master resources.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer elapsed(ctx, "FindAvailableMaster")()

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return instance.unsafeFindAvailableMaster(ctx)
}

// ListNodes lists node instances corresponding to the nodes in the ClassicCluster
// satisfies interface ClassicCluster.Controller
func (instance *ClassicCluster) ListNodes(ctx context.Context) (list resources.IndexedListOfClusterNodes, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	res, xerr := instance.unsafeListNodes(ctx)
	return res, xerr
}

// beingRemoved tells if the ClassicCluster is currently marked as Removed (meaning a removal operation is running)
func (instance *ClassicCluster) beingRemoved(ctx context.Context) fail.Error {
	state, xerr := instance.unsafeGetState(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if state == clusterstate.Removed {
		return fail.NotAvailableError("ClassicCluster is being removed")
	}

	return nil
}

// ListNodeNames lists the names of the nodes in the ClassicCluster
func (instance *ClassicCluster) ListNodeNames(ctx context.Context) (list data.IndexedListOfStrings, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = make(data.IndexedListOfStrings, len(nodesV3.PrivateNodes))
			for _, v := range nodesV3.PrivateNodes {
				if node, found := nodesV3.ByNumericalID[v]; found {
					list[node.NumericalID] = node.Name
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return nil, xerr
	}

	return list, nil
}

// deleteMaster deletes the master specified by its ID
func (instance *ClassicCluster) deleteMaster(ctx context.Context, host string) (ferr fail.Error) {
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	if valid.IsNil(host) {
		return fail.InvalidParameterCannotBeNilError("host")
	}

	// FIXME: Bad idea, the first thing to go must be the resource, then the metadata; if not we can have zombie instances without metadata (it happened)
	// which means that the code doing the "restore" never worked

	xerr := instance.Alter(cleanupContextFrom(ctx), func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			// Removes master from ClassicCluster properties
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hid := host

			numericalID, found := nodesV3.MasterByID[hid]
			if !found {
				return abstract.ResourceNotFoundError("master", host)
			}

			delete(nodesV3.ByNumericalID, numericalID)
			delete(nodesV3.MasterByID, hid)
			if found, indexInSlice := containsClusterNode(nodesV3.Masters, numericalID); found {
				length := len(nodesV3.Masters)
				if indexInSlice < length-1 {
					nodesV3.Masters = append(nodesV3.Masters[:indexInSlice], nodesV3.Masters[indexInSlice+1:]...)
				} else {
					nodesV3.Masters = nodesV3.Masters[:indexInSlice]
				}
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return xerr
	}

	svc := instance.Service()

	lh, xerr := LoadHost(ctx, svc, host)
	if xerr != nil {
		return xerr
	}

	xerr = lh.Delete(ctx)
	if xerr != nil {
		return xerr
	}

	return nil
}

// deleteNode deletes a node
func (instance *ClassicCluster) deleteNode(inctx context.Context, node *propertiesv3.ClusterNode, master *Host) (_ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			nodeRef := node.ID
			if nodeRef == "" {
				nodeRef = node.Name
			}

			// FIXME: Bad idea, the first thing to go must be the resource, then the metadata; if not we can have zombie instances without metadata (it happened)
			// which means that the code doing the "restore" never worked

			// Identify the node to delete and remove it preventively from metadata
			xerr := instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					delete(nodesV3.ByNumericalID, node.NumericalID)

					if found, indexInSlice := containsClusterNode(nodesV3.PrivateNodes, node.NumericalID); found {
						length := len(nodesV3.PrivateNodes)
						if indexInSlice < length-1 {
							nodesV3.PrivateNodes = append(nodesV3.PrivateNodes[:indexInSlice], nodesV3.PrivateNodes[indexInSlice+1:]...)
						} else {
							nodesV3.PrivateNodes = nodesV3.PrivateNodes[:indexInSlice]
						}
					}
					delete(nodesV3.PrivateNodeByID, node.ID)
					delete(nodesV3.PrivateNodeByName, node.Name)
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{xerr}, xerr
			}

			// Deletes node
			hostInstance, xerr := LoadHost(ctx, instance.Service(), nodeRef)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Host already deleted, consider as a success, continue
					return result{nil}, nil // nolint
				default:
					return result{xerr}, xerr
				}
			}

			// host still exists, leave it from ClassicCluster, if master is not null
			if master != nil && !valid.IsNil(master) {
				xerr = instance.leaveNodesFromList(ctx, []resources.Host{hostInstance}, master)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return result{xerr}, xerr
				}

				makers, xerr := instance.getMaker(ctx)
				if xerr != nil {
					return result{xerr}, xerr
				}

				incrementExpVar("cluster.cache.hit")
				if makers.UnconfigureNode != nil {
					xerr = makers.UnconfigureNode(ctx, instance, hostInstance, master)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						return result{xerr}, xerr
					}
				}
			}

			// Finally delete host
			xerr = hostInstance.Delete(cleanupContextFrom(ctx))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// Host seems already deleted, so it's a success
				default:
					return result{xerr}, xerr
				}
			}

			return result{nil}, nil // nolint
		}() // nolint
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer cleanup
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer cleanup
		return fail.ConvertError(inctx.Err())
	}
}

// Delete deletes the ClassicCluster
func (instance *ClassicCluster) Delete(ctx context.Context, force bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	defer func() {
		// drop the cache when we are done creating the cluster
		if ka, err := instance.Service().GetCache(context.Background()); err == nil {
			if ka != nil {
				_ = ka.Clear(context.Background())
			}
		}
	}()

	if !force {
		xerr := instance.beingRemoved(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	clusterName := instance.GetName()

	xerr := instance.delete(cleanupContextFrom(ctx), clusterName)
	if xerr != nil {
		logrus.WithContext(cleanupContextFrom(ctx)).Error(xerr)
		if strings.Contains(xerr.Error(), "Alter") {
			return fail.NewError("severe metadata corruption")
		}
		return xerr
	}

	return nil
}

// delete does the work to delete ClassicCluster
func (instance *ClassicCluster) delete(inctx context.Context, cluName string) (_ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			var cleaningErrors []error

			if valid.IsNil(instance) {
				xerr := fail.InvalidInstanceError()
				return result{xerr}, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					derr := instance.Alter(cleanupContextFrom(ctx), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
						return props.Alter(
							clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
								stateV1, ok := clonable.(*propertiesv1.ClusterState)
								if !ok {
									return fail.InconsistentError(
										"'*propertiesv1.ClusterState' expected, '%s' provided",
										reflect.TypeOf(clonable).String(),
									)
								}

								stateV1.State = clusterstate.Degraded
								instance.state = clusterstate.Degraded
								return nil
							},
						)
					})
					if derr != nil {
						_ = ferr.AddConsequence(
							fail.Wrap(
								derr, "cleaning up on %s, failed to set ClassicCluster state to DEGRADED", ActionFromError(ferr),
							),
						)
					}
				}
			}()

			var (
				all            map[uint]*propertiesv3.ClusterNode
				nodes, masters []uint
			)
			// Mark the ClassicCluster as Removed and get nodes from properties
			xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				// Updates ClassicCluster state to mark ClassicCluster as Removing
				innerXErr := props.Alter(
					clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
						stateV1, ok := clonable.(*propertiesv1.ClusterState)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String(),
							)
						}

						stateV1.State = clusterstate.Removed
						instance.state = clusterstate.Removed
						return nil
					},
				)
				if innerXErr != nil {
					return innerXErr
				}

				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
						)
					}

					nodes = nodesV3.PrivateNodes
					masters = nodesV3.Masters
					all = nodesV3.ByNumericalID
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{xerr}, xerr
			}

			masterCount, nodeCount := len(masters), len(nodes)
			if masterCount+nodeCount > 0 {
				egKill := new(errgroup.Group)

				foundSomething := false
				for _, v := range nodes {
					v := v
					if n, ok := all[v]; ok {
						foundSomething = true

						egKill.Go(func() error {
							_, err := instance.taskDeleteNodeWithCtx(cleanupContextFrom(ctx), taskDeleteNodeParameters{node: n, clusterName: cluName})
							return err
						})
					}
				}

				for _, v := range masters {
					v := v
					if n, ok := all[v]; ok {
						foundSomething = true

						egKill.Go(func() error {
							_, err := instance.taskDeleteMaster(cleanupContextFrom(ctx), taskDeleteNodeParameters{node: n, clusterName: cluName})
							return err
						})
					}
				}

				if foundSomething {
					xerr = fail.ConvertError(egKill.Wait())
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						cleaningErrors = append(cleaningErrors, xerr)
					}
				}
			}
			if len(cleaningErrors) > 0 {
				xerr = fail.Wrap(fail.NewErrorList(cleaningErrors), "failed to delete Hosts")
				return result{xerr}, xerr
			}

			// From here, make sure there is nothing in nodesV3.ByNumericalID; if there is something, delete all the remaining
			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
					nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
						)
					}

					all = nodesV3.ByNumericalID
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				xerr = fail.Wrap(xerr, callstack.WhereIsThis())
				return result{xerr}, xerr
			}

			allCount := len(all)
			if allCount > 0 {
				egKill := new(errgroup.Group)

				for _, v := range all {
					v := v
					egKill.Go(func() error {
						_, err := instance.taskDeleteNodeWithCtx(cleanupContextFrom(ctx), taskDeleteNodeParameters{node: v, clusterName: cluName})
						return err
					})
				}

				xerr = fail.ConvertError(egKill.Wait())
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					cleaningErrors = append(cleaningErrors, xerr)
				}
				if len(cleaningErrors) > 0 {
					xerr = fail.Wrap(fail.NewErrorList(cleaningErrors), "failed to delete Hosts")
					return result{xerr}, xerr
				}
			}

			// --- Deletes the Network, Subnet and gateway ---
			networkInstance, deleteNetwork, subnetInstance, xerr := instance.extractNetworkingInfo(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// missing Network and Subnet is considered as a successful deletion, continue
					debug.IgnoreError2(ctx, xerr)
				default:
					return result{xerr}, xerr
				}
			}

			svc := instance.Service()
			timings, xerr := svc.Timings()
			if xerr != nil {
				return result{xerr}, xerr
			}

			if subnetInstance != nil && !valid.IsNil(subnetInstance) {
				subnetName := subnetInstance.GetName()
				logrus.WithContext(ctx).Debugf("ClassicCluster Deleting Subnet '%s'", subnetName)
				xerr = retry.WhileUnsuccessfulWithHardTimeout(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						innerXErr := subnetInstance.Delete(cleanupContextFrom(ctx))
						if innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotAvailable, *fail.ErrNotFound:
								return retry.StopRetryError(innerXErr)
							default:
								return innerXErr
							}
						}
						return nil
					},
					timings.NormalDelay(),
					timings.HostOperationTimeout(),
				)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						debug.IgnoreError2(ctx, xerr)
					case *fail.ErrTimeout, *fail.ErrAborted:
						nerr := fail.ConvertError(fail.Cause(xerr))
						switch nerr.(type) {
						case *fail.ErrNotFound:
							// Subnet not found, considered as a successful deletion and continue
							debug.IgnoreError2(ctx, nerr)
						default:
							xerr = fail.Wrap(nerr, "failed to delete Subnet '%s'", subnetName)
							return result{xerr}, xerr
						}
					default:
						xerr = fail.Wrap(xerr, "failed to delete Subnet '%s'", subnetName)
						return result{xerr}, xerr
					}
				}
			}

			if networkInstance != nil && !valid.IsNil(networkInstance) && deleteNetwork {
				networkName := networkInstance.GetName()
				logrus.WithContext(ctx).Debugf("Deleting Network '%s'...", networkName)
				xerr = retry.WhileUnsuccessfulWithHardTimeout(
					func() error {
						select {
						case <-ctx.Done():
							return retry.StopRetryError(ctx.Err())
						default:
						}

						innerXErr := networkInstance.Delete(cleanupContextFrom(ctx))
						if innerXErr != nil {
							switch innerXErr.(type) {
							case *fail.ErrNotFound, *fail.ErrInvalidRequest:
								return retry.StopRetryError(innerXErr)
							default:
								return innerXErr
							}
						}
						return nil
					},
					timings.NormalDelay(),
					timings.HostOperationTimeout(),
				)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// network not found, considered as a successful deletion and continue
						debug.IgnoreError2(ctx, xerr)
					case *retry.ErrStopRetry:
						xerr = fail.Wrap(xerr.Cause(), "stopping retries")
						return result{xerr}, xerr
					case *retry.ErrTimeout:
						xerr = fail.Wrap(xerr.Cause(), "timeout")
						return result{xerr}, xerr
					default:
						xerr = fail.Wrap(xerr, "failed to delete Network '%s'", networkName)
						logrus.WithContext(ctx).Errorf(xerr.Error())
						return result{xerr}, xerr
					}
				}
				logrus.WithContext(ctx).Infof("Network '%s' successfully deleted.", networkName)
			}

			// --- Delete metadata ---
			xerr = instance.MetadataCore.Delete(cleanupContextFrom(ctx))
			if xerr != nil {
				return result{xerr}, xerr
			}

			if ka, err := instance.Service().GetCache(ctx); err == nil {
				theID, _ := instance.GetID()
				if ka != nil {
					if theID != "" {
						_ = ka.Delete(ctx, fmt.Sprintf("%T/%s", instance, theID))
					}
				}
			}

			return result{nil}, nil // nolint
		}() // nolint
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		<-chRes // wait for defer cleanup
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes // wait for defer cleanup
		return fail.ConvertError(inctx.Err())
	}
}

// extractNetworkingInfo returns the ID of the network from properties, taking care of ascending compatibility
func (instance *ClassicCluster) extractNetworkingInfo(ctx context.Context) (networkInstance resources.Network, deleteNetwork bool, subnetInstance resources.Subnet, ferr fail.Error) {
	networkInstance, subnetInstance = nil, nil
	deleteNetwork = false

	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var inErr fail.Error
			if networkV3.SubnetID != "" {
				if subnetInstance, inErr = LoadSubnet(ctx, instance.Service(), networkV3.NetworkID, networkV3.SubnetID); inErr != nil {
					return inErr
				}
			}

			if networkV3.NetworkID != "" {
				networkInstance, inErr = LoadNetwork(ctx, instance.Service(), networkV3.NetworkID)
				if inErr != nil {
					return inErr
				}
				deleteNetwork = networkV3.CreatedNetwork
			}
			if networkV3.SubnetID != "" {
				subnetInstance, inErr = LoadSubnet(ctx, instance.Service(), networkV3.NetworkID, networkV3.SubnetID)
				if inErr != nil {
					return inErr
				}
				if networkInstance == nil {
					networkInstance, inErr = subnetInstance.InspectNetwork(ctx)
					if inErr != nil {
						return inErr
					}
				}
				deleteNetwork = networkV3.CreatedNetwork
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, deleteNetwork, nil, xerr
	}

	return networkInstance, deleteNetwork, subnetInstance, nil
}

func containsClusterNode(list []uint, numericalID uint) (bool, int) {
	var idx int
	found := false
	for i, v := range list {
		if v == numericalID {
			found = true
			idx = i
			break
		}
	}
	return found, idx
}

// configureCluster ...
// params contains a data.Map with primary and secondary getGateway hosts
func (instance *ClassicCluster) configureCluster(inctx context.Context, req abstract.ClusterRequest) (ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	logrus.WithContext(ctx).Infof("[ClassicCluster %s] configuring ClassicCluster...", instance.GetName())
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			logrus.WithContext(ctx).Errorf("[ClassicCluster %s] configuration failed: %s", instance.GetName(), ferr.Error())
		} else {
			logrus.WithContext(ctx).Infof("[ClassicCluster %s] configuration successful.", instance.GetName())
		}
	}()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)

		efe, serr := ExtractFeatureParameters(req.FeatureParameters)
		if serr != nil {
			chRes <- result{fail.ConvertError(serr)}
			return
		}

		parameters := efe

		// FIXME: This should use instance.AddFeature instead

		// Install reverse-proxy feature on ClassicCluster (gateways)
		fla, xerr := instance.unsafeGetFlavor(inctx)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		switch fla {
		case clusterflavor.K8S:
			// Reverse proxy disabled by default: EOL, unsafe, undocumented
			// FIXME: k8s has an UNDOCUMENTED dependency on reverse proxy...
			// reverseproxy CANNOT be disabled on K8S and expect K8S to work...
			xerr := instance.installReverseProxy(ctx, parameters, req)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
		default:
		}

		// Install remote-desktop feature on ClassicCluster (all masters)

		// FIXME: Enable this ONLY after remotedesktop feature is UPDATED AND TESTED
		// Also, EOL, unsafe, undocumented, 4 releases have passed since 1.0.0 was published
		for _, v := range req.Enabled { // if some explicitly asks for it
			if v == "remotedesktop" {
				xerr := instance.installRemoteDesktop(ctx, parameters, req)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					// Break execution flow only if the Feature cannot be run (file transfer, Host unreachable, ...), not if it ran but has failed
					if annotation, found := xerr.Annotation("ran_but_failed"); !found || !annotation.(bool) {
						chRes <- result{xerr}
						return
					}
				}
			}
		}

		// Install ansible feature on ClassicCluster (all masters) // aaaand it's gone...
		/*
			xerr = instance.installAnsible(ctx, parameters)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				chRes <- result{xerr}
				return
			}
		*/

		// disabling ansible also disables ansible-for-cluster
		if aitis, err := instance.isFeatureDisabled(ctx, "ansible"); !aitis && err == nil {
			if itis, err := instance.isFeatureDisabled(ctx, "ansible-for-cluster"); !itis && err == nil {
				xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
					return props.Alter(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
						featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
						if !ok {
							return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}

						featuresV1.Installed["ansible"] = &propertiesv1.ClusterInstalledFeature{Name: "ansible"}
						featuresV1.Installed["ansible-for-cluster"] = &propertiesv1.ClusterInstalledFeature{Name: "ansible-for-cluster"}
						return nil
					})
				})
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					xerr = fail.Wrap(xerr, callstack.WhereIsThis())
					chRes <- result{xerr}
					return
				}

				xerr = instance.regenerateClusterInventory(ctx)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					chRes <- result{xerr}
					return
				}
			}
		}

		// configure what has to be done ClassicCluster-wide
		makers, xerr := instance.getMaker(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			chRes <- result{xerr}
			return
		}

		incrementExpVar("cluster.cache.hit")
		if makers.ConfigureCluster != nil {
			chRes <- result{makers.ConfigureCluster(ctx, instance, parameters, false)}
			return
		}

		chRes <- result{nil}
	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

func (instance *ClassicCluster) determineRequiredNodes(ctx context.Context) (uint, uint, uint, fail.Error) {
	makers, xerr := instance.getMaker(ctx)
	if xerr != nil {
		return 0, 0, 0, xerr
	}
	if makers.MinimumRequiredServers != nil {
		g, m, n, xerr := makers.MinimumRequiredServers(ctx, *instance.cluID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return 0, 0, 0, xerr
		}

		return g, m, n, nil
	}
	return 0, 0, 0, nil
}

// realizeTemplate generates a file from box template with variables updated
func realizeTemplate(tmplName string, adata map[string]interface{}, fileName string) (string, string, fail.Error) {
	tmplString, err := clusterFlavorScripts.ReadFile(tmplName)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to load template")
	}

	tmplCmd, err := template.Parse(fileName, string(tmplString))
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to parse template")
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplCmd.Option("missingkey=error").Execute(dataBuffer, adata)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", "", fail.Wrap(err, "failed to execute  template")
	}

	cmd := dataBuffer.String()
	remotePath := utils.TempFolder + "/" + fileName

	return cmd, remotePath, nil
}

//go:embed scripts/*
var ansibleScripts embed.FS

// Regenerate ansible inventory
func (instance *ClassicCluster) regenerateClusterInventory(inctx context.Context) fail.Error {
	// Check incoming parameters
	if inctx == nil {
		return fail.InvalidParameterCannotBeNilError("inctx")
	}
	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		logrus.WithContext(ctx).Infof("[ClassicCluster %s] Update ansible inventory", instance.GetName())

		// Collect data
		featureAnsibleInventoryInstalled := false
		var masters []resources.Host
		var params = map[string]interface{}{
			"ClusterName":          "",
			"ClusterAdminUsername": "cladm",
			"ClusterAdminPassword": "",
			"PrimaryGatewayName":   fmt.Sprintf("gw-%s", instance.GetName()),
			"PrimaryGatewayIP":     "",
			"PrimaryGatewayPort":   "22",
			"SecondaryGatewayName": fmt.Sprintf("gw2-%s", instance.GetName()),
			"SecondaryGatewayIP":   "",
			"SecondaryGatewayPort": "22",
			"ClusterMasters":       resources.IndexedListOfClusterNodes{},
			"ClusterNodes":         resources.IndexedListOfClusterNodes{},
		}

		xerr := instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			// Check if feature ansible is installed
			innerXErr := props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
				featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
				if !ok {
					return fail.InconsistentError("`propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				_, featureAnsibleInventoryInstalled = featuresV1.Installed["ansible-for-cluster"]
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}
			if !featureAnsibleInventoryInstalled {
				return nil
			}

			// Collect get network config
			var networkCfg *propertiesv3.ClusterNetwork
			innerXErr = props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
				networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				if networkV3 == nil {
					return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", "nil")
				}
				networkCfg = networkV3
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			// Collect template data, list masters hosts
			aci, ok := clonable.(*abstract.ClusterIdentity)
			if !ok {
				return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if aci == nil {
				return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", "nil")
			}
			if reflect.TypeOf(aci.Name).Kind() != reflect.String && aci.Name == "" {
				return fail.InconsistentError("ClassicCluster name must be a not empty string")
			}

			params["Clustername"] = aci.Name
			params["ClusterAdminUsername"] = "cladm"
			params["ClusterAdminPassword"] = aci.AdminPassword
			params["PrimaryGatewayIP"] = networkCfg.GatewayIP
			if networkCfg.SecondaryGatewayIP != "" {
				params["SecondaryGatewayIP"] = networkCfg.SecondaryGatewayIP
			}

			return props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				if nodesV3 == nil {
					return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", "nil")
				}

				// Template params: gateways
				rh, err := LoadHost(ctx, instance.Service(), networkCfg.GatewayID)
				if err != nil {
					err = fail.Wrap(err, callstack.WhereIsThis())
					return fail.InconsistentErrorWithCause(err, nil, "Fail to load primary gateway '%s'", networkCfg.GatewayID)
				}
				err = rh.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
					ahc, ok := clonable.(*abstract.HostCore)
					if !ok {
						return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					if ahc == nil {
						return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", "nil")
					}
					params["PrimaryGatewayPort"] = strconv.Itoa(int(ahc.SSHPort))
					if ahc.Name != "" {
						params["PrimaryGatewayName"] = ahc.Name
					}
					return nil
				})
				if err != nil {
					err = fail.Wrap(err, callstack.WhereIsThis())
					return fail.InconsistentErrorWithCause(err, nil, "Fail to load primary gateway '%s'", networkCfg.GatewayID)
				}

				if networkCfg.SecondaryGatewayIP != "" {
					rh, err = LoadHost(ctx, instance.Service(), networkCfg.SecondaryGatewayID)
					if err != nil {
						return fail.InconsistentError("Fail to load secondary gateway '%s'", networkCfg.SecondaryGatewayID)
					}
					err = rh.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
						ahc, ok := clonable.(*abstract.HostCore)
						if !ok {
							return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						if ahc == nil {
							return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", "nil")
						}
						params["SecondaryGatewayPort"] = strconv.Itoa(int(ahc.SSHPort))
						if ahc.Name != "" {
							params["SecondaryGatewayName"] = ahc.Name
						}
						return nil
					})
					if err != nil {
						err = fail.Wrap(err, callstack.WhereIsThis())
						return fail.InconsistentErrorWithCause(err, nil, "Fail to load secondary gateway '%s'", networkCfg.SecondaryGatewayID)
					}
				}

				// Template params: masters
				nodes := make(resources.IndexedListOfClusterNodes, len(nodesV3.Masters))
				for _, v := range nodesV3.Masters {
					if node, found := nodesV3.ByNumericalID[v]; found {
						nodes[node.NumericalID] = node
						master, err := LoadHost(ctx, instance.Service(), node.ID)
						if err != nil {
							switch err.(type) {
							case *fail.ErrNotFound:
								continue
							default:
								return fail.Wrap(err, "Fail to load master '%s'", node.ID)
							}
						}
						if does, err := master.Exists(ctx); err == nil && does {
							masters = append(masters, master)
						}
					}
				}
				params["ClusterMasters"] = nodes

				// Template params: nodes
				nodes = make(resources.IndexedListOfClusterNodes, len(nodesV3.PrivateNodes))
				for _, v := range nodesV3.PrivateNodes {
					if node, found := nodesV3.ByNumericalID[v]; found {
						nodes[node.NumericalID] = node
					}
				}
				params["ClusterNodes"] = nodes
				return nil

			})
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			xerr = fail.Wrap(xerr, callstack.WhereIsThis())
			ar := result{xerr}
			chRes <- ar
			return
		}

		prerr := fmt.Sprintf("[ClassicCluster %s] Update ansible inventory: ", instance.GetName())

		// Feature ansible found ?
		if !featureAnsibleInventoryInstalled {
			logrus.WithContext(ctx).Infof("%snothing to update (feature not installed)", prerr)
			ar := result{nil}
			chRes <- ar
			return
		}
		// Has at least one master ?
		if len(masters) == 0 {
			logrus.WithContext(ctx).Infof("%s nothing to update (no masters in cluster)", prerr)
			ar := result{nil}
			chRes <- ar
			return
		}

		tmplString, err := ansibleScripts.ReadFile("scripts/ansible_inventory.py")
		if err != nil {
			ar := result{fail.Wrap(err, "%s failed to load template 'ansible_inventory.py'", prerr)}
			chRes <- ar
			return
		}

		// --------- Build ansible inventory --------------
		fileName := fmt.Sprintf("cluster-inventory-%s.py", params["Clustername"])
		tmplCmd, err := template.Parse(fileName, string(tmplString))
		if err != nil {
			ar := result{fail.Wrap(err, "%s failed to parse template 'ansible_inventory.py'", prerr)}
			chRes <- ar
			return
		}

		dataBuffer := bytes.NewBufferString("")
		err = tmplCmd.Execute(dataBuffer, params)
		if err != nil {
			ar := result{fail.Wrap(err, "%s failed to execute template 'ansible_inventory.py'", prerr)}
			chRes <- ar
			return
		}

		// --------- Upload file for each master and test it (parallelized) --------------
		tg := new(errgroup.Group)
		for master := range masters {
			master := master
			logrus.WithContext(ctx).Infof("%s Update master %s", prerr, masters[master].GetName())

			tg.Go(func() error {
				_, err := instance.taskRegenerateClusterInventory(ctx, taskRegenerateClusterInventoryParameters{
					ctx:           ctx,
					master:        masters[master],
					inventoryData: dataBuffer.String(),
					clusterName:   params["Clustername"].(string),
				})
				return err
			})
		}

		xerr = fail.ConvertError(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			if withTimeout(xerr) {
				logrus.WithContext(ctx).Warnf("%s Timeouts ansible update inventory", prerr)
			}
			ar := result{xerr}
			chRes <- ar
			return
		}

		logrus.WithContext(ctx).Debugf("%s update inventory successful", prerr)

		ar := result{nil}
		chRes <- ar

	}()
	select {
	case res := <-chRes:
		return res.rErr
	case <-ctx.Done():
		return fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return fail.ConvertError(inctx.Err())
	}
}

func (instance *ClassicCluster) isFeatureDisabled(ctx context.Context, name string) (bool, fail.Error) {
	var disabled map[string]struct{}
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			disabled = featuresV1.Disabled
			return nil
		})
	})
	if xerr != nil {
		return false, xerr
	}

	_, ok := disabled[name]
	if ok {
		return true, nil
	}
	return false, nil
}

func (instance *ClassicCluster) isFeatureInstalled(ctx context.Context, name string) (bool, fail.Error) {
	var installed map[string]*propertiesv1.ClusterInstalledFeature
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			installed = featuresV1.Installed
			return nil
		})
	})
	if xerr != nil {
		return false, xerr
	}

	_, ok := installed[name]
	if ok {
		return true, nil
	}
	return false, nil
}

// configureNodesFromList configures nodes from a list
func (instance *ClassicCluster) configureNodesFromList(ctx context.Context, name string, nodes []*propertiesv3.ClusterNode, parameters data.Map) (ferr fail.Error) {
	var disabled map[string]struct{}
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			disabled = featuresV1.Disabled
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	length := len(nodes)
	if length > 0 {
		eg := new(errgroup.Group)
		for i := 0; i < length; i++ {
			captured := i
			eg.Go(func() error {
				_, xerr := instance.taskConfigureNode(ctx, taskConfigureNodeParameters{
					node:        nodes[captured],
					variables:   parameters,
					clusterName: name,
					request: abstract.ClusterRequest{ // FIXME: This requires another hack
						DisabledDefaultFeatures: disabled,
					},
				})
				return xerr
			})
		}

		xerr := fail.ConvertError(eg.Wait())
		if xerr != nil {
			return xerr
		}
	}

	return nil
}

// joinNodesFromList makes nodes from a list join the ClassicCluster
func (instance *ClassicCluster) joinNodesFromList(ctx context.Context, nodes []*propertiesv3.ClusterNode) fail.Error {
	logrus.WithContext(ctx).Debugf("Joining nodes to ClassicCluster...")

	// Joins to ClassicCluster is done sequentially, experience shows too many join at the same time
	// may fail (depending on the ClassicCluster Flavor)
	makers, xerr := instance.getMaker(ctx)
	if xerr != nil {
		return xerr
	}
	if makers.JoinNodeToCluster != nil {
		for _, v := range nodes {
			hostInstance, xerr := LoadHost(ctx, instance.Service(), v.ID)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = makers.JoinNodeToCluster(ctx, instance, hostInstance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// leaveNodesFromList makes nodes from a list leave the ClassicCluster
func (instance *ClassicCluster) leaveNodesFromList(ctx context.Context, hosts []resources.Host, selectedMaster resources.Host) (ferr fail.Error) {
	logrus.WithContext(ctx).Debugf("Instructing nodes to leave ClassicCluster...")

	// Un-joins from ClassicCluster are done sequentially, experience shows too many (un)join at the same time
	// may fail (depending on the ClassicCluster Flavor)
	makers, xerr := instance.getMaker(ctx)
	if xerr != nil {
		return xerr
	}
	if makers.LeaveNodeFromCluster != nil {
		var xerr fail.Error
		for _, node := range hosts {
			xerr = makers.LeaveNodeFromCluster(ctx, instance, node, selectedMaster)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}

	return nil
}

// BuildHostname builds a unique hostname in the ClassicCluster
func (instance *ClassicCluster) buildHostname(ctx context.Context, core string, nodeType clusternodetype.Enum) (_ string, _ fail.Error) {
	var index int
	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(
			clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
				if !ok {
					return fail.InconsistentError(
						"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}
				switch nodeType {
				case clusternodetype.Node:
					nodesV3.PrivateLastIndex++
					index = nodesV3.PrivateLastIndex
				case clusternodetype.Master:
					nodesV3.MasterLastIndex++
					index = nodesV3.MasterLastIndex
				}
				return nil
			},
		)
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return "", xerr
	}
	return instance.GetName() + "-" + core + "-" + strconv.Itoa(index), nil
}

// ToProtocol converts instance to protocol.ClusterResponse message
func (instance *ClassicCluster) ToProtocol(ctx context.Context) (_ *protocol.ClusterResponse, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	out := &protocol.ClusterResponse{}
	xerr = instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		ci, ok := clonable.(*abstract.ClusterIdentity)
		if !ok {
			return fail.InconsistentError("'*abstract.ClusterIdentity' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		out.Identity = converters.ClusterIdentityFromAbstractToProtocol(*ci)

		innerXErr := props.Inspect(clusterproperty.ControlPlaneV1, func(clonable data.Clonable) fail.Error {
			controlplaneV1, ok := clonable.(*propertiesv1.ClusterControlplane)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterControlplane' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.Controlplane = converters.ClusterControlplaneFromPropertyToProtocol(*controlplaneV1)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.CompositeV1, func(clonable data.Clonable) fail.Error {
			compositeV1, ok := clonable.(*propertiesv1.ClusterComposite)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterComposite' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.Composite = converters.ClusterCompositeFromPropertyToProtocol(*compositeV1)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		if props.Lookup(clusterproperty.DefaultsV3) {
			innerXErr = props.Inspect(clusterproperty.DefaultsV3, func(clonable data.Clonable) fail.Error {
				defaultsV3, ok := clonable.(*propertiesv3.ClusterDefaults)
				if !ok {
					return fail.InconsistentError("'*propertiesv3.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				out.Defaults = converters.ClusterDefaultsFromPropertyV3ToProtocol(*defaultsV3)
				return nil
			})
		} else {
			innerXErr = props.Inspect(clusterproperty.DefaultsV2, func(clonable data.Clonable) fail.Error {
				defaultsV2, ok := clonable.(*propertiesv2.ClusterDefaults)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.ClusterDefaults' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				out.Defaults = converters.ClusterDefaultsFromPropertyV2ToProtocol(*defaultsV2)
				return nil
			})
		}
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.NetworkV3, func(clonable data.Clonable) fail.Error {
			networkV3, ok := clonable.(*propertiesv3.ClusterNetwork)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNetwork' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.Network = converters.ClusterNetworkFromPropertyToProtocol(*networkV3)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(clusterproperty.NodesV3, func(clonable data.Clonable) fail.Error {
			nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
			if !ok {
				return fail.InconsistentError("'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			convertClusterNodes := func(in []uint) []*protocol.Host {
				list := make([]*protocol.Host, 0, len(in))
				for _, v := range in {
					if node, found := nodesV3.ByNumericalID[v]; found {
						ph := &protocol.Host{
							Name:      node.Name,
							Id:        node.ID,
							PublicIp:  node.PublicIP,
							PrivateIp: node.PrivateIP,
						}
						list = append(list, ph)
					}
				}
				return list
			}

			out.Nodes = convertClusterNodes(nodesV3.PrivateNodes)
			out.Masters = convertClusterNodes(nodesV3.Masters)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(
			clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
				featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				out.InstalledFeatures, out.DisabledFeatures = converters.ClusterFeaturesFromPropertyToProtocol(*featuresV1)
				return nil
			},
		)
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			out.State = protocol.ClusterState(stateV1.State)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return out, nil
}

// Shrink reduces cluster size by 'count' nodes
func (instance *ClassicCluster) Shrink(ctx context.Context, cluName string, count uint) (_ []*propertiesv3.ClusterNode, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if count == 0 {
		return nil, fail.InvalidParameterError("count", "cannot be 0")
	}

	defer func() {
		// drop the cache when we are done shrinking the cluster
		if ka, err := instance.Service().GetCache(context.Background()); err == nil {
			if ka != nil {
				_ = ka.Clear(context.Background())
			}
		}
	}()

	xerr := instance.beingRemoved(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	var (
		removedNodes []*propertiesv3.ClusterNode
		errors       []error
		toRemove     []uint
	)

	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(
			clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
				nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
				if !ok {
					return fail.InconsistentError(
						"'*propertiesv3.ClusterNodes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}

				length := uint(len(nodesV3.PrivateNodes))
				if length < count {
					return fail.InvalidRequestError(
						"cannot shrink by %d node%s, only %d node%s available", count, strprocess.Plural(count),
						length, strprocess.Plural(length),
					)
				}

				first := length - count
				toRemove = nodesV3.PrivateNodes[first:]
				nodesV3.PrivateNodes = nodesV3.PrivateNodes[:first]
				for _, v := range toRemove {
					if node, ok := nodesV3.ByNumericalID[v]; ok {
						removedNodes = append(removedNodes, node)
						delete(nodesV3.ByNumericalID, v)
						delete(nodesV3.PrivateNodeByID, node.ID)
						delete(nodesV3.PrivateNodeByName, node.Name)
					}
				}
				return nil
			},
		)
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return nil, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := instance.Alter(cleanupContextFrom(ctx), func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Alter(
					clusterproperty.NodesV3, func(clonable data.Clonable) (innerXErr fail.Error) {
						nodesV3, ok := clonable.(*propertiesv3.ClusterNodes)
						if !ok {
							return fail.InconsistentError(
								"'*propertiesv3.ClusterNodes' expected, '%s' provided",
								reflect.TypeOf(clonable).String(),
							)
						}

						nodesV3.PrivateNodes = append(nodesV3.PrivateNodes, toRemove...)
						for _, v := range removedNodes {
							nodesV3.ByNumericalID[v.NumericalID] = v
							nodesV3.PrivateNodeByName[v.Name] = v.NumericalID
							nodesV3.PrivateNodeByID[v.ID] = v.NumericalID
						}
						return nil
					},
				)
			})
			if derr != nil {
				_ = ferr.AddConsequence(
					fail.Wrap(
						derr, "cleaning up on %s, failed to restore ClassicCluster nodes metadata", ActionFromError(ferr),
					),
				)
			}
		}
	}()

	if len(removedNodes) > 0 {
		tg := new(errgroup.Group)

		selectedMaster, xerr := instance.unsafeFindAvailableMaster(ctx)
		if xerr != nil {
			return nil, xerr
		}

		for _, v := range removedNodes {
			v := v
			tg.Go(func() error {
				_, err := instance.taskDeleteNodeWithCtx(cleanupContextFrom(ctx), taskDeleteNodeParameters{node: v, master: selectedMaster.(*Host), clusterName: cluName})
				return err
			})
		}
		xerr = fail.ConvertError(tg.Wait())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			errors = append(errors, xerr)
		}
	}
	if len(errors) > 0 {
		return nil, fail.NewErrorList(errors)
	}
	xerr = instance.regenerateClusterInventory(ctx)
	if xerr != nil {
		return nil, xerr
	}

	return removedNodes, nil
}

// IsFeatureInstalled tells if a Feature identified by name is installed on ClassicCluster, using only metadata
func (instance *ClassicCluster) IsFeatureInstalled(inctx context.Context, name string) (_ bool, _ fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  bool
		rErr fail.Error
	}

	chRes := make(chan result)

	go func() {
		defer close(chRes)
		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			found := false
			if valid.IsNil(instance) {
				ar := result{false, fail.InvalidInstanceError()}
				return ar, ar.rErr
			}
			if ctx == nil {
				ar := result{false, fail.InvalidParameterCannotBeNilError("ctx")}
				return ar, ar.rErr
			}
			if name = strings.TrimSpace(name); name == "" {
				ar := result{false, fail.InvalidParameterCannotBeEmptyStringError("name")}
				return ar, ar.rErr
			}

			xerr := instance.beingRemoved(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{false, xerr}
				return ar, ar.rErr
			}

			xerr = instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
					featuresV1, ok := clonable.(*propertiesv1.ClusterFeatures)
					if !ok {
						return fail.InconsistentError("`propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					_, found = featuresV1.Installed[name]
					return nil
				})
			})

			ar := result{found, xerr}
			return ar, ar.rErr
		}() // nolint
		chRes <- gres
	}()
	select {
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		<-chRes
		return false, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		<-chRes
		return false, fail.ConvertError(inctx.Err())
	}
}

func (instance *ClassicCluster) changeStatusTo(ctx context.Context, stat clusterstate.Enum) fail.Error {
	// Mark ClassicCluster as state Degraded
	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(clusterproperty.StateV1, func(clonable data.Clonable) fail.Error {
			stateV1, ok := clonable.(*propertiesv1.ClusterState)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.ClusterState' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			stateV1.State = stat
			instance.state = stat
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		xerr = fail.Wrap(xerr, callstack.WhereIsThis())
		return xerr
	}
	return nil
}
