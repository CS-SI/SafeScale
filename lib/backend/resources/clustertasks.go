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

// // trxDeleteMaster deletes one master
// func (clusterTrx *clusterTransactionImpl) deleteMaster(inctx context.Context, node *propertiesv3.ClusterNode) (_ interface{}, _ fail.Error) {
// 	if valid.IsNil(clusterTrx) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if inctx == nil {
// 		return nil, fail.InvalidParameterCannotBeNilError("inctx")
// 	}
// 	if node == nil {
// 		return nil, fail.InvalidParameterCannotBeNilError("node")
// 	}
// 	if node.ID == "" && node.Name == "" {
// 		return nil, fail.InvalidParameterError("node.ID|node.Name", "ID or Name must be set")
// 	}
// 	nodeRef := node.Name
// 	if nodeRef == "" {
// 		nodeRef = node.ID
// 	}
//
// 	ctx, cancel := context.WithCancel(inctx)
// 	defer cancel()
//
// 	if oldKey := ctx.Value("ID"); oldKey != nil {
// 		ctx = context.WithValue(ctx, "ID", fmt.Sprintf("%s/Delete/master/%s", oldKey, nodeRef)) // nolint
// 	}
//
// 	type localresult struct {
// 		rTr  interface{}
// 		rErr fail.Error
// 	}
// 	chRes := make(chan localresult)
// 	go func() {
// 		defer close(chRes)
// 		gres, _ := func() (_ localresult, ferr fail.Error) {
// 			defer fail.OnPanic(&ferr)
//
// 			svc, xerr := clusterTrx.Service()
// 			if xerr != nil {
// 				return localresult{nil, xerr}, xerr
// 			}
//
// 			logrus.WithContext(ctx).Debugf("Deleting Master %s", nodeRef)
// 			trueMasterID := node.ID
// 			xerr = clusterTrx.deleteMaster(ctx, trueMasterID)
// 			xerr = debug.InjectPlannedFail(xerr)
// 			if xerr != nil {
// 				switch xerr.(type) {
// 				case *fail.ErrNotFound:
// 				default:
// 					return localresult{nil, xerr}, xerr
// 				}
// 			}
//
// 			// kill zombies (instances without metadata)
// 			_ = svc.DeleteHost(ctx, trueMasterID)
//
// 			logrus.WithContext(ctx).Debugf("Successfully deleted Master '%s'", node.Name)
// 			return localresult{nil, nil}, nil
// 		}()
// 		chRes <- gres
// 	}()
//
// 	select {
// 	case res := <-chRes:
// 		return res.rTr, res.rErr
// 	case <-ctx.Done():
// 		return nil, fail.Wrap(ctx.Err())
// 	case <-inctx.Done():
// 		cancel()
// 		<-chRes
// 		return nil, fail.Wrap(inctx.Err())
// 	}
// }

// // updateClusterInventoryMaster task to update a Host (master) ansible inventory
// func (clusterTrx *clusterTransactionImpl) updateClusterInventoryMaster(inctx context.Context, params any) (_ any, _ fail.Error) {
// 	if valid.IsNil(clusterTrx) {
// 		return nil, fail.InvalidInstanceError()
// 	}
// 	if inctx == nil {
// 		return nil, fail.InvalidParameterCannotBeNilError("inctx")
// 	}
// 	// Convert and validate params
// 	casted, ok := params.(taskUpdateClusterInventoryMasterParameters)
// 	if !ok {
// 		return nil, fail.InvalidParameterError("params", "must be a 'taskUpdateClusterInventoryMasterParameters'")
// 	}
//
// 	ctx, cancel := context.WithCancel(inctx)
// 	defer cancel()
//
// 	type localresult struct {
// 		rTr  interface{}
// 		rErr fail.Error
// 	}
//
// 	chRes := make(chan localresult)
// 	go func() {
// 		defer close(chRes)
// 		gres, _ := func() (_ localresult, ferr fail.Error) {
// 			defer fail.OnPanic(&ferr)
//
// 			xerr := clusterTrx.updateClusterInventoryMaster(ctx, casted)
// 			return localresult{nil, xerr}, xerr
// 		}()
// 		chRes <- gres
// 	}()
//
// 	select {
// 	case res := <-chRes:
// 		return res.rTr, res.rErr
// 	case <-ctx.Done():
// 		return nil, fail.Wrap(ctx.Err())
// 	case <-inctx.Done():
// 		cancel()
// 		<-chRes
// 		return nil, fail.Wrap(inctx.Err())
// 	}
// }
