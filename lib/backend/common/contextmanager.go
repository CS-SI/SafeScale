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

package common

import (
	"context"
	"sync"

	uuid "github.com/gofrs/uuid"
	"google.golang.org/grpc/metadata"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var (
	clientRPCUUID       uuid.UUID
	uuidSet             bool
	mutexContextManager sync.Mutex
)

// --------------------- CLIENT ---------------------------------

// ContextForGRPC ...
func ContextForGRPC(storeUUID bool) (context.Context, fail.Error) {
	clientContext := context.Background()
	aUUID, xerr := generateUUID(storeUUID)
	if xerr != nil {
		return nil, xerr
	}

	clientContext = metadata.AppendToOutgoingContext(clientContext, "UUID", aUUID)
	return clientContext, nil
}

// VPL: not used
// ContextForGRPCWithTimeout return a context for gRPC commands
// func ContextForGRPCWithTimeout(parentCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, fail.Error) {
// 	if parentCtx != nil { // nolint
// 		ctx, cancel := context.WithTimeout(parentCtx, timeout)
// 		return ctx, cancel, nil
// 	}
//
// 	aContext, xerr := ContextForGRPC(true)
// 	if xerr != nil {
// 		return nil, nil, xerr
// 	}
//
// 	ctx, cancel := context.WithTimeout(aContext, timeout)
// 	return ctx, cancel, nil
// }

// GetUUID ...
func GetUUID() string {
	mutexContextManager.Lock()
	defer mutexContextManager.Unlock()

	return clientRPCUUID.String()
}

// generateUUID ...
func generateUUID(store bool) (string, fail.Error) {
	mutexContextManager.Lock()
	defer mutexContextManager.Unlock()

	newUUID, err := uuid.NewV4()
	if err != nil {
		return "", fail.ConvertError(err)
	}

	if store {
		uuidSet = true
		clientRPCUUID = newUUID
	}
	return newUUID.String(), nil
}
