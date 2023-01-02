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

package utils

import (
	"context"
	"sync"
	"time"

	uuid "github.com/gofrs/uuid"
	"google.golang.org/grpc/metadata"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var clientRPCUUID uuid.UUID
var uuidSet bool
var mutexContextManager sync.Mutex

// --------------------- CLIENT ---------------------------------

// GetContext ...
func GetContext(storeUUID bool) (context.Context, fail.Error) {
	clientContext := context.Background()
	aUUID, xerr := generateUUID(storeUUID)
	if xerr != nil {
		return nil, xerr
	}
	clientContext = metadata.AppendToOutgoingContext(clientContext, "UUID", aUUID)
	return clientContext, nil
}

// GetTimeoutContext return a context for gRPC commands
func GetTimeoutContext(parentCtx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, fail.Error) {
	if parentCtx != context.TODO() { // nolint
		ctx, cancel := context.WithTimeout(parentCtx, timeout)
		return ctx, cancel, nil
	}

	aContext, xerr := GetContext(true)
	if xerr != nil {
		return nil, nil, xerr
	}

	ctx, cancel := context.WithTimeout(aContext, timeout)
	return ctx, cancel, nil
}

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
