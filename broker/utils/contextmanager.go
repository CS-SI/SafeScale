/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	uuid "github.com/satori/go.uuid"
	"google.golang.org/grpc/metadata"
)

var client_RPCUUID uuid.UUID
var uuid_set bool
var mutex_contextManager sync.Mutex

//--------------------- CLIENT ---------------------------------

// GetContext ...
func GetContext(storeUUID bool) context.Context {
	clientContext := context.Background()
	clientContext = metadata.AppendToOutgoingContext(clientContext, "UUID", generateUUID(storeUUID))
	return clientContext
}

// GetTimeoutContext return a context for grpc commands
func GetTimeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	// Contact the server and print out its response.
	return context.WithTimeout(GetContext(true), timeout)
}

//GetUUID ...
func GetUUID() string {
	mutex_contextManager.Lock()
	defer mutex_contextManager.Unlock()
	return client_RPCUUID.String()
}

// generateUUID ...
func generateUUID(store bool) string {
	mutex_contextManager.Lock()
	defer mutex_contextManager.Unlock()
	uuid, err := uuid.NewV4()
	if err != nil {
		panic("Failed to generate UUID")
	}
	if store {
		uuid_set = true
		client_RPCUUID = uuid
	}
	return uuid.String()
}
