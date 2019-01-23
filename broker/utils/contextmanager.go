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
	"fmt"
	"time"
)

var grpcCancelContext context.Context
var grpcCancelFunc func()

// GetCancelContext ...
func GetCancelContext() context.Context {
	if grpcCancelContext == nil {
		grpcCancelContext, grpcCancelFunc = context.WithCancel(context.Background())
	}
	return grpcCancelContext
}

// GetTimeoutContext return a context for grpc commands
func GetTimeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	// Contact the server and print out its response.
	return context.WithTimeout(GetCancelContext(), timeout)
}

// Cancel ...
func Cancel() {
	grpcCancelFunc()
}

// TaskStatus ...
func TaskStatus(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return fmt.Errorf("Task canceled by broker")
	default:
		return nil
	}
}
