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
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	pb "github.com/CS-SI/SafeScale/broker"
	"google.golang.org/grpc"
)

const (
	// TimeoutCtxDefault default timeout for grpc command invocation
	TimeoutCtxDefault = 1 * time.Minute
	// TimeoutCtxHost timeout for grpc command relative to host creation
	TimeoutCtxHost = 5 * time.Minute
)

// GetTimeoutCtxDefault ...
func GetTimeoutCtxDefault() time.Duration {
	sshDefaultTimeout := int(TimeoutCtxDefault.Minutes())

	if sshDefaultTimeoutCandidate := os.Getenv("CTX_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		num, err := strconv.Atoi(sshDefaultTimeoutCandidate)
		if err == nil {
			sshDefaultTimeout = num
		}
	}

	return time.Duration(sshDefaultTimeout) * time.Minute
}

// GetTimeoutCtxHost ...
func GetTimeoutCtxHost() time.Duration {
	sshDefaultTimeout := int(TimeoutCtxHost.Minutes())

	if sshDefaultTimeoutCandidate := os.Getenv("CTX_HOST_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		num, err := strconv.Atoi(sshDefaultTimeoutCandidate)
		if err == nil {
			sshDefaultTimeout = num
		}
	}

	return time.Duration(sshDefaultTimeout) * time.Minute
}

// GetConnection returns a connection to GRPC server
func GetConnection(host string, port int) *grpc.ClientConn {
	address := fmt.Sprintf("%s:%d", host, port)

	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("Failed to connect to brokerd (%s:%d): %v", host, port, err)
	}
	return conn
}

// GetContext return a context for grpc commands
func GetContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	// Contact the server and print out its response.
	return context.WithTimeout(context.Background(), timeout)
}

// GetReference return a reference from the name or id given in the pb.Reference
func GetReference(in *pb.Reference) string {
	var ref string
	name := in.GetName()
	if strings.TrimSpace(name) != "" {
		ref = name
	}
	id := in.GetID()
	if strings.TrimSpace(id) != "" {
		ref = id
	}
	return ref
}
