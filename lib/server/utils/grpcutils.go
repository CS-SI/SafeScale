/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"fmt"
	pb "github.com/CS-SI/SafeScale/lib"
	"google.golang.org/grpc"
	"log"
	"strings"
)

// GetConnection returns a connection to GRPC server
func GetConnection(host string, port int) *grpc.ClientConn {
	address := fmt.Sprintf("%s:%d", host, port)

	// Set up a connection to the server.
	conn, err := grpc.Dial(address, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to connect to safescaled (%s:%d): %v", host, port, err)
	}
	return conn
}

// GetReference return a reference from the name or id given in the pb.Reference
func GetReference(in *pb.Reference) string {
	var ref string
	name := in.GetName()
	if strings.TrimSpace(name) != "" {
		ref = name
	}
	id := in.GetId()
	if strings.TrimSpace(id) != "" {
		ref = id
	}
	return ref
}
