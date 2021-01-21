/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"log"
	"strings"

	"google.golang.org/grpc"

	"github.com/CS-SI/SafeScale/lib/protocol"
)

// GetConnection returns a connection to GRPC server
func GetConnection(server string) *grpc.ClientConn {
	// Set up a connection to the server.
	conn, err := grpc.Dial(server, grpc.WithInsecure())
	if err != nil {
		log.Fatalf("failed to connect to safescaled (%s): %v", server, err)
	}
	return conn
}

// GetReference return a reference from the name or id given in the protocol.Reference
// returns value and its display representation (without '' if id, with '' if name)
func GetReference(in *protocol.Reference) (string, string) {
	var ref, refLabel string
	name := in.GetName()
	if strings.TrimSpace(name) != "" {
		ref = name
		refLabel = "'" + ref + "'"
	}
	id := in.GetId()
	if strings.TrimSpace(id) != "" {
		ref = id
		refLabel = id
	}
	return ref, refLabel
}
