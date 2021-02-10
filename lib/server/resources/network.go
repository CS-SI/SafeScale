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

// Package resources ...
package resources

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Network links Object Storage folder and Network
type Network interface {
	Metadata
	data.Identifiable

	Browse(task concurrency.Task, callback func(*abstract.Network) fail.Error) fail.Error // ...
	Create(task concurrency.Task, req abstract.NetworkRequest) fail.Error                 // creates a network
	InspectSubnet(task concurrency.Task, subnetRef string) (Subnet, fail.Error)           // returns the Subnet instance corresponding to subnet reference (ID or name) provided
	ToProtocol(task concurrency.Task) (*protocol.Network, fail.Error)                     // converts the network to protobuf message
}
