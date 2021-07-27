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
	"context"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Network links Object Storage folder and Network
type Network interface {
	Metadata
	data.Identifiable
	observer.Observable
	cache.Cacheable

	AbandonSubnet(ctx context.Context, subnetID string) fail.Error                      // used to detach a Subnet from the Network
	AdoptSubnet(ctx context.Context, subnet Subnet) fail.Error                          // used to attach a Subnet to the Network
	Browse(ctx context.Context, callback func(*abstract.Network) fail.Error) fail.Error // call the callback for each entry of the metadata folder of Networks
	Create(ctx context.Context, req abstract.NetworkRequest) fail.Error                 // creates a Network
	Delete(ctx context.Context) fail.Error
	Import(ctx context.Context, ref string) fail.Error
	InspectSubnet(subnetRef string) (Subnet, fail.Error) // returns the Subnet instance corresponding to Subnet reference (ID or name) provided (if Subnet is attached to the Network)
	ToProtocol() (*protocol.Network, fail.Error)        // converts the network to protobuf message
}
