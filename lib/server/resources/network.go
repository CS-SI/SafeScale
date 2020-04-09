/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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
)

// Network links Object Storage folder and Network
type Network interface {
	Metadata
	data.Identifyable
	data.NullValue

	Browse(task concurrency.Task, callback func(*abstract.Network) error) error                                                // ...
	Create(task concurrency.Task, req abstract.NetworkRequest, gwname string, gwSizing *abstract.HostSizingRequirements) error // creates a network
	AttachHost(task concurrency.Task, host Host) error                                                                         // links host ID to the network
	DetachHost(task concurrency.Task, hostID string) error                                                                     // unlinks host ID from network
	ListHosts(task concurrency.Task) ([]Host, error)                                                                           // returns the list of Host attached to the network (excluding gateway)
	GetGateway(task concurrency.Task, primary bool) (Host, error)                                                              // returns the gateway related to network
	GetDefaultRouteIP(task concurrency.Task) (string, error)                                                                   // returns the IP of the default route of the network
	GetEndpointIP(task concurrency.Task) (string, error)                                                                       // returns the IP address corresponding to the default route
	SafeGetGateway(task concurrency.Task, primary bool) Host                                                                   // returns the gateway related to network
	SafeGetDefaultRouteIP(task concurrency.Task) string                                                                        // returns the IP of the default route of the network
	SafeGetEndpointIP(task concurrency.Task) string                                                                            // returns the IP address corresponding to the default route
	HasVirtualIP(task concurrency.Task) bool                                                                                   // tells if the network is using a VIP a default route
	ToProtocol(task concurrency.Task) (*protocol.Network, error)
}
