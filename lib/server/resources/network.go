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
	"github.com/CS-SI/SafeScale/lib/server/resources/abstracts"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
)

// Network links Object Storage folder and Network
type Network interface {
	Metadata
	data.Identifyable

	Browse(task concurrency.Task, callback func(*abstracts.Network) error) error                                             // Browse ...
	Create(task concurrency.Task, req abstracts.NetworkRequest, gwname string, gwSizing *abstracts.SizingRequirements) error // Create creates a network
	AttachHost(task concurrency.Task, host Host) error                                                                       // AttachHost links host ID to the network
	DetachHost(task concurrency.Task, hostID string) error                                                                   // DetachHost unlinks host ID from network
	ListHosts(task concurrency.Task) ([]Host, error)                                                                         // ListHosts returns the list of Host attached to the network (excluding gateway)
	Gateway(task concurrency.Task, primary bool) (Host, error)                                                               // Gateway returns the gateway related to network
	DefaultRouteIP(task concurrency.Task) (string, error)
	EndpointIP(task concurrency.Task) (string, error)
}
