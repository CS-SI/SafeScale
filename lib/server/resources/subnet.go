/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetstate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Subnet links Object Storage folder and Network
type Subnet interface {
	Metadata
	data.Identifiable
	data.NullValue

	BindHost(concurrency.Task, Host) fail.Error                                                                                    // links host ID to the subnet
	BindSecurityGroup(concurrency.Task, SecurityGroup, SecurityGroupActivation) fail.Error                                         // binds a security group to the subnet
	Browse(task concurrency.Task, callback func(*abstract.Subnet) fail.Error) fail.Error                                           // ...
	Create(task concurrency.Task, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements) fail.Error // creates a subnet
	DisableSecurityGroup(concurrency.Task, SecurityGroup) fail.Error                                                               // disables a binded security group on host
	EnableSecurityGroup(concurrency.Task, SecurityGroup) fail.Error                                                                // enables a binded security group on host
	GetGateway(task concurrency.Task, primary bool) (Host, fail.Error)                                                             // returns the gateway related to subnet
	GetDefaultRouteIP(concurrency.Task) (string, fail.Error)                                                                       // returns the IP of the default route of the subnet
	GetEndpointIP(concurrency.Task) (string, fail.Error)                                                                           // returns the IP address corresponding to the default route
	GetState(concurrency.Task) (subnetstate.Enum, fail.Error)                                                                      // gives the current state of the subnet
	HasVirtualIP(concurrency.Task) bool                                                                                            // tells if the subnet is using a VIP a default route
	InspectNetwork(concurrency.Task) (Network, fail.Error)                                                                         // returns the instance of the parent Network of the Subnet
	ListHosts(concurrency.Task) ([]Host, fail.Error)                                                                               // returns the list of Host attached to the subnet (excluding gateway)
	ListSecurityGroups(task concurrency.Task, state securitygroupstate.Enum) ([]*propertiesv1.SecurityGroupBond, fail.Error)       // lists the security groups bound to the subnet
	ToProtocol(concurrency.Task) (*protocol.Subnet, fail.Error)                                                                    // converts the subnet to protobuf message
	UnbindHost(task concurrency.Task, hostID string) fail.Error                                                                    // unlinks host ID from subnet
	UnbindSecurityGroup(concurrency.Task, SecurityGroup) fail.Error                                                                // unbinds a security group from the subnet
}
