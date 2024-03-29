/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetstate"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/resources.Subnet -o mocks/mock_subnet.go

// Subnet links Object Storage folder and Network
type Subnet interface {
	Metadata
	data.Identifiable
	Consistent

	GetName() string
	DetachHost(ctx context.Context, hostID string) fail.Error                                                                                       // unlinks host ID from subnet
	AttachHost(context.Context, Host) fail.Error                                                                                                    // links Host to the Subnet
	BindSecurityGroup(context.Context, SecurityGroup, SecurityGroupActivation) fail.Error                                                           // binds a Security Group to the Subnet
	Browse(ctx context.Context, callback func(*abstract.Subnet) fail.Error) fail.Error                                                              // ...
	Create(ctx context.Context, req abstract.SubnetRequest, gwname string, gwSizing *abstract.HostSizingRequirements, extra interface{}) fail.Error // creates a Subnet
	Delete(ctx context.Context) fail.Error                                                                                                          // deletes a Subnet
	DisableSecurityGroup(context.Context, SecurityGroup) fail.Error                                                                                 // disables a bound Security Group on Subnet
	EnableSecurityGroup(context.Context, SecurityGroup) fail.Error                                                                                  // enables a bound Security Group on Subnet
	GetGatewayPublicIP(ctx context.Context, primary bool) (string, fail.Error)                                                                      // returns the gateway related to Subnet
	GetGatewayPublicIPs(ctx context.Context) ([]string, fail.Error)                                                                                 // returns the gateway IPs of the Subnet
	GetDefaultRouteIP(ctx context.Context) (string, fail.Error)                                                                                     // returns the private IP of the default route of the Subnet
	GetEndpointIP(ctx context.Context) (string, fail.Error)                                                                                         // returns the public IP to reach the Subnet from Internet
	GetCIDR(ctx context.Context) (string, fail.Error)                                                                                               // return the CIDR
	GetState(ctx context.Context) (subnetstate.Enum, fail.Error)                                                                                    // gives the current state of the Subnet
	HasVirtualIP(ctx context.Context) (bool, fail.Error)                                                                                            // tells if the Subnet is using a VIP as default route
	InspectGateway(ctx context.Context, primary bool) (Host, fail.Error)                                                                            // returns the gateway related to Subnet
	InspectGatewaySecurityGroup(ctx context.Context) (SecurityGroup, fail.Error)                                                                    // returns the SecurityGroup responsible of network security on Gateway
	InspectInternalSecurityGroup(ctx context.Context) (SecurityGroup, fail.Error)                                                                   // returns the SecurityGroup responsible of internal network security
	InspectPublicIPSecurityGroup(ctx context.Context) (SecurityGroup, fail.Error)                                                                   // returns the SecurityGroup responsible of Hosts with Public IP (excluding gateways)
	InspectNetwork(ctx context.Context) (Network, fail.Error)                                                                                       // returns the instance of the parent Network of the Subnet
	ListHosts(ctx context.Context) ([]Host, fail.Error)                                                                                             // returns the list of Host attached to the subnet (excluding gateway)
	ListSecurityGroups(ctx context.Context, state securitygroupstate.Enum) ([]*propertiesv1.SecurityGroupBond, fail.Error)                          // lists the security groups bound to the subnet
	ToProtocol(ctx context.Context) (*protocol.Subnet, fail.Error)                                                                                  // converts the subnet to protobuf message
	UnbindSecurityGroup(context.Context, SecurityGroup) fail.Error                                                                                  // unbinds a security group from the subnet
}
