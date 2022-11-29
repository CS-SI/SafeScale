/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package resources

import (
	"context"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// SecurityGroupActivation represents activation state of a Security Group
type SecurityGroupActivation bool

const (
	// SecurityGroupEnable means the security group is enabled
	SecurityGroupEnable SecurityGroupActivation = true
	// SecurityGroupDisable means the security group is disabled
	SecurityGroupDisable SecurityGroupActivation = false
)

type SecurityGroupMark bool

const (
	MarkSecurityGroupAsDefault      = true  // mark the Security Group as a default
	MarkSecurityGroupAsSupplemental = false // mark the Security Group as supplemental
	KeepCurrentSecurityGroupMark    = false // Do not change current Security Group mark
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/resources.SecurityGroup -o mocks/mock_securitygroup.go

// SecurityGroup links Object Storage folder and SecurityGroup
type SecurityGroup interface {
	Metadata
	data.Identifiable
	Consistent

	GetName() string
	AddRule(context.Context, *abstract.SecurityGroupRule) fail.Error                                               // returns true if the host is member of a cluster
	AddRules(context.Context, abstract.SecurityGroupRules) fail.Error                                              // returns true if the host is member of a cluster
	BindToHost(context.Context, Host, SecurityGroupActivation, SecurityGroupMark) fail.Error                       // binds a security group to a host
	BindToSubnet(context.Context, Subnet, SecurityGroupActivation, SecurityGroupMark) fail.Error                   // binds a security group to a network
	Browse(ctx context.Context, callback func(*abstract.SecurityGroup) fail.Error) fail.Error                      // browses the metadata folder of Security Groups and call the callback on each entry
	Clear(ctx context.Context) fail.Error                                                                          // removes rules from the security group
	Create(ctx context.Context, networkID, name, description string, rules abstract.SecurityGroupRules) fail.Error // creates a new host and its metadata
	Delete(ctx context.Context, force bool) fail.Error                                                             // deletes the Security Group
	DeleteRule(ctx context.Context, rule *abstract.SecurityGroupRule) fail.Error                                   // deletes a rule from a Security Group
	GetBoundHosts(ctx context.Context) ([]*propertiesv1.SecurityGroupBond, fail.Error)                             // returns a slice of bonds corresponding to hosts bound to the security group
	GetBoundSubnets(ctx context.Context) ([]*propertiesv1.SecurityGroupBond, fail.Error)                           // returns a slice of bonds corresponding to networks bound to the security group
	Reset(ctx context.Context) fail.Error                                                                          // resets the rules of the security group from the ones registered in metadata
	ToProtocol(ctx context.Context) (*protocol.SecurityGroupResponse, fail.Error)                                  // converts a SecurityGroup to equivalent gRPC message
	UnbindFromHost(context.Context, Host) fail.Error                                                               // unbinds a Security Group from Host
	UnbindFromHostByReference(context.Context, string) fail.Error                                                  // unbinds a Security Group from Host
	UnbindFromSubnet(context.Context, Subnet) fail.Error                                                           // unbinds a Security Group from Subnet
	UnbindFromSubnetByReference(context.Context, string) fail.Error                                                // unbinds a Security group from a Subnet identified by reference (ID or name)
}
