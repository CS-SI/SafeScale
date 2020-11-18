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

package resources

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
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

// SecurityGroup links Object Storage folder and SecurityGroup
type SecurityGroup interface {
	Metadata
	data.NullValue
	data.Identifiable

	AddRule(concurrency.Task, abstract.SecurityGroupRule) fail.Error                                                  // returns true if the host is member of a cluster
	AddRules(concurrency.Task, abstract.SecurityGroupRules) fail.Error                                                // returns true if the host is member of a cluster
	BindToHost(concurrency.Task, Host, SecurityGroupActivation, SecurityGroupMark) fail.Error                         // binds a security group to a host
	BindToSubnet(concurrency.Task, Subnet, SecurityGroupActivation, SecurityGroupMark) fail.Error                     // binds a security group to a network
	Browse(task concurrency.Task, callback func(*abstract.SecurityGroup) fail.Error) fail.Error                       // browses the metadata folder of Security Groups and call the callback on each entry
	CheckConsistency(concurrency.Task) fail.Error                                                                     // tells if the security group described exists on Provider side with exact same parameters
	Clear(concurrency.Task) fail.Error                                                                                // removes rules from the security group
	Create(task concurrency.Task, networkID, name, description string, rules []abstract.SecurityGroupRule) fail.Error // creates a new host and its metadata
	DeleteRule(task concurrency.Task, rule abstract.SecurityGroupRule) fail.Error                                     // deletes a rule from a Security Group
	GetBoundHosts(concurrency.Task) ([]*propertiesv1.SecurityGroupBond, fail.Error)                                   // returns a slice of bonds corresponding to hosts bound to the security group
	GetBoundSubnets(concurrency.Task) ([]*propertiesv1.SecurityGroupBond, fail.Error)                                 // returns a slice of bonds corresponding to networks bound to the security group
	ForceDelete(task concurrency.Task) fail.Error                                                                     // deletes a security group unconditionally
	Reset(concurrency.Task) fail.Error                                                                                // resets the rules of the security group from the ones registered in metadata
	ToProtocol(concurrency.Task) (*protocol.SecurityGroupResponse, fail.Error)                                        // converts a SecurityGroup to equivalent gRPC message
	UnbindFromHost(concurrency.Task, Host) fail.Error                                                                 // unbinds a Security Group from Host
	UnbindFromHostByReference(concurrency.Task, string) fail.Error                                                    // unbinds a Security Group from Host
	UnbindFromSubnet(concurrency.Task, Subnet) fail.Error                                                             // unbinds a Security Group from Subnet
	UnbindFromSubnetByReference(concurrency.Task, string) fail.Error                                                  // unbinds a Security group from a Subnet identified by reference (ID or name)
}
