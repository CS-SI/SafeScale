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

package resources

import (
	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// SecurityGroup links Object Storage folder and SecurityGroup
type SecurityGroup interface {
	Metadata
	data.NullValue
	data.Identifiable

	AddRule(task concurrency.Task, rule abstract.SecurityGroupRule) fail.Error                             // returns true if the host is member of a cluster
	BindToHost(task concurrency.Task, host Host, disabled bool) fail.Error                                 // binds a security group to a host
	BindToNetwork(task concurrency.Task, network Network, disabled bool) fail.Error                        // binds a security group to a network
	Browse(task concurrency.Task, callback func(*abstract.SecurityGroup) fail.Error) fail.Error            // ...
	CheckConsistency(task concurrency.Task) fail.Error                                                     // tells if the security group described exists on Provider side with exact same parameters
	Clear(task concurrency.Task) fail.Error                                                                // removes rules from the security group
	Create(task concurrency.Task, name, description string, rules []abstract.SecurityGroupRule) fail.Error // creates a new host and its metadata
	DeleteRule(task concurrency.Task, ruleID string) fail.Error                                            // deletes a rule from a Security Group
	GetBoundHosts(task concurrency.Task) ([]*propertiesv1.SecurityGroupBond, fail.Error)                   // returns a slice of bonds corresponding to hosts bound to the security group
	GetBoundNetworks(task concurrency.Task) ([]*propertiesv1.SecurityGroupBond, fail.Error)                // returns a slice of bonds corresponding to networks bound to the security group
	Remove(task concurrency.Task, force bool) fail.Error                                                   // deletes a security group
	Reset(task concurrency.Task) fail.Error                                                                // resets the rules of the security group from the ones registered in metadata
	UnbindFromHost(task concurrency.Task, host Host) fail.Error                                            // unbinds a security group from host
	UnbindFromNetwork(task concurrency.Task, network Network) fail.Error                                   // unbinds a security group from network

	ToProtocol(task concurrency.Task) (*protocol.SecurityGroupResponse, fail.Error) // converts a SecurityGroup to equivalent gRPC message
}
