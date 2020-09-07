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
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/data"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// SecurityGroup links Object Storage folder and SecurityGroup
type SecurityGroup interface {
    Metadata
    data.NullValue

    AddRule(task concurrency.Task, rule *abstract.SecurityGroupRule) fail.Error                                      // returns true if the host is member of a cluster
    Browse(task concurrency.Task, callback func(*abstract.SecurityGroup) fail.Error) fail.Error                      // ...
    Create(task concurrency.Task, rules []*abstract.SecurityGroupRule) fail.Error                                    // creates a new host and its metadata
    Remove(task concurrency.Task)                                                                                    // deletes a security group and all its rules
    RemoveRule(task concurrency.Task, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroupRule, fail.Error)    // removes a rule by name from SecurityGroup
    CheckConsistency(task concurrency.Task, ref string) fail.Error                                                   // tells if the security group described exists on Provider side with exact same parameters
    ToProtocol(task concurrency.Task) (*protocol.SecurityGroupResponse, fail.Error)                                  // converts a SecurityGroup to equivalent gRPC message
}
