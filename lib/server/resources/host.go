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
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/system"
	"time"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Host links Object Storage folder and Host
type Host interface {
	Metadata
	Targetable
	data.NullValue

	BindSecurityGroup(task concurrency.Task, sg SecurityGroup, enable SecurityGroupActivation) fail.Error                                          // Binds a security group to host
	Browse(task concurrency.Task, callback func(*abstract.HostCore) fail.Error) fail.Error                                                         // ...
	Create(task concurrency.Task, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements) (*userdata.Content, fail.Error)           // creates a new host and its metadata
	DisableSecurityGroup(task concurrency.Task, sg SecurityGroup) fail.Error                                                                       // disables a binded security group on host
	EnableSecurityGroup(task concurrency.Task, sg SecurityGroup) fail.Error                                                                        // enables a binded security group on host
	ForceGetState(task concurrency.Task) (hoststate.Enum, fail.Error)                                                                              // returns the real current state of the host, with error handling
	GetAccessIP(task concurrency.Task) (string, fail.Error)                                                                                        // returns the IP to reach the host, with error handling
	GetDefaultSubnet(task concurrency.Task) (Subnet, fail.Error)                                                                                   // returns the resources.Subnet instance corresponding to the default subnet of the host, with error handling
	GetMounts(task concurrency.Task) (*propertiesv1.HostMounts, fail.Error)                                                                        // returns the mounts on the host
	GetPrivateIP(task concurrency.Task) (ip string, err fail.Error)                                                                                // returns the IP address of the host on the default subnet, with error handling
	GetPrivateIPOnSubnet(task concurrency.Task, subnetID string) (ip string, err fail.Error)                                                       // returns the IP address of the host on the requested subnet, with error handling
	GetPublicIP(task concurrency.Task) (ip string, err fail.Error)                                                                                 // returns the public IP address of the host, with error handling
	GetShare(task concurrency.Task, shareRef string) (*propertiesv1.HostShare, fail.Error)                                                         // returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
	GetShares(task concurrency.Task) (*propertiesv1.HostShares, fail.Error)                                                                        // returns the shares hosted on the host
	GetSSHConfig(task concurrency.Task) (*system.SSHConfig, fail.Error)                                                                            // loads SSH configuration for host from metadata
	GetState(task concurrency.Task) hoststate.Enum                                                                                                 // returns the current state of the host, with error handling
	GetVolumes(task concurrency.Task) (*propertiesv1.HostVolumes, fail.Error)                                                                      // returns the volumes attached to the host
	IsClusterMember(task concurrency.Task) (bool, fail.Error)                                                                                      // returns true if the host is member of a cluster
	IsGateway(task concurrency.Task) (bool, fail.Error)                                                                                            // tells of  the host acts as a gateway
	ListSecurityGroups(task concurrency.Task, state securitygroupstate.Enum) ([]*propertiesv1.SecurityGroupBond, fail.Error)                       // returns a slice of properties.SecurityGroupBond corresponding to bound Security Group of the host
	Pull(task concurrency.Task, target, source string, timeout time.Duration) (int, string, string, fail.Error)                                    // downloads a file from host
	Push(task concurrency.Task, source, target, owner, mode string, timeout time.Duration) (int, string, string, fail.Error)                       // uploads a file to host
	PushStringToFile(task concurrency.Task, content string, filename string) fail.Error                                                            // creates a file 'filename' on remote 'host' with the content 'content'
	PushStringToFileWithOwnership(task concurrency.Task, content string, filename string, owner, mode string) fail.Error                           // creates a file 'filename' on remote 'host' with the content 'content' and apply ownership to it
	Reboot(task concurrency.Task) fail.Error                                                                                                       // reboots the host
	Resize(hostSize abstract.HostSizingRequirements) fail.Error                                                                                    // resize the host (probably not yet implemented on some proviers if not all)
	Run(task concurrency.Task, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (int, string, string, fail.Error) // tries to execute command 'cmd' on the host
	Start(task concurrency.Task) fail.Error                                                                                                        // starts the host
	Stop(task concurrency.Task) fail.Error                                                                                                         // stops the host
	ToProtocol(task concurrency.Task) (*protocol.Host, fail.Error)                                                                                 // converts a host to equivalent gRPC message
	UnbindSecurityGroup(task concurrency.Task, sg SecurityGroup) fail.Error                                                                        // Unbinds a security group from host
	WaitSSHReady(task concurrency.Task, timeout time.Duration) (status string, err fail.Error)                                                     // Wait for remote SSH to respond
}
