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
	"time"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/securitygroupstate"
	propertiesv1 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v21/lib/system"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/observer"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v21/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v21/lib/server/resources.Host -o mocks/mock_host.go

// Host links Object Storage folder and Host
type Host interface {
	Metadata
	Targetable
	observer.Observable
	cache.Cacheable

	BindSecurityGroup(ctx context.Context, sg SecurityGroup, enable SecurityGroupActivation) fail.Error                                // Binds a security group to host
	Browse(ctx context.Context, callback func(*abstract.HostCore) fail.Error) fail.Error                                               // ...
	Create(ctx context.Context, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements) (*userdata.Content, fail.Error) // creates a new host and its metadata
	Delete(ctx context.Context) fail.Error
	DisableSecurityGroup(ctx context.Context, sg SecurityGroup) fail.Error                                                                       // disables a binded security group on host
	EnableSecurityGroup(ctx context.Context, sg SecurityGroup) fail.Error                                                                        // enables a binded security group on host
	ForceGetState(ctx context.Context) (hoststate.Enum, fail.Error)                                                                              // returns the real current state of the host, with error handling
	GetAccessIP(ctx context.Context) (string, fail.Error)                                                                                        // returns the IP to reach the host, with error handling
	GetDefaultSubnet(ctx context.Context) (Subnet, fail.Error)                                                                                   // returns the resources.Subnet instance corresponding to the default subnet of the host, with error handling
	GetMounts() (*propertiesv1.HostMounts, fail.Error)                                                                                           // returns the mounts on the host
	GetPrivateIP(ctx context.Context) (ip string, err fail.Error)                                                                                // returns the IP address of the host on the default subnet, with error handling
	GetPrivateIPOnSubnet(subnetID string) (ip string, err fail.Error)                                                                            // returns the IP address of the host on the requested subnet, with error handling
	GetPublicIP(ctx context.Context) (ip string, err fail.Error)                                                                                 // returns the public IP address of the host, with error handling
	GetShare(shareRef string) (*propertiesv1.HostShare, fail.Error)                                                                              // returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
	GetShares() (*propertiesv1.HostShares, fail.Error)                                                                                           // returns the shares hosted on the host
	GetSSHConfig(ctx context.Context) (*system.SSHConfig, fail.Error)                                                                            // loads SSH configuration for host from metadata
	GetState() (hoststate.Enum, fail.Error)                                                                                                      // returns the current state of the host, with error handling
	GetVolumes() (*propertiesv1.HostVolumes, fail.Error)                                                                                         // returns the volumes attached to the host
	IsClusterMember() (bool, fail.Error)                                                                                                         // returns true if the host is member of a cluster
	IsFeatureInstalled(f string) (bool, fail.Error)                                                                                              // tells if a feature is installed on Host, using only metadata
	IsGateway() (bool, fail.Error)                                                                                                               // tells of  the host acts as a gateway
	IsSingle() (bool, fail.Error)                                                                                                                // tells of  the host acts as a gateway
	ListEligibleFeatures(ctx context.Context) ([]Feature, fail.Error)                                                                            // returns the list of eligible features for the Cluster
	ListInstalledFeatures(ctx context.Context) ([]Feature, fail.Error)                                                                           // returns the list of installed features on the Cluster
	ListSecurityGroups(state securitygroupstate.Enum) ([]*propertiesv1.SecurityGroupBond, fail.Error)                                            // returns a slice of properties.SecurityGroupBond corresponding to bound Security Group of the host
	Pull(ctx context.Context, target, source string, timeout time.Duration) (int, string, string, fail.Error)                                    // downloads a file from host
	Push(ctx context.Context, source, target, owner, mode string, timeout time.Duration) (int, string, string, fail.Error)                       // uploads a file to host
	PushStringToFile(ctx context.Context, content string, filename string) fail.Error                                                            // creates a file 'filename' on remote 'host' with the content 'content'
	PushStringToFileWithOwnership(ctx context.Context, content string, filename string, owner, mode string) fail.Error                           // creates a file 'filename' on remote 'host' with the content 'content' and apply ownership to it
	Reboot(ctx context.Context, soft bool) fail.Error                                                                                            // reboots the host
	Resize(ctx context.Context, hostSize abstract.HostSizingRequirements) fail.Error                                                             // resize the host (probably not yet implemented on some providers if not all)
	Run(ctx context.Context, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (int, string, string, fail.Error) // tries to execute command 'cmd' on the host
	Start(ctx context.Context) fail.Error                                                                                                        // starts the host
	Stop(ctx context.Context) fail.Error                                                                                                         // stops the host
	ToProtocol(ctx context.Context) (*protocol.Host, fail.Error)                                                                                 // converts a host to equivalent gRPC message
	UnbindSecurityGroup(ctx context.Context, sg SecurityGroup) fail.Error                                                                        // Unbinds a security group from host
	WaitSSHReady(ctx context.Context, timeout time.Duration) (status string, err fail.Error)                                                     // Wait for remote SSH to respond
}
