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

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	_ "github.com/CS-SI/SafeScale/v22/lib/utils/data" // nolint needed for minimock
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

//go:generate minimock -i github.com/CS-SI/SafeScale/v22/lib/backend/resources.Host -o mocks/mock_host.go

// Host links Object Storage folder and Host
type Host interface {
	Metadata
	Targetable
	Consistent

	GetName() string
	BindLabel(ctx context.Context, labelInstance Label, value string) fail.Error
	BindSecurityGroup(ctx context.Context, sg SecurityGroup, enable SecurityGroupActivation) fail.Error                                                   // Binds a security group to host
	Browse(ctx context.Context, callback func(*abstract.HostCore) fail.Error) fail.Error                                                                  // ...
	Create(ctx context.Context, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements, extra interface{}) (*userdata.Content, fail.Error) // creates a new host and its metadata
	Delete(ctx context.Context) fail.Error
	DisableSecurityGroup(ctx context.Context, sg SecurityGroup) fail.Error                                                 // disables a bound security group on host
	EnableSecurityGroup(ctx context.Context, sg SecurityGroup) fail.Error                                                  // enables a bound security group on host
	ForceGetState(ctx context.Context) (hoststate.Enum, fail.Error)                                                        // returns the real current state of the host, with error handling
	GetAccessIP(ctx context.Context) (string, fail.Error)                                                                  // returns the IP to reach the host, with error handling
	GetDefaultSubnet(ctx context.Context) (Subnet, fail.Error)                                                             // returns the resources.Subnet instance corresponding to the default subnet of the host, with error handling
	GetMounts(ctx context.Context) (*propertiesv1.HostMounts, fail.Error)                                                  // returns the mounts on the host
	GetPrivateIP(ctx context.Context) (string, fail.Error)                                                                 // returns the IP address of the host on the default subnet, with error handling
	GetPrivateIPOnSubnet(ctx context.Context, subnetID string) (string, fail.Error)                                        // returns the IP address of the host on the requested subnet, with error handling
	GetPublicIP(ctx context.Context) (string, fail.Error)                                                                  // returns the public IP address of the host, with error handling
	GetShare(ctx context.Context, shareRef string) (*propertiesv1.HostShare, fail.Error)                                   // returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
	GetShares(ctx context.Context) (*propertiesv1.HostShares, fail.Error)                                                  // returns the shares hosted on the host
	GetSSHConfig(ctx context.Context) (sshapi.Config, fail.Error)                                                          // loads SSH configuration for host from metadata
	GetState(ctx context.Context) (hoststate.Enum, fail.Error)                                                             // returns the current state of the host, with error handling
	GetVolumes(ctx context.Context) (*propertiesv1.HostVolumes, fail.Error)                                                // returns the volumes attached to the host
	IsClusterMember(ctx context.Context) (bool, fail.Error)                                                                // returns true if the host is member of a cluster
	IsFeatureInstalled(ctx context.Context, name string) (bool, fail.Error)                                                // tells if a feature is installed on Host, using only metadata
	IsGateway(ctx context.Context) (bool, fail.Error)                                                                      // tells of  the host acts as a gateway
	IsSingle(ctx context.Context) (bool, fail.Error)                                                                       // tells of  the host acts as a gateway
	ListEligibleFeatures(ctx context.Context) ([]Feature, fail.Error)                                                      // returns the list of eligible features for the Cluster
	ListInstalledFeatures(ctx context.Context) ([]Feature, fail.Error)                                                     // returns the list of installed features on the Cluster
	ListSecurityGroups(ctx context.Context, state securitygroupstate.Enum) ([]*propertiesv1.SecurityGroupBond, fail.Error) // returns a slice of properties.SecurityGroupBond corresponding to bound Security Group of the host
	ListLabels(ctx context.Context) (list map[string]string, err fail.Error)
	Pull(ctx context.Context, target, source string, timeout time.Duration) (int, string, string, fail.Error)              // downloads a file from host
	Push(ctx context.Context, source, target, owner, mode string, timeout time.Duration) (int, string, string, fail.Error) // uploads a file to host
	PushStringToFileWithOwnership(ctx context.Context, content string, filename string, owner, mode string) fail.Error     // creates a file 'filename' on remote 'host' with the content 'content' and apply ownership to it
	Reboot(ctx context.Context, soft bool) fail.Error                                                                      // reboots the host
	ResetLabel(ctx context.Context, labelInstance Label) fail.Error
	Run(ctx context.Context, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (int, string, string, fail.Error) // tries to execute command 'cmd' on the host
	Start(ctx context.Context) fail.Error                                                                                                        // starts the host
	Stop(ctx context.Context) fail.Error                                                                                                         // stops the host
	ToProtocol(ctx context.Context) (*protocol.Host, fail.Error)                                                                                 // converts a host to equivalent gRPC message
	UnbindSecurityGroup(ctx context.Context, sg SecurityGroup) fail.Error                                                                        // Unbinds a security group from host
	UnbindLabel(ctx context.Context, label Label) fail.Error                                                                                     // Untag a host
	UpdateLabel(ctx context.Context, labelInstance Label, value string) fail.Error
	WaitSSHReady(ctx context.Context, timeout time.Duration) (status string, err fail.Error)
}
