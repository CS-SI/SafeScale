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

package api

import (
	"context"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

//go:generate minimock -o ../mocks/mock_stack.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks/api.Stack

// Stack is the interface to cloud stack
type Stack interface {
	GetStackName() (string, fail.Error)

	// ListAvailabilityZones lists the usable Availability Zones
	ListAvailabilityZones(ctx context.Context) (map[string]bool, fail.Error)

	// ListRegions returns a list with the regions available
	ListRegions(ctx context.Context) ([]string, fail.Error)

	// InspectImage returns the Image referenced by id
	InspectImage(ctx context.Context, id string) (*abstract.Image, fail.Error)

	// InspectTemplate returns the Template referenced by id
	InspectTemplate(ctx context.Context, id string) (*abstract.HostTemplate, fail.Error)

	// CreateKeyPair creates and import a key pair
	CreateKeyPair(ctx context.Context, name string) (*abstract.KeyPair, fail.Error)
	// InspectKeyPair returns the key pair identified by id
	InspectKeyPair(ctx context.Context, id string) (*abstract.KeyPair, fail.Error)
	// ListKeyPairs lists available key pairs
	ListKeyPairs(ctx context.Context) ([]*abstract.KeyPair, fail.Error)
	// DeleteKeyPair deletes the key pair identified by id
	DeleteKeyPair(ctx context.Context, id string) fail.Error

	// ListSecurityGroups lists the security groups
	ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error)
	// CreateSecurityGroup creates a security group
	CreateSecurityGroup(ctx context.Context, networkRef, name, description string, rules abstract.SecurityGroupRules) (*abstract.SecurityGroup, fail.Error)
	// InspectSecurityGroup returns information about a security group
	InspectSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error)
	// ClearSecurityGroup removes rules from group
	ClearSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter) (*abstract.SecurityGroup, fail.Error)
	// DeleteSecurityGroup deletes a security group and all its rules
	DeleteSecurityGroup(context.Context, *abstract.SecurityGroup) fail.Error
	// AddRuleToSecurityGroup adds a rule to an existing security group
	AddRuleToSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error)
	// DeleteRuleFromSecurityGroup deletes a rule identified by ID from a security group
	DeleteRuleFromSecurityGroup(ctx context.Context, sgParam stacks.SecurityGroupParameter, rule *abstract.SecurityGroupRule) (*abstract.SecurityGroup, fail.Error)
	// GetDefaultSecurityGroupName returns the name of the default security group automatically bound to new host
	GetDefaultSecurityGroupName(ctx context.Context) (string, fail.Error)
	// EnableSecurityGroup enables a Security Group
	EnableSecurityGroup(context.Context, *abstract.SecurityGroup) fail.Error
	// DisableSecurityGroup disables a Security Group
	DisableSecurityGroup(context.Context, *abstract.SecurityGroup) fail.Error

	// CreateNetwork creates a network named name
	CreateNetwork(ctx context.Context, req abstract.NetworkRequest) (*abstract.Network, fail.Error)
	// InspectNetwork returns the network identified by id
	InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error)
	// InspectNetworkByName returns the network identified by name
	InspectNetworkByName(ctx context.Context, name string) (*abstract.Network, fail.Error)
	// ListNetworks lists all networks
	ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error)
	// DeleteNetwork deletes the network identified by id
	DeleteNetwork(ctx context.Context, id string) fail.Error
	// HasDefaultNetwork tells if the stack has a default network (defined in tenant settings)
	HasDefaultNetwork(ctx context.Context) (bool, fail.Error)
	// GetDefaultNetwork returns the abstract.Network used as default Network
	GetDefaultNetwork(ctx context.Context) (*abstract.Network, fail.Error)

	// CreateSubnet creates a subnet in an existing network
	CreateSubnet(ctx context.Context, req abstract.SubnetRequest) (*abstract.Subnet, fail.Error)
	// InspectSubnet returns the network identified by id
	InspectSubnet(ctx context.Context, id string) (*abstract.Subnet, fail.Error)
	// InspectSubnetByName returns the network identified by 'name'
	InspectSubnetByName(ctx context.Context, networkID, name string) (*abstract.Subnet, fail.Error)
	// ListSubnets lists all subnets of a network (or all subnets if no networkRef is provided)
	ListSubnets(ctx context.Context, networkID string) ([]*abstract.Subnet, fail.Error)
	// DeleteSubnet deletes the subnet identified by id
	DeleteSubnet(ctx context.Context, id string) fail.Error

	// CreateVIP ...
	CreateVIP(ctx context.Context, networkID, subnetID, name string, securityGroups []string) (*abstract.VirtualIP, fail.Error)
	// AddPublicIPToVIP adds a public IP to VIP
	AddPublicIPToVIP(context.Context, *abstract.VirtualIP) fail.Error
	// BindHostToVIP makes the host passed as parameter an allowed "target" of the VIP
	BindHostToVIP(context.Context, *abstract.VirtualIP, string) fail.Error
	// UnbindHostFromVIP removes the bind between the VIP and a host
	UnbindHostFromVIP(context.Context, *abstract.VirtualIP, string) fail.Error
	// DeleteVIP deletes the port corresponding to the VIP
	DeleteVIP(context.Context, *abstract.VirtualIP) fail.Error

	// CreateHost creates a host that fulfills the request
	CreateHost(ctx context.Context, request abstract.HostRequest) (*abstract.HostFull, *userdata.Content, fail.Error)
	// ClearHostStartupScript clears the Startup Script of the Host (if the stack can do it)
	ClearHostStartupScript(context.Context, stacks.HostParameter) fail.Error

	ChangeSecurityGroupSecurity(context.Context, bool, bool, string, string) fail.Error

	// InspectHost returns the information of the Host identified by id
	InspectHost(context.Context, stacks.HostParameter) (*abstract.HostFull, fail.Error)
	// GetHostState returns the current state of the host identified by id
	GetHostState(context.Context, stacks.HostParameter) (hoststate.Enum, fail.Error)
	// ListHosts lists all hosts
	ListHosts(context.Context, bool) (abstract.HostList, fail.Error)
	// DeleteHost deletes the host identified by id
	DeleteHost(context.Context, stacks.HostParameter) fail.Error
	// StopHost stops the host identified by id
	StopHost(ctx context.Context, host stacks.HostParameter, gracefully bool) fail.Error
	// StartHost starts the host identified by id
	StartHost(context.Context, stacks.HostParameter) fail.Error
	// RebootHost reboots a host
	RebootHost(context.Context, stacks.HostParameter) fail.Error
	// ResizeHost resizes a host
	ResizeHost(context.Context, stacks.HostParameter, abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error)
	// WaitHostReady waits until host defined in hostParam is reachable by SSH
	WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error)
	// BindSecurityGroupToHost attaches a security group to a host
	BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error
	// UnbindSecurityGroupFromHost detaches a security group from a host
	UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error

	// CreateVolume creates a block volume
	CreateVolume(ctx context.Context, request abstract.VolumeRequest) (*abstract.Volume, fail.Error)
	// InspectVolume returns the volume identified by id
	InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error)
	// ListVolumes list available volumes
	ListVolumes(context.Context) ([]*abstract.Volume, fail.Error)
	// DeleteVolume deletes the volume identified by id
	DeleteVolume(ctx context.Context, id string) fail.Error

	// CreateVolumeAttachment attaches a volume to a host
	CreateVolumeAttachment(ctx context.Context, request abstract.VolumeAttachmentRequest) (string, fail.Error)
	// InspectVolumeAttachment returns the volume attachment identified by id
	InspectVolumeAttachment(ctx context.Context, serverID, id string) (*abstract.VolumeAttachment, fail.Error)
	// ListVolumeAttachments lists available volume attachment
	ListVolumeAttachments(ctx context.Context, serverID string) ([]*abstract.VolumeAttachment, fail.Error)
	// DeleteVolumeAttachment deletes the volume attachment identified by id
	DeleteVolumeAttachment(ctx context.Context, serverID, id string) fail.Error

	// Timings ...
	Timings() (temporal.Timings, fail.Error)

	// UpdateTags updates provider's tags
	UpdateTags(ctx context.Context, kind abstract.Enum, id string, lmap map[string]string) fail.Error

	// DeleteTags removes provider's tags
	DeleteTags(ctx context.Context, kind abstract.Enum, id string, keys []string) fail.Error
}

// ReservedForProviderUse is an interface about the methods only available to providers internally
type ReservedForProviderUse interface {
	ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error)                   // lists available OS images
	ListTemplates(ctx context.Context, all bool) ([]*abstract.HostTemplate, fail.Error)         // lists available host templates
	GetRawConfigurationOptions(ctx context.Context) (stacks.ConfigurationOptions, fail.Error)   // Returns a read-only struct containing configuration options
	GetRawAuthenticationOptions(ctx context.Context) (stacks.AuthenticationOptions, fail.Error) // Returns a read-only struct containing authentication options
}

// FullStack is the interface that MUST actually implement all the providers; don't do it, and we can encounter runtime panics
type FullStack interface {
	Stack
	ReservedForProviderUse
}
