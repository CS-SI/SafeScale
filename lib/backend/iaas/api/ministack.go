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

package iaasapi

import (
	"context"

	iaasoptions "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/options"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

//go:generate minimock -o mocks/mock_stack.go -i github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api.Stack

// MiniStack is the interface to minimum set of Cloud stack to complete terraform (list, inspect, ...)
type MiniStack interface {
	AuthenticationOptions() (iaasoptions.Authentication, fail.Error)
	ConfigurationOptions() (iaasoptions.Configuration, fail.Error)

	GetStackName() (string, fail.Error)

	// ListAvailabilityZones lists the usable Availability Zones
	ListAvailabilityZones(ctx context.Context) (map[string]bool, fail.Error)

	// ListRegions returns a list with the regions available
	ListRegions(ctx context.Context) ([]string, fail.Error)

	// ListImages lists available images
	ListImages(ctx context.Context, all bool) ([]*abstract.Image, fail.Error)
	InspectImage(ctx context.Context, id string) (*abstract.Image, fail.Error)

	ListTemplates(ctx context.Context, _ bool) ([]*abstract.HostTemplate, fail.Error)
	InspectTemplate(ctx context.Context, id string) (*abstract.HostTemplate, fail.Error)

	// ListKeyPairs lists available key pairs
	ListKeyPairs(ctx context.Context) ([]*abstract.KeyPair, fail.Error)

	// ListSecurityGroups lists the security groups
	ListSecurityGroups(ctx context.Context, networkRef string) ([]*abstract.SecurityGroup, fail.Error)
	// InspectSecurityGroup returns information about a security group
	InspectSecurityGroup(ctx context.Context, sgParam SecurityGroupIdentifier) (*abstract.SecurityGroup, fail.Error)
	// InspectNetwork returns the network identified by id
	InspectNetwork(ctx context.Context, id string) (*abstract.Network, fail.Error)
	// InspectNetworkByName returns the network identified by name
	InspectNetworkByName(ctx context.Context, name string) (*abstract.Network, fail.Error)
	// ListNetworks lists all networks
	ListNetworks(ctx context.Context) ([]*abstract.Network, fail.Error)

	// InspectSubnet returns the network identified by id
	InspectSubnet(ctx context.Context, id string) (*abstract.Subnet, fail.Error)
	// InspectSubnetByName returns the network identified by 'name'
	InspectSubnetByName(ctx context.Context, networkID, name string) (*abstract.Subnet, fail.Error)
	// ListSubnets lists all subnets of a network (or all subnets if no networkRef is provided)
	ListSubnets(ctx context.Context, networkID string) ([]*abstract.Subnet, fail.Error)

	// InspectHost returns the information of the Host identified by id
	InspectHost(context.Context, HostIdentifier) (*abstract.HostFull, fail.Error)
	// ListHosts lists all hosts
	ListHosts(context.Context, bool) (abstract.HostList, fail.Error)

	// InspectVolume returns the volume identified by id
	InspectVolume(ctx context.Context, id string) (*abstract.Volume, fail.Error)
	// ListVolumes list available volumes
	ListVolumes(context.Context) ([]*abstract.Volume, fail.Error)

	// InspectVolumeAttachment returns the volume attachment identified by id
	InspectVolumeAttachment(ctx context.Context, serverID, id string) (*abstract.VolumeAttachment, fail.Error)
	// ListVolumeAttachments lists available volume attachment
	ListVolumeAttachments(ctx context.Context, serverID string) ([]*abstract.VolumeAttachment, fail.Error)

	// Timings ...
	Timings() (temporal.Timings, fail.Error)
}

//
// // Stack is the interface that MUST actually implement all the providers; don't do it, and we can encounter runtime panics
// type Stack interface {
// 	Stack
// 	ReservedForProviderUse
// }
