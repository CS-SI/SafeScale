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

package openstack

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/davecgh/go-spew/spew"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/secgroups"
	"github.com/sirupsen/logrus"

	"github.com/gophercloud/gophercloud"
	az "github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/availabilityzones"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/floatingips"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/keypairs"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/extensions/startstop"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/flavors"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/gophercloud/gophercloud/openstack/identity/v3/regions"
	"github.com/gophercloud/gophercloud/openstack/imageservice/v2/images"
	"github.com/gophercloud/gophercloud/openstack/networking/v2/ports"
	"github.com/gophercloud/gophercloud/pagination"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
)

// ListRegions ...
func (s stack) ListRegions(ctx context.Context) (list []string, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	var allPages pagination.Page
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			listOpts := regions.ListOpts{
				// ParentRegionID: "RegionOne",
			}
			allPages, innerErr = regions.List(s.IdentityClient, listOpts).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	allRegions, err := regions.ExtractRegions(allPages)
	if err != nil {
		return nil, fail.ConvertError(err)
	}

	var results []string
	for _, v := range allRegions {
		results = append(results, v.ID)
	}
	return results, nil
}

// ListAvailabilityZones lists the usable AvailabilityZones
func (s stack) ListAvailabilityZones(ctx context.Context) (list map[string]bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptyMap map[string]bool
	if valid.IsNil(s) {
		return emptyMap, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	var allPages pagination.Page
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			allPages, innerErr = az.List(s.ComputeClient).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptyMap, xerr
	}

	content, err := az.ExtractAvailabilityZones(allPages)
	if err != nil {
		return emptyMap, fail.ConvertError(err)
	}

	azList := map[string]bool{}
	for _, zone := range content {
		if zone.ZoneState.Available {
			azList[zone.ZoneName] = zone.ZoneState.Available
		}
	}

	// VPL: what's the point if there ios
	if len(azList) == 0 {
		logrus.WithContext(ctx).Warnf("no Availability Zones detected !")
	}

	return azList, nil
}

// ListImages lists available OS images
func (s stack) ListImages(ctx context.Context, _ bool) (imgList []*abstract.Image, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	opts := images.ListOpts{
		Status: images.ImageStatusActive,
		Sort:   "name=asc,updated_at:desc",
	}

	// Retrieve a pager (i.e. a paginated collection)
	pager := images.List(s.ComputeClient, opts)

	// Define an anonymous function to be executed on each page's iteration
	imgList = []*abstract.Image{}
	err := pager.EachPage(
		func(page pagination.Page) (bool, error) {
			imageList, err := images.ExtractImages(page)
			if err != nil {
				return false, err
			}

			for _, img := range imageList {
				imgList = append(imgList, &abstract.Image{ID: img.ID, Name: img.Name})
			}
			return true, nil
		},
	)
	if err != nil {
		return nil, NormalizeError(err)
	}
	return imgList, nil
}

// InspectImage returns the Image referenced by id
func (s stack) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	var img *images.Image
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			img, innerErr = images.Get(s.ComputeClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	out := &abstract.Image{
		ID:       img.ID,
		Name:     img.Name,
		DiskSize: int64(img.MinDiskGigabytes),
	}
	return out, nil
}

// InspectTemplate returns the Template referenced by id
func (s stack) InspectTemplate(ctx context.Context, id string) (template *abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Try to get template
	var flv *flavors.Flavor
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			flv, innerErr = flavors.Get(s.ComputeClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	template = &abstract.HostTemplate{
		Cores:    flv.VCPUs,
		RAMSize:  float32(flv.RAM) / 1000.0,
		DiskSize: flv.Disk,
		ID:       flv.ID,
		Name:     flv.Name,
	}
	return template, nil
}

// ListTemplates lists available Host templates
// Host templates are sorted using Dominant Resource Fairness Algorithm
func (s stack) ListTemplates(ctx context.Context, _ bool) ([]*abstract.HostTemplate, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering()
	defer tracer.Exiting()

	opts := flavors.ListOpts{}

	var flvList []*abstract.HostTemplate
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return flavors.ListDetail(s.ComputeClient, opts).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := flavors.ExtractFlavors(page)
					if err != nil {
						return false, err
					}
					flvList = make([]*abstract.HostTemplate, 0, len(list))
					for _, v := range list {
						flvList = append(
							flvList, &abstract.HostTemplate{
								Cores:    v.VCPUs,
								RAMSize:  float32(v.RAM) / 1000.0,
								DiskSize: v.Disk,
								ID:       v.ID,
								Name:     v.Name,
							},
						)
					}
					return true, nil
				},
			)
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *fail.ErrTimeout:
			return nil, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return nil, xerr
		}
	}
	if len(flvList) == 0 {
		logrus.WithContext(ctx).Debugf("Template list empty")
	}
	return flvList, nil
}

// CreateKeyPair TODO: replace with code to create KeyPair on provider side if it exists
// creates and import a key pair
func (s stack) CreateKeyPair(ctx context.Context, name string) (*abstract.KeyPair, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	// FIXME: OPP Look at CreateKeyPair from aws/compute.go

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return abstract.NewKeyPair(name)
}

// InspectKeyPair TODO: replace with openstack code to get keypair (if it exits)
// returns the key pair identified by id
func (s stack) InspectKeyPair(ctx context.Context, id string) (*abstract.KeyPair, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	kp, err := keypairs.Get(s.ComputeClient, id, nil).Extract()
	if err != nil {
		return nil, fail.Wrap(err, "error getting keypair")
	}
	return &abstract.KeyPair{
		ID:         kp.Name,
		Name:       kp.Name,
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
	}, nil
}

// ListKeyPairs lists available key pairs
// Returned list can be empty
func (s stack) ListKeyPairs(ctx context.Context) ([]*abstract.KeyPair, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	var kpList []*abstract.KeyPair
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return keypairs.List(s.ComputeClient, nil).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := keypairs.ExtractKeyPairs(page)
					if err != nil {
						return false, err
					}

					for _, v := range list {
						kpList = append(
							kpList, &abstract.KeyPair{
								ID:         v.Name,
								Name:       v.Name,
								PublicKey:  v.PublicKey,
								PrivateKey: v.PrivateKey,
							},
						)
					}
					return true, nil
				},
			)
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	// Note: empty list is not an error, so do not raise one
	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(ctx context.Context, id string) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()

	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return keypairs.Delete(s.ComputeClient, id, nil).ExtractErr()
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	return nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into abstract.HostEffectiveSizing
func (s stack) toHostSize(ctx context.Context, flavor map[string]interface{}) (ahes *abstract.HostEffectiveSizing, ferr fail.Error) {
	hostSizing := abstract.NewHostEffectiveSizing()
	if i, ok := flavor["id"]; ok {
		fid, ok := i.(string)
		if !ok {
			return hostSizing, fail.NewError("flavor is not a string: %v", i)
		}
		tpl, xerr := s.InspectTemplate(ctx, fid)
		if xerr != nil {
			return hostSizing, xerr
		}
		hostSizing.Cores = tpl.Cores
		hostSizing.DiskSize = tpl.DiskSize
		hostSizing.RAMSize = tpl.RAMSize
	} else if _, ok := flavor["vcpus"]; ok {
		hostSizing.Cores, ok = flavor["vcpus"].(int)
		if !ok {
			return hostSizing, fail.NewError("flavor[vcpus] is not an int: %v", flavor["vcpus"])
		}
		hostSizing.DiskSize, ok = flavor["disk"].(int)
		if !ok {
			return hostSizing, fail.NewError("flavor[disk] is not an int: %v", flavor["disk"])
		}
		hostSizing.RAMSize, ok = flavor["ram"].(float32)
		if !ok {
			return hostSizing, fail.NewError("flavor[ram] is not a float32: %v", flavor["ram"])
		}
		hostSizing.RAMSize /= 1000.0
	}
	return hostSizing, nil
}

// toHostState converts host status returned by OpenStack driver into HostState enum
func toHostState(status string) hoststate.Enum {
	switch strings.ToLower(status) {
	case "build", "building":
		return hoststate.Starting
	case "active":
		return hoststate.Started
	case "rescued":
		return hoststate.Stopping
	case "stopped", "shutoff":
		return hoststate.Stopped
	default:
		return hoststate.Error
	}
}

// InspectHost gathers host information from provider
func (s stack) InspectHost(ctx context.Context, hostParam stacks.HostParameter) (*abstract.HostFull, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	server, xerr := s.WaitHostState(ctx, ahf, hoststate.Any, timings.OperationTimeout())
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			if server != nil {
				ahf.Core.ID = server.ID
				ahf.Core.Name = server.Name
				ahf.Core.LastState = hoststate.Error
				return ahf, fail.Wrap(xerr, "host '%s' is in Error state", hostLabel) // FIXME, This is wrong, it is not a ErrNotAvailable, it's a 404
			}
			return nil, fail.Wrap(xerr, "host '%s' is in Error state", hostLabel) // FIXME, This is wrong, it is not a ErrNotAvailable, it's a 404
		default:
			return nil, xerr
		}
	}

	state := toHostState(server.Status)
	ahf.CurrentState, ahf.Core.LastState = state, state

	// refresh tags
	for k, v := range server.Metadata {
		ahf.Core.Tags[k] = v
	}

	ct, ok := ahf.Core.Tags["CreationDate"]
	if !ok || ct == "" {
		ahf.Core.Tags["CreationDate"] = server.Created.Format(time.RFC3339)
	}

	if !ahf.OK() {
		logrus.WithContext(ctx).Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(ahf))
	}

	return ahf, nil
}

// complementHost complements Host data with content of server parameter
func (s stack) complementHost(ctx context.Context, hostCore *abstract.HostCore, server servers.Server, hostNets []servers.Network, hostPorts []ports.Port) (host *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Updates intrinsic data of host if needed
	if hostCore.ID == "" {
		hostCore.ID = server.ID
	}
	if hostCore.Name == "" {
		hostCore.Name = server.Name
	}

	state := toHostState(server.Status)
	if state == hoststate.Error || state == hoststate.Starting {
		logrus.WithContext(ctx).Warnf("[TRACE] Unexpected host's last state: %v", state)
	}

	host = abstract.NewHostFull()
	host.Core = hostCore
	host.CurrentState, hostCore.LastState = state, state
	host.Description = &abstract.HostDescription{
		Created: server.Created,
		Updated: server.Updated,
	}

	host.Core.Tags["Template"], _ = server.Image["id"].(string) // nolint
	host.Core.Tags["Image"], _ = server.Flavor["id"].(string)   // nolint

	// recover metadata
	for k, v := range server.Metadata {
		host.Core.Tags[k] = v
	}

	ct, ok := host.Core.Tags["CreationDate"]
	if !ok || ct == "" {
		host.Core.Tags["CreationDate"] = server.Created.Format(time.RFC3339)
	}

	var xerr fail.Error
	host.Sizing, xerr = s.toHostSize(ctx, server.Flavor)
	if xerr != nil {
		return nil, xerr
	}

	if len(hostNets) > 0 {
		if len(hostPorts) != len(hostNets) {
			return nil, fail.InconsistentError("count of host ports must be equal to the count of host subnets")
		}

		var ipv4, ipv6 string
		subnetsByID := map[string]string{}
		subnetsByName := map[string]string{}

		// Fill the ID of subnets
		for k := range hostNets {
			port := hostPorts[k]
			if port.NetworkID != s.ProviderNetworkID {
				subnetsByID[port.FixedIPs[0].SubnetID] = ""
			} else {
				for _, ip := range port.FixedIPs {
					if valid.IsIPv6(ip.IPAddress) {
						ipv6 = ip.IPAddress
					} else {
						ipv4 = ip.IPAddress
					}
				}
			}
		}

		// Fill the name of subnets
		for k := range subnetsByID {
			as, xerr := s.InspectSubnet(ctx, k)
			if xerr != nil {
				return nil, xerr
			}
			subnetsByID[k] = as.Name
			subnetsByName[as.Name] = k
		}

		// Now fills the ip addresses
		ipv4Addresses := map[string]string{}
		ipv6Addresses := map[string]string{}
		for k := range hostNets {
			port := hostPorts[k]
			for _, ip := range port.FixedIPs {
				subnetID := ip.SubnetID
				if valid.IsIPv6(ip.IPAddress) {
					ipv6Addresses[subnetID] = ip.IPAddress
				} else {
					ipv4Addresses[subnetID] = ip.IPAddress
				}
			}
		}

		host.Networking.PublicIPv4 = ipv4
		host.Networking.PublicIPv6 = ipv6
		host.Networking.SubnetsByID = subnetsByID
		host.Networking.SubnetsByName = subnetsByName
		host.Networking.IPv4Addresses = ipv4Addresses
		host.Networking.IPv6Addresses = ipv6Addresses
	}
	return host, nil
}

// InspectHostByName returns the host using the name passed as parameter
func (s stack) InspectHostByName(ctx context.Context, name string) (*abstract.HostFull, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "('%s')", name).WithStopwatch().Entering().Exiting()

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := servers.GetResult{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			_, r.Err = s.ComputeClient.Get(
				s.ComputeClient.ServiceURL("servers?name="+name), &r.Body, &gophercloud.RequestOpts{
					OkCodes: []int{200, 203},
				},
			)
			return r.Err
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}

	serverList, found := r.Body.(map[string]interface{})["servers"].([]interface{})
	if found && len(serverList) > 0 {
		for _, anon := range serverList {
			entry, ok := anon.(map[string]interface{})
			if !ok {
				return nil, fail.InconsistentError("anon should be a map[string]interface{}")
			}
			if entry["name"].(string) == name {
				host := abstract.NewHostCore()
				host.ID, ok = entry["id"].(string)
				if !ok {
					return nil, fail.InconsistentError("entry[id] should be a string")
				}
				host.Name = name
				hostFull, xerr := s.InspectHost(ctx, host)
				if xerr != nil {
					return nil, fail.Wrap(xerr, "failed to inspect host '%s'", name)
				}
				return hostFull, nil
			}
		}
	}
	return nil, abstract.ResourceNotFoundError("host", name)
}

// CreateHost creates a new host
func (s stack) CreateHost(ctx context.Context, request abstract.HostRequest) (host *abstract.HostFull, userData *userdata.Content, ferr fail.Error) {
	var xerr fail.Error
	if valid.IsNil(s) {
		return nil, nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)",
		request.ResourceName).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&ferr)

	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if len(request.Subnets) == 0 && !request.PublicIP {
		return nil, nil, abstract.ResourceInvalidRequestError(
			"host creation", "cannot create a host without --public flag and without attached Network/Subnet",
		)
	}

	// The Default Networking is the first of the provided list, by convention
	defaultSubnet := request.Subnets[0]
	defaultSubnetID := defaultSubnet.ID

	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to provide credentials for the host")
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData = userdata.NewContent()
	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, nil, xerr
	}

	xerr = userData.Prepare(s.cfgOpts, request, defaultSubnet.CIDR, "", timings)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to prepare user data content")
	}

	template, xerr := s.InspectTemplate(ctx, request.TemplateID)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to get image")
	}

	rim, xerr := s.InspectImage(ctx, request.ImageID)
	if xerr != nil {
		return nil, nil, xerr
	}

	diskSize := request.DiskSize
	if diskSize > template.DiskSize {
		diskSize = request.DiskSize
	}

	if int(rim.DiskSize) > diskSize {
		diskSize = int(rim.DiskSize)
	}

	if diskSize == 0 {
		// Determines appropriate disk size
		// if still zero here, we take template.DiskSize
		if template.DiskSize != 0 {
			diskSize = template.DiskSize
		} else {
			if template.Cores < 16 { // nolint
				template.DiskSize = 100
			} else if template.Cores < 32 {
				template.DiskSize = 200
			} else {
				template.DiskSize = 400
			}
		}
	}

	if diskSize < 10 {
		diskSize = 10
	}

	// Sets provider parameters to create host
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nil, nil, xerr
	}

	// Select usable availability zone, the first one in the list
	azone, xerr := s.SelectedAvailabilityZone(ctx)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to select availability zone")
	}

	// --- Initializes abstract.HostCore ---

	ahc := abstract.NewHostCore()
	ahc.PrivateKey = userData.FirstPrivateKey
	ahc.Password = request.Password

	// --- query provider for host creation ---

	// Starting from here, delete host if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			cleanCtx := cleanupContextFrom(ctx)
			if ahc.IsConsistent() {
				logrus.WithContext(cleanCtx).Infof("Cleaning up on failure, deleting host '%s'", ahc.Name)
				if derr := s.DeleteHost(cleanCtx, ahc.ID); derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						logrus.WithContext(cleanCtx).Errorf("Cleaning up on failure, failed to delete host, resource not found: '%v'", derr)
					case *fail.ErrTimeout:
						logrus.WithContext(cleanCtx).Errorf("Cleaning up on failure, failed to delete host, timeout: '%v'", derr)
					default:
						logrus.WithContext(cleanCtx).Errorf("Cleaning up on failure, failed to delete host: '%v'", derr)
					}
					_ = fail.AddConsequence(ferr, derr)
				}
			}
		}
	}()

	logrus.WithContext(ctx).Debugf("Creating host resource '%s' ...", request.ResourceName)

	// Retry creation until success, for 10 minutes
	var (
		finalServer    *servers.Server
		finalHostNets  []servers.Network
		finalHostPorts []ports.Port
	)

	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			var hostNets []servers.Network
			var hostPorts []ports.Port
			var createdPorts []string

			var server *servers.Server
			var innerXErr fail.Error

			// Starting from here, delete created ports if exiting with error
			defer func() {
				if innerXErr != nil {
					if derr := s.deletePortsInSlice(cleanupContextFrom(ctx), createdPorts); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete ports"))
					}
				}
			}()

			hostNets, hostPorts, createdPorts, innerXErr = s.identifyOpenstackSubnetsAndPorts(ctx, request, defaultSubnet)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrDuplicate, *fail.ErrNotFound: // This kind of error means actually there is no more Ip address available
					return retry.StopRetryError(innerXErr)
				default:
					return fail.Wrap(xerr, "failed to construct list of Subnets for the Host")
				}
			}

			// Starting from here, delete host if exiting with error
			defer func() {
				if innerXErr != nil {
					cleanCtx := cleanupContextFrom(ctx)
					if server != nil && server.ID != "" {
						logrus.WithContext(cleanCtx).Debugf("deleting unresponsive server '%s'...", request.ResourceName)
						if derr := s.DeleteHost(cleanCtx, server.ID); derr != nil {
							logrus.WithContext(cleanCtx).Debugf(derr.Error())
							_ = innerXErr.AddConsequence(
								fail.Wrap(
									derr, "cleaning up on failure, failed to delete Host '%s'", request.ResourceName,
								),
							)
							return
						}
						logrus.WithContext(cleanCtx).Debugf("unresponsive server '%s' deleted", request.ResourceName)
					}
				}
			}()

			server, innerXErr = s.rpcCreateServer(
				ctx, request.ResourceName, hostNets, request.TemplateID, request.ImageID, diskSize, userDataPhase1, azone,
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrStopRetry:
					return fail.Wrap(fail.Cause(innerXErr), "stopping retries")
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(innerXErr)
				default:
					return innerXErr
				}
			}

			ahc.ID = server.ID
			ahc.Name = request.ResourceName

			creationZone, innerXErr := s.GetAvailabilityZoneOfServer(ctx, ahc.ID)
			if innerXErr != nil {
				logrus.WithContext(ctx).Tracef("Host '%s' successfully created but cannot confirm AZ: %s", ahc.Name, innerXErr)
			} else {
				logrus.WithContext(ctx).Tracef("Host '%s' successfully created in requested AZ '%s'", ahc.Name, creationZone)
				if creationZone != azone && azone != "" {
					logrus.WithContext(ctx).Warnf(
						"Host '%s' created in the WRONG availability zone: requested '%s' and got instead '%s'",
						ahc.Name, azone, creationZone,
					)
				}
			}

			// Wait that host is ready, not just that the build is started
			timeout := timings.HostOperationTimeout()
			server, innerXErr = s.WaitHostState(ctx, ahc, hoststate.Started, timeout)
			if innerXErr != nil {
				logrus.WithContext(ctx).Errorf(
					"failed to reach server '%s' after %s; deleting it and trying again", request.ResourceName,
					temporal.FormatDuration(timeout),
				)
				switch innerXErr.(type) {
				case *fail.ErrNotAvailable:
					return fail.Wrap(innerXErr, "host '%s' is in Error state", request.ResourceName)
				default:
					return innerXErr
				}
			}

			// FIXME: OPP Fucking incredible, do we need another Hard Reset here ??

			finalServer = server
			finalHostNets = hostNets
			finalHostPorts = hostPorts

			return nil
		},
		timings.NormalDelay(),
		timings.HostLongOperationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return nil, nil, fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry, *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
			return nil, nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotAvailable); ok {
				if finalServer != nil {
					ahc.ID = finalServer.ID
					ahc.Name = finalServer.Name
					ahc.LastState = hoststate.Error
				}
			}
			return nil, nil, xerr
		}
	}

	if finalServer == nil {
		return nil, nil, fail.NewError("invalid server")
	}

	newHost, xerr := s.complementHost(ctx, ahc, *finalServer, finalHostNets, finalHostPorts)
	if xerr != nil {
		return nil, nil, xerr
	}
	newHost.Networking.DefaultSubnetID = defaultSubnetID
	// newHost.Networking.DefaultGatewayID = defaultGatewayID
	// newHost.Networking.DefaultGatewayPrivateIP = request.DefaultRouteIP
	newHost.Networking.IsGateway = request.IsGateway
	newHost.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

	// if Floating IP are used and public address is requested
	if s.cfgOpts.UseFloatingIP && request.PublicIP {
		// Create the floating IP
		var ip *floatingips.FloatingIP

		// Starting from here, delete Floating IP if exiting with error
		defer func() {
			ferr = debug.InjectPlannedFail(ferr)
			if ferr != nil {
				if ip != nil {
					cleanupCtx := cleanupContextFrom(ctx)
					logrus.WithContext(cleanupCtx).Debugf("Cleaning up on failure, deleting floating ip '%s'", ip.ID)
					if derr := s.rpcDeleteFloatingIP(cleanupCtx, ip.ID); derr != nil {
						derr = fail.Wrap(derr, "cleaning up on failure, failed to delete Floating IP")
						_ = ferr.AddConsequence(derr)
						return
					}
					logrus.WithContext(cleanupCtx).Debugf("Cleaning up on failure, floating ip '%s' successfully deleted", ip.ID)
				}
			}
		}()

		if ip, xerr = s.rpcCreateFloatingIP(ctx); xerr != nil {
			return nil, nil, xerr
		}

		// Associate floating IP to host
		xerr = stacks.RetryableRemoteCall(ctx,
			func() error {
				return floatingips.AssociateInstance(
					s.ComputeClient, newHost.Core.ID, floatingips.AssociateOpts{
						FloatingIP: ip.IP,
					},
				).ExtractErr()
			},
			NormalizeError,
		)
		if xerr != nil {
			return nil, nil, xerr
		}

		if ipversion.IPv4.Is(ip.IP) {
			newHost.Networking.PublicIPv4 = ip.IP
		} else if ipversion.IPv6.Is(ip.IP) {
			newHost.Networking.PublicIPv6 = ip.IP
		}
		userData.PublicIP = ip.IP
	}

	logrus.WithContext(ctx).Infoln(msgSuccess)
	return newHost, userData, nil
}

// deletePortsInSlice deletes ports listed in slice
func (s stack) deletePortsInSlice(ctx context.Context, ports []string) fail.Error {
	var errors []error
	for _, v := range ports {
		if rerr := s.rpcDeletePort(ctx, v); rerr != nil {
			switch rerr.(type) {
			case *fail.ErrNotFound:
				// consider a not found port as a successful deletion
				debug.IgnoreError2(ctx, rerr)
			default:
				errors = append(errors, fail.Wrap(rerr, "failed to delete port %s", v))
			}
		}
	}
	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}
	return nil
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
// Does nothing for OpenStack, userdata cannot be updated
func (s stack) ClearHostStartupScript(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	return nil
}

func (s stack) ChangeSecurityGroupSecurity(ctx context.Context, cleanSG bool, enabledPort bool, net string, machine string) fail.Error {
	// list ports to be able to remove them
	req := ports.ListOpts{
		NetworkID:   net,
		DeviceOwner: "compute:nova",
	}
	portList, xerr := s.rpcListPorts(ctx, req)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError2(ctx, xerr)
		default:
			return xerr
		}
	}

	var collected []error
	goodEnough := false
	if cleanSG {
		for _, p := range portList {
			check := (machine == "") || (machine != "" && strings.Contains(p.Name, machine))
			if check {
				_, xerr = s.rpcRemoveSGFromPort(ctx, p.ID)
				if xerr != nil {
					debug.IgnoreError2(ctx, xerr)
					collected = append(collected, xerr)
				} else {
					goodEnough = true
				}
			}
		}
	}

	if !goodEnough && len(collected) > 0 {
		return fail.NewErrorList(collected)
	}

	portList, xerr = s.rpcListPorts(ctx, req)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError2(ctx, xerr)
		default:
			return xerr
		}
	}

	goodEnough = false
	for _, p := range portList {
		check := (machine == "") || (machine != "" && strings.Contains(p.Name, machine))
		if check {
			_, xerr = s.rpcChangePortSecurity(ctx, p.ID, enabledPort)
			if xerr != nil {
				debug.IgnoreError2(ctx, xerr)
				collected = append(collected, xerr)
			} else {
				goodEnough = true
			}
		}
	}

	if !goodEnough && len(collected) > 0 {
		return fail.NewErrorList(collected)
	}

	return nil
}

func (s stack) GetMetadataOfInstance(ctx context.Context, id string) (map[string]string, fail.Error) {
	return s.rpcGetMetadataOfInstance(ctx, id)
}

// identifyOpenstackSubnetsAndPorts ...
func (s stack) identifyOpenstackSubnetsAndPorts(ctx context.Context, request abstract.HostRequest, defaultSubnet *abstract.Subnet) (nets []servers.Network, netPorts []ports.Port, createdPorts []string, ferr fail.Error) { // nolint
	nets = []servers.Network{}
	netPorts = []ports.Port{}
	createdPorts = []string{}

	// cleanup if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if derr := s.deletePortsInSlice(cleanupContextFrom(ctx), createdPorts); derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete ports"))
			}
		}
	}()

	// If floating IPs are not used and host is public
	// then add provider external network to host networks
	// Note: order is important: at least at OVH, public network has to be
	//       the first network attached to, otherwise public interface is not UP...
	if !s.cfgOpts.UseFloatingIP && request.PublicIP {
		adminState := true
		req := ports.CreateOpts{
			NetworkID: s.ProviderNetworkID,
			Name:      fmt.Sprintf("nic_%s_external", request.ResourceName),
			Description: fmt.Sprintf(
				"nic of host '%s' on external network %s", request.ResourceName, s.cfgOpts.ProviderNetwork,
			),
			AdminStateUp:   &adminState,
			SecurityGroups: &[]string{},
		}
		port, xerr := s.rpcCreatePort(ctx, req)
		if xerr != nil {
			return nets, netPorts, createdPorts, fail.Wrap(
				xerr, "failed to create port on external network '%s'", s.cfgOpts.ProviderNetwork,
			)
		}

		// FIXME: OPP workaround for Stein disaster, so we have to make sure it is OVH
		if !s.cfgOpts.Safe && s.cfgOpts.ProviderName == "ovh" {
			port, xerr = s.rpcChangePortSecurity(ctx, port.ID, false)
			if xerr != nil {
				return nets, netPorts, createdPorts, fail.Wrap(
					xerr, "failed to disable port on external network '%s'", s.cfgOpts.ProviderNetwork,
				)
			}
		}

		createdPorts = append(createdPorts, port.ID)

		nets = append(nets, servers.Network{Port: port.ID})
		netPorts = append(netPorts, *port)
	}

	// private networks
	for _, n := range request.Subnets {
		req := ports.CreateOpts{
			NetworkID:      n.Network,
			Name:           fmt.Sprintf("nic_%s_subnet_%s", request.ResourceName, n.Name),
			Description:    fmt.Sprintf("nic of host '%s' on subnet '%s'", request.ResourceName, n.Name),
			FixedIPs:       []ports.IP{{SubnetID: n.ID}},
			SecurityGroups: &[]string{},
		}
		port, xerr := s.rpcCreatePort(ctx, req)
		if xerr != nil {
			return nets, netPorts, createdPorts, fail.Wrap(
				xerr, "failed to create port on subnet '%s'", n.Name,
			)
		}

		// Fix for Stein
		if !s.cfgOpts.Safe && s.cfgOpts.ProviderName == "ovh" {
			port, xerr = s.rpcRemoveSGFromPort(ctx, port.ID)
			if xerr != nil {
				return nets, netPorts, createdPorts, fail.Wrap(
					xerr, "failed to disable port on subnet '%s'", n.Name,
				)
			}
		}

		createdPorts = append(createdPorts, port.ID)
		nets = append(nets, servers.Network{Port: port.ID})
		netPorts = append(netPorts, *port)
	}

	return nets, netPorts, createdPorts, nil
}

// GetAvailabilityZoneOfServer retrieves the availability zone of server 'serverID'
func (s stack) GetAvailabilityZoneOfServer(ctx context.Context, serverID string) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}
	if serverID == "" {
		return "", fail.InvalidParameterError("serverID", "cannot be empty string")
	}

	type ServerWithAZ struct {
		servers.Server
		az.ServerAvailabilityZoneExt
	}

	var (
		allPages   pagination.Page
		allServers []ServerWithAZ
	)
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (innerErr error) {
			allPages, innerErr = servers.List(s.ComputeClient, nil).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return "", xerr
	}

	err := servers.ExtractServersInto(allPages, &allServers)
	if err != nil {
		return "", NormalizeError(err)
	}

	for _, server := range allServers {
		if server.ID == serverID {
			return server.AvailabilityZone, nil
		}
	}

	return "", fail.NotFoundError("unable to find availability zone information for server '%s'", serverID)
}

// SelectedAvailabilityZone returns the selected availability zone
func (s stack) SelectedAvailabilityZone(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(s) {
		return "", fail.InvalidInstanceError()
	}

	if s.selectedAvailabilityZone == "" {
		opts, err := s.GetRawAuthenticationOptions(ctx)
		if err != nil {
			return "", err
		}
		s.selectedAvailabilityZone = opts.AvailabilityZone
		if s.selectedAvailabilityZone == "" {
			azList, xerr := s.ListAvailabilityZones(ctx)
			if xerr != nil {
				return "", xerr
			}
			var azone string
			for azone = range azList {
				break
			}
			s.selectedAvailabilityZone = azone
		}
		logrus.WithContext(ctx).Debugf("Selected Availability Zone: '%s'", s.selectedAvailabilityZone)
	}
	return s.selectedAvailabilityZone, nil
}

// WaitHostReady waits a host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s stack) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	server, xerr := s.WaitHostState(ctx, hostParam, hoststate.Started, timeout)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			if server != nil {
				ahf.Core.ID = server.ID
				ahf.Core.Name = server.Name
				ahf.Core.LastState = hoststate.Error
				return ahf.Core, fail.Wrap(xerr, "host '%s' is in Error state", hostRef)
			}
			return nil, fail.Wrap(xerr, "host '%s' is in Error state", hostRef)
		default:
			return nil, xerr
		}
	}

	ahf, xerr = s.complementHost(ctx, ahf.Core, *server, nil, nil)
	if xerr != nil {
		return nil, xerr
	}

	return ahf.Core, nil
}

// WaitHostState waits a host achieve defined state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s stack) WaitHostState(ctx context.Context, hostParam stacks.HostParameter, state hoststate.Enum, timeout time.Duration) (server *servers.Server, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	ahf, hostLabel, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s, %s, %v)", hostLabel,
		state.String(), timeout).WithStopwatch().Entering().Exiting()

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() (innerErr error) {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			if ahf.Core.ID != "" {
				server, innerErr = s.rpcGetHostByID(ctx, ahf.Core.ID)
			} else {
				server, innerErr = s.rpcGetHostByName(ctx, ahf.Core.Name)
			}

			if innerErr != nil {
				switch innerErr.(type) {
				case *fail.ErrNotFound:
					// If error is "resource not found", we want to return error as-is to be able
					// to behave differently in this special case. To do so, stop the retry
					return retry.StopRetryError(abstract.ResourceNotFoundError("host", ahf.Core.Name), "")
				case *fail.ErrInvalidRequest:
					// If error is "invalid request", no need to retry, it will always be so
					return retry.StopRetryError(innerErr, "error getting Host %s", hostLabel)
				case *fail.ErrNotAvailable:
					return innerErr
				default:
					if errorMeansServiceUnavailable(innerErr) {
						return innerErr
					}

					// Any other error stops the retry
					return retry.StopRetryError(innerErr, "error getting Host %s", hostLabel)
				}
			}

			if server == nil {
				return fail.NotFoundError("provider did not send information for Host %s", hostLabel)
			}

			ahf.Core.ID = server.ID // makes sure that on next turn we get IPAddress by ID
			lastState := toHostState(server.Status)

			// If we had a response, and the target state is Any, this is a success no matter what
			if state == hoststate.Any {
				return nil
			}

			// If state matches, we consider this a success no matter what
			switch lastState {
			case state:
				return nil
			case hoststate.Error:
				return retry.StopRetryError(fail.NotAvailableError("state of Host '%s' is 'ERROR'", hostLabel))
			case hoststate.Starting, hoststate.Stopping:
				return fail.NewError("host '%s' not ready yet", hostLabel)
			default:
				return retry.StopRetryError(
					fail.NewError(
						"host status of '%s' is in state '%s'", hostLabel, lastState.String(),
					),
				)
			}
		},
		timings.SmallDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *fail.ErrTimeout:
			return nil, fail.Wrap(
				fail.Cause(retryErr), "timeout waiting to get host '%s' information after %v", hostLabel, timeout,
			)
		case *fail.ErrAborted:
			cause := retryErr.Cause()
			if cause != nil {
				retryErr = fail.ConvertError(cause)
			}
			return server, retryErr // Not available error keeps the server info, good
		default:
			return nil, retryErr
		}
	}
	if server == nil {
		return nil, fail.NotFoundError("failed to query Host '%s'", hostLabel)
	}
	return server, nil
}

// GetHostState returns the current state of host identified by id
// hostParam can be a string or an instance of *abstract.HostCore; any other type will return an fail.InvalidParameterError
func (s stack) GetHostState(ctx context.Context, hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if valid.IsNil(s) {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	host, xerr := s.InspectHost(ctx, hostParam)
	if xerr != nil {
		return hoststate.Error, xerr
	}
	return host.CurrentState, nil
}

func (s stack) GetTrueHostState(ctx context.Context, hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if valid.IsNil(s) {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	if ahf.Core.ID != "" {
		server, innerErr := s.rpcGetHostByID(ctx, ahf.Core.ID)
		if innerErr != nil {
			return hoststate.Unknown, innerErr
		}

		return toHostState(server.Status), nil
	} else {
		server, innerErr := s.rpcGetHostByName(ctx, ahf.Core.Name)
		if innerErr != nil {
			return hoststate.Unknown, innerErr
		}

		return toHostState(server.Status), nil
	}
}

// ListHosts lists all hosts
func (s stack) ListHosts(ctx context.Context, details bool) (abstract.HostList, fail.Error) {
	var emptyList abstract.HostList
	if valid.IsNil(s) {
		return emptyList, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	hostList := abstract.HostList{}
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return servers.List(s.ComputeClient, servers.ListOpts{}).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := servers.ExtractServers(page)
					if err != nil {
						return false, err
					}

					for _, srv := range list {
						ahc := abstract.NewHostCore()
						ahc.ID = srv.ID
						var ahf *abstract.HostFull
						if details {
							ahf, err = s.complementHost(ctx, ahc, srv, nil, nil)
							if err != nil {
								return false, err
							}
						} else {
							ahf = abstract.NewHostFull()
							ahf.Core = ahc
						}
						hostList = append(hostList, ahf)
					}
					return true, nil
				},
			)
		},
		NormalizeError,
	)
	return hostList, xerr
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to a host
func (s stack) getFloatingIP(ctx context.Context, hostID string) (*floatingips.FloatingIP, fail.Error) {
	var fips []floatingips.FloatingIP
	xerr := stacks.RetryableRemoteCall(ctx,
		func() error {
			return floatingips.List(s.ComputeClient).EachPage(
				func(page pagination.Page) (bool, error) {
					list, err := floatingips.ExtractFloatingIPs(page)
					if err != nil {
						return false, err
					}

					for _, fip := range list {
						if fip.InstanceID == hostID {
							fips = append(fips, fip)
							break // No need to go through the rest of the floating ip, as there can be only one Floating IP by host, by convention
						}
					}
					return true, nil
				},
			)
		},
		NormalizeError,
	)
	if xerr != nil {
		return nil, xerr
	}
	if len(fips) == 0 {
		return nil, fail.NotFoundError()
	}
	if len(fips) > 1 {
		return nil, fail.InconsistentError(
			"configuration error, more than one Floating IP associated to host '%s'", hostID,
		)
	}
	return &fips[0], nil
}

// DeleteHost deletes the host identified by id
func (s stack) DeleteHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// Detach floating IP
	if s.cfgOpts.UseFloatingIP {
		fip, xerr := s.getFloatingIP(ctx, ahf.Core.ID)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
				debug.IgnoreError2(ctx, xerr)
			default:
				return fail.Wrap(xerr, "failed to find floating ip of host '%s'", hostRef)
			}
		} else if fip != nil {
			err := floatingips.DisassociateInstance(
				s.ComputeClient, ahf.Core.ID, floatingips.DisassociateOpts{
					FloatingIP: fip.IP,
				},
			).ExtractErr()
			if err != nil {
				return NormalizeError(err)
			}

			err = floatingips.Delete(s.ComputeClient, fip.ID).ExtractErr()
			if err != nil {
				return NormalizeError(err)
			}
		}
	}

	// list ports to be able to remove them
	req := ports.ListOpts{
		DeviceID: ahf.Core.ID,
	}
	portList, xerr := s.rpcListPorts(ctx, req)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError2(ctx, xerr)
		default:
			return xerr
		}
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	// Try to remove host for 3 minutes
	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			if innerXErr := s.rpcDeleteServer(ctx, ahf.Core.ID); innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrTimeout:
					return fail.Wrap(innerXErr, "failed to submit Host '%s' deletion", hostRef)
				case *fail.ErrNotFound:
					return retry.StopRetryError(innerXErr)
				default:
					return fail.Wrap(innerXErr, "failed to delete Host '%s'", hostRef)
				}
			}

			// 2nd, check host status every 5 seconds until check failed.
			// If check succeeds but state is Error, retry the deletion.
			// If check fails and error is not 'not found', retry
			var state = hoststate.Unknown
			innerXErr := retry.WhileUnsuccessful(
				func() error {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}

					server, gerr := s.rpcGetServer(ctx, ahf.Core.ID)
					if gerr != nil {
						switch gerr.(type) { // nolint
						case *fail.ErrNotFound:
							state = hoststate.Terminated
							return nil
						}
						return gerr
					}
					// if Host is found but in error state, exist inner retry but retry the deletion
					if state = toHostState(server.Status); state == hoststate.Error {
						return nil
					}
					return fail.NewError("host %s state is '%s'", hostRef, server.Status)
				},
				timings.NormalDelay(),
				timings.ContextTimeout(),
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrStopRetry:
					return fail.Wrap(fail.Cause(innerXErr), "stopping retries")
				case *retry.ErrTimeout:
					return fail.Wrap(fail.Cause(innerXErr), "timeout")
				default:
					return innerXErr
				}
			}
			if state == hoststate.Error {
				return fail.NotAvailableError("failed to trigger server deletion, retrying...")
			}
			return nil
		},
		0,
		timings.HostCleanupTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotFound); ok {
				debug.IgnoreError2(ctx, xerr)
			} else {
				return fail.ConvertError(cause)
			}
		case *retry.ErrStopRetry:
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotFound); ok {
				debug.IgnoreError2(ctx, xerr)
			} else {
				return fail.ConvertError(cause)
			}
		case *fail.ErrNotFound:
			// if host disappeared (rpcListPorts succeeded and host was still there at this moment), consider the error as a successful deletion;
			// leave a chance to remove ports
			debug.IgnoreError2(ctx, xerr)
		default:
			return xerr
		}
	}

	// Remove ports freed from host
	var errors []error
	for _, v := range portList {
		if rerr := s.rpcDeletePort(ctx, v.ID); rerr != nil {
			switch rerr.(type) {
			case *fail.ErrNotFound:
				// consider a not found port as a successful deletion
				debug.IgnoreError2(ctx, rerr)
			default:
				errors = append(errors, fail.Wrap(rerr, "failed to delete port %s (%s)", v.ID, v.Description))
			}
		}
	}
	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}

	return nil
}

// rpcGetServer returns
func (s stack) rpcGetServer(ctx context.Context, id string) (_ *servers.Server, ferr fail.Error) {
	if id == "" {
		return &servers.Server{}, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	var resp *servers.Server
	xerr := stacks.RetryableRemoteCall(ctx,
		func() (err error) {
			resp, err = servers.Get(s.ComputeClient, id).Extract()
			return err
		},
		NormalizeError,
	)
	if xerr != nil {
		return &servers.Server{}, xerr
	}
	return resp, nil
}

// StopHost stops the host identified by id
func (s stack) StopHost(ctx context.Context, hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return startstop.Stop(s.ComputeClient, ahf.Core.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// RebootHost reboots unconditionally the host identified by id
func (s stack) RebootHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// Only hard reboot actually solves problems
	return stacks.RetryableRemoteCall(ctx,
		func() error {
			innerErr := servers.Reboot(
				s.ComputeClient, ahf.Core.ID, servers.RebootOpts{Type: servers.HardReboot},
			).ExtractErr()
			return innerErr
		},
		NormalizeError,
	)
}

// StartHost starts the host identified by id
func (s stack) StartHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			return startstop.Start(s.ComputeClient, ahf.Core.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// ResizeHost ...
func (s stack) ResizeHost(ctx context.Context, hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	_ /*ahf*/, hostRef, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// TODO: RESIZE Resize IPAddress HERE
	logrus.WithContext(ctx).Warn("Trying to resize a Host...") // FIXME: OPP This should trigger a build failure

	// TODO: RESIZE Call this
	// servers.Resize()

	return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// BindSecurityGroupToHost binds a security group to a host
// If Security Group is already bound to IPAddress, returns *fail.ErrDuplicate
func (s stack) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	asg, xerr = s.InspectSecurityGroup(ctx, asg)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			// list ports to be able to remove them
			req := ports.ListOpts{
				DeviceID: ahf.Core.ID,
			}

			portList, xerr := s.rpcListPorts(ctx, req)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreError2(ctx, xerr)
				default:
					return xerr
				}
			}

			// In order to add a SG, port security has to be activated
			for _, p := range portList {
				_, xerr = s.rpcChangePortSecurity(ctx, p.ID, true)
				if xerr != nil {
					if strings.Contains(xerr.Error(), "policy") {
						debug.IgnoreError2(ctx, xerr)
					} else {
						return xerr
					}
				}
			}

			// Fix for Stein
			if s.cfgOpts.ProviderName == "ovh" {
				return nil
			}

			return secgroups.AddServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// UnbindSecurityGroupFromHost unbinds a security group from a host
func (s stack) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(ctx,
		func() error {
			// Fix for Stein
			if s.cfgOpts.ProviderName == "ovh" {
				return nil
			}

			return secgroups.RemoveServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}
