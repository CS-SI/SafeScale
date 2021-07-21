/*
 * Copyright 2018-2021, CS Systemes d'Information, http://csgroup.eu
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
	"fmt"
	"strings"
	"time"

	"github.com/asaskevich/govalidator"
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

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// ListRegions ...
func (s Stack) ListRegions() (list []string, xerr fail.Error) {
	var emptySlice []string
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	var allPages pagination.Page
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			listOpts := regions.ListOpts{
				//ParentRegionID: "RegionOne",
			}
			allPages, innerErr = regions.List(s.IdentityClient, listOpts).AllPages()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}

	allRegions, err := regions.ExtractRegions(allPages)
	if err != nil {
		return emptySlice, fail.ConvertError(err)
	}

	var results []string
	for _, v := range allRegions {
		results = append(results, v.ID)
	}
	return results, nil
}

// ListAvailabilityZones lists the usable AvailabilityZones
func (s Stack) ListAvailabilityZones() (list map[string]bool, xerr fail.Error) {
	var emptyMap map[string]bool
	if s.IsNull() {
		return emptyMap, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	var allPages pagination.Page
	xerr = stacks.RetryableRemoteCall(
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
		logrus.Warnf("no Availability Zones detected !")
	}

	return azList, nil
}

// ListImages lists available OS images
func (s Stack) ListImages() (imgList []abstract.Image, xerr fail.Error) {
	var emptySlice []abstract.Image
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	opts := images.ListOpts{
		Status: images.ImageStatusActive,
		Sort:   "name=asc,updated_at:desc",
	}

	// Retrieve a pager (i.e. a paginated collection)
	pager := images.List(s.ComputeClient, opts)

	// Define an anonymous function to be executed on each page's iteration
	imgList = []abstract.Image{}
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		imageList, err := images.ExtractImages(page)
		if err != nil {
			return false, err
		}

		for _, img := range imageList {
			imgList = append(imgList, abstract.Image{ID: img.ID, Name: img.Name})
		}
		return true, nil
	})
	if err != nil {
		return emptySlice, NormalizeError(err)
	}
	return imgList, nil
}

// InspectImage returns the Image referenced by id
func (s Stack) InspectImage(id string) (_ abstract.Image, xerr fail.Error) {
	nullAI := abstract.Image{}
	if s.IsNull() {
		return nullAI, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAI, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	var img *images.Image
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			img, innerErr = images.Get(s.ComputeClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullAI, xerr
	}

	out := abstract.Image{
		ID:       img.ID,
		Name:     img.Name,
		DiskSize: int64(img.MinDiskGigabytes),
	}
	return out, nil
}

// InspectTemplate returns the Template referenced by id
func (s Stack) InspectTemplate(id string) (template abstract.HostTemplate, xerr fail.Error) {
	nullAHT := abstract.HostTemplate{}
	if s.IsNull() {
		return nullAHT, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAHT, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	// Try to get template
	var flv *flavors.Flavor
	xerr = stacks.RetryableRemoteCall(
		func() (innerErr error) {
			flv, innerErr = flavors.Get(s.ComputeClient, id).Extract()
			return innerErr
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullAHT, xerr
	}
	template = abstract.HostTemplate{
		Cores:    flv.VCPUs,
		RAMSize:  float32(flv.RAM) / 1000.0,
		DiskSize: flv.Disk,
		ID:       flv.ID,
		Name:     flv.Name,
	}
	return template, nil
}

// ListTemplates lists available IPAddress templates
// IPAddress templates are sorted using Dominant Resource Fairness Algorithm
func (s Stack) ListTemplates() ([]abstract.HostTemplate, fail.Error) {
	var emptySlice []abstract.HostTemplate
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering()
	defer tracer.Exiting()

	opts := flavors.ListOpts{}

	var flvList []abstract.HostTemplate
	xerr := stacks.RetryableRemoteCall(
		func() error {
			return flavors.ListDetail(s.ComputeClient, opts).EachPage(func(page pagination.Page) (bool, error) {
				list, err := flavors.ExtractFlavors(page)
				if err != nil {
					return false, err
				}
				flvList = make([]abstract.HostTemplate, 0, len(list))
				for _, v := range list {
					flvList = append(flvList, abstract.HostTemplate{
						Cores:    v.VCPUs,
						RAMSize:  float32(v.RAM) / 1000.0,
						DiskSize: v.Disk,
						ID:       v.ID,
						Name:     v.Name,
					})
				}
				return true, nil
			})
		},
		NormalizeError,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return emptySlice, xerr
		default:
			return emptySlice, xerr
		}
	}
	if len(flvList) == 0 {
		logrus.Debugf("Template list empty")
	}
	return flvList, nil
}

// CreateKeyPair TODO: replace with code to create KeyPair on provider side if it exists
// creates and import a key pair
func (s Stack) CreateKeyPair(name string) (*abstract.KeyPair, fail.Error) {
	nullAKP := &abstract.KeyPair{}
	if s.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAKP, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", name).WithStopwatch().Entering()
	defer tracer.Exiting()

	return abstract.NewKeyPair(name)
}

// InspectKeyPair TODO: replace with openstack code to get keypair (if it exits)
// returns the key pair identified by id
func (s Stack) InspectKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	nullAKP := &abstract.KeyPair{}
	if s.IsNull() {
		return nullAKP, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAKP, fail.InvalidParameterError("id", "cannot be empty string")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering()
	defer tracer.Exiting()

	kp, err := keypairs.Get(s.ComputeClient, id).Extract()
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
func (s Stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	var emptySlice []abstract.KeyPair
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	var kpList []abstract.KeyPair
	xerr := stacks.RetryableRemoteCall(
		func() error {
			return keypairs.List(s.ComputeClient).EachPage(func(page pagination.Page) (bool, error) {
				list, err := keypairs.ExtractKeyPairs(page)
				if err != nil {
					return false, err
				}

				for _, v := range list {
					kpList = append(kpList, abstract.KeyPair{
						ID:         v.Name,
						Name:       v.Name,
						PublicKey:  v.PublicKey,
						PrivateKey: v.PrivateKey,
					})
				}
				return true, nil
			})
		},
		NormalizeError,
	)
	if xerr != nil {
		return emptySlice, xerr
	}
	// Note: empty list is not an error, so do not raise one
	return kpList, nil
}

// DeleteKeyPair deletes the key pair identified by id
func (s Stack) DeleteKeyPair(id string) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	if id == "" {
		return fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()

	xerr := stacks.RetryableRemoteCall(
		func() error {
			return keypairs.Delete(s.ComputeClient, id).ExtractErr()
		},
		NormalizeError,
	)
	if xerr != nil {
		return xerr
	}
	return nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into abstract.HostEffectiveSizing
func (s Stack) toHostSize(flavor map[string]interface{}) (ahes *abstract.HostEffectiveSizing) {
	hostSizing := abstract.NewHostEffectiveSizing()
	if i, ok := flavor["id"]; ok {
		fid, ok := i.(string)
		if !ok {
			return hostSizing
		}
		tpl, xerr := s.InspectTemplate(fid)
		if xerr != nil {
			return hostSizing
		}
		hostSizing.Cores = tpl.Cores
		hostSizing.DiskSize = tpl.DiskSize
		hostSizing.RAMSize = tpl.RAMSize
	} else if _, ok := flavor["vcpus"]; ok {
		hostSizing.Cores = flavor["vcpus"].(int)
		hostSizing.DiskSize = flavor["disk"].(int)
		hostSizing.RAMSize = flavor["ram"].(float32) / 1000.0
	}
	return hostSizing
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
func (s Stack) InspectHost(hostParam stacks.HostParameter) (*abstract.HostFull, fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHF, xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).WithStopwatch().Entering().Exiting()

	server, xerr := s.WaitHostState(ahf, hoststate.Started, temporal.GetOperationTimeout())
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			return nullAHF, xerr
		default:
			return nullAHF, xerr
		}
	}

	state := toHostState(server.Status)
	ahf.CurrentState, ahf.Core.LastState = state, state

	if !ahf.OK() {
		logrus.Warnf("[TRACE] Unexpected host status: %s", spew.Sdump(ahf))
	}

	return ahf, nil
}

// complementHost complements IPAddress data with content of server parameter
func (s Stack) complementHost(hostCore *abstract.HostCore, server servers.Server, hostNets []servers.Network, hostPorts []ports.Port) (host *abstract.HostFull, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	// Updates intrinsic data of host if needed
	if hostCore.ID == "" {
		hostCore.ID = server.ID
	}
	if hostCore.Name == "" {
		hostCore.Name = server.Name
	}

	state := toHostState(server.Status)
	if state == hoststate.Error || state == hoststate.Starting {
		logrus.Warnf("[TRACE] Unexpected host's last state: %v", state)
	}

	host = abstract.NewHostFull()
	host.Core = hostCore
	host.CurrentState, hostCore.LastState = state, state
	host.Description = &abstract.HostDescription{
		Created: server.Created,
		Updated: server.Updated,
	}

	host.Sizing = s.toHostSize(server.Flavor)

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
					if govalidator.IsIPv6(ip.IPAddress) {
						ipv6 = ip.IPAddress
					} else {
						ipv4 = ip.IPAddress
					}
				}
			}
		}

		// Fill the name of subnets
		for k := range subnetsByID {
			as, xerr := s.InspectSubnet(k)
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
				if govalidator.IsIPv6(ip.IPAddress) {
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
func (s Stack) InspectHostByName(name string) (*abstract.HostFull, fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}
	if name == "" {
		return nullAHF, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "('%s')", name).WithStopwatch().Entering().Exiting()

	// Gophercloud doesn't propose the way to get a host by name, but OpenStack knows how to do it...
	r := servers.GetResult{}
	xerr := stacks.RetryableRemoteCall(
		func() error {
			_, r.Err = s.ComputeClient.Get(s.ComputeClient.ServiceURL("servers?name="+name), &r.Body, &gophercloud.RequestOpts{
				OkCodes: []int{200, 203},
			})
			return r.Err
		},
		NormalizeError,
	)
	if xerr != nil {
		return nullAHF, xerr
	}

	serverList, found := r.Body.(map[string]interface{})["servers"].([]interface{})
	if found && len(serverList) > 0 {
		for _, anon := range serverList {
			entry := anon.(map[string]interface{})
			if entry["name"].(string) == name {
				host := abstract.NewHostCore()
				host.ID = entry["id"].(string)
				host.Name = name
				hostFull, xerr := s.InspectHost(host)
				if xerr != nil {
					return nullAHF, fail.Wrap(xerr, "failed to inspect host '%s'", name)
				}
				return hostFull, nil
			}
		}
	}
	return nullAHF, abstract.ResourceNotFoundError("host", name)
}

// CreateHost creates a new host
func (s Stack) CreateHost(request abstract.HostRequest) (host *abstract.HostFull, userData *userdata.Content, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	nullUDC := userdata.NewContent()
	if s.IsNull() {
		return nullAHF, nullUDC, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", request.ResourceName).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&xerr)

	// msgFail := "failed to create Host resource: %s"
	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if len(request.Subnets) == 0 && !request.PublicIP {
		return nullAHF, nullUDC, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without --public flag and without attached Network/Subnet")
	}

	// The Default Networking is the first of the provided list, by convention
	defaultSubnet := request.Subnets[0]
	defaultSubnetID := defaultSubnet.ID

	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nullAHF, nullUDC, fail.Wrap(xerr, "failed to provide credentials for the host")
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData = userdata.NewContent()
	xerr = userData.Prepare(s.cfgOpts, request, defaultSubnet.CIDR, "")
	if xerr != nil {
		xerr = fail.Wrap(xerr, "failed to prepare user data content")
		logrus.Debugf(strprocess.Capitalize(xerr.Error()))
		return nullAHF, nullUDC, xerr
	}

	template, xerr := s.InspectTemplate(request.TemplateID)
	if xerr != nil {
		return nullAHF, nullUDC, fail.Wrap(xerr, "failed to get image")
	}

	// Sets provider parameters to create host
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}

	// Select usable availability zone, the first one in the list
	azone, xerr := s.SelectedAvailabilityZone()
	if xerr != nil {
		return nullAHF, nullUDC, fail.Wrap(xerr, "failed to select availability zone")
	}

	// --- Initializes abstract.HostCore ---

	ahc := abstract.NewHostCore()
	ahc.PrivateKey = userData.FirstPrivateKey
	ahc.Password = request.Password

	// --- query provider for host creation ---

	logrus.Debugf("Creating host resource '%s' ...", request.ResourceName)
	// Retry creation until success, for 10 minutes
	var (
		server       *servers.Server
		hostNets     []servers.Network
		hostPorts    []ports.Port
		createdPorts []string
	)
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var innerXErr fail.Error

			hostNets, hostPorts, createdPorts, innerXErr = s.identifyOpenstackSubnetsAndPorts(request, defaultSubnet)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrDuplicate: // This kind of error means actually there is no more Ip address available
					return retry.StopRetryError(innerXErr)
				default:
					return fail.Wrap(xerr, "failed to construct list of Subnets for the Host")
				}
			}

			// Starting from here, delete created ports if exiting with error
			defer func() {
				if innerXErr != nil {
					if derr := s.deletePortsInSlice(createdPorts); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete ports"))
					}
				}
			}()

			server, innerXErr = s.rpcCreateServer(request.ResourceName, hostNets, request.TemplateID, request.ImageID, userDataPhase1, azone)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrStopRetry:
					innerXErr = fail.ConvertError(innerXErr.Cause())
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(innerXErr)
				}
				if server != nil && server.ID != "" {
					if derr := s.DeleteHost(server.ID); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete host '%s'", request.ResourceName))
					}
				}
				return innerXErr
			}
			if server == nil || server.ID == "" {
				innerXErr = fail.NewError("failed to create server")
				return innerXErr
			}

			ahc.ID = server.ID
			ahc.Name = request.ResourceName

			// Starting from here, delete host if exiting with error
			defer func() {
				if innerXErr != nil {
					logrus.Debugf("deleting unresponsive server '%s'...", request.ResourceName)
					if derr := s.DeleteHost(ahc.ID); derr != nil {
						logrus.Debugf(derr.Error())
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host '%s'", request.ResourceName))
						return
					}
					logrus.Debugf("unresponsive server '%s' deleted", request.ResourceName)
				}
			}()

			creationZone, innerXErr := s.GetAvailabilityZoneOfServer(ahc.ID)
			if innerXErr != nil {
				logrus.Tracef("Host '%s' successfully created but cannot confirm AZ: %s", ahc.Name, innerXErr)
			} else {
				logrus.Tracef("Host '%s' successfully created in requested AZ '%s'", ahc.Name, creationZone)
				if creationZone != azone && azone != "" {
					logrus.Warnf("Host '%s' created in the WRONG availability zone: requested '%s' and got instead '%s'", ahc.Name, azone, creationZone)
				}
			}

			// Wait that host is ready, not just that the build is started
			timeout := temporal.GetHostTimeout()
			server, innerXErr = s.WaitHostState(ahc, hoststate.Started, timeout)
			if innerXErr != nil {
				logrus.Errorf("failed to reach server '%s' after %s; deleting it and trying again", request.ResourceName, temporal.FormatDuration(timeout))
				switch innerXErr.(type) {
				case *fail.ErrNotAvailable:
					return fail.Wrap(innerXErr, "host '%s' is in Error state", request.ResourceName)
				default:
					return fail.Wrap(innerXErr, "timeout waiting host '%s' ready", request.ResourceName)
				}
			}
			return nil
		},
		temporal.GetLongOperationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			if cerr := xerr.Cause(); cerr != nil {
				xerr = fail.ConvertError(cerr)
			}
		case *retry.ErrStopRetry:
			if cerr := xerr.Cause(); cerr != nil {
				xerr = fail.ConvertError(cerr)
			}
		}
		return nullAHF, nullUDC, xerr
	}

	// Starting from here, delete host if exiting with error
	defer func() {
		if xerr != nil {
			logrus.Infof("Cleaning up on failure, deleting host '%s'", ahc.Name)
			if derr := s.DeleteHost(ahc.ID); derr != nil {
				switch derr.(type) {
				case *fail.ErrNotFound:
					logrus.Errorf("Cleaning up on failure, failed to delete host, resource not found: '%v'", derr)
				case *fail.ErrTimeout:
					logrus.Errorf("Cleaning up on failure, failed to delete host, timeout: '%v'", derr)
				default:
					logrus.Errorf("Cleaning up on failure, failed to delete host: '%v'", derr)
				}
				_ = fail.AddConsequence(xerr, derr)
			}
		}
	}()

	newHost, xerr := s.complementHost(ahc, *server, hostNets, hostPorts)
	if xerr != nil {
		return nullAHF, nullUDC, xerr
	}
	newHost.Networking.DefaultSubnetID = defaultSubnetID
	// newHost.Networking.DefaultGatewayID = defaultGatewayID
	// newHost.Networking.DefaultGatewayPrivateIP = request.DefaultRouteIP
	newHost.Networking.IsGateway = request.IsGateway
	newHost.Sizing = converters.HostTemplateToHostEffectiveSizing(template)

	// if Floating IP are used and public address is requested
	if s.cfgOpts.UseFloatingIP && request.PublicIP {
		// Create the floating IP
		var ip *floatingips.FloatingIP
		if ip, xerr = s.rpcCreateFloatingIP(); xerr != nil {
			return nullAHF, nullUDC, xerr
		}

		// Starting from here, delete Floating IP if exiting with error
		defer func() {
			if xerr != nil {
				logrus.Debugf("Cleaning up on failure, deleting floating ip '%s'", ip.ID)
				if derr := s.rpcDeleteFloatingIP(ip.ID); derr != nil {
					derr = fail.Wrap(derr, "cleaning up on failure, failed to delete Floating IP")
					_ = xerr.AddConsequence(derr)
					logrus.Error(derr.Error())
				} else {
					logrus.Debugf("Cleaning up on failure, floating ip '%s' successfully deleted", ip.ID)
				}
			}
		}()

		// Associate floating IP to host
		xerr = stacks.RetryableRemoteCall(
			func() error {
				return floatingips.AssociateInstance(s.ComputeClient, newHost.Core.ID, floatingips.AssociateOpts{
					FloatingIP: ip.IP,
				}).ExtractErr()
			},
			NormalizeError,
		)
		if xerr != nil {
			return nullAHF, nullUDC, xerr
		}

		if ipversion.IPv4.Is(ip.IP) {
			newHost.Networking.PublicIPv4 = ip.IP
		} else if ipversion.IPv6.Is(ip.IP) {
			newHost.Networking.PublicIPv6 = ip.IP
		}
		userData.PublicIP = ip.IP
	}

	logrus.Infoln(msgSuccess)
	return newHost, userData, nil
}

// deletePortsInSlice deletes ports listed in slice
func (s Stack) deletePortsInSlice(ports []string) fail.Error {
	var errors []error
	for _, v := range ports {
		if derr := s.rpcDeletePort(v); derr != nil {
			switch derr.(type) {
			case *fail.ErrNotFound:
				// consider a not found port as a successful deletion
				debug.IgnoreError(derr)
			default:
				errors = append(errors, fail.Wrap(derr, "failed to delete port %s", v))
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
func (s Stack) ClearHostStartupScript(hostParam stacks.HostParameter) fail.Error {
	return nil
}

func (s Stack) GetMetadataOfInstance(id string) (map[string]string, fail.Error) {
	return s.rpcGetMetadataOfInstance(id)
}

// identifyOpenstackSubnetsAndPorts ...
func (s Stack) identifyOpenstackSubnetsAndPorts(request abstract.HostRequest, defaultSubnet *abstract.Subnet) (nets []servers.Network, netPorts []ports.Port, createdPorts []string, xerr fail.Error) {
	nets = []servers.Network{}
	netPorts = []ports.Port{}
	createdPorts = []string{}

	// cleanup if exiting with error
	defer func() {
		if xerr != nil {
			if derr := s.deletePortsInSlice(createdPorts); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete ports"))
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
			NetworkID:    s.ProviderNetworkID,
			Name:         fmt.Sprintf("nic_%s_external", request.ResourceName),
			Description:  fmt.Sprintf("nic of host '%s' on external network %s", request.ResourceName, s.cfgOpts.ProviderNetwork),
			AdminStateUp: &adminState,
		}
		port, xerr := s.rpcCreatePort(req)
		if xerr != nil {
			return nets, netPorts, createdPorts, fail.Wrap(xerr, "failed to create port on external network '%s'", s.cfgOpts.ProviderNetwork)
		}
		createdPorts = append(createdPorts, port.ID)

		nets = append(nets, servers.Network{Port: port.ID})
		netPorts = append(netPorts, *port)
	}

	// private networks
	for _, n := range request.Subnets {
		req := ports.CreateOpts{
			NetworkID:   n.Network,
			Name:        fmt.Sprintf("nic_%s_subnet_%s", request.ResourceName, n.Name),
			Description: fmt.Sprintf("nic of host '%s' on subnet '%s'", request.ResourceName, n.Name),
			FixedIPs:    []ports.IP{{SubnetID: n.ID}},
		}
		port, xerr := s.rpcCreatePort(req)
		if xerr != nil {
			return nets, netPorts /*, sgs */, createdPorts, fail.Wrap(xerr, "failed to create port on subnet '%s'", n.Name)
		}

		createdPorts = append(createdPorts, port.ID)
		nets = append(nets, servers.Network{Port: port.ID})
		netPorts = append(netPorts, *port)
	}

	return nets, netPorts, createdPorts, nil
}

// GetAvailabilityZoneOfServer retrieves the availability zone of server 'serverID'
func (s Stack) GetAvailabilityZoneOfServer(serverID string) (string, fail.Error) {
	if s.IsNull() {
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
	xerr := stacks.RetryableRemoteCall(
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
func (s Stack) SelectedAvailabilityZone() (string, fail.Error) {
	if s.IsNull() {
		return "", fail.InvalidInstanceError()
	}

	if s.selectedAvailabilityZone == "" {
		s.selectedAvailabilityZone = s.GetAuthenticationOptions().AvailabilityZone
		if s.selectedAvailabilityZone == "" {
			azList, xerr := s.ListAvailabilityZones()
			if xerr != nil {
				return "", xerr
			}
			var azone string
			for azone = range azList {
				break
			}
			s.selectedAvailabilityZone = azone
		}
		logrus.Debugf("Selected Availability Zone: '%s'", s.selectedAvailabilityZone)
	}
	return s.selectedAvailabilityZone, nil
}

// WaitHostReady waits an host achieve ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s Stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	nullAHC := abstract.NewHostCore()
	if s.IsNull() {
		return nullAHC, fail.InvalidInstanceError()
	}

	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHC, xerr
	}

	server, xerr := s.WaitHostState(hostParam, hoststate.Started, timeout)
	if xerr != nil {
		return nullAHC, xerr
	}

	ahf, xerr = s.complementHost(ahf.Core, *server, nil, nil)
	if xerr != nil {
		return nullAHC, xerr
	}

	return ahf.Core, nil
}

// WaitHostState waits an host achieve defined state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter
func (s Stack) WaitHostState(hostParam stacks.HostParameter, state hoststate.Enum, timeout time.Duration) (server *servers.Server, xerr fail.Error) {
	nullServer := &servers.Server{}
	if s.IsNull() {
		return nullServer, fail.InvalidInstanceError()
	}

	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullServer, xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s, %s, %v)", hostLabel, state.String(), timeout).WithStopwatch().Entering().Exiting()

	retryErr := retry.WhileUnsuccessful(
		func() (innerErr error) {
			if ahf.Core.ID != "" {
				server, innerErr = s.rpcGetHostByID(ahf.Core.ID)
			} else {
				server, innerErr = s.rpcGetHostByName(ahf.Core.Name)
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
			// If state matches, we consider this a success no matter what
			if lastState == state {
				return nil
			}

			if lastState == hoststate.Error {
				return retry.StopRetryError(fail.NotAvailableError("state of Host '%s' is 'ERROR'", hostLabel))
			}

			if lastState != hoststate.Starting && lastState != hoststate.Stopping {
				return retry.StopRetryError(nil, "host status of '%s' is in state '%s', and that's not a transition state", hostLabel, server.Status)
			}

			return fail.NewError("host '%s' not ready yet", hostLabel)
		},
		temporal.GetMinDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *fail.ErrTimeout:
			retryErr = fail.TimeoutError(retryErr.Cause(), timeout, "timeout waiting to get host '%s' information after %v", hostLabel, timeout)
		case *fail.ErrAborted:
			retryErr = fail.ConvertError(retryErr.Cause())
		}
	}
	if retryErr != nil {
		return nullServer, retryErr
	}
	if server == nil {
		return nullServer, fail.NotFoundError("failed to query Host")
	}
	return server, nil
}

// GetHostState returns the current state of host identified by id
// hostParam can be a string or an instance of *abstract.HostCore; any other type will return an fail.InvalidParameterError
func (s Stack) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if s.IsNull() {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("Stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	host, xerr := s.InspectHost(hostParam)
	if xerr != nil {
		return hoststate.Error, xerr
	}
	return host.CurrentState, nil
}

// ListHosts lists all hosts
func (s Stack) ListHosts(details bool) (abstract.HostList, fail.Error) {
	var emptyList abstract.HostList
	if s.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "").WithStopwatch().Entering().Exiting()

	hostList := abstract.HostList{}
	xerr := stacks.RetryableRemoteCall(
		func() error {
			return servers.List(s.ComputeClient, servers.ListOpts{}).EachPage(func(page pagination.Page) (bool, error) {
				list, err := servers.ExtractServers(page)
				if err != nil {
					return false, err
				}

				for _, srv := range list {
					ahc := abstract.NewHostCore()
					ahc.ID = srv.ID
					var ahf *abstract.HostFull
					if details {
						ahf, err = s.complementHost(ahc, srv, nil, nil)
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
			})
		},
		NormalizeError,
	)
	return hostList, xerr
}

// getFloatingIP returns the floating IP associated with the host identified by hostID
// By convention only one floating IP is allocated to an host
func (s Stack) getFloatingIP(hostID string) (*floatingips.FloatingIP, fail.Error) {
	var fips []floatingips.FloatingIP
	xerr := stacks.RetryableRemoteCall(
		func() error {
			return floatingips.List(s.ComputeClient).EachPage(func(page pagination.Page) (bool, error) {
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
			})
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
		return nil, fail.InconsistentError("configuration error, more than one Floating IP associated to host '%s'", hostID)
	}
	return &fips[0], nil
}

// DeleteHost deletes the host identified by id
func (s Stack) DeleteHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// Detach floating IP
	if s.cfgOpts.UseFloatingIP {
		fip, xerr := s.getFloatingIP(ahf.Core.ID)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
				debug.IgnoreError(xerr)
			default:
				return fail.Wrap(xerr, "failed to find floating ip of host '%s'", hostRef)
			}
		} else if fip != nil {
			err := floatingips.DisassociateInstance(s.ComputeClient, ahf.Core.ID, floatingips.DisassociateOpts{
				FloatingIP: fip.IP,
			}).ExtractErr()
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
	portList, xerr := s.rpcListPorts(req)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	// Try to remove host for 3 minutes
	xerr = retry.WhileUnsuccessful(
		func() error {
			if innerXErr := s.rpcDeleteServer(ahf.Core.ID); innerXErr != nil {
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
			var state hoststate.Enum = hoststate.Unknown
			innerXErr := retry.WhileUnsuccessfulDelay5Seconds(
				func() error {
					server, gerr := s.rpcGetServer(ahf.Core.ID)
					if gerr != nil {
						switch gerr.(type) { //nolint
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
				temporal.GetContextTimeout(),
			)
			if innerXErr != nil {
				return innerXErr
			}
			if state == hoststate.Error {
				return fail.NotAvailableError("failed to trigger server deletion, retrying...")
			}
			return nil
		},
		0,
		temporal.GetHostCleanupTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout, *retry.ErrStopRetry:
			// On timeout or abort, recover the error cause
			xerr = fail.ConvertError(xerr.Cause())
		}
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// if host disappeared (rpcListPorts succeeded and host was still there at this moment), consider the error as a successful deletion;
			// leave a chance to remove ports
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	// Removes ports freed from host
	var errors []error
	for _, v := range portList {
		if derr := s.rpcDeletePort(v.ID); derr != nil {
			switch derr.(type) {
			case *fail.ErrNotFound:
				// consider a not found port as a successful deletion
				debug.IgnoreError(derr)
			default:
				errors = append(errors, fail.Wrap(derr, "failed to delete port %s (%s)", v.ID, v.Description))
			}
		}
	}
	if len(errors) > 0 {
		return fail.NewErrorList(errors)
	}

	return nil
}

// rpcGetServer returns
func (s Stack) rpcGetServer(id string) (_ *servers.Server, xerr fail.Error) {
	if id == "" {
		return &servers.Server{}, fail.InvalidParameterCannotBeEmptyStringError("id")
	}

	var resp *servers.Server
	xerr = stacks.RetryableRemoteCall(
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
func (s Stack) StopHost(hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(
		func() error {
			return startstop.Stop(s.ComputeClient, ahf.Core.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// RebootHost reboots unconditionally the host identified by id
func (s Stack) RebootHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// Try first a soft reboot, and if it fails (because host isn't in ACTIVE state), tries a hard reboot
	return stacks.RetryableRemoteCall(
		func() error {
			innerErr := servers.Reboot(s.ComputeClient, ahf.Core.ID, servers.RebootOpts{Type: servers.SoftReboot}).ExtractErr()
			if innerErr != nil {
				innerErr = servers.Reboot(s.ComputeClient, ahf.Core.ID, servers.RebootOpts{Type: servers.HardReboot}).ExtractErr()
			}
			return innerErr
		},
		NormalizeError,
	)
}

// StartHost starts the host identified by id
func (s Stack) StartHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	return stacks.RetryableRemoteCall(
		func() error {
			return startstop.Start(s.ComputeClient, ahf.Core.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// ResizeHost ...
func (s Stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}
	_ /*ahf*/, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHF, xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.openstack") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// TODO: RESIZE Resize IPAddress HERE
	logrus.Warn("Trying to resize a Host...")

	// TODO: RESIZE Call this
	// servers.Resize()

	return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// BindSecurityGroupToHost binds a security group to a host
// If Security Group is already bound to IPAddress, returns *fail.ErrDuplicate
func (s Stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	asg, xerr = s.InspectSecurityGroup(asg)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(
		func() error {
			return secgroups.AddServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}

// UnbindSecurityGroupFromHost unbinds a security group from a host
func (s Stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	return stacks.RetryableRemoteCall(
		func() error {
			return secgroups.RemoveServer(s.ComputeClient, ahf.Core.ID, asg.ID).ExtractErr()
		},
		NormalizeError,
	)
}
