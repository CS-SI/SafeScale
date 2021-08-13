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

package gcp

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// -------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s stack) ListImages() (out []abstract.Image, xerr fail.Error) {
	var emptySlice []abstract.Image
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	resp, xerr := s.rpcListImages()
	if xerr != nil {
		return emptySlice, xerr
	}
	out = make([]abstract.Image, 0, len(resp))
	for _, v := range resp {
		out = append(out, toAbstractImage(*v))
	}
	return out, nil
}

func toAbstractImage(in compute.Image) abstract.Image {
	return abstract.Image{
		Name:        in.Name,
		URL:         in.SelfLink,
		ID:          strconv.FormatUint(in.Id, 10),
		Description: in.Description,
		DiskSize:    in.DiskSizeGb,
	}
}

// InspectImage returns the Image referenced by id
func (s stack) InspectImage(id string) (_ abstract.Image, xerr fail.Error) {
	nullAI := abstract.Image{}
	if s.IsNull() {
		return nullAI, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAI, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	resp, xerr := s.rpcGetImageByID(id)
	if xerr != nil {
		return nullAI, xerr
	}
	return toAbstractImage(*resp), nil
}

// -------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStackGcp ListTemplate method to filter wind and flex instance and add GPU configuration
func (s stack) ListTemplates() (templates []abstract.HostTemplate, xerr fail.Error) {
	var emptySlice []abstract.HostTemplate
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	resp, xerr := s.rpcListMachineTypes()
	if xerr != nil {
		return emptySlice, xerr
	}

	templates = make([]abstract.HostTemplate, 0, len(resp))
	for _, v := range resp {
		templates = append(templates, toAbstractHostTemplate(*v))
	}
	return templates, nil
}

func toAbstractHostTemplate(in compute.MachineType) abstract.HostTemplate {
	return abstract.HostTemplate{
		Cores:   int(in.GuestCpus),
		RAMSize: float32(in.MemoryMb / 1024),
		// GCP Template disk sizing is ridiculous at best, so fill it to 0 and let us size the disk ourselves
		// DiskSize: int(v.ImageSpaceGb),
		DiskSize: 0,
		ID:       strconv.FormatUint(in.Id, 10),
		Name:     in.Name,
	}
}

// InspectTemplate ...
func (s stack) InspectTemplate(id string) (_ abstract.HostTemplate, xerr fail.Error) {
	nullAHT := abstract.HostTemplate{}
	if s.IsNull() {
		return nullAHT, fail.InvalidInstanceError()
	}
	if id == "" {
		return nullAHT, fail.InvalidParameterError("id", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%s)", id).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	resp, xerr := s.rpcGetMachineType(id)
	if xerr != nil {
		return nullAHT, xerr
	}
	return toAbstractHostTemplate(*resp), nil
}

// -------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair FIXME: change code to really create a keypair on provider side
// CreateKeyPair creates and import a key pair
func (s stack) CreateKeyPair(name string) (_ *abstract.KeyPair, xerr fail.Error) {
	if s.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute")).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)

	return abstract.NewKeyPair(name)
}

// InspectKeyPair returns the key pair identified by id
func (s stack) InspectKeyPair(id string) (*abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("InspectKeyPair() not implemented yet") // FIXME: Technical debt
}

// ListKeyPairs lists available key pairs
func (s stack) ListKeyPairs() ([]abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("ListKeyPairs() not implemented yet") // FIXME: Technical debt
}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(id string) fail.Error {
	return fail.NotImplementedError("DeleteKeyPair() not implemented yet") // FIXME: Technical debt
}

// CreateHost creates a host meeting the requirements specified by request
func (s stack) CreateHost(request abstract.HostRequest) (ahf *abstract.HostFull, userData *userdata.Content, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	nullUD := userdata.NewContent()
	if s.IsNull() {
		return nullAHF, nullUD, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%v)", request).WithStopwatch().Entering().Exiting()
	defer fail.OnExitLogError(&xerr)
	defer fail.OnPanic(&xerr)

	resourceName := request.ResourceName
	subnets := request.Subnets
	hostMustHavePublicIP := request.PublicIP || request.Single

	if len(subnets) == 0 {
		return nullAHF, nullUD, fail.InvalidRequestError("the host %s must be on at least one network (even if public)", resourceName)
	}

	// If no key pair is supplied create one
	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nullAHF, nullUD, fail.Wrap(xerr, "failed to provide credentials for Host")
	}

	defaultSubnet := request.Subnets[0]
	defaultSubnetID := defaultSubnet.ID
	an, xerr := s.InspectNetwork(defaultSubnet.Network)
	if xerr != nil {
		switch xerr.(type) { //nolint
		case *fail.ErrNotFound:
			an, xerr = s.InspectNetworkByName(defaultSubnet.Network)
			if xerr != nil {
				return nullAHF, nullUD, fail.NotFoundError("failed to find Network %s", defaultSubnet.Network)
			}
		default:
			return nullAHF, nullUD, fail.NotFoundError("failed to find Network %s", defaultSubnet.Network)
		}
	}

	if request.DefaultRouteIP == "" && !hostMustHavePublicIP {
		return nullAHF, nullUD, fail.InvalidRequestError("the host '%s' must have a gateway or be public", resourceName)
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData = userdata.NewContent()
	if xerr = userData.Prepare(*s.Config, request, defaultSubnet.CIDR, ""); xerr != nil {
		xerr = fail.Wrap(xerr, "failed to prepare user data content")
		logrus.Debugf(strprocess.Capitalize(xerr.Error()))
		return nullAHF, nullUD, xerr
	}

	// Determine system disk size based on vcpus count
	template, xerr := s.InspectTemplate(request.TemplateID)
	if xerr != nil {
		return nullAHF, nullUD, fail.Wrap(xerr, "failed to get image")
	}

	if request.DiskSize > template.DiskSize {
		template.DiskSize = request.DiskSize
	} else if template.DiskSize == 0 {
		// Determines appropriate disk size
		switch {
		case template.Cores < 16:
			template.DiskSize = 100
		case template.Cores < 32:
			template.DiskSize = 200
		default:
			template.DiskSize = 400
		}
	}

	rim, xerr := s.InspectImage(request.ImageID)
	if xerr != nil {
		return nullAHF, nullUD, xerr
	}

	logrus.Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

	// Select usable availability zone, the first one in the list
	if s.GcpConfig.Zone == "" {
		azList, xerr := s.ListAvailabilityZones()
		if xerr != nil {
			return nullAHF, nullUD, xerr
		}
		var az string
		for az = range azList {
			break
		}
		s.GcpConfig.Zone = az
		logrus.Debugf("Selected Availability Zone: '%s'", az)
	}

	// Sets provider parameters to create ahf
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nullAHF, nullUD, xerr
	}

	// FIXME: if host is single, we need to create firewall rules for the net-safescale network. But should they be
	//        created here, as they won't have associated metadata ?

	// --- query provider for Host creation ---

	logrus.Debugf("requesting host '%s' resource creation...", request.ResourceName)

	// Retry creation until success, for 10 minutes
	retryErr := retry.WhileUnsuccessful(
		func() error {
			var innerXErr fail.Error
			if ahf, innerXErr = s.buildGcpMachine(request.ResourceName, an, defaultSubnet, template, rim.URL, string(userDataPhase1), hostMustHavePublicIP, request.SecurityGroupIDs); innerXErr != nil {
				captured := normalizeError(innerXErr)
				switch captured.(type) {
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(captured)
				default:
					return captured
				}
			}

			// Starting from here, delete host if exiting with error, to be in good shape to retry
			defer func() {
				if innerXErr != nil {
					hostName := ahf.GetName()
					logrus.Debugf("Clean up on failure, deleting host '%s'", hostName)
					if derr := s.DeleteHost(ahf); derr != nil {
						msg := fmt.Sprintf("cleaning up on failure, failed to delete Host '%s'", hostName)
						logrus.Errorf(strprocess.Capitalize(msg))
						_ = innerXErr.AddConsequence(fail.Wrap(derr, msg))
					} else {
						logrus.Debugf("Cleaning up on failure, deleted Host '%s' successfully.", hostName)
					}
				}
			}()

			// Wait that Host is ready, not just that the build is started
			if _, innerXErr = s.WaitHostReady(ahf.GetID(), temporal.GetLongOperationTimeout()); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrInvalidRequest:
					return retry.StopRetryError(innerXErr)
				default:
					return innerXErr
				}
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		temporal.GetLongOperationTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return nullAHF, nullUD, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nullAHF, nullUD, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return nullAHF, nullUD, retryErr
		}
	}

	logrus.Debugf("Host '%s' created.", ahf.GetName())

	// Add to abstract.HostFull data that does not come with creation data from provider
	ahf.Core.PrivateKey = userData.FirstPrivateKey // Add PrivateKey to Host description
	ahf.Core.Password = request.Password           // and OperatorUsername's password
	ahf.Networking.IsGateway = request.IsGateway
	ahf.Networking.DefaultSubnetID = defaultSubnetID
	ahf.Sizing = converters.HostTemplateToHostEffectiveSizing(template)

	return ahf, userData, nil
}

// WaitHostReady waits until a host reaches ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return an utils.ErrInvalidParameter.
func (s stack) WaitHostReady(hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, xerr fail.Error) {
	nullAHC := abstract.NewHostCore()
	if s.IsNull() {
		return nullAHC, fail.InvalidInstanceError()
	}
	ahf, hostRef, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHC, xerr
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostRef).Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	retryErr := retry.WhileUnsuccessful(
		func() error {
			hostComplete, innerErr := s.InspectHost(ahf)
			if innerErr != nil {
				return innerErr
			}

			if hostComplete.CurrentState != hoststate.Started {
				return fail.NotAvailableError("not in ready state (current state: %s)", hostComplete.CurrentState.String())
			}
			return nil
		},
		temporal.GetDefaultDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return nullAHC, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nullAHC, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return nullAHC, retryErr
		}
	}

	return ahf.Core, nil
}

// buildGcpMachine ...
func (s stack) buildGcpMachine(
	instanceName string,
	network *abstract.Network,
	subnet *abstract.Subnet,
	template abstract.HostTemplate,
	imageURL string,
	userdata string,
	isPublic bool,
	securityGroups map[string]struct{},
) (*abstract.HostFull, fail.Error) {

	nullAHF := abstract.NewHostFull()
	resp, xerr := s.rpcCreateInstance(instanceName, network.Name, subnet.ID, subnet.Name, template.Name, imageURL, int64(template.DiskSize), userdata, isPublic, securityGroups)
	if xerr != nil {
		return nullAHF, xerr
	}

	ahf := abstract.NewHostFull()
	if xerr = s.complementHost(ahf, resp); xerr != nil {
		return nullAHF, xerr
	}

	return ahf, nil
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
func (s stack) ClearHostStartupScript(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}
	if !ahf.IsConsistent() {
		return fail.InvalidParameterError("hostParam", "must be either ID as string or an '*abstract.HostCore' or '*abstract.HostFull' with value in 'ID' field")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).Entering()
	defer tracer.Exiting()
	defer fail.OnPanic(&xerr)

	return s.rpcResetStartupScriptOfInstance(ahf.GetID())
}

// InspectHost returns the host identified by ref (name or id) or by a *abstract.HostFull containing an id
func (s stack) InspectHost(hostParam stacks.HostParameter) (host *abstract.HostFull, xerr fail.Error) {
	nullAHF := abstract.NewHostFull()
	if s.IsNull() {
		return nullAHF, fail.InvalidInstanceError()
	}

	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nullAHF, xerr
	}
	if !ahf.IsConsistent() {
		return nullAHF, fail.InvalidParameterError("hostParam", "must be either ID as string or an '*abstract.HostCore' or '*abstract.HostFull' with value in 'ID' field")
	}

	tracer := debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).Entering()
	defer tracer.Exiting()
	defer fail.OnPanic(&xerr)

	var (
		tryByName = true
		instance  *compute.Instance
	)
	if ahf.Core.ID != "" {
		if instance, xerr = s.rpcGetInstance(ahf.Core.ID); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
				debug.IgnoreError(xerr)
			default:
				return nullAHF, xerr
			}
		} else {
			tryByName = false
		}
	}
	if tryByName && ahf.Core.Name != "" {
		instance, xerr = s.rpcGetInstance(ahf.Core.Name)
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nullAHF, fail.NotFoundError("failed to find Host %s", hostLabel)
		default:
			return nullAHF, xerr
		}
	}

	if xerr = s.complementHost(ahf, instance); xerr != nil {
		return nullAHF, xerr
	}

	return ahf, nil
}

func (s stack) complementHost(host *abstract.HostFull, instance *compute.Instance) fail.Error {
	state, xerr := stateConvert(instance.Status)
	if xerr != nil {
		return xerr
	}

	host.CurrentState, host.Core.LastState = state, state
	host.Core.Name = instance.Name
	host.Core.ID = fmt.Sprintf("%d", instance.Id)

	var subnets []IPInSubnet
	for _, nit := range instance.NetworkInterfaces {
		snet := genURL(nit.Subnetwork)
		if !utils.IsEmpty(snet) {
			pubIP := ""
			for _, aco := range nit.AccessConfigs {
				if aco != nil {
					if aco.NatIP != "" {
						pubIP = aco.NatIP
					}
				}
			}

			subnets = append(subnets, IPInSubnet{
				Subnet:   snet,
				IP:       nit.NetworkIP,
				PublicIP: pubIP,
			})
		}
	}

	var resourceNetworks []IPInSubnet
	for _, sn := range subnets {
		region, xerr := getRegionFromSelfLink(sn.Subnet)
		if xerr != nil {
			continue
		}
		psg, xerr := s.rpcGetSubnetByNameAndRegion(getResourceNameFromSelfLink(sn.Subnet), region)
		if xerr != nil {
			continue
		}

		resourceNetworks = append(resourceNetworks, IPInSubnet{
			Subnet:   sn.Subnet,
			Name:     psg.Name,
			ID:       strconv.FormatUint(psg.Id, 10),
			IP:       sn.IP,
			PublicIP: sn.PublicIP,
		})
	}

	ip4BySubnetID := make(map[string]string)
	subnetNameByID := make(map[string]string)
	subnetIDByName := make(map[string]string)

	ipv4 := ""
	for _, rn := range resourceNetworks {
		ip4BySubnetID[rn.ID] = rn.IP
		subnetNameByID[rn.ID] = rn.Name
		subnetIDByName[rn.Name] = rn.ID
		if rn.PublicIP != "" {
			ipv4 = rn.PublicIP
		}
	}

	host.Networking.IPv4Addresses = ip4BySubnetID
	host.Networking.SubnetsByID = subnetNameByID
	host.Networking.SubnetsByName = subnetIDByName
	host.Networking.PublicIPv4 = ipv4

	return nil
}

func stateConvert(gcpHostStatus string) (hoststate.Enum, fail.Error) {
	switch strings.ToUpper(gcpHostStatus) {
	case "PROVISIONING":
		return hoststate.Starting, nil
	case "REPAIRING":
		return hoststate.Error, nil
	case "RUNNING":
		return hoststate.Started, nil
	case "STAGING":
		return hoststate.Starting, nil
	case "STOPPED":
		return hoststate.Stopped, nil
	case "STOPPING":
		return hoststate.Stopping, nil
	case "SUSPENDED":
		return hoststate.Stopped, nil
	case "SUSPENDING":
		return hoststate.Stopping, nil
	case "TERMINATED":
		return hoststate.Stopped, nil
	default:
		return -1, fail.NewError("unexpected host status '%s'", gcpHostStatus)
	}
}

// DeleteHost deletes the host identified by id
func (s stack) DeleteHost(hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).Entering().Exiting()

	if xerr := s.rpcDeleteInstance(ahf.Core.ID); xerr != nil {
		return xerr
	}

	// Wait until instance disappear
	xerr = retry.WhileSuccessful(
		func() error {
			_, innerXErr := s.rpcGetInstance(ahf.Core.ID)
			return innerXErr
		},
		temporal.GetDefaultDelay(),
		temporal.GetContextTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout:
			return fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return xerr
		}
	}
	return nil
}

// ResizeHost change the template used by an host
func (s stack) ResizeHost(hostParam stacks.HostParameter, request abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

// ListHosts lists available hosts
func (s stack) ListHosts(detailed bool) (_ abstract.HostList, xerr fail.Error) {
	var emptyList abstract.HostList
	if s.IsNull() {
		return emptyList, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(detailed=%v)", detailed).Entering().Exiting()

	resp, xerr := s.rpcListInstances()
	if xerr != nil {
		return emptyList, xerr
	}

	out := make(abstract.HostList, 0, len(resp))
	for _, v := range resp {
		nhost := abstract.NewHostCore()
		nhost.ID = strconv.FormatUint(v.Id, 10)
		nhost.Name = v.Name
		nhost.LastState, _ = stateConvert(v.Status)

		var hostFull *abstract.HostFull
		if detailed {
			hostFull, xerr = s.InspectHost(nhost)
			if xerr != nil {
				return nil, xerr
			}
		} else {
			hostFull = abstract.NewHostFull()
			hostFull.Core.Replace(nhost)
		}

		// FIXME: Populate host, what's missing ?
		out = append(out, hostFull)
	}

	return out, nil
}

// StopHost stops the host identified by id
func (s stack) StopHost(hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).Entering().Exiting()

	return s.rpcStopInstance(ahf.Core.ID)
}

// StartHost starts the host identified by id
func (s stack) StartHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).Entering().Exiting()

	return s.rpcStartInstance(ahf.Core.ID)
}

// RebootHost reboot the host identified by id
func (s stack) RebootHost(hostParam stacks.HostParameter) fail.Error {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute"), "(%s)", hostLabel).Entering().Exiting()

	if xerr := s.rpcStopInstance(ahf.Core.ID); xerr != nil {
		return xerr
	}

	return s.rpcStartInstance(ahf.Core.ID)
}

// GetHostState returns the host identified by id
func (s stack) GetHostState(hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if s.IsNull() {
		return hoststate.Error, fail.InvalidInstanceError()
	}

	host, xerr := s.InspectHost(hostParam)
	if xerr != nil {
		return hoststate.Error, xerr
	}

	return host.CurrentState, nil
}

// -------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s stack) ListAvailabilityZones() (_ map[string]bool, xerr fail.Error) {
	emptyMap := make(map[string]bool)
	if s.IsNull() {
		return emptyMap, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute")).Entering().Exiting()

	resp, xerr := s.rpcListZones()
	if xerr != nil {
		return emptyMap, xerr
	}

	zones := make(map[string]bool, len(resp))
	for _, v := range resp {
		zones[v.Name] = v.Status == "UP"
	}
	return zones, nil
}

// ListRegions ...
func (s stack) ListRegions() (_ []string, xerr fail.Error) {
	var emptySlice []string
	if s.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute")).Entering().Exiting()

	resp, xerr := s.rpcListRegions()
	if xerr != nil {
		return emptySlice, xerr
	}

	out := make([]string, 0, len(resp))
	for _, v := range resp {
		out = append(out, v.Name)
	}
	return out, nil
}

// BindSecurityGroupToHost ...
func (s stack) BindSecurityGroupToHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (xerr fail.Error) {
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
	if !ahf.IsConsistent() {
		if ahf, xerr = s.InspectHost(ahf); xerr != nil {
			return fail.InvalidParameterError("hostParam", "must contain 'ID' field")
		}
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute")).Entering().Exiting()

	return s.rpcAddTagsToInstance(ahf.GetID(), []string{asg.GetID()})
}

// UnbindSecurityGroupFromHost unbinds a Security Group from a IPAddress
func (s stack) UnbindSecurityGroupFromHost(sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (xerr fail.Error) {
	if s.IsNull() {
		return fail.InvalidInstanceError()
	}
	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		return fail.InvalidParameterError("sgParam", "must contain 'ID' field")
	}
	ahf, _, xerr := stacks.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	defer debug.NewTracer(nil, tracing.ShouldTrace("stack.gcp") || tracing.ShouldTrace("stacks.compute")).Entering().Exiting()

	return s.rpcRemoveTagsFromInstance(ahf.GetID(), []string{asg.GetID()})
}
