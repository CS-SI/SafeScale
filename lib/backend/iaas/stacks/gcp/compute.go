/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/sirupsen/logrus"

	"google.golang.org/api/compute/v1"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
)

// -------------IMAGES---------------------------------------------------------------------------------------------------

// ListImages lists available OS images
func (s stack) ListImages(ctx context.Context, _ bool) (out []*abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	resp, xerr := s.rpcListImages(ctx)
	if xerr != nil {
		return nil, xerr
	}
	out = make([]*abstract.Image, 0, len(resp))
	for _, v := range resp {
		out = append(out, toAbstractImage(*v))
	}
	return out, nil
}

func toAbstractImage(in compute.Image) *abstract.Image {
	return &abstract.Image{
		Name:        in.Name,
		URL:         in.SelfLink,
		ID:          strconv.FormatUint(in.Id, 10),
		Description: in.Description,
		DiskSize:    in.DiskSizeGb,
	}
}

// InspectImage returns the Image referenced by id
func (s stack) InspectImage(ctx context.Context, id string) (_ *abstract.Image, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	resp, xerr := s.rpcGetImageByID(ctx, id)
	if xerr != nil {
		return nil, xerr
	}
	return toAbstractImage(*resp), nil
}

// -------------TEMPLATES------------------------------------------------------------------------------------------------

// ListTemplates overload OpenStackGcp ListTemplate method to filter wind and flex instance and add GPU configuration
func (s stack) ListTemplates(ctx context.Context, _ bool) (templates []*abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	resp, xerr := s.rpcListMachineTypes(ctx)
	if xerr != nil {
		return nil, xerr
	}

	templates = make([]*abstract.HostTemplate, 0, len(resp))
	for _, v := range resp {
		templates = append(templates, toAbstractHostTemplate(*v))
	}
	return templates, nil
}

func toAbstractHostTemplate(in compute.MachineType) *abstract.HostTemplate {
	return &abstract.HostTemplate{
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
func (s stack) InspectTemplate(ctx context.Context, id string) (_ *abstract.HostTemplate, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if id == "" {
		return nil, fail.InvalidParameterError("id", "cannot be empty string")
	}

	resp, xerr := s.rpcGetMachineType(ctx, id)
	if xerr != nil {
		return nil, xerr
	}
	return toAbstractHostTemplate(*resp), nil
}

// -------------SSH KEYS-------------------------------------------------------------------------------------------------

// CreateKeyPair FIXME: change code to really create a keypair on provider side
// CreateKeyPair creates and import a key pair
func (s stack) CreateKeyPair(ctx context.Context, name string) (_ *abstract.KeyPair, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	return abstract.NewKeyPair(name)
}

// InspectKeyPair returns the key pair identified by id
func (s stack) InspectKeyPair(ctx context.Context, id string) (*abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("InspectKeyPair() not implemented yet") // FIXME: Technical debt
}

// ListKeyPairs lists available key pairs
func (s stack) ListKeyPairs(context.Context) ([]*abstract.KeyPair, fail.Error) {
	return nil, fail.NotImplementedError("ListKeyPairs() not implemented yet") // FIXME: Technical debt
}

// DeleteKeyPair deletes the key pair identified by id
func (s stack) DeleteKeyPair(ctx context.Context, id string) fail.Error {
	return fail.NotImplementedError("DeleteKeyPair() not implemented yet") // FIXME: Technical debt
}

// CreateHost creates a host meeting the requirements specified by request
func (s stack) CreateHost(ctx context.Context, request abstract.HostRequest, extra interface{}) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, nil, fail.InvalidInstanceError()
	}

	resourceName := request.ResourceName
	subnets := request.Subnets
	hostMustHavePublicIP := request.PublicIP || request.Single

	if len(subnets) == 0 {
		return nil, nil, fail.InvalidRequestError(
			"the host %s must be on at least one network (even if public)", resourceName,
		)
	}

	// If no key pair is supplied create one
	var xerr fail.Error
	if xerr = stacks.ProvideCredentialsIfNeeded(&request); xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to provide credentials for Host")
	}

	defaultSubnet := request.Subnets[0]
	defaultSubnetID := defaultSubnet.ID
	an, xerr := s.InspectNetwork(ctx, defaultSubnet.Network)
	if xerr != nil {
		switch xerr.(type) { // nolint
		case *fail.ErrNotFound:
			an, xerr = s.InspectNetworkByName(ctx, defaultSubnet.Network)
			if xerr != nil {
				return nil, nil, fail.NotFoundError("failed to find Network %s", defaultSubnet.Network)
			}
		default:
			return nil, nil, fail.NotFoundError("failed to find Network %s", defaultSubnet.Network)
		}
	}

	if request.DefaultRouteIP == "" && !hostMustHavePublicIP {
		return nil, nil, fail.InvalidRequestError("the host '%s' must have a gateway or be public", resourceName)
	}

	// --- prepares data structures for Provider usage ---

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, nil, xerr
	}

	// Constructs userdata content
	userData := userdata.NewContent()
	if xerr = userData.Prepare(*s.Config, request, defaultSubnet.CIDR, "", timings); xerr != nil {
		xerr = fail.Wrap(xerr, "failed to prepare user data content")
		logrus.WithContext(ctx).Debugf(strprocess.Capitalize(xerr.Error()))
		return nil, nil, xerr
	}

	// Determine system disk size based on vcpus count
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

	logrus.WithContext(ctx).Debugf("Selected template: '%s', '%s'", template.ID, template.Name)

	// Select usable availability zone, the first one in the list
	if s.GcpConfig.Zone == "" {
		azList, xerr := s.ListAvailabilityZones(ctx)
		if xerr != nil {
			return nil, nil, xerr
		}
		var az string
		for az = range azList {
			break
		}
		s.GcpConfig.Zone = az
		logrus.WithContext(ctx).Debugf("Selected Availability Zone: '%s'", az)
	}

	// Sets provider parameters to create ahf
	userDataPhase1, xerr := userData.Generate(userdata.PHASE1_INIT)
	if xerr != nil {
		return nil, nil, xerr
	}

	// --- query provider for Host creation ---

	logrus.WithContext(ctx).Debugf("requesting host '%s' resource creation...", request.ResourceName)

	var ahf *abstract.HostFull

	defer func() {
		if ferr != nil {
			if ahf.IsConsistent() {
				if !request.KeepOnFailure {
					logrus.WithContext(ctx).Debugf("Clean up on failure, deleting host '%s'", ahf.GetName())
					if derr := s.DeleteHost(context.Background(), ahf); derr != nil {
						msg := fmt.Sprintf("cleaning up on failure, failed to delete Host '%s'", ahf.GetName())
						_ = ferr.AddConsequence(fail.Wrap(derr, msg))
					} else {
						logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleted Host '%s' successfully.", ahf.GetName())
					}
				}
			}
		}
	}()

	// Retry creation until success, for 10 minutes
	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			var innerXErr fail.Error
			var lahf *abstract.HostFull

			// Starting from here, delete host if exiting with error, to be in good shape to retry
			defer func() {
				if innerXErr != nil {
					if lahf.IsConsistent() {
						logrus.WithContext(ctx).Debugf("Clean up on failure, deleting host '%s'", lahf.GetName())
						if derr := s.DeleteHost(context.Background(), lahf); derr != nil {
							msg := fmt.Sprintf("cleaning up on failure, failed to delete Host '%s'", lahf.GetName())
							_ = innerXErr.AddConsequence(fail.Wrap(derr, msg))
						} else {
							logrus.WithContext(ctx).Debugf("Cleaning up on failure, deleted Host '%s' successfully.", lahf.GetName())
						}
					}
				}
			}()

			lahf, innerXErr = s.buildGcpMachine(ctx, request.ResourceName, an, defaultSubnet, *template, rim.URL, diskSize, string(userDataPhase1), hostMustHavePublicIP, request.SecurityGroupIDs, extra)
			if innerXErr != nil {
				captured := normalizeError(innerXErr)
				switch captured.(type) {
				case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
					return retry.StopRetryError(captured)
				default:
					return captured
				}
			}

			ahf = lahf
			ahfid, err := ahf.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			// Wait that Host is ready, not just that the build is started
			if _, innerXErr = s.WaitHostReady(ctx, ahfid, timings.HostLongOperationTimeout()); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrInvalidRequest:
					return retry.StopRetryError(innerXErr)
				default:
					return innerXErr
				}
			}
			return nil
		},
		timings.NormalDelay(),
		timings.HostLongOperationTimeout(),
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry, *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it's going to fail anyway
			return nil, nil, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nil, nil, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return nil, nil, retryErr
		}
	}

	logrus.WithContext(ctx).Debugf("Host '%s' created.", ahf.GetName())

	// Add to abstract.HostFull data that does not come with creation data from provider
	ahf.Core.PrivateKey = userData.FirstPrivateKey // Add PrivateKey to Host description
	ahf.Core.Password = request.Password           // and OperatorUsername's password
	ahf.Networking.IsGateway = request.IsGateway
	ahf.Networking.DefaultSubnetID = defaultSubnetID
	ahf.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

	return ahf, userData, nil
}

// WaitHostReady waits until a host reaches ready state
// hostParam can be an ID of host, or an instance of *abstract.HostCore; any other type will return a utils.ErrInvalidParameter.
func (s stack) WaitHostReady(ctx context.Context, hostParam stacks.HostParameter, timeout time.Duration) (_ *abstract.HostCore, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return nil, xerr
	}

	retryErr := retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			hostComplete, innerErr := s.InspectHost(ctx, ahf)
			if innerErr != nil {
				return innerErr
			}

			if hostComplete.CurrentState != hoststate.Started {
				return fail.NotAvailableError(
					"not in ready state (current state: %s)", hostComplete.CurrentState.String(),
				)
			}
			return nil
		},
		timings.NormalDelay(),
		timeout,
	)
	if retryErr != nil {
		switch retryErr.(type) {
		case *retry.ErrStopRetry:
			return nil, fail.Wrap(fail.Cause(retryErr), "stopping retries")
		case *retry.ErrTimeout:
			return nil, fail.Wrap(fail.Cause(retryErr), "timeout")
		default:
			return nil, retryErr
		}
	}

	return ahf.Core, nil
}

// buildGcpMachine ...
func (s stack) buildGcpMachine(
	ctx context.Context,
	instanceName string,
	network *abstract.Network,
	subnet *abstract.Subnet,
	template abstract.HostTemplate,
	imageURL string,
	diskSize int,
	userData string,
	isPublic bool,
	securityGroups map[string]struct{},
	extra interface{},
) (*abstract.HostFull, fail.Error) {
	resp, xerr := s.rpcCreateInstance(ctx, instanceName, network.Name, subnet.ID, subnet.Name, template.Name, imageURL, int64(diskSize), userData, isPublic, securityGroups, extra)
	if xerr != nil {
		return nil, xerr
	}

	ahf := abstract.NewHostFull()
	if xerr = s.complementHost(ctx, ahf, resp); xerr != nil {
		return nil, xerr
	}

	ahf.Core.Tags["Image"] = imageURL
	if extra != nil {
		into, ok := extra.(map[string]string)
		if !ok {
			return nil, fail.InvalidParameterError("extra", "must be a map[string]string")
		}
		for k, v := range into {
			k, v := k, v
			ahf.Core.Tags[k] = v
		}
	}

	return ahf, nil
}

// ClearHostStartupScript clears the userdata startup script for Host instance (metadata service)
func (s stack) ClearHostStartupScript(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}
	if !ahf.IsConsistent() {
		return fail.InvalidParameterError(
			"hostParam",
			"must be either ID as string or an '*abstract.HostCore' or '*abstract.HostFull' with value in 'ID' field",
		)
	}

	ahfid, err := ahf.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	return s.rpcResetStartupScriptOfInstance(ctx, ahfid)
}

func (s stack) ChangeSecurityGroupSecurity(ctx context.Context, b bool, b2 bool, net string, s2 string) fail.Error {
	return nil
}

// InspectHost returns the host identified by ref (name or id) or by a *abstract.HostFull containing an id
func (s stack) InspectHost(ctx context.Context, hostParam stacks.HostParameter) (host *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	ahf, hostLabel, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}
	if !(ahf.Core.ID != "" || ahf.Core.Name != "") {
		return nil, fail.InvalidParameterError(
			"hostParam",
			"must be either ID as string or an '*abstract.HostCore' or '*abstract.HostFull' with value in 'ID' field",
		)
	}

	var (
		tryByName = true
		instance  *compute.Instance
	)
	if ahf.Core.ID != "" {
		if instance, xerr = s.rpcGetInstance(ctx, ahf.Core.ID); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// continue
				debug.IgnoreError2(ctx, xerr)
			default:
				return nil, xerr
			}
		} else {
			tryByName = false
		}
	}
	if tryByName && ahf.Core.Name != "" {
		instance, xerr = s.rpcGetInstance(ctx, ahf.Core.Name)
	}
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return nil, fail.NotFoundError("failed to find Host %s", hostLabel)
		default:
			return nil, xerr
		}
	}

	if xerr = s.complementHost(ctx, ahf, instance); xerr != nil {
		return nil, xerr
	}

	return ahf, nil
}

func (s stack) complementHost(ctx context.Context, host *abstract.HostFull, instance *compute.Instance) fail.Error {
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

			subnets = append(
				subnets, IPInSubnet{
					Subnet:   snet,
					IP:       nit.NetworkIP,
					PublicIP: pubIP,
				},
			)
		}
	}

	var resourceNetworks []IPInSubnet
	for _, sn := range subnets {
		region, xerr := getRegionFromSelfLink(sn.Subnet)
		if xerr != nil {
			continue
		}
		psg, xerr := s.rpcGetSubnetByNameAndRegion(ctx, getResourceNameFromSelfLink(sn.Subnet), region)
		if xerr != nil {
			continue
		}

		resourceNetworks = append(
			resourceNetworks, IPInSubnet{
				Subnet:   sn.Subnet,
				Name:     psg.Name,
				ID:       strconv.FormatUint(psg.Id, 10),
				IP:       sn.IP,
				PublicIP: sn.PublicIP,
			},
		)
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

	if instance.Metadata != nil {
		for _, item := range instance.Metadata.Items {
			if item.Value != nil {
				host.Core.Tags[item.Key] = *item.Value
			}
		}
	}

	host.Core.Tags["CreationDate"] = instance.CreationTimestamp
	host.Core.Tags["Template"] = instance.MachineType
	delete(host.Core.Tags, "startup-script")

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
func (s stack) DeleteHost(ctx context.Context, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	timings, xerr := s.Timings()
	if xerr != nil {
		return xerr
	}

	if xerr := s.rpcDeleteInstance(ctx, ahf.Core.ID); xerr != nil {
		return xerr
	}

	// Wait until instance disappear
	xerr = retry.WhileSuccessful(
		func() error {
			_, innerXErr := s.rpcGetInstance(ctx, ahf.Core.ID)
			return innerXErr
		},
		timings.NormalDelay(),
		timings.ContextTimeout(),
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

// ListHosts lists available hosts
func (s stack) ListHosts(ctx context.Context, detailed bool) (_ abstract.HostList, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	resp, xerr := s.rpcListInstances(ctx)
	if xerr != nil {
		return nil, xerr
	}

	out := make(abstract.HostList, 0, len(resp))
	for _, v := range resp {
		nhost := abstract.NewHostCore()
		nhost.ID = strconv.FormatUint(v.Id, 10)
		nhost.Name = v.Name
		nhost.LastState, xerr = stateConvert(v.Status)
		if xerr != nil {
			return nil, xerr
		}

		var hostFull *abstract.HostFull
		if detailed {
			hostFull, xerr = s.InspectHost(ctx, nhost)
			if xerr != nil {
				return nil, xerr
			}
		} else {
			hostFull = abstract.NewHostFull()
			hostFull.Core = nhost
		}

		out = append(out, hostFull)
	}

	return out, nil
}

// StopHost stops the host identified by id
func (s stack) StopHost(ctx context.Context, hostParam stacks.HostParameter, gracefully bool) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return s.rpcStopInstance(ctx, ahf.Core.ID)
}

// StartHost starts the host identified by id
func (s stack) StartHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	return s.rpcStartInstance(ctx, ahf.Core.ID)
}

// RebootHost reboot the host identified by id
func (s stack) RebootHost(ctx context.Context, hostParam stacks.HostParameter) fail.Error {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	if xerr := s.rpcStopInstance(ctx, ahf.Core.ID); xerr != nil {
		return xerr
	}

	return s.rpcStartInstance(ctx, ahf.Core.ID)
}

func (s stack) GetHostState(ctx context.Context, hostParam stacks.HostParameter) (hoststate.Enum, fail.Error) {
	if valid.IsNil(s) {
		return hoststate.Error, fail.InvalidInstanceError()
	}

	host, xerr := s.InspectHost(ctx, hostParam)
	if xerr != nil {
		return hoststate.Error, xerr
	}

	return host.CurrentState, nil
}

// -------------Provider Infos-------------------------------------------------------------------------------------------

// ListAvailabilityZones lists the usable AvailabilityZones
func (s stack) ListAvailabilityZones(ctx context.Context) (_ map[string]bool, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	resp, xerr := s.rpcListZones(ctx)
	if xerr != nil {
		return nil, xerr
	}

	zones := make(map[string]bool, len(resp))
	for _, v := range resp {
		zones[v.Name] = v.Status == "UP"
	}
	return zones, nil
}

// ListRegions ...
func (s stack) ListRegions(ctx context.Context) (_ []string, ferr fail.Error) {
	if valid.IsNil(s) {
		return nil, fail.InvalidInstanceError()
	}

	resp, xerr := s.rpcListRegions(ctx)
	if xerr != nil {
		return nil, xerr
	}

	out := make([]string, 0, len(resp))
	for _, v := range resp {
		out = append(out, v.Name)
	}
	return out, nil
}

// BindSecurityGroupToHost ...
func (s stack) BindSecurityGroupToHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
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
	if !ahf.IsConsistent() {
		if ahf, xerr = s.InspectHost(ctx, ahf); xerr != nil {
			return fail.InvalidParameterError("hostParam", "must contain 'ID' field")
		}
	}

	ahfid, err := ahf.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	asgid, err := asg.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	return s.rpcAddTagsToInstance(ctx, ahfid, []string{asgid})
}

// UnbindSecurityGroupFromHost unbinds a Security Group from a Host
func (s stack) UnbindSecurityGroupFromHost(ctx context.Context, sgParam stacks.SecurityGroupParameter, hostParam stacks.HostParameter) (ferr fail.Error) {
	if valid.IsNil(s) {
		return fail.InvalidInstanceError()
	}

	asg, _, xerr := stacks.ValidateSecurityGroupParameter(sgParam)
	if xerr != nil {
		return xerr
	}
	if !asg.IsConsistent() {
		return fail.InvalidParameterError("sgParam", "must contain 'ID' field")
	}
	ahf, _, xerr := stacks.ValidateHostParameter(ctx, hostParam)
	if xerr != nil {
		return xerr
	}

	ahfid, err := ahf.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	asgid, err := asg.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	return s.rpcRemoveTagsFromInstance(ctx, ahfid, []string{asgid})
}
