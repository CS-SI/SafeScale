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

package ovhtf

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	terraformer "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer"
	terraformerapi "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
	"github.com/gophercloud/gophercloud/openstack/compute/v2/servers"
	"github.com/sirupsen/logrus"
)

const (
	hostDesignResourceSnippetPath = "snippets/resource_host_design.tf"
)

// CreateHost creates a Host satisfying request
func (p *provider) CreateHost(inctx context.Context, request abstract.HostRequest, extra interface{}) (_ *abstract.HostFull, _ *userdata.Content, ferr fail.Error) {
	if valid.IsNil(p) {
		return nil, nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, nil, fail.InvalidParameterCannotBeNilError("inctx")
	}

	defer debug.NewTracer(inctx, tracing.ShouldTrace("stack.ovhtf") || tracing.ShouldTrace("stacks.compute"), "(%s)", request.ResourceName).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&ferr)

	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if len(request.Subnets) == 0 && !request.PublicIP {
		return nil, nil, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without --public flag and without attached Network/Subnet")
	}

	// The Default Networking is the first of the provided list, by convention
	defaultSubnet := request.Subnets[0]

	xerr := stacks.ProvideCredentialsIfNeeded(&request)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to provide credentials for the host")
	}

	// --- prepares data structures for Provider usage ---

	// Constructs userdata content
	userData := userdata.NewContent()
	timings, xerr := p.Timings()
	if xerr != nil {
		return nil, nil, xerr
	}

	cfgOpts, xerr := p.ConfigurationOptions()
	if xerr != nil {
		return nil, nil, xerr
	}

	xerr = userData.Prepare(cfgOpts, request, defaultSubnet.CIDR, "", timings)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to prepare user data content")
	}

	template, xerr := p.InspectTemplate(inctx, request.TemplateID)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to get image")
	}

	rim, xerr := p.InspectImage(inctx, request.ImageID)
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

	// Select usable availability zone, the first one in the list
	azone, xerr := p.selectedAvailabilityZone(inctx)
	if xerr != nil {
		return nil, nil, fail.Wrap(xerr, "failed to select availability zone")
	}
	_ = azone

	// --- Initializes abstract.HostFull ---
	ahf, xerr := p.newAbstract(request.ResourceName)
	if xerr != nil {
		return nil, nil, xerr
	}

	ahf.PrivateKey = userData.FirstPrivateKey
	ahf.Password = request.Password
	ahf.Sizing.DiskSize = diskSize
	ahf.Sizing.ImageID = request.ImageID
	if request.ImageID != "" {
		ahf.Sizing.ImageID = request.ImageID
	} else {
		ahf.Sizing.ImageID = request.ImageRef
	}
	ahf.Networking.IsGateway = request.IsGateway
	for _, v := range request.Subnets {
		ahf.Networking.SubnetsByName[v.Name] = v.ID
	}

	if extra != nil {
		casted, ok := extra.(map[string]string)
		if ok {
			for k, v := range casted {
				ahf.Tags[k] = v
			}
		}
	}

	xerr = ahf.AddOptions(abstract.WithExtraData("Request", request))
	if xerr != nil {
		return nil, nil, xerr
	}

	// --- query provider for host creation ---

	// Starting from here, delete host if exiting with error
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			if ahf.IsConsistent() {
				logrus.WithContext(inctx).Infof("Cleaning up on failure, deleting host '%s'", ahf.Name)
				derr := p.DeleteHost(jobapi.NewContextPropagatingJob(inctx), ahf.ID)
				if derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						logrus.WithContext(inctx).Errorf("Cleaning up on failure, failed to delete host, resource not found: '%v'", derr)
					case *fail.ErrTimeout:
						logrus.WithContext(inctx).Errorf("Cleaning up on failure, failed to delete host, timeout: '%v'", derr)
					default:
						logrus.WithContext(inctx).Errorf("Cleaning up on failure, failed to delete host: '%v'", derr)
					}
					_ = fail.AddConsequence(ferr, derr)
				}
			}
		}
	}()

	logrus.WithContext(inctx).Debugf("Creating host resource '%s' ...", request.ResourceName)

	// Retry creation until success, for 10 minutes
	var (
		server *servers.Server
		// hostNets     []servers.Network
		// hostPorts    []ports.Port
		// createdPorts []string
	)
	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return nil, nil, xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return nil, nil, xerr
	}

	// Sets provider parameters to create host
	workDir, xerr := renderer.WorkDir()
	if xerr != nil {
		return nil, nil, xerr
	}

	userdataFilename := filepath.Join(workDir, request.ResourceName+"_userdata")
	xerr = userData.GenerateToFile(userdata.PHASE1_INIT, userdataFilename)
	if xerr != nil {
		return nil, nil, xerr
	}

	def, xerr := renderer.Assemble(ahf)
	if xerr != nil {
		return nil, nil, xerr
	}

	xerr = retry.WhileUnsuccessful(
		func() (innerFErr error) {
			// hostNets, hostPorts, createdPorts, innerXErr = p.identifyOpenstackSubnetsAndPorts(inctx, request, defaultSubnet)
			// if innerXErr != nil {
			// 	switch innerXErr.(type) {
			// 	case *fail.ErrDuplicate, *fail.ErrNotFound: // This kind of error means actually there is no more Ip address available
			// 		return retry.StopRetryError(innerXErr)
			// 	default:
			// 		return fail.Wrap(xerr, "failed to construct list of Subnets for the Host")
			// 	}
			// }

			// // Starting from here, delete created ports if exiting with error
			// defer func() {
			// 	if innerXErr != nil {
			// 		derr := p.deletePortsInSlice(jobapi.NewContextPropagatingJob(inctx), createdPorts)
			// 		if derr != nil {
			// 			_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete ports"))
			// 		}
			// 	}
			// }()
			//
			// server, innerXErr = p.rpcCreateServer(inctx, request.ResourceName, hostNets, request.TemplateID, request.ImageID, diskSize, userDataPhase1, azone)
			// if innerXErr != nil {
			// 	switch innerXErr.(type) {
			// 	case *retry.ErrStopRetry:
			// 		return fail.Wrap(fail.Cause(innerXErr), "stopping retries")
			// 	case *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it'instance going to fail anyway
			// 		return retry.StopRetryError(innerXErr)
			// 	}
			// 	if server != nil && server.ID != "" {
			// 		rerr := p.DeleteHost(inctx, server.ID)
			// 		if rerr != nil {
			// 			_ = innerXErr.AddConsequence(fail.Wrap(rerr, "cleaning up on failure, failed to delete host '%s'", request.ResourceName))
			// 		}
			// 	}
			// 	return innerXErr
			// }
			// if server == nil || server.ID == "" { // TODO: this should be a validation method
			// 	innerXErr = fail.NewError("failed to create server")
			// 	return innerXErr
			// }

			outputs, innerXErr := renderer.Apply(inctx, def)
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to create Host '%s'", ahf.Name)
			}

			// Starting from here, delete server if exit with error
			defer func() {
				if innerFErr != nil && request.CleanOnFailure() {
					logrus.WithContext(inctx).Infof("Cleaning up on failure, deleting Host '%s'", ahf.Name)
					derr := renderer.Destroy(inctx, def, terraformerapi.WithTarget(ahf))
					if derr != nil {
						logrus.WithContext(inctx).Errorf("failed to delete Network '%s': %v", request.ResourceName, derr)
						_ = ferr.AddConsequence(derr)
					}
				}
			}()

			ahf.ID, innerXErr = unmarshalOutput[string](outputs["host"+request.ResourceName+"_id"])
			if innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to recover Host id")
			}

			// // Starting from here, delete host if exiting with error
			// defer func() {
			// 	if innerXErr != nil {
			// 		if ahf.IsConsistent() {
			// 			logrus.WithContext(inctx).Debugf("deleting unresponsive server '%s'...", request.ResourceName)
			// 			derr := p.DeleteHost(jobapi.NewContextPropagatingJob(inctx), ahf.ID)
			// 			if derr != nil {
			// 				logrus.WithContext(inctx).Debugf(derr.Error())
			// 				_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host '%s'", request.ResourceName))
			// 				return
			// 			}
			//
			// 			logrus.WithContext(inctx).Debugf("unresponsive server '%s' deleted", request.ResourceName)
			// 		}
			// 	}
			// }()

			state, innerXErr := renderer.State(inctx)
			_ = state

			// creationZone, innerXErr := p.GetAvailabilityZoneOfServer(inctx, ahf.ID)
			// if innerXErr != nil {
			// 	logrus.WithContext(inctx).Tracef("Host '%s' successfully created but cannot confirm AZ: %s", ahf.Name, innerXErr)
			// } else {
			// 	logrus.WithContext(inctx).Tracef("Host '%s' successfully created in requested AZ '%s'", ahf.Name, creationZone)
			// 	if creationZone != azone && azone != "" {
			// 		logrus.WithContext(inctx).Warnf("Host '%s' created in the WRONG availability zone: requested '%s' and got instead '%s'", ahf.Name, azone, creationZone)
			// 	}
			// }

			// Wait that host is ready, not just that the build is started
			// FIXME: restore this check
			// timeout := timings.HostOperationTimeout()
			// server, innerXErr = p.WaitHostState(inctx, ahf.HostCore, hoststate.Started, timeout)
			// if innerXErr != nil {
			// 	logrus.WithContext(inctx).Errorf("failed to reach server '%s' after %s; deleting it and trying again", request.ResourceName, temporal.FormatDuration(timeout))
			// 	switch innerXErr.(type) {
			// 	case *fail.ErrNotAvailable:
			// 		return fail.Wrap(innerXErr, "host '%s' is in Error state", request.ResourceName)
			// 	default:
			// 		return innerXErr
			// 	}
			// }

			return nil
		},
		timings.NormalDelay(),
		timings.HostLongOperationTimeout(),
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return nil, nil, fail.Wrap(fail.Cause(xerr), "timeout")
		case *retry.ErrStopRetry, *fail.ErrNotFound, *fail.ErrDuplicate, *fail.ErrInvalidRequest, *fail.ErrNotAuthenticated, *fail.ErrForbidden, *fail.ErrOverflow, *fail.ErrSyntax, *fail.ErrInconsistent, *fail.ErrInvalidInstance, *fail.ErrInvalidInstanceContent, *fail.ErrInvalidParameter, *fail.ErrRuntimePanic: // Do not retry if it'instance going to fail anyway
			return nil, nil, fail.Wrap(fail.Cause(xerr), "stopping retries")
		default:
			cause := fail.Cause(xerr)
			if _, ok := cause.(*fail.ErrNotAvailable); ok {
				if server != nil {
					ahf.ID = server.ID
					ahf.Name = server.Name
					ahf.LastState = hoststate.Error
				}
			}
			return nil, nil, xerr
		}
	}

	// FIXME: restore that
	// newHost, xerr := p.complementHost(inctx, ahf.HostCore, *server, hostNets, hostPorts)
	// if xerr != nil {
	// 	return nil, nil, xerr
	// }
	// newHost.Networking.DefaultSubnetID = defaultSubnetID
	// // newHost.Networking.DefaultGatewayID = defaultGatewayID
	// // newHost.Networking.DefaultGatewayPrivateIP = request.DefaultRouteIP
	// newHost.Networking.IsGateway = request.IsGateway
	// newHost.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

	// FIXME: reimplement this, with new resource type PublicIP?
	// // if Floating IP are used and public address is requested
	// if cfgOpts.UseFloatingIP && request.PublicIP {
	// 	// Create the floating IP
	// 	var ip *floatingips.FloatingIP
	// 	if ip, xerr = p.rpcCreateFloatingIP(inctx); xerr != nil {
	// 		return nil, nil, xerr
	// 	}
	//
	// 	// Starting from here, delete Floating IP if exiting with error
	// 	defer func() {
	// 		ferr = debug.InjectPlannedFail(ferr)
	// 		if ferr != nil {
	// 			logrus.WithContext(inctx).Debugf("Cleaning up on failure, deleting floating ip '%s'", ip.ID)
	// 			derr := p.rpcDeleteFloatingIP(jobapi.NewContextPropagatingJob(inctx), ip.ID)
	// 			if derr != nil {
	// 				derr = fail.Wrap(derr, "cleaning up on failure, failed to delete Floating IP")
	// 				_ = ferr.AddConsequence(derr)
	// 				logrus.Error(derr.Error())
	// 				return
	// 			}
	// 			logrus.WithContext(inctx).Debugf("Cleaning up on failure, floating ip '%s' successfully deleted", ip.ID)
	// 		}
	// 	}()
	//
	// 	// Associate floating IP to host
	// 	xerr = stacks.RetryableRemoteCall(inctx,
	// 		func() error {
	// 			return floatingips.AssociateInstance(p.ComputeClient, newHost.ID, floatingips.AssociateOpts{FloatingIP: ip.IP}).ExtractErr()
	// 		},
	// 		NormalizeError,
	// 	)
	// 	if xerr != nil {
	// 		return nil, nil, xerr
	// 	}
	//
	// 	if ipversion.IPv4.Is(ip.IP) {
	// 		newHost.Networking.PublicIPv4 = ip.IP
	// 	} else if ipversion.IPv6.Is(ip.IP) {
	// 		newHost.Networking.PublicIPv6 = ip.IP
	// 	}
	// 	userData.PublicIP = ip.IP
	// }

	logrus.Infoln(msgSuccess)
	return ahf /*newHost*/, userData, nil
}

func (p *provider) newAbstract(name string) (*abstract.HostFull, fail.Error) {
	ahf, xerr := abstract.NewHostFull(
		abstract.WithName(name),
		abstract.WithResourceType("openstack_networking_port_v2"),
		abstract.WithResourceType("openstack_compute_instance_v2"),
		abstract.WithResourceType("openstack_images_image_v2"),
	)
	if xerr != nil {
		return nil, xerr
	}

	return ahf, nil
}

// SelectedAvailabilityZone returns the selected availability zone
func (p *provider) selectedAvailabilityZone(ctx context.Context) (string, fail.Error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.availabilityZone == "" {
		opts, err := p.AuthenticationOptions()
		if err != nil {
			return "", err
		}
		p.availabilityZone = opts.AvailabilityZone
		if p.availabilityZone == "" {
			azList, xerr := p.ListAvailabilityZones(ctx)
			if xerr != nil {
				return "", xerr
			}

			var azone string
			for azone = range azList {
				break
			}
			p.availabilityZone = azone
		}
		logrus.WithContext(ctx).Debugf("Selected Availability Zone: '%s'", p.availabilityZone)
	}
	return p.availabilityZone, nil
}

/*// complementHost complements Host data with content of server parameter
func (p provider) complementHost(ctx context.Context, hostCore *abstract.HostCore, server servers.Server, hostNets []servers.Network, hostPorts []ports.Port) (_ *abstract.HostFull, ferr fail.Error) {
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
		logrus.WithContext(ctx).Warnf("[TRACE] Unexpected host'instance last state: %v", state)
	}

	host, xerr := abstract.NewHostFull(abstract.WithName(hostCore.Name))
	if xerr != nil {
		return nil, xerr
	}

	host.HostCore = hostCore
	host.CurrentState, hostCore.LastState = state, state
	host.Description = &abstract.HostDescription{
		Created: server.Created,
		Updated: server.Updated,
	}

	host.Tags["Template"], _ = server.Image["id"].(string) // nolint
	host.Tags["Image"], _ = server.Flavor["id"].(string)   // nolint

	// recover metadata
	for k, v := range server.Metadata {
		host.Tags[k] = v
	}

	ct, ok := host.Tags["CreationDate"]
	if !ok || ct == "" {
		host.Tags["CreationDate"] = server.Created.Format(time.RFC3339)
	}

	host.Sizing, xerr = instance.toHostSize(ctx, server.Flavor)
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
			if port.NetworkID != instance.ProviderNetworkID {
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
			as, xerr := instance.InspectSubnet(ctx, k)
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
*/

func (p *provider) ClearHostStartupScript(ctx context.Context, hostParam iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

// InspectHost ...
func (p *provider) InspectHost(ctx context.Context, hostParam iaasapi.HostParameter) (*abstract.HostFull, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	_, hostLabel, xerr := iaasapi.ValidateHostParameter(hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", hostLabel).WithStopwatch().Entering().Exiting()

	return p.MiniStack.InspectHost(ctx, hostParam)
}

func (p *provider) GetHostState(ctx context.Context, hostParam iaasapi.HostParameter) (hoststate.Enum, fail.Error) {
	// TODO implement me
	panic("implement me")
}

// ListHosts ...
func (p *provider) ListHosts(ctx context.Context, b bool) (abstract.HostList, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("stack.ovhtf") || tracing.ShouldTrace("stacks.compute"), "()").WithStopwatch().Entering().Exiting()

	return p.MiniStack.ListHosts(ctx, b)
}

func (p *provider) DeleteHost(ctx context.Context, hostParam iaasapi.HostParameter) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := iaasapi.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	ahf, xerr = p.InspectHost(ctx, ahf)
	if xerr != nil {
		return xerr
	}

	xerr = ahf.AddOptions(
		abstract.UseTerraformSnippet(hostDesignResourceSnippetPath),
		abstract.WithExtraData("MarkedForDestroy", true),
	)
	if xerr != nil {
		return xerr
	}

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return xerr
	}

	def, xerr := renderer.Assemble(ahf)
	if xerr != nil {
		return xerr
	}

	xerr = renderer.Destroy(ctx, def, terraformerapi.WithTarget(ahf))
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete Network '%s'", ahf.Name)
	}

	return nil
}

func (p *provider) StopHost(ctx context.Context, hostParam iaasapi.HostParameter, gracefully bool) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := iaasapi.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	ahf, xerr = p.InspectHost(ctx, ahf)
	if xerr != nil {
		return xerr
	}

	xerr = ahf.AddOptions(
		abstract.UseTerraformSnippet(hostDesignResourceSnippetPath),
		abstract.WithExtraData("MarkedForStop", true),
	)
	if xerr != nil {
		return xerr
	}

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return xerr
	}

	def, xerr := renderer.Assemble(ahf)
	if xerr != nil {
		return xerr
	}

	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete Network '%s'", ahf.Name)
	}
	_ = outputs

	return nil
}

func (p *provider) StartHost(ctx context.Context, hostParam iaasapi.HostParameter) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := iaasapi.ValidateHostParameter(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("stack.network"), "(%s)", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	ahf, xerr = p.InspectHost(ctx, ahf)
	if xerr != nil {
		return xerr
	}

	xerr = ahf.AddOptions(
		abstract.UseTerraformSnippet(hostDesignResourceSnippetPath),
		abstract.WithExtraData("MarkedForStop", false),
	)
	if xerr != nil {
		return xerr
	}

	renderer, xerr := terraformer.New(p, p.TerraformerOptions())
	if xerr != nil {
		return xerr
	}
	defer func() { _ = renderer.Close() }()

	xerr = renderer.SetEnv("OS_AUTH_URL", p.authOptions.IdentityEndpoint)
	if xerr != nil {
		return xerr
	}

	def, xerr := renderer.Assemble(ahf)
	if xerr != nil {
		return xerr
	}

	outputs, xerr := renderer.Apply(ctx, def)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete Network '%s'", ahf.Name)
	}
	_ = outputs

	return nil
}

func (p *provider) RebootHost(ctx context.Context, hostParam iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ResizeHost(ctx context.Context, hostParam iaasapi.HostParameter, requirements abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) WaitHostReady(ctx context.Context, hostParam iaasapi.HostParameter, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	// TODO implement me
	panic("implement me")
}

func (p *provider) BindSecurityGroupToHost(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, hostParam iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) UnbindSecurityGroupFromHost(ctx context.Context, sgParam iaasapi.SecurityGroupParameter, hostParam iaasapi.HostParameter) fail.Error {
	// TODO implement me
	panic("implement me")
}

func (p *provider) ConsolidateHostSnippet(ahc *abstract.HostCore) {
	if valid.IsNil(p) || ahc == nil {
		return
	}

	_ = ahc.AddOptions(abstract.UseTerraformSnippet(networkDesignResourceSnippetPath))
}
