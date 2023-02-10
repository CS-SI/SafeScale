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

package ovhtf

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	terraformer "github.com/CS-SI/SafeScale/v22/lib/backend/externals/terraform/consumer"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/stacks"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
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

	defer debug.NewTracer(inctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "(%s)", request.ResourceName).WithStopwatch().Entering().Exiting()
	defer fail.OnPanic(&ferr)

	msgSuccess := fmt.Sprintf("Host resource '%s' created successfully", request.ResourceName)

	if len(request.Subnets) == 0 && !request.PublicIP {
		return nil, nil, abstract.ResourceInvalidRequestError("host creation", "cannot create a host without --public flag and without attached Network/Subnet")
	}

	// The Default Networking is the first of the provided list, by convention
	defaultSubnet := request.Subnets[0]
	defaultSubnetID := defaultSubnet.ID

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

	request.TemplateRef = template.Name

	rim, xerr := p.InspectImage(inctx, request.ImageID)
	if xerr != nil {
		return nil, nil, xerr
	}

	request.ImageRef = rim.Name

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
				diskSize = 100
			} else if template.Cores < 32 {
				diskSize = 200
			} else {
				diskSize = 400
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

	// --- Initializes abstract.HostFull ---
	ahf, xerr := p.designHostFull(request.ResourceName)
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

	xerr = ahf.AddOptions(
		abstract.MarkForCreation(),
		abstract.WithExtraData("Request", request),
		abstract.WithExtraData("AvailabilityZone", azone),
		abstract.WithExtraData("Subnets", request.Subnets),
		abstract.WithExtraData("PublicIP", request.PublicIP || request.IsGateway),
		abstract.WithExtraData("SecurityGroupByID", request.SecurityGroupByID),
		abstract.WithExtraData("DiskSize", ahf.Sizing.DiskSize),
		abstract.WithExtraData("Image", ahf.Sizing.ImageID),
		abstract.WithExtraData("Template", template.Name),
	)
	if xerr != nil {
		return nil, nil, xerr
	}

	// --- query provider for host creation ---

	logrus.WithContext(inctx).Debugf("Creating host resource '%s' ...", request.ResourceName)

	// Retry creation until success, for 10 minutes
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

	def, xerr := renderer.Assemble(inctx, ahf)
	if xerr != nil {
		return nil, nil, xerr
	}

	var outputs map[string]tfexec.OutputMeta
	xerr = retry.WhileUnsuccessful(
		func() (innerFErr error) {
			select {
			case <-inctx.Done():
				return retry.StopRetryError(inctx.Err())
			default:
			}

			var innerXErr fail.Error
			outputs, innerXErr = renderer.Apply(inctx, def)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrSyntax, *fail.ErrNotFound:
					return retry.StopRetryError(innerXErr)
				case fail.Error:
					lowered := strings.ToLower(innerXErr.Error())
					if strings.Contains(lowered, "overlaps with another subnet") {
						return retry.StopRetryError(fail.DuplicateError("requested CIDR overlaps with existing Subnet"))
					}
					if strings.Contains(lowered, "unable to find flavor with name") {
						return retry.StopRetryError(fail.NotFoundError(innerXErr.Error()))
					}
					if strings.Contains(lowered, "bad request with") {
						return retry.StopRetryError(fail.InvalidRequestError(innerXErr.Error()))
					}
					if strings.Contains(lowered, "no suitable endpoint could be found in the service catalog") {
						return retry.StopRetryError(fail.InvalidRequestError(innerXErr.Error()))
					}
				default:
				}
				return fail.Wrap(innerXErr, "failed to create Host '%s'", ahf.Name)
			}

			// Starting from here, delete server if exit with error
			defer func() {
				if innerFErr != nil && request.CleanOnFailure() {
					logrus.WithContext(inctx).Debugf("deleting unresponsive server '%s'...", request.ResourceName)

					// Recreates def without host to destroy what has been created
					derr := renderer.Reset()
					if derr != nil {
						innerFErr = fail.Wrap(innerFErr).AddConsequence(derr)
						return
					}

					def, derr := renderer.Assemble(inctx)
					if derr != nil {
						innerFErr = fail.Wrap(innerFErr).AddConsequence(derr)
						return
					}

					derr = renderer.Destroy(jobapi.NewContextPropagatingJob(inctx), def)
					if derr != nil {
						logrus.WithContext(inctx).Errorf("failed to delete Host '%s': %v", request.ResourceName, derr)
						innerFErr = fail.Wrap(innerFErr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete Host '%s'", request.ResourceName))
					} else {
						logrus.WithContext(inctx).Debugf("unresponsive server '%s' deleted", request.ResourceName)
					}
				}
			}()

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
			return nil, nil, xerr
		}
	}

	defer func() {
		if ferr != nil && request.CleanOnFailure() {
			logrus.WithContext(inctx).Infof("Cleaning up on failure, deleting Host '%s'", ahf.Name)

			// Recreates def without host to destroy what has been created
			derr := renderer.Reset()
			if derr != nil {
				_ = ferr.AddConsequence(derr)
				return
			}

			def, derr := renderer.Assemble(inctx)
			if derr != nil {
				_ = ferr.AddConsequence(derr)
				return
			}

			derr = renderer.Destroy(jobapi.NewContextPropagatingJob(inctx), def)
			if derr != nil {
				logrus.WithContext(inctx).Errorf("failed to delete Host '%s': %v", ahf.Name, derr)
				_ = ferr.AddConsequence(derr)
			} else {
				logrus.WithContext(inctx).Infof("Cleaning up on failure, deleted Host '%s'", ahf.Name)
			}
		}
	}()

	xerr = ahf.AddOptions(abstract.ClearMarkForCreation())
	if xerr != nil {
		return nil, nil, xerr
	}

	newHost, xerr := p.complementHost(inctx, ahf.HostCore, outputs, azone)
	if xerr != nil {
		return nil, nil, xerr
	}

	newHost.Sizing, xerr = p.toHostSize(template)
	if xerr != nil {
		return nil, nil, xerr
	}

	newHost.Networking.DefaultSubnetID = defaultSubnetID
	newHost.Networking.IsGateway = request.IsGateway
	newHost.Sizing = converters.HostTemplateToHostEffectiveSizing(*template)

	// FIXME: Now that OVH supports FloatingIP, reimplement this, with new resource type PublicIP? And maybe moved in previous renderer.Assemble to
	//        make a single call to terraform...
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
	return newHost, userData, nil
}

// designHostFull ...
func (p *provider) designHostFull(name string) (*abstract.HostFull, fail.Error) {
	ahf, xerr := abstract.NewHostFull(abstract.WithName(name))
	if xerr != nil {
		return nil, xerr
	}

	return ahf, p.ConsolidateHostSnippet(ahf.HostCore)
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

// complementHost complements Host data with content of server parameter
func (p *provider) complementHost(ctx context.Context, hostCore *abstract.HostCore, outputs map[string]tfexec.OutputMeta, az string) (_ *abstract.HostFull, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var err error

	hostOutputs, xerr := unmarshalOutput[map[string]any](outputs["host_"+hostCore.Name])
	if xerr != nil {
		return nil, xerr
	}

	creationZone, innerErr := lang.Cast[string](hostOutputs["availability_zone"])
	if innerErr != nil {
		logrus.WithContext(ctx).Tracef("Host '%s' successfully created but cannot confirm AZ: %s", hostCore.Name, innerErr)
	} else {
		logrus.WithContext(ctx).Tracef("Host '%s' successfully created in requested AZ '%s'", hostCore.Name, creationZone)
		if creationZone != az && az != "" {
			logrus.WithContext(ctx).Warnf("Host '%s' created in the WRONG availability zone: requested '%s' and got instead '%s'", hostCore.Name, az, creationZone)
		}
	}

	host, xerr := abstract.NewHostFullFromCore(hostCore)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: restore this
	// state := toHostState(server.Status)
	// if state == hoststate.Error || state == hoststate.Starting {
	// 	logrus.WithContext(ctx).Warnf("[TRACE] Unexpected host last state: %v", state)
	// }
	// FIXME: restore this
	// host.CurrentState, hostCore.LastState = state, state
	// host.Description = &abstract.HostDescription{
	// 	Created: server.Created,
	// 	Updated: server.Updated,
	// }

	if host.ID == "" {
		host.ID, err = lang.Cast[string](hostOutputs["id"])
		if err != nil {
			return nil, fail.Wrap(err)
		}
	}

	// recover OpenStack metadata into Tags
	metadata, err := lang.Cast[map[string]any](hostOutputs["metadata"])
	if err != nil {
		return nil, fail.Wrap(err)
	}

	for k, v := range metadata {
		host.Tags[k], err = lang.Cast[string](v)
		if err != nil {
			return nil, fail.Wrap(err)
		}
	}

	host.Tags["Template"], err = lang.Cast[string](hostOutputs["flavor_id"])
	if err != nil {
		return nil, fail.Wrap(err)
	}

	host.Tags["Image"], err = lang.Cast[string](hostOutputs["image_id"])
	if err != nil {
		return nil, fail.Wrap(err)
	}

	networks, err := lang.Cast[[]interface{}](hostOutputs["network"])
	if err != nil {
		return nil, fail.Wrap(err)
	}

	if len(networks) > 0 {
		var ipv4, ipv6 string
		subnetsByID := map[string]string{}
		subnetsByName := map[string]string{}
		ipv4Addresses := map[string]string{}
		ipv6Addresses := map[string]string{}

		// gather subnets data
		for _, v := range networks {
			entry, err := lang.Cast[map[string]any](v)
			if err != nil {
				return nil, fail.Wrap(err)
			}

			name, err := lang.Cast[string](entry["name"])
			if err != nil {
				return nil, fail.Wrap(err)
			}

			if name != "Ext-Net" {
				subnetOutputs, xerr := unmarshalOutput[map[string]any](outputs["subnet_"+name])
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						continue
					default:
						return nil, xerr
					}
				}

				subnetID, err := lang.Cast[string](subnetOutputs["id"])
				if err != nil {
					return nil, fail.Wrap(err)
				}

				subnetsByID[subnetID] = name
				subnetsByName[name] = subnetID

				ip, err := lang.Cast[string](entry["fixed_ip_v4"])
				if err == nil && ip != "" {
					ipv4Addresses[subnetID] = ip
				}

				ip, err = lang.Cast[string](entry["fixed_ip_v6"])
				if err == nil && ip != "" {
					ipv6Addresses[subnetID] = ip
				}

				// FIXME: never created floatin IP with OVH, code never tested...
				// if ipv4 == "" || ipv6 == "" {
				// 	ip, err = lang.Cast[string](entry["floating_ip"])
				// 	if err == nil && ip != "" {
				// 		if valid.IsIPv6(ip) {
				// 			ipv6Addresses[subnetID] = ip
				// 		} else {
				// 			ipv4Addresses[subnetID] = ip
				// 		}
				// 	}
				// }
			} else {
				ip, err := lang.Cast[string](entry["fixed_ip_v4"])
				if err == nil && ip != "" {
					ipv4 = ip
				}

				ip, err = lang.Cast[string](entry["fixed_ip_v6"])
				if err == nil && ip != "" {
					ipv6 = ip
				}

				// FIXME: never created floatin IP with OVH, code never tested...
				// if ipv4 == "" || ipv6 == "" {
				// 	ip, err = lang.Cast[string](entry["floating_ip"])
				// 	if err == nil && ip != "" {
				// 		if valid.IsIPv6(ip) && ipv6 == ""{
				// 			ipv6 = ip
				// 		} else if ipv4 == "" {
				// 			ipv4 = ip
				// 		}
				// 	}
				// }
			}
		}

		host.Networking.PublicIPv4 = ipv4
		host.Networking.PublicIPv6 = ipv6
		host.Networking.SubnetsByID = subnetsByID
		host.Networking.SubnetsByName = subnetsByName
		host.Networking.IPv4Addresses = ipv4Addresses
		host.Networking.IPv6Addresses = ipv6Addresses

		host.Description.AZ = creationZone
	}
	return host, nil
}

// toHostSize converts flavor attributes returned by OpenStack driver into abstract.HostEffectiveSizing
func (p *provider) toHostSize(tpl *abstract.HostTemplate) (_ *abstract.HostEffectiveSizing, ferr fail.Error) {
	hostSizing := abstract.NewHostEffectiveSizing()
	hostSizing.Cores = tpl.Cores
	hostSizing.DiskSize = tpl.DiskSize
	hostSizing.RAMSize = tpl.RAMSize
	return hostSizing, nil
}

// ClearHostStartupScript ...
func (p *provider) ClearHostStartupScript(ctx context.Context, hostParam iaasapi.HostIdentifier) fail.Error {
	return nil
}

// InspectHost ...
func (p *provider) InspectHost(ctx context.Context, hostParam iaasapi.HostIdentifier) (*abstract.HostFull, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}
	_, hostLabel, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "(%s)", hostLabel).WithStopwatch().Entering().Exiting()

	ahf, xerr := p.MiniStack.InspectHost(ctx, hostParam)
	if xerr != nil {
		return nil, xerr
	}

	return ahf, p.ConsolidateHostSnippet(ahf.HostCore)
}

// GetHostState ...
func (p *provider) GetHostState(ctx context.Context, hostParam iaasapi.HostIdentifier) (hoststate.Enum, fail.Error) {
	if valid.IsNull(p) {
		return hoststate.Unknown, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "()").WithStopwatch().Entering().Exiting()

	return p.MiniStack.GetHostState(ctx, hostParam)
}

// ListHosts ...
func (p *provider) ListHosts(ctx context.Context, b bool) (abstract.HostList, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "()").WithStopwatch().Entering().Exiting()

	return p.MiniStack.ListHosts(ctx, b)
}

// DeleteHost ...
func (p *provider) DeleteHost(ctx context.Context, hostParam iaasapi.HostIdentifier) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	switch hostParam.(type) {
	case string:
		return fail.InvalidParameterError("hostParam", "must be an *abstract.HostCore or *abstract.HostFull")
	default:
	}
	ahf, hostLabel, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "(%s)", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	xerr = ahf.AddOptions(abstract.MarkForDestruction())
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

	def, xerr := renderer.Assemble(ctx, ahf)
	if xerr != nil {
		return xerr
	}

	xerr = renderer.Destroy(ctx, def /*, terraformerapi.WithTarget(ahf)*/)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete Network '%s'", ahf.Name)
	}

	return nil
}

func (p *provider) StopHost(ctx context.Context, hostParam iaasapi.HostIdentifier, gracefully bool) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "(%s)", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	ahf, xerr = p.InspectHost(ctx, ahf)
	if xerr != nil {
		return xerr
	}

	// FIXME: change this to abstract.MarkForStop()
	xerr = ahf.AddOptions(abstract.WithExtraData("MarkedForStop", true))
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

	def, xerr := renderer.Assemble(ctx, ahf)
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

func (p *provider) StartHost(ctx context.Context, hostParam iaasapi.HostIdentifier) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	ahf, hostLabel, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "(%s)", hostLabel).WithStopwatch().Entering()
	defer tracer.Exiting()

	ahf, xerr = p.InspectHost(ctx, ahf)
	if xerr != nil {
		return xerr
	}

	// FIXME: change this to abstract.MarkForStart()
	xerr = ahf.AddOptions(abstract.WithExtraData("MarkedForStop", false))
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

	def, xerr := renderer.Assemble(ctx, ahf)
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

func (p *provider) RebootHost(ctx context.Context, hostParam iaasapi.HostIdentifier) fail.Error {
	xerr := p.StopHost(ctx, hostParam, true)
	if xerr != nil {
		return xerr
	}

	return p.StartHost(ctx, hostParam)
}

func (p *provider) ResizeHost(ctx context.Context, hostParam iaasapi.HostIdentifier, requirements abstract.HostSizingRequirements) (*abstract.HostFull, fail.Error) {
	if valid.IsNil(p) {
		return nil, fail.InvalidInstanceError()
	}
	_ /*ahf*/, hostRef, xerr := iaasapi.ValidateHostIdentifier(hostParam)
	if xerr != nil {
		return nil, xerr
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "(%s)", hostRef).WithStopwatch().Entering().Exiting()

	// TODO: RESIZE Call this
	// servers.Resize()

	return nil, fail.NotImplementedError("ResizeHost() not implemented yet") // FIXME: Technical debt
}

func (p *provider) WaitHostReady(ctx context.Context, hostParam iaasapi.HostIdentifier, timeout time.Duration) (*abstract.HostCore, fail.Error) {
	if valid.IsNull(p) {
		return nil, fail.InvalidInstanceError()
	}

	defer debug.NewTracer(ctx, tracing.ShouldTrace("provider.ovhtf") || tracing.ShouldTrace("providers.compute"), "()").WithStopwatch().Entering().Exiting()

	return p.MiniStack.WaitHostReady(ctx, hostParam, timeout)
}

// BindSecurityGroupToHost ...
func (p *provider) BindSecurityGroupToHost(ctx context.Context, asg *abstract.SecurityGroup, ahc *abstract.HostCore) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	if asg == nil {
		return fail.InvalidParameterCannotBeNilError("asg")
	}
	if !asg.IsConsistent() {
		return fail.InvalidParameterError("asg", "is not consistent")
	}
	if ahc == nil {
		return fail.InvalidParameterCannotBeNilError("ahf")
	}
	if !ahc.IsConsistent() {
		return fail.InvalidParameterError("ahc", "is not consistent")
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

	var sgs map[string]string
	entry, ok := ahc.Extra()["SecurityGroupByID"]
	if !ok {
		sgs = map[string]string{}
	} else {
		var err error
		sgs, err = lang.Cast[map[string]string](entry)
		if err != nil {
			return fail.Wrap(err)
		}
	}
	sgs[asg.ID] = asg.Name
	xerr = ahc.AddOptions(abstract.WithExtraData("SecurityGroupByID", sgs), abstract.WithExtraData("MarkedForCreation", false))
	if xerr != nil {
		return xerr
	}

	def, xerr := renderer.Assemble(ctx, ahc)
	if xerr != nil {
		return xerr
	}

	_, xerr = renderer.Apply(ctx, def)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to update Security Groups of Host '%s'", ahc.Name)
	}

	return nil
}

// UnbindSecurityGroupFromHost ...
func (p *provider) UnbindSecurityGroupFromHost(ctx context.Context, asg *abstract.SecurityGroup, ahc *abstract.HostCore) fail.Error {
	if valid.IsNull(p) {
		return fail.InvalidInstanceError()
	}
	if asg == nil {
		return fail.InvalidParameterCannotBeNilError("asg")
	}
	if !asg.IsConsistent() {
		return fail.InvalidParameterError("asg", "is not consistent")
	}
	if ahc == nil {
		return fail.InvalidParameterCannotBeNilError("ahc")
	}
	if !ahc.IsConsistent() {
		return fail.InvalidParameterError("ahc", "is not consistent")
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

	currentSGs := map[string]string{}
	newSGs := map[string]string{}
	for k, v := range currentSGs {
		if v != asg.Name {
			newSGs[k] = v
		}
	}
	xerr = ahc.AddOptions(abstract.WithExtraData("SecurityGroupByID", newSGs), abstract.WithExtraData("MarkedForCreation", false))
	if xerr != nil {
		return xerr
	}

	def, xerr := renderer.Assemble(ctx, ahc)
	if xerr != nil {
		return xerr
	}

	_, xerr = renderer.Apply(ctx, def)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to delete Network '%s'", ahc.Name)
	}

	return nil
}

// ConsolidateHostSnippet ensures the abstract HostCore contains necessary options
func (p *provider) ConsolidateHostSnippet(ahc *abstract.HostCore) fail.Error {
	if valid.IsNil(p) || ahc == nil {
		return nil
	}

	return ahc.AddOptions(abstract.UseTerraformSnippet(hostDesignResourceSnippetPath))
}
