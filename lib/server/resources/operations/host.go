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

package operations

import (
	"fmt"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	// hostsFolderName is the technical name of the container used to store networks info
	hostsFolderName = "hosts"

	defaultHostSecurityGroupNamePattern = "safescale-sg_host_%s.%s.%s" // safescale-sg_host_<hostname>.<subnet name>.<network name>; should be unique across a tenant
)

// host ...
// follows interface resources.Host
type host struct {
	*core

	installMethods                map[uint8]installmethod.Enum
	privateIP, publicIP, accessIP string
	sshProfile                    *system.SSHConfig
}

// NewHost ...
func NewHost(svc iaas.Service) (_ *host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nil, fail.InvalidParameterError("svc", "cannot be nil")
	}

	coreInstance, xerr := newCore(svc, "host", hostsFolderName, &abstract.HostCore{})
	if xerr != nil {
		return nil, xerr
	}

	return &host{core: coreInstance}, nil
}

// nullHost returns a *host corresponding to NullValue
func nullHost() *host {
	return &host{core: nullCore()}
}

// LoadHost ...
func LoadHost(task concurrency.Task, svc iaas.Service, ref string) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task.IsNull() {
		return nullHost(), fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if svc.IsNull() {
		return nullHost(), fail.InvalidParameterError("svc", "cannot be null value of 'iaas.Service'")
	}
	if ref == "" {
		return nullHost(), fail.InvalidParameterError("ref", "cannot be empty string")
	}

	rh, xerr := NewHost(svc)
	if xerr != nil {
		return nullHost(), xerr
	}

	// TODO: core.Read() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
	if xerr = rh.Read(task, ref); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata message
			return nullHost(), fail.NotFoundError("failed to find Host '%s'", ref)
		default:
			return nullHost(), xerr
		}
	}

	if xerr = rh.upgradeIfNeeded(task); xerr != nil {
		return nil, fail.Wrap(xerr, "failed to upgrade Host metadata")
	}

	// (re)cache information only if there was no error
	return rh, rh.cacheAccessInformation(task)
}

// upgradeIfNeeded upgrades IPAddress properties if needed
func (rh *host) upgradeIfNeeded(task concurrency.Task) fail.Error {
	rh.SafeLock(task)
	defer rh.SafeUnlock(task)

	return rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {

		// upgrade hostproperty.NetworkV1 to hostproperty.NetworkV2
		if !props.Lookup(hostproperty.NetworkV2) {
			xerr := props.Alter(task, hostproperty.NetworkV1, func(clonable data.Clonable) fail.Error {
				hnV1, ok := clonable.(*propertiesv1.HostNetwork)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				innerXErr := props.Alter(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
					hnV2, ok := clonable.(*propertiesv2.HostNetworking)
					if !ok {
						return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					hnV2.DefaultSubnetID = hnV1.DefaultNetworkID
					hnV2.IPv4Addresses = hnV1.IPv4Addresses
					hnV2.IPv6Addresses = hnV1.IPv6Addresses
					hnV2.IsGateway = hnV1.IsGateway
					hnV2.PublicIPv4 = hnV1.PublicIPv4
					hnV2.PublicIPv6 = hnV1.PublicIPv6
					hnV2.SubnetsByID = hnV1.NetworksByID
					hnV2.SubnetsByName = hnV1.NetworksByName
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}
				// FIXME: clean old property or leave it ? will differ from v2 through time if Subnets are added for example
				// hnV1 = &propertiesv1.HostNetworking{}
				return nil
			})
			if xerr != nil {
				return xerr
			}
		}

		return nil
	})
}

// cacheAccessInformation loads in cache SSH configuration to access host; this information will not change over time
func (rh *host) cacheAccessInformation(task concurrency.Task) fail.Error {
	svc := rh.GetService()

	rh.SafeLock(task)
	defer rh.SafeUnlock(task)

	return rh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		var primaryGatewayConfig, secondaryGatewayConfig *system.SSHConfig

		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		innerXErr := props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(hnV2.IPv4Addresses) > 0 {
				rh.privateIP = hnV2.IPv4Addresses[hnV2.DefaultSubnetID]
				if rh.privateIP == "" {
					rh.privateIP = hnV2.IPv6Addresses[hnV2.DefaultSubnetID]
				}
			}
			rh.publicIP = hnV2.PublicIPv4
			if rh.publicIP == "" {
				rh.publicIP = hnV2.PublicIPv6
			}
			if rh.publicIP != "" {
				rh.accessIP = rh.publicIP
			} else {
				rh.accessIP = rh.privateIP
			}

			if !hnV2.IsGateway {
				rs, xerr := LoadSubnet(task, svc, "", hnV2.DefaultSubnetID)
				if xerr != nil {
					return xerr
				}
				rgw, xerr := rs.InspectGateway(task, true)
				if xerr != nil {
					return xerr
				}
				gwErr := rgw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					gwahc, ok := clonable.(*abstract.HostCore)
					if !ok {
						return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					ip := rgw.(*host).getAccessIP(task)
					primaryGatewayConfig = &system.SSHConfig{
						PrivateKey: gwahc.PrivateKey,
						Port:       int(gwahc.SshPort),
						IPAddress:  ip,
						Hostname:   gwahc.Name,
						User:       abstract.DefaultUser,
					}
					return nil
				})
				if gwErr != nil {
					return gwErr
				}

				// Secondary gateway may not exist...
				rgw, xerr = rs.InspectGateway(task, false)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// continue
					default:
						return xerr
					}
				} else {
					gwErr = rgw.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
						gwahc, ok := clonable.(*abstract.HostCore)
						if !ok {
							return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}
						secondaryGatewayConfig = &system.SSHConfig{
							PrivateKey: gwahc.PrivateKey,
							Port:       int(gwahc.SshPort),
							IPAddress:  rgw.(*host).getAccessIP(task),
							Hostname:   rgw.GetName(),
							User:       abstract.DefaultUser,
						}
						return nil
					})
					if gwErr != nil {
						return gwErr
					}
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		rh.sshProfile = &system.SSHConfig{
			Port:                   int(ahc.SshPort),
			IPAddress:              rh.accessIP,
			Hostname:               rh.GetName(),
			User:                   abstract.DefaultUser,
			PrivateKey:             ahc.PrivateKey,
			GatewayConfig:          primaryGatewayConfig,
			SecondaryGatewayConfig: secondaryGatewayConfig,
		}
		return nil
	})
}

// IsNull tests if instance is nil or empty
func (rh *host) IsNull() bool {
	return rh == nil || rh.core.IsNull()
}

// Browse walks through host folder and executes a callback for each entries
func (rh host) Browse(task concurrency.Task, callback func(*abstract.HostCore) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if callback == nil {
		return fail.InvalidParameterError("callback", "cannot be nil")
	}

	return rh.core.BrowseFolder(task, func(buf []byte) (innerXErr fail.Error) {
		ahc := abstract.NewHostCore()
		if innerXErr = ahc.Deserialize(buf); innerXErr != nil {
			return innerXErr
		}

		return callback(ahc)
	})
}

// ForceGetState returns the current state of the provider host
func (rh *host) ForceGetState(task concurrency.Task) (state hoststate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	state = hoststate.UNKNOWN
	if rh.IsNull() {
		return state, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return state, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	if xerr = rh.Reload(task); xerr != nil {
		return state, xerr
	}

	xerr = rh.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		state = ahc.LastState
		return nil

	})
	return state, xerr
}

// Reload reloads host from metadata and current host state on provider state
func (rh *host) Reload(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	// Read data from metadata storage
	hostID := rh.GetID()
	xerr = retry.WhileUnsuccessfulDelay1Second(
		func() error {
			return rh.Read(task, hostID)
		},
		10*time.Second,
	)
	if xerr != nil {
		// If retry timed out, log it and return error ErrNotFound
		if _, ok := xerr.(*retry.ErrTimeout); ok {
			xerr = fail.NotFoundError("metadata of host '%s' not found; host deleted?", hostID)
		}
		return xerr
	}

	// Request host inspection from provider
	ahf, xerr := rh.GetService().InspectHost(rh.GetID())
	if xerr != nil {
		return xerr
	}

	// Updates the host metadata
	xerr = rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' received", reflect.TypeOf(clonable).String())
		}
		changed := false
		if ahc.LastState != ahf.CurrentState {
			ahc.LastState = ahf.CurrentState
			changed = true
		}

		innerXErr := props.Alter(task, hostproperty.SizingV1, func(clonable data.Clonable) fail.Error {
			hostSizingV1, ok := clonable.(*propertiesv1.HostSizing)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			allocated := converters.HostEffectiveSizingFromAbstractToPropertyV1(ahf.Sizing)
			// FIXME: how to compare the 2 structs ?
			if allocated != hostSizingV1.AllocatedSize {
				hostSizingV1.AllocatedSize = allocated
				changed = true
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Updates host property propertiesv1.HostNetworking
		innerXErr = props.Alter(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_ = hnV2.Replace(converters.HostNetworkingFromAbstractToPropertyV2(*ahf.Networking))
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}
		if !changed {
			return fail.AlteredNothingError()
		}
		return nil
	})
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			return nil
		default:
			return xerr
		}
	}

	return rh.cacheAccessInformation(task)
}

// GetState returns the last known state of the host, without forced inspect
func (rh host) GetState(task concurrency.Task) (state hoststate.Enum) {
	state = hoststate.UNKNOWN
	if rh.IsNull() || task.IsNull() {
		return state
	}

	_ = rh.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}
		state = ahc.LastState
		return nil
	})
	return state
}

// Create creates a new host and its metadata
// If the metadata is already carrying a host, returns fail.ErrNotAvailable
func (rh *host) Create(task concurrency.Task, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements) (_ *userdata.Content, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	hostname := rh.GetName()
	if hostname != "" {
		return nil, fail.NotAvailableError("already carrying host '%s'", hostname)
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", hostReq.ResourceName).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitTraceError(&xerr, "failed to create host")

	svc := rh.GetService()

	// Check if host exists and is managed bySafeScale
	if _, xerr = LoadHost(task, svc, hostReq.ResourceName); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		// continue
		default:
			return nil, fail.Wrap(xerr, "failed to check if host '%s' already exists", hostReq.ResourceName)
		}
	} else {
		return nil, fail.DuplicateError("'%s' already exists", hostReq.ResourceName)
	}

	// Check if host exists but is not managed by SafeScale
	if _, xerr = svc.InspectHost(abstract.NewHostCore().SetName(hostReq.ResourceName)); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return nil, fail.Wrap(xerr, "failed to check if host resource name '%s' is already used", hostReq.ResourceName)
		}
	} else {
		return nil, fail.DuplicateError("found an existing Host named '%s' (but not managed by SafeScale)", hostReq.ResourceName)
	}

	// If TemplateID is not explicitly provided, search the appropriate template to satisfy 'hostDef'
	if hostReq.TemplateID == "" {
		if hostDef.Template != "" {
			tmpl, xerr := svc.FindTemplateByName(hostDef.Template)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				// continue
				default:
					return nil, xerr
				}
			} else {
				hostReq.TemplateID = tmpl.ID
			}
		}
	}
	if hostReq.TemplateID == "" {
		hostReq.TemplateID, xerr = rh.findTemplateID(hostDef)
		if xerr != nil {
			return nil, xerr
		}
	}

	// identify default Subnet
	var defaultSubnet resources.Subnet
	if len(hostReq.Subnets) > 0 {
		// By convention, default subnet is the first of the list
		as := hostReq.Subnets[0]
		if defaultSubnet, xerr = LoadSubnet(task, svc, "", as.ID); xerr != nil {
			return nil, xerr
		}
		if hostReq.DefaultRouteIP == "" {
			hostReq.DefaultRouteIP = defaultSubnet.(*subnet).getDefaultRouteIP(task)
		}
	} else {
		if defaultSubnet, _, xerr = getOrCreateDefaultSubnet(task, svc); xerr != nil {
			return nil, xerr
		}
		xerr = defaultSubnet.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			as, ok := clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Networking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostReq.Subnets = append(hostReq.Subnets, as)
			return nil
		})
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to consult details of Subnet '%s'", defaultSubnet.GetName())
		}
	}

	// If hostReq.ImageID is not explicitly defined, find an image ID corresponding to the content of hostDef.Image
	if hostReq.ImageID == "" {
		hostReq.ImageID, xerr = rh.findImageID(&hostDef)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to find image to use on compute resource")
		}
	}

	// list IDs of Security Groups to apply to host
	if len(hostReq.SecurityGroupIDs) == 0 {
		hostReq.SecurityGroupIDs = make(map[string]struct{}, len(hostReq.Subnets)+1)
		for _, v := range hostReq.Subnets {
			hostReq.SecurityGroupIDs[v.InternalSecurityGroupID] = struct{}{}
		}

		opts, xerr := svc.GetConfigurationOptions()
		if xerr != nil {
			return nil, xerr
		}
		anon, ok := opts.Get("UseNATService")
		useNATService := ok && anon.(bool)
		if hostReq.PublicIP || useNATService {
			xerr = defaultSubnet.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				as, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError("*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				if as.PublicIPSecurityGroupID != "" {
					hostReq.SecurityGroupIDs[as.PublicIPSecurityGroupID] = struct{}{}
				}
				return nil
			})
			if xerr != nil {
				return nil, fail.Wrap(xerr, "failed to consult details of Subnet '%s'", defaultSubnet.GetName())
			}
		}
	}

	// // Give a chance to set a password by safescaled environment (meaning for all Hosts)
	// if hostReq.Password == "" {
	// 	hostReq.Password = os.Getenv("SAFESCALE_UNSAFE_PASSWORD")
	// }

	ahf, userdataContent, xerr := svc.CreateHost(hostReq)
	if xerr != nil {
		if _, ok := xerr.(*fail.ErrInvalidRequest); ok {
			return nil, xerr
		}
		return nil, fail.Wrap(xerr, "failed to create compute resource '%s'", hostReq.ResourceName)
	}

	defer func() {
		if xerr != nil && !hostReq.KeepOnFailure {
			if derr := svc.DeleteHost(ahf.Core.ID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up after failure, failed to delete host '%s'", ahf.Core.Name))
			}
		}
	}()

	// Make sure ssh port wanted is set
	if hostReq.SshPort > 0 {
		ahf.Core.SshPort = hostReq.SshPort
	} else {
		ahf.Core.SshPort = 22
	}

	// Creates metadata early to "reserve" host name
	if xerr = rh.Carry(task, ahf.Core); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !hostReq.KeepOnFailure {
			if derr := rh.core.Delete(task); derr != nil {
				logrus.Errorf("cleaning up after failure, failed to delete host '%s' metadata: %v", ahf.Core.Name, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	xerr = rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		innerXErr := props.Alter(task, hostproperty.SizingV1, func(clonable data.Clonable) fail.Error {
			hostSizingV1, ok := clonable.(*propertiesv1.HostSizing)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostSizingV1.AllocatedSize = converters.HostEffectiveSizingFromAbstractToPropertyV1(ahf.Sizing)
			hostSizingV1.RequestedSize = converters.HostSizingRequirementsFromAbstractToPropertyV1(hostDef)
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Sets host extension DescriptionV1
		innerXErr = props.Alter(task, hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
			hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_ = hostDescriptionV1.Replace(converters.HostDescriptionFromAbstractToPropertyV1(*ahf.Description))
			creator := ""
			hostname, _ := os.Hostname()
			if curUser, err := user.Current(); err == nil {
				creator = curUser.Username
				if hostname != "" {
					creator += "@" + hostname
				}
				if curUser.Name != "" {
					creator += " (" + curUser.Name + ")"
				}
			} else {
				creator = "unknown@" + hostname
			}
			hostDescriptionV1.Creator = creator
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Updates host property propertiesv2.HostNetworking
		innerXErr = props.Alter(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			_ = hnV2.Replace(converters.HostNetworkingFromAbstractToPropertyV2(*ahf.Networking))
			hnV2.DefaultSubnetID = defaultSubnet.GetID()
			hnV2.IsGateway = hostReq.IsGateway
			hnV2.PublicIPv4 = ahf.Networking.PublicIPv4
			hnV2.PublicIPv6 = ahf.Networking.PublicIPv6
			hnV2.SubnetsByID = ahf.Networking.SubnetsByID
			hnV2.SubnetsByName = ahf.Networking.SubnetsByName
			hnV2.IPv4Addresses = ahf.Networking.IPv4Addresses
			hnV2.IPv6Addresses = ahf.Networking.IPv6Addresses
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Updates properties in metadata
		return rh.setSecurityGroups(task, hostReq, defaultSubnet)
	})
	if xerr != nil {
		return nil, xerr
	}
	defer rh.onFailureUndoSetSecurityGroups(task, &xerr, hostReq.KeepOnFailure)

	if xerr = rh.cacheAccessInformation(task); xerr != nil {
		return nil, xerr
	}

	logrus.Infof("Compute resource created: '%s'", rh.GetName())

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting SSH availability on Host '%s' ...", rh.GetName())

	// FIXME: configurable timeout here
	status, xerr := rh.waitInstallPhase(task, userdata.PHASE1_INIT, time.Duration(0))
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return nil, fail.Wrap(xerr, "timeout after Host creation waiting for SSH availability")
		default:
			if abstract.IsProvisioningError(xerr) {
				logrus.Errorf("%+v", xerr)
				return nil, fail.Wrap(xerr, "error provisioning the new host, please check safescaled logs", rh.GetName())
			}
			return nil, xerr
		}
	}

	xerr = rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		// update host system property
		return props.Alter(task, hostproperty.SystemV1, func(clonable data.Clonable) fail.Error {
			systemV1, ok := clonable.(*propertiesv1.HostSystem)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSystem' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			parts := strings.Split(status, ",")
			systemV1.Type = parts[1]
			systemV1.Flavor = parts[2]
			systemV1.Image = hostReq.ImageID
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}

	// -- Updates host link with subnets --
	if xerr = rh.updateSubnets(task, hostReq); xerr != nil {
		return nil, xerr
	}
	defer rh.undoUpdateSubnets(task, hostReq, &xerr)

	if xerr = rh.finalizeProvisioning(task, userdataContent); xerr != nil {
		return nil, xerr
	}

	logrus.Infof("host '%s' created successfully", rh.GetName())
	return userdataContent, nil
}

// setSecurityGroups sets the Security Groups for the host
func (rh *host) setSecurityGroups(task concurrency.Task, req abstract.HostRequest, defaultSubnet resources.Subnet) fail.Error {
	return rh.properties.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) (innerXErr fail.Error) {
		hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
		if !ok {
			return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := rh.GetService()

		subnetCount := len(req.Subnets)
		isolatedHost := !req.IsGateway && req.PublicIP && (subnetCount == 0 || (subnetCount == 1 && defaultSubnet.GetName() == abstract.SingleHostNetworkName))

		// get default Subnet core data
		var as *abstract.Subnet
		innerXErr = defaultSubnet.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			var ok bool
			as, ok = clonable.(*abstract.Subnet)
			if !ok {
				return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		var (
			gwsg, pubipsg, lansg resources.SecurityGroup
		)

		// Apply Security Group for gateways in default Subnet
		if req.IsGateway {
			if gwsg, innerXErr = LoadSecurityGroup(task, svc, as.GWSecurityGroupID); innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to query Subnet '%s' Security Group '%s'", defaultSubnet.GetName(), as.GWSecurityGroupID)
			}
			if innerXErr = gwsg.BindToHost(task, rh, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to apply Subnet's Security Group for gateway '%s' on host '%s'", gwsg.GetName(), req.ResourceName)
			}

			defer func() {
				if innerXErr != nil && !req.KeepOnFailure {
					if derr := gwsg.UnbindFromHost(task, rh); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind Security Group '%s' from Host '%s'", gwsg.GetName(), rh.GetName()))
					}
				}
			}()

			item := &propertiesv1.SecurityGroupBond{
				ID:         gwsg.GetID(),
				Name:       gwsg.GetName(),
				Disabled:   false,
				FromSubnet: true,
			}
			hsgV1.ByID[item.ID] = item
			hsgV1.ByName[item.Name] = item.ID
		}

		// Apply Security Group for hosts with public IP in default Subnet
		if req.IsGateway || isolatedHost {
			if pubipsg, innerXErr = LoadSecurityGroup(task, svc, as.PublicIPSecurityGroupID); innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to query Subnet '%s' Security Group with ID %s", defaultSubnet.GetName(), as.PublicIPSecurityGroupID)
			}
			if innerXErr = pubipsg.BindToHost(task, rh, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to apply Subnet's Security Group for gateway '%s' on host '%s'", pubipsg.GetName(), req.ResourceName)
			}

			defer func() {
				if innerXErr != nil && !req.KeepOnFailure {
					if derr := pubipsg.UnbindFromHost(task, rh); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind Security Group '%s' from Host '%s'", pubipsg.GetName(), rh.GetName()))
					}
				}
			}()

			item := &propertiesv1.SecurityGroupBond{
				ID:         pubipsg.GetID(),
				Name:       pubipsg.GetName(),
				Disabled:   false,
				FromSubnet: true,
			}
			hsgV1.ByID[item.ID] = item
			hsgV1.ByName[item.Name] = item.ID
		}

		// Apply internal Security Group of each subnets
		if req.IsGateway || !isolatedHost {
			defer func() {
				if innerXErr != nil && !req.KeepOnFailure {
					var (
						sg     resources.SecurityGroup
						derr   error
						errors []error
					)
					for _, v := range req.Subnets {
						if sg, derr = LoadSecurityGroup(task, svc, v.InternalSecurityGroupID); derr == nil {
							derr = sg.UnbindFromHost(task, rh)
						}
						if derr != nil {
							errors = append(errors, derr)
						}
					}
					if len(errors) > 0 {
						_ = innerXErr.AddConsequence(fail.Wrap(fail.NewErrorList(errors), "failed to unbind Subnets Security Group from host '%s'", sg.GetName(), req.ResourceName))
					}
				}
			}()

			for _, v := range req.Subnets {
				if lansg, innerXErr = LoadSecurityGroup(task, svc, v.InternalSecurityGroupID); innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to load Subnet '%s' internal Security Group %s", v.Name, v.InternalSecurityGroupID)
				}
				if innerXErr = lansg.BindToHost(task, rh, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to apply Subnet '%s' internal Security Group '%s' to host '%s'", v.Name, lansg.GetName(), req.ResourceName)
				}

				// register security group in properties
				item := &propertiesv1.SecurityGroupBond{
					ID:         lansg.GetID(),
					Name:       lansg.GetName(),
					Disabled:   false,
					FromSubnet: true,
				}
				hsgV1.ByID[item.ID] = item
				hsgV1.ByName[item.Name] = item.ID
			}
		}

		// Create and bind a dedicated Security Group to the host (with no rules by default)
		var (
			rn resources.Network
			an *abstract.Network
		)
		if rn, innerXErr = defaultSubnet.InspectNetwork(task); innerXErr == nil {
			innerXErr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				an, ok = clonable.(*abstract.Network)
				if !ok {
					return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
		}
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to query Network of Subnet '%s'", defaultSubnet.GetName())
		}
		// sgName := fmt.Sprintf(defaultHostSecurityGroupNamePattern, req.ResourceName, defaultSubnet.GetName(), an.Name)
		// hostSG, innerXErr := NewSecurityGroup(svc)
		// if innerXErr != nil {
		// 	return fail.Wrap(innerXErr, "failed to instantiate a new Security Group")
		// }
		// if innerXErr = hostSG.Create(task, an.ID, sgName, fmt.Sprintf("Host %s default Security Group", req.ResourceName), abstract.SecurityGroupRules{}); innerXErr != nil {
		// 	return fail.Wrap(innerXErr, "failed to create Host '%s' default Security Group '%s'", req.ResourceName, sgName)
		// }
		//
		// // Starting from here, delete host Security group if exiting with error
		// defer func() {
		// 	if innerXErr != nil && !req.KeepOnFailure {
		// 		if derr := hostSG.Delete(task); derr != nil {
		// 			_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning unp on failure, failed to delete Host's Security Group '%s'", hostSG.GetName()))
		// 		}
		// 	}
		// }()
		//
		// // Bind freshly created Security Group to the host as default
		// if innerXErr = hostSG.BindToHost(task, rh, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsDefault); innerXErr != nil {
		// 	return fail.Wrap(innerXErr, "failed to bind Security Group '%s' to host '%s'", sgName, req.ResourceName)
		// }
		//
		// // Starting from here, unbind hosts security group if exiting with error
		// defer func() {
		// 	if innerXErr != nil && !req.KeepOnFailure {
		// 		if derr := hostSG.UnbindFromHost(task, rh); derr != nil {
		// 			_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to unbind Security Group '%s' from Host '%s'", hostSG.GetName(), rh.GetName()))
		// 		}
		// 	}
		// }()

		// Unbind "default" Security Group from Host if it is bound
		if sgName := svc.GetDefaultSecurityGroupName(); sgName != "" {
			adsg, innerXErr := svc.InspectSecurityGroupByName(an.ID, sgName)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// ignore this error
				default:
					return innerXErr
				}
			} else if innerXErr = svc.UnbindSecurityGroupFromHost(adsg, rh.GetID()); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					// Consider a security group not found as a successful unbind
				default:
					return fail.Wrap(innerXErr, "failed to unbind Security Group '%s' from Host", sgName)
				}
			}
		}

		// // register the security group in properties
		// item := &propertiesv1.SecurityGroupBond{
		// 	ID:         hostSG.GetID(),
		// 	Name:       hostSG.GetName(),
		// 	Disabled:   false,
		// 	FromSubnet: false,
		// }
		// hsgV1.ByID[item.ID] = item
		// hsgV1.ByName[item.Name] = item.ID
		// hsgV1.DefaultID = item.ID

		return nil
	})
}

func (rh *host) onFailureUndoSetSecurityGroups(task concurrency.Task, errorPtr *fail.Error, keepOnFailure bool) {
	if errorPtr == nil {
		logrus.Errorf("trying to call a cancel function from a nil error; cancel not run")
		return
	}
	if *errorPtr != nil && !keepOnFailure {
		svc := rh.GetService()
		derr := rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) (innerXErr fail.Error) {
				hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				var (
					opXErr fail.Error
					sg     resources.SecurityGroup
					errors []error
				)

				// unbind security groups
				for _, v := range hsgV1.ByName {
					if sg, opXErr = LoadSecurityGroup(task, svc, v); opXErr == nil {
						opXErr = sg.UnbindFromHost(task, rh)
					}
					if opXErr != nil {
						errors = append(errors, opXErr)
					}
				}
				if len(errors) > 0 {
					return fail.Wrap(fail.NewErrorList(errors), "cleaning up on failure, failed to unbind Security Groups from Host")
				}

				// // delete host default security group
				// if hsgV1.DefaultID != "" {
				// 	sg, innerXErr = LoadSecurityGroup(task, svc, hsgV1.DefaultID)
				// 	if innerXErr != nil {
				// 		switch innerXErr.(type) {
				// 		case *fail.ErrNotFound:
				// 		// consider non existence as a deletion success
				// 		default:
				// 			return innerXErr
				// 		}
				// 	} else {
				// 		if innerXErr = sg.Delete(task); innerXErr != nil {
				// 			return innerXErr
				// 		}
				// 	}
				// }
				return nil
			})
		})
		if derr != nil {
			_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to cleanup Security Groups"))
		}
	}
}

func (rh host) findTemplateID(hostDef abstract.HostSizingRequirements) (string, fail.Error) {
	svc := rh.GetService()
	if hostDef.Template != "" {
		if tpl, xerr := svc.FindTemplateByName(hostDef.Template); xerr == nil {
			return tpl.ID, nil
		}
		logrus.Warning(fail.NotFoundError("failed to find template '%s', trying to guess from sizing...", hostDef.Template))
	}

	template, xerr := svc.FindTemplateBySizing(hostDef)
	if xerr != nil {
		return "", xerr
	}
	//useScannerDB := hostDef.MinGPU > 0 || hostDef.MinCPUFreq > 0
	//templates, xerr := svc.ListTemplatesBySizing(hostDef, useScannerDB)
	//if xerr != nil {
	//	return "", fail.Wrap(xerr, "failed to find template corresponding to requested resources")
	//}
	//var template abstract.HostTemplate
	//if len(templates) > 0 {
	//	template = *(templates[0])
	//	msg := fmt.Sprintf("Selected host template: '%s' (%d core%s", template.Name, template.Cores, strprocess.Plural(uint(template.Cores)))
	//	if template.CPUFreq > 0 {
	//		msg += fmt.Sprintf(" at %.01f GHz", template.CPUFreq)
	//	}
	//	msg += fmt.Sprintf(", %.01f GB RAM, %d GB disk", template.RAMSize, template.DiskSize)
	//	if template.GPUNumber > 0 {
	//		msg += fmt.Sprintf(", %d GPU%s", template.GPUNumber, strprocess.Plural(uint(template.GPUNumber)))
	//		if template.GPUType != "" {
	//			msg += fmt.Sprintf(" %s", template.GPUType)
	//		}
	//	}
	//	msg += ")"
	//	logrus.Infof(msg)
	//} else {
	//	logrus.Errorf("failed to find template corresponding to requested resources")
	//	return "", fail.Wrap(xerr, "failed to find template corresponding to requested resources")
	//}
	return template.ID, nil
}

func (rh host) findImageID(hostDef *abstract.HostSizingRequirements) (string, fail.Error) {
	svc := rh.GetService()
	if hostDef.Image == "" {
		cfg, xerr := svc.GetConfigurationOptions()
		if xerr != nil {
			return "", xerr
		}
		hostDef.Image = cfg.GetString("DefaultImage")
	}

	var img *abstract.Image
	xerr := retry.WhileUnsuccessfulDelay1Second(
		func() error {
			var innerXErr fail.Error
			img, innerXErr = svc.SearchImage(hostDef.Image)
			return innerXErr
		},
		10*time.Second,
	)
	if xerr != nil {
		return "", xerr
	}
	return img.ID, nil
}

// runInstallPhase uploads then starts script corresponding to phase 'phase'
func (rh host) runInstallPhase(task concurrency.Task, phase userdata.Phase, userdataContent *userdata.Content) fail.Error {
	// execute userdata 'final' (phase4) script to final install/configure of the host (no need to reboot)
	content, xerr := userdataContent.Generate(phase)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil)
	}

	file := fmt.Sprintf("/opt/safescale/var/tmp/user_data.%s.sh", phase)
	if xerr = rh.PushStringToFile(task, string(content), file); xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil)
	}

	command := fmt.Sprintf("sudo bash %s; exit $?", file)
	// Executes the script on the remote host
	retcode, _, stderr, xerr := rh.Run(task, command, outputs.COLLECT, 0, 0)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to apply configuration phase '%s'", phase)
	}
	if retcode != 0 {
		if retcode == 255 {
			return fail.NewError("failed to execute install phase '%s' on host '%s': SSH connection failed", phase, rh.GetName())
		}
		return fail.NewError("failed to execute install phase '%s' on host '%s': %s", phase, rh.GetName(), stderr)
	}
	return nil
}

func (rh *host) waitInstallPhase(task concurrency.Task, phase userdata.Phase, timeout time.Duration) (string, fail.Error) {
	sshDefaultTimeout := int(temporal.GetHostTimeout().Minutes())
	if sshDefaultTimeoutCandidate := os.Getenv("SSH_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		if num, err := strconv.Atoi(sshDefaultTimeoutCandidate); err == nil {
			logrus.Debugf("Using custom timeout of %d minutes", num)
			sshDefaultTimeout = num
		}
	}
	sshCfg := rh.getSSHConfig(task)

	// TODO: configurable timeout here
	duration := time.Duration(sshDefaultTimeout) * time.Minute
	status, xerr := sshCfg.WaitServerReady(task, string(phase), time.Duration(sshDefaultTimeout)*time.Minute)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return status, fail.Wrap(xerr.Cause(), "failed to wait for SSH on Host '%s' to be ready after %s (phase %s): %s", rh.GetName(), temporal.FormatDuration(duration), phase, status)
		}
		if abstract.IsProvisioningError(xerr) {
			logrus.Errorf("%+v", xerr)
			return status, fail.Wrap(xerr, "error provisioning Host '%s', please check safescaled logs", rh.GetName())
		}
	}
	return status, xerr
}

// updateSubnets updates subnets on which host is attached and host property HostNetworkV2
func (rh *host) updateSubnets(task concurrency.Task, req abstract.HostRequest) fail.Error {
	// If host is a gateway, do not add it as host attached to the Subnet, it's considered as part of the subnet
	if !req.IsGateway {
		return rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hnV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hostID := rh.GetID()
				hostName := rh.GetName()

				for _, as := range req.Subnets {
					rs, innerXErr := LoadSubnet(task, rh.core.GetService(), "", as.ID)
					if innerXErr != nil {
						return innerXErr
					}

					innerXErr = rs.Alter(task, func(clonable data.Clonable, properties *serialize.JSONProperties) fail.Error {
						return properties.Alter(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
							subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
							if !ok {
								return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
							}

							subnetHostsV1.ByName[hostName] = hostID
							subnetHostsV1.ByID[hostID] = hostName
							return nil
						})
					})
					if innerXErr != nil {
						return innerXErr
					}

					hnV2.SubnetsByID[as.ID] = as.Name
					hnV2.SubnetsByName[as.Name] = as.ID
				}
				return nil
			})
		})
	}
	return nil
}

// undoUpdateSubnets removes what updateSubnets have done
func (rh *host) undoUpdateSubnets(task concurrency.Task, req abstract.HostRequest, errorPtr *fail.Error) {
	if errorPtr != nil && *errorPtr != nil && !req.IsGateway && !req.KeepOnFailure {
		xerr := rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hsV1, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hostID := rh.GetID()
				hostName := rh.GetName()

				for _, as := range req.Subnets {
					rs, innerXErr := LoadSubnet(task, rh.core.GetService(), "", as.ID)
					if innerXErr != nil {
						return innerXErr
					}

					innerXErr = rs.Alter(task, func(clonable data.Clonable, properties *serialize.JSONProperties) fail.Error {
						return properties.Alter(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
							subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
							if !ok {
								return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
							}

							delete(subnetHostsV1.ByID, hostID)
							delete(subnetHostsV1.ByName, hostName)
							return nil
						})
					})
					if innerXErr != nil {
						return innerXErr
					}

					delete(hsV1.SubnetsByID, as.ID)
					delete(hsV1.SubnetsByName, as.ID)
				}
				return nil
			})
		})
		if xerr != nil {
			_ = (*errorPtr).AddConsequence(fail.Wrap(xerr, "cleaning up on failure, failed to remove Host relationships with Subnets"))
		}
	}
}

func (rh *host) finalizeProvisioning(task concurrency.Task, userdataContent *userdata.Content) fail.Error {
	// Reset userdata script for Host from Cloud Provider metadata service (if stack is able to do so)
	if xerr := rh.GetService().ClearHostStartupScript(rh.GetID()); xerr != nil {
		return xerr
	}

	// Executes userdata.PHASE2_NETWORK_AND_SECURITY script to configure subnet and security
	if xerr := rh.runInstallPhase(task, userdata.PHASE2_NETWORK_AND_SECURITY, userdataContent); xerr != nil {
		return xerr
	}

	// Update Keypair of the Host with the one set in HostRequest
	xerr := rh.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ah, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		ah.PrivateKey = userdataContent.FinalPrivateKey
		return nil
	})
	if xerr != nil {
		return fail.Wrap(xerr, "failed to update Keypair")
	}
	if xerr = rh.cacheAccessInformation(task); xerr != nil {
		return xerr
	}

	// Reboot host
	command := "sudo systemctl reboot"
	if _, _, _, xerr = rh.Run(task, command, outputs.COLLECT, temporal.GetContextTimeout(), temporal.GetHostTimeout()); xerr != nil {
		return xerr
	}

	if _, xerr = rh.waitInstallPhase(task, userdata.PHASE2_NETWORK_AND_SECURITY, 0); xerr != nil {
		return xerr
	}

	// if host is not a gateway, executes userdata.PHASE4/5 scripts to fix possible system issues and finalize host creation
	// For a gateway, userdata.PHASE3 to 5 have to be run explicitly (cf. operations/subnet.go)
	if !userdataContent.IsGateway {
		// execute userdata.PHASE4_SYSTEM_FIXES script to fix possible misconfiguration in system
		if xerr = rh.runInstallPhase(task, userdata.PHASE4_SYSTEM_FIXES, userdataContent); xerr != nil {
			return xerr
		}

		// Reboot host
		command = "sudo systemctl reboot"
		if _, _, _, xerr = rh.Run(task, command, outputs.COLLECT, 0, 0); xerr != nil {
			return xerr
		}

		if _, xerr = rh.waitInstallPhase(task, userdata.PHASE4_SYSTEM_FIXES, 0); xerr != nil {
			return xerr
		}

		// execute userdata.PHASE5_FINAL script to final install/configure of the host (no need to reboot)
		if xerr = rh.runInstallPhase(task, userdata.PHASE5_FINAL, userdataContent); xerr != nil {
			return xerr
		}

		if _, xerr = rh.waitInstallPhase(task, userdata.PHASE5_FINAL, temporal.GetHostTimeout()); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrTimeout:
				return fail.Wrap(xerr, "timeout creating a host")
			}
			if abstract.IsProvisioningError(xerr) {
				logrus.Errorf("%+v", xerr)
				return fail.Wrap(xerr, "error provisioning the new host, please check safescaled logs", rh.GetName())
			}
			return xerr
		}
	}
	return nil
}

// WaitSSHReady waits until SSH responds successfully
func (rh *host) WaitSSHReady(task concurrency.Task, timeout time.Duration) (_ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return "", fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	return rh.waitInstallPhase(task, userdata.PHASE5_FINAL, timeout)
}

// getOrCreateDefaultSubnet gets network abstract.SingleHostNetworkName or create it if necessary
func getOrCreateDefaultSubnet(task concurrency.Task, svc iaas.Service) (rs resources.Subnet, gw resources.Host, xerr fail.Error) {
	rn, xerr := LoadNetwork(task, svc, abstract.SingleHostNetworkName)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		// continue
		default:
			return nil, nil, xerr
		}
	}
	if rn == nil {
		rn, xerr = NewNetwork(svc)
		if xerr != nil {
			return nil, nil, xerr
		}
		req := abstract.NetworkRequest{
			Name: abstract.SingleHostNetworkName,
			CIDR: stacks.DefaultNetworkCIDR,
		}
		xerr = rn.Create(task, req)
		if xerr != nil {
			return nil, nil, xerr
		}

		defer func() {
			if xerr != nil {
				derr := rn.Delete(task)
				if derr != nil {
					_ = xerr.AddConsequence(derr)
				}
			}
		}()
	}

	rs, xerr = LoadSubnet(task, svc, rn.GetID(), abstract.SingleHostSubnetName)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
		default:
			return nil, nil, xerr
		}
	}
	if rs.IsNull() {
		rs, xerr = NewSubnet(svc)
		if xerr != nil {
			return nil, nil, xerr
		}
		var DNSServers []string
		if opts, xerr := svc.GetConfigurationOptions(); xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
			default:
				return nil, nil, xerr
			}
		} else {
			DNSServers = strings.Split(opts.GetString("DNSServers"), ",")
		}
		req := abstract.SubnetRequest{
			Name:       abstract.SingleHostSubnetName,
			CIDR:       "10.0.0.0/17",
			DNSServers: DNSServers,
			HA:         false,
		}
		if xerr = rs.Create(task, req, "", nil); xerr != nil {
			return nil, nil, xerr
		}

		defer func() {
			if xerr != nil {
				derr := rs.Delete(task)
				if derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to delete subnet '%s'", abstract.SingleHostSubnetName))
				}
			}
		}()
	}

	rh, xerr := rs.InspectGateway(task, true)
	if xerr != nil {
		return nil, nil, xerr
	}

	return rs, rh, nil
}

// Delete deletes a host with its metadata and updates subnet links
func (rh *host) Delete(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	rh.SafeLock(task)
	defer rh.SafeUnlock(task)

	xerr = rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Don't remove a host that is a gateway
		return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostNetworkV2.IsGateway {
				return fail.NotAvailableError("cannot delete host, it's a gateway that can only be deleted through its subnet")
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	return rh.relaxedDeleteHost(task)
}

// relaxedDeleteHost is the method that really deletes a host, being a gateway or not
func (rh *host) relaxedDeleteHost(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	rh.SafeLock(task)
	defer rh.SafeUnlock(task)

	svc := rh.GetService()

	var shares map[string]*propertiesv1.HostShare
	xerr = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Don't remove a host having shares that are currently remotely mounted
		innerXErr := props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			shares = sharesV1.ByID
			shareCount := len(shares)
			for _, hostShare := range shares {
				count := len(hostShare.ClientsByID)
				if count > 0 {
					// clients found, checks if these clients already exists...
					for _, hostID := range hostShare.ClientsByID {
						_, inErr := LoadHost(task, svc, hostID)
						if inErr == nil {
							return fail.NotAvailableError("exports %d share%s and at least one share is mounted", shareCount, strprocess.Plural(uint(shareCount)))
						}
					}
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Do not delete a Host with Volumes attached
		return props.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			nAttached := len(hostVolumesV1.VolumesByID)
			if nAttached > 0 {
				return fail.NotAvailableError("host has %d volume%s attached", nAttached, strprocess.Plural(uint(nAttached)))
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	xerr = rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// If Host has mounted shares, unmounts them before anything else
		var mounts []*propertiesv1.HostShare
		innerXErr := props.Inspect(task, hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			for _, i := range hostMountsV1.RemoteMountsByPath {
				// Retrieve item data
				rshare, loopErr := LoadShare(task, svc, i.ShareID)
				if loopErr != nil {
					return loopErr
				}

				// Retrieve data about the server serving the item
				rhServer, loopErr := rshare.GetServer(task)
				if loopErr != nil {
					return loopErr
				}
				// Retrieve data about item from its server
				item, loopErr := rhServer.GetShare(task, i.ShareID)
				if loopErr != nil {
					return loopErr
				}
				mounts = append(mounts, item)
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Unmounts tier shares mounted on host (done outside the previous host.properties.Reading() section, because
		// Unmount() have to lock for write, and won't succeed while host.properties.Reading() is running,
		// leading to a deadlock)
		for _, item := range mounts {
			rs, loopErr := LoadShare(task, svc, item.ID)
			if loopErr != nil {
				return loopErr
			}
			loopErr = rs.Unmount(task, rh)
			if loopErr != nil {
				return loopErr
			}
		}

		// if host exports shares, delete them
		for _, v := range shares {
			rs, loopErr := LoadShare(task, svc, v.Name)
			if loopErr != nil {
				return loopErr
			}

			loopErr = rs.Delete(task)
			if loopErr != nil {
				return loopErr
			}
		}

		// Walk through property propertiesv1.HostNetworking to remove the reference to the host in Subnets
		innerXErr = props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostID := rh.GetID()
			// hostName := rh.GetName()
			var errors []error
			for k := range hostNetworkV2.SubnetsByID {
				rs, loopErr := LoadSubnet(task, svc, "", k)
				if loopErr == nil{
					loopErr = rs.UnbindHost(task, hostID)
				}
				if loopErr != nil {
					logrus.Errorf(loopErr.Error())
					errors = append(errors, loopErr)
					continue
				}
				// loopErr = rs.Alter(task, func(_ data.Clonable, netprops *serialize.JSONProperties) fail.Error {
				// 	return netprops.Alter(task, subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
				// 		subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
				// 		if !ok {
				// 			return fail.InconsistentError("'*propertiesv1.SubnetHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
				// 		}
				// 		delete(subnetHostsV1.ByID, hostID)
				// 		delete(subnetHostsV1.ByName, hostName)
				// 		return nil
				// 	})
				// })
				// if loopErr != nil {
				// 	logrus.Errorf(loopErr.Error())
				// 	errors = append(errors, loopErr)
				// }
			}
			if len(errors) > 0 {
				return fail.Wrap(fail.NewErrorList(errors), "failed to update metadata for Subnets of Host")
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Unbind Security Group from Host
		innerXErr = props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Unbind Security Groups from IPAddress
			var errors []error
			for _, v := range hsgV1.ByID {
				rsg, derr := LoadSecurityGroup(task, svc, v.ID)
				if derr == nil {
					derr = rsg.UnbindFromHost(task, rh)
				}
				if derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						// Consider that a Security Group that cannot be loaded or is not bound as a success
					default:
						errors = append(errors, derr)
					}
				}
			}
			if len(errors) > 0 {
				return fail.Wrap(fail.NewErrorList(errors), "failed to unbind some Security Groups")
			}

			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to unbind Security Groups from Host")
		}

		// Conditions are met, delete host
		waitForDeletion := true
		innerXErr = retry.WhileUnsuccessfulDelay1Second(
			func() error {
				if derr := svc.DeleteHost(rh.GetID()); derr != nil {
					switch derr.(type) {
					case *fail.ErrNotFound:
						// A host not found is considered as a successful deletion
					default:
						return fail.Wrap(derr, "cannot delete host")
					}
					waitForDeletion = false
				}
				return nil
			},
			time.Minute*5, // FIXME: hardcoded timeout
		)
		if innerXErr != nil {
			return innerXErr
		}

		// wait for effective host deletion
		if waitForDeletion {
			innerXErr = retry.WhileUnsuccessfulDelay5SecondsTimeout(
				func() error {
					state, stateErr := svc.GetHostState(rh.GetID())
					if stateErr != nil {
						switch stateErr.(type) {
						case *fail.ErrNotFound:
							// If host is not found anymore, consider this as a success
							return nil
						default:
							return stateErr
						}
					}
					if state == hoststate.ERROR {
						return fail.NotAvailableError("host is in state ERROR")
					}
					return nil
				},
				time.Minute*2, // FIXME: hardcoded duration
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrStopRetry:
					innerXErr = fail.ToError(innerXErr.Cause())
				}
			}
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
				// continue
				default:
					return innerXErr
				}
			}
		}

		return nil
		// // Delete default Security Group of Host
		// return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
		// 	hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
		// 	if !ok {
		// 		return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
		// 	}
		//
		// 	if hsgV1.DefaultID != "" {
		// 		rsg, derr := LoadSecurityGroup(task, svc, hsgV1.DefaultID)
		// 		if derr == nil {
		// 			derr = rsg.Delete(task)
		// 		}
		// 		if derr != nil {
		// 			switch derr.(type) {
		// 			case *fail.ErrNotFound:
		// 				// Consider a Security Group that cannot be found as a success
		// 			default:
		// 				return fail.Wrap(derr, "failed to delete default Security Group of Host")
		// 			}
		// 		}
		// 	}
		// 	return nil
		// })
	})
	if xerr != nil {
		return xerr
	}

	// Deletes metadata from Object Storage
	if xerr = rh.core.Delete(task); xerr != nil {
		// If entry not found, considered as success
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return xerr
		}
	}

	rh.Dispose()

	newHost := nullHost()
	*rh = *newHost
	return nil
}

// GetSSHConfig loads SSH configuration for host from metadata
//
// FIXME: verify that system.SSHConfig carries data about secondary getGateway
func (rh host) GetSSHConfig(task concurrency.Task) (_ *system.SSHConfig, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	return rh.getSSHConfig(task), nil
}

// getSSHConfig loads SSH configuration for host from metadata, for internal use
func (rh host) getSSHConfig(task concurrency.Task) *system.SSHConfig {
	if rh.IsNull() || task == nil {
		return &system.SSHConfig{}
	}

	rh.SafeRLock(task)
	defer rh.SafeRUnlock(task)

	return rh.sshProfile
}

// Run tries to execute command 'cmd' on the host
func (rh host) Run(task concurrency.Task, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return 0, "", "", fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return 0, "", "", fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if cmd == "" {
		return 0, "", "", fail.InvalidParameterError("cmd", "cannot be empty string")
	}

	var (
		stdOut, stdErr string
		retCode        int
	)

	// retrieve ssh config to perform some commands
	ssh, xerr := rh.GetSSHConfig(task)
	if xerr != nil {
		return 0, "", "", xerr
	}

	if executionTimeout < temporal.GetHostTimeout() {
		executionTimeout = temporal.GetHostTimeout()
	}
	if connectionTimeout < temporal.GetConnectSSHTimeout() {
		connectionTimeout = temporal.GetConnectSSHTimeout()
	}
	// FIXME: Whaaaaat ?
	if connectionTimeout > executionTimeout {
		connectionTimeout = executionTimeout + temporal.GetContextTimeout()
	}

	hostName := rh.GetName()
	retCode, stdOut, stdErr, xerr = run(task, ssh, cmd, outs, executionTimeout)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry: // == *fail.ErrAborted
			if cerr := xerr.Cause(); cerr != nil {
				xerr = fail.ToError(cerr)
			}
		case *fail.ErrTimeout:
			switch xerr.Cause().(type) {
			case *fail.ErrTimeout:
				xerr = fail.Wrap(xerr.Cause(), "failed to execute command on Host '%s' in %s", hostName, temporal.FormatDuration(executionTimeout))
			default:
				xerr = fail.Wrap(xerr.Cause(), "failed to connect by SSH to Host '%s' after %s", hostName, temporal.FormatDuration(connectionTimeout))
			}
		}
	}

	return retCode, stdOut, stdErr, xerr
}

// run executes command on the host
// If run fails to connect to remote host, returns *fail.ErrNotAvailable
// In case of error, can return:
// - *fail.ErrExecution: // FIXME: complete comment
// - *fail.ErrNotAvailable: // FIXME: complete comment
// - *fail.ErrTimeout: // FIXME: complete comment
// - *fail.ErrAborted: // FIXME: complete comment
func run(task concurrency.Task, ssh *system.SSHConfig, cmd string, outs outputs.Enum, timeout time.Duration) (int, string, string, fail.Error) {
	// Create the command
	sshCmd, xerr := ssh.NewCommand(task, cmd)
	if xerr != nil {
		return 0, "", "", xerr
	}

	defer func() { _ = sshCmd.Close() }()

	var (
		retcode        int
		stdout, stderr string
	)
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var innerXErr fail.Error
			retcode = -1
			if retcode, stdout, stderr, innerXErr = sshCmd.RunWithTimeout(task, outs, timeout); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrExecution:
					// Adds stdout annotation to xerr
					_ = innerXErr.Annotate("stdout", stdout)
					_ = innerXErr.Annotate("stderr", stderr)
				}
				return innerXErr
			}
			// If retcode == 255, ssh connection failed
			if retcode == 255 {
				return fail.NotAvailableError("failed to connect")
			}
			return nil
		},
		timeout+time.Minute,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout:
			xerr = fail.Wrap(xerr.Cause(), "failed to execute command after %s", temporal.FormatDuration(timeout))
		case *retry.ErrStopRetry:
			if xerr.Cause() != nil {
				xerr = fail.ToError(xerr.Cause())
			}
		}
	}
	return retcode, stdout, stderr, xerr
}

// Pull downloads a file from host
func (rh host) Pull(task concurrency.Task, target, source string, timeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return 0, "", "", fail.InvalidInstanceError()
	}
	if source == "" {
		return 0, "", "", fail.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return 0, "", "", fail.InvalidParameterError("target", "cannot be empty string")
	}

	// retrieve ssh config to perform some commands
	ssh, xerr := rh.GetSSHConfig(task)
	if xerr != nil {
		return 0, "", "", xerr
	}

	// FIXME: reintroduce timeout on ssh.
	// if timeout < temporal.GetHostTimeout() {
	// 	timeout = temporal.GetHostTimeout()
	// }
	var (
		retcode int
		stdout, stderr string
	)
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var innerXErr fail.Error
			if retcode, stdout, stderr, innerXErr = ssh.Copy(task, target, source, false);  innerXErr != nil {
				return innerXErr
			}
			switch retcode {
			case 1:
				if strings.Contains(stdout, "lost connection") {
					return fail.NewError("lost connection, retrying...")
				}
			}
			return nil
		},
		2*timeout,
	)
	return retcode, stdout, stderr, xerr
}

// Push uploads a file to host
func (rh host) Push(task concurrency.Task, source, target, owner, mode string, timeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return 0, "", "", fail.InvalidInstanceError()
	}
	if source == "" {
		return 0, "", "", fail.InvalidParameterError("source", "cannot be empty string")
	}
	if target == "" {
		return 0, "", "", fail.InvalidParameterError("target", "cannot be empty string")
	}

	// retrieve ssh config to perform some commands
	ssh, xerr := rh.GetSSHConfig(task)
	if xerr != nil {
		return 0, "", "", xerr
	}

	if timeout < temporal.GetHostTimeout() {
		timeout = temporal.GetHostTimeout()
	}

	var (
		retcode int
		stdout, stderr string
	)
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var innerXErr fail.Error
			if retcode, stdout, stderr, innerXErr = ssh.Copy(task, target, source, true);  innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 {
				if retcode == 1 && strings.Contains(stdout, "lost connection") {
					return fail.NewError("lost connection, retrying...")
				}
			}
			return nil
		},
		2*timeout,
	)
	if xerr != nil {
		return retcode, stdout, stderr, xerr
	}

	cmd := ""
	if owner != "" {
		cmd += "sudo chown " + owner + ` '` + target + `' ;`
	}
	if mode != "" {
		cmd += "sudo chmod " + mode + ` '` + target + `'`
	}
	if cmd != "" {
		retcode, stdout, stderr, xerr = run(task, ssh, cmd, outputs.DISPLAY, timeout)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrTimeout:
				xerr = fail.Wrap(xerr.Cause(), "failed to update access rights in %v delay", timeout)
			}
		}
	}
	return retcode, stdout, stderr, xerr
}

// GetShare returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
func (rh host) GetShare(task concurrency.Task, shareRef string) (_ *propertiesv1.HostShare, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if shareRef == "" {
		return nil, fail.InvalidParameterError("shareRef", "cannot be empty string")
	}

	var (
		hostShare *propertiesv1.HostShare
		// ok        bool
	)
	err := rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if hostShare, ok = sharesV1.ByID[shareRef].Clone().(*propertiesv1.HostShare); ok {
				return nil
			}
			if _, ok := sharesV1.ByName[shareRef]; ok {
				hostShare = sharesV1.ByID[sharesV1.ByName[shareRef]].Clone().(*propertiesv1.HostShare)
				return nil
			}
			return fail.NotFoundError("share '%s' not found in server '%s' metadata", shareRef, rh.GetName())
		})
	})
	if err != nil {
		return nil, err
	}

	return hostShare, nil
}

// GetVolumes returns information about volumes attached to the host
func (rh host) GetVolumes(task concurrency.Task) (_ *propertiesv1.HostVolumes, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	var hvV1 *propertiesv1.HostVolumes
	err := rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			hvV1, ok = clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.getVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return hvV1, nil
}

// getVolumes returns information about volumes attached to the host
func (rh host) getVolumes(task concurrency.Task) *propertiesv1.HostVolumes {
	out, _ := rh.GetVolumes(task)
	return out
}

// Start starts the host
func (rh host) Start(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	hostName := rh.GetName()
	hostID := rh.GetID()

	svc := rh.GetService()
	if xerr = svc.StartHost(hostID); xerr != nil {
		return xerr
	}

	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return svc.WaitHostState(hostID, hoststate.STARTED, temporal.GetHostTimeout())
		},
		5*time.Minute,
	)
	if xerr != nil {
		return fail.Wrap(xerr, "timeout waiting host '%s' to be started", hostName)
	}
	return nil
}

// Stop stops the host
func (rh host) Stop(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	hostName := rh.GetName()
	hostID := rh.GetID()

	svc := rh.GetService()
	if xerr = svc.StopHost(hostID); xerr != nil {
		return xerr
	}

	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			return svc.WaitHostState(hostID, hoststate.STOPPED, temporal.GetHostTimeout())
		},
		// FIXME: static value
		5*time.Minute,
	)
	if xerr != nil {
		return fail.Wrap(xerr, "timeout waiting host '%s' to be stopped", hostName)
	}
	return nil
}

// Reboot reboots the host
func (rh host) Reboot(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	if xerr := rh.Stop(task); xerr != nil {
		return xerr
	}
	return rh.Start(task)
}

// Resize ...
// not yet implemented
func (rh *host) Resize(hostSize abstract.HostSizingRequirements) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	return fail.NotImplementedError("Host.Resize() not yet implemented")
}

// AddFeature handles 'safescale host add-feature <host name or id> <feature name>'
func (rh *host) AddFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (outcomes resources.Results, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", name).Entering()
	defer tracer.Exiting()

	feat, xerr := NewFeature(task, name)
	if xerr != nil {
		return nil, xerr
	}
	xerr = rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		var innerXErr fail.Error
		outcomes, innerXErr = feat.Add(rh, vars, settings)
		if innerXErr != nil {
			return innerXErr
		}

		// updates HostFeatures property for host
		return props.Alter(task, hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("expected '*propertiesv1.HostFeatures', received '%s'", reflect.TypeOf(clonable))
			}
			requires, innerXErr := feat.GetRequirements()
			if innerXErr != nil {
				return innerXErr
			}
			hostFeaturesV1.Installed[name] = &propertiesv1.HostInstalledFeature{
				HostContext: true,
				Requires:    requires,
			}
			return nil
		})
	})
	if xerr != nil {
		return nil, xerr
	}
	return outcomes, nil
}

// CheckFeature ...
func (rh host) CheckFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", name).Entering()
	defer tracer.Exiting()

	feat, xerr := NewFeature(task, name)
	if xerr != nil {
		return nil, xerr
	}

	// Wait for SSH service on remote host first
	// ssh, err := mh.GetSSHConfig(task)
	// if err != nil {
	// 	return srvutils.ThrowErr(err)
	// }
	// _, err = ssh.WaitServerReady(2 * time.Minute)
	// if err != nil {
	// 	return srvutils.ThrowErr(err)
	// }

	return feat.Check(&rh, vars, settings)
}

// DeleteFeature handles 'safescale host delete-feature <host name> <feature name>'
func (rh *host) DeleteFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, false /*Trace.IPAddress, */, "(%s)", name).Entering()
	defer tracer.Exiting()

	feat, xerr := NewFeature(task, name)
	if xerr != nil {
		return nil, xerr
	}

	// // Wait for SSH service on remote host first
	// ssh, err := mh.GetSSHConfig(task)
	// if err != nil {
	// 	return srvutils.ThrowErr(err)
	// }
	// _, err = ssh.WaitServerReady(2 * time.Minute)
	// if err != nil {
	// 	return srvutils.ThrowErr(err)
	// }

	xerr = rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		outcomes, innerXErr := feat.Remove(rh, vars, settings)
		if innerXErr != nil {
			return fail.NewError(innerXErr, nil, "error uninstalling feature '%s' on '%s'", name, rh.GetName())
		}

		if !outcomes.Successful() {
			msg := fmt.Sprintf("failed to delete feature '%s' from host '%s'", name, rh.GetName())
			tracer.Trace(strprocess.Capitalize(msg) + ":\n" + outcomes.AllErrorMessages())
			return fail.NewError(msg)
		}

		// updates HostFeatures property for host
		return props.Alter(task, hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("expected '*propertiesv1.HostFeatures', received '%s'", reflect.TypeOf(clonable))
			}

			delete(hostFeaturesV1.Installed, name)
			return nil
		})
	})
	return nil, xerr
}

// TargetType returns the type of the target.
// satisfies install.Targetable interface.
func (rh host) TargetType() featuretargettype.Enum {
	if rh.IsNull() {
		return featuretargettype.UNKNOWN
	}
	return featuretargettype.HOST
}

// GetPublicIP returns the public IP address of the host
func (rh host) GetPublicIP(task concurrency.Task) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if rh.IsNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return ip, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	if ip = rh.getPublicIP(task); ip == "" {
		return ip, fail.NotFoundError("no public IP associated with Host '%s'", rh.GetName())
	}
	return ip, nil
}

// getPublicIP returns the public IP address of the host
// To be used when rh is notoriously not null value
func (rh host) getPublicIP(task concurrency.Task) string {
	if task.IsNull() {
		return ""
	}

	rh.SafeRLock(task)
	defer rh.SafeRUnlock(task)

	return rh.publicIP
}

// GetPrivateIP returns the private IP of the host on its default Networking
func (rh host) GetPrivateIP(task concurrency.Task) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if rh.IsNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return ip, fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}

	return rh.getPrivateIP(task), nil
}

// getPrivateIP returns the private IP of the host on its default Networking
// To be used when rh is notoriously not nil
func (rh host) getPrivateIP(task concurrency.Task) string {
	if task.IsNull() {
		return ""
	}

	rh.SafeRLock(task)
	defer rh.SafeRUnlock(task)

	return rh.privateIP
}

// GetPrivateIPOnSubnet returns the private IP of the host on its default Subnet
func (rh host) GetPrivateIPOnSubnet(task concurrency.Task, subnetID string) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if rh.IsNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return ip, fail.InvalidParameterError("task", "cannot be nil")
	}
	if subnetID = strings.TrimSpace(subnetID); subnetID == "" {
		return ip, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	xerr = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(hostproperty.NetworkV2) {
			return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				if ip, ok = hostNetworkV2.IPv4Addresses[subnetID]; !ok {
					return fail.InvalidRequestError("host '%s' does not have an IP address on subnet '%s'", rh.GetName(), subnetID)
				}
				return nil
			})
		}
		return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if ip, ok = hostNetworkV2.IPv4Addresses[subnetID]; !ok {
				return fail.InvalidRequestError("host '%s' does not have an IP address on subnet '%s'", rh.GetName(), subnetID)
			}
			return nil
		})
	})
	return ip, xerr
}

// GetAccessIP returns the IP to reach the host
func (rh host) GetAccessIP(task concurrency.Task) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if rh.IsNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return ip, fail.InvalidParameterError("task", "cannot be nil")
	}

	return rh.getAccessIP(task), nil
}

// getAccessIP returns the IP to reach the host
// To be used when rh is notoriously not nil
func (rh host) getAccessIP(task concurrency.Task) string {
	if task.IsNull() {
		return ""
	}

	rh.SafeRLock(task)
	defer rh.SafeRUnlock(task)

	return rh.accessIP
}

// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
// satisfies interface install.Targetable
func (rh host) InstallMethods(task concurrency.Task) map[uint8]installmethod.Enum {
	if rh.IsNull() {
		logrus.Error(fail.InvalidInstanceError().Error())
		return map[uint8]installmethod.Enum{}
	}
	if task.IsNull() {
		logrus.Error(fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'").Error())
		return map[uint8]installmethod.Enum{}
	}

	rh.SafeLock(task)
	defer rh.SafeUnlock(task)

	if rh.installMethods == nil {
		rh.installMethods = map[uint8]installmethod.Enum{}

		_ = rh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			// props, inErr := rh.properties(task)
			// if inErr != nil {
			// 	return inErr
			// }

			// Ignore error in this special case; will fallback to use bash method if cannot determine operating system type and flavor
			var index uint8
			_ = props.Inspect(task, hostproperty.SystemV1, func(clonable data.Clonable) fail.Error {
				systemV1, ok := clonable.(*propertiesv1.HostSystem)
				if !ok {
					logrus.Error(fail.InconsistentError("'*propertiesv1.HostSystem' expected, '%s' provided", reflect.TypeOf(clonable).String()))
				}
				if systemV1.Type == "linux" {
					switch systemV1.Flavor {
					case "centos", "redhat":
						index++
						rh.installMethods[index] = installmethod.Yum
					case "debian":
						fallthrough
					case "ubuntu":
						index++
						rh.installMethods[index] = installmethod.Apt
					case "fedora", "rhel":
						index++
						rh.installMethods[index] = installmethod.Dnf
					}
				}
				return nil
			})
			index++
			rh.installMethods[index] = installmethod.Bash
			return nil
		})
	}
	return rh.installMethods
}

// GetShares returns the information about the shares hosted by the host
func (rh host) GetShares(task concurrency.Task) (shares *propertiesv1.HostShares, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	shares = &propertiesv1.HostShares{}
	if rh.IsNull() {
		return shares, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return shares, fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			shares = hostSharesV1
			return nil
		})
	})
	return shares, xerr
}

// GetMounts returns the information abouts the mounts of the host
func (rh host) GetMounts(task concurrency.Task) (mounts *propertiesv1.HostMounts, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	mounts = nil
	if rh.IsNull() {
		return mounts, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return mounts, fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			mounts = hostMountsV1
			return nil
		})
	})
	return mounts, xerr
}

// getMounts returns the information about the mounts of the host
// Intended to be used when objh is notoriously not nil (because previously checked)
func (rh host) getMounts(task concurrency.Task) *propertiesv1.HostMounts {
	mounts, _ := rh.GetMounts(task)
	return mounts
}

// InstalledFeatures returns a list of installed features
//
// satisfies interface install.Targetable
func (rh host) InstalledFeatures(task concurrency.Task) []string {
	var list []string
	return list
}

// ComplementFeatureParameters configures parameters that are appropriate for the target
// satisfies interface install.Targetable
func (rh host) ComplementFeatureParameters(task concurrency.Task, v data.Map) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if v == nil {
		return fail.InvalidParameterError("v", "cannot be nil")
	}

	v["ShortHostname"] = rh.GetName()
	domain := ""
	xerr = rh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
			hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			domain = hostDescriptionV1.Domain

			if domain != "" {
				domain = "." + domain
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	v["Hostname"] = rh.GetName() + domain

	v["HostIP"] = rh.getPrivateIP(task)
	v["PublicIP"] = rh.getPublicIP(task)

	if _, ok := v["Username"]; !ok {
		v["Username"] = abstract.DefaultUser
	}

	rs, xerr := rh.GetDefaultSubnet(task)
	if xerr != nil {
		return xerr
	}

	rgw, xerr := rs.InspectGateway(task, true)
	if xerr != nil {
		return xerr
	}
	defer rgw.Dispose()

	rgwi := rgw.(*host)
	v["PrimaryGatewayIP"] = rgwi.getPrivateIP(task)
	v["GatewayIP"] = v["PrimaryGatewayIP"] // legacy
	v["PrimaryPublicIP"] = rgwi.getPublicIP(task)
	if rgw, xerr = rs.InspectGateway(task, false); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return xerr
		}
	} else {
		defer rgw.Dispose()

		rgwi = rgw.(*host)
		v["SecondaryGatewayIP"] = rgwi.getPrivateIP(task)
		v["SecondaryPublicIP"] = rgwi.getPublicIP(task)
	}

	if v["EndpointIP"], xerr = rs.GetEndpointIP(task); xerr != nil {
		return xerr
	}

	v["PublicIP"] = v["EndpointIP"]
	if v["DefaultRouteIP"], xerr = rs.GetDefaultRouteIP(task); xerr != nil {
		return xerr
	}

	return nil
}

// IsClusterMember returns true if the host is member of a cluster
func (rh host) IsClusterMember(task concurrency.Task) (yes bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	yes = false
	if rh.IsNull() {
		return yes, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return yes, fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.ClusterMembershipV1, func(clonable data.Clonable) fail.Error {
			hostClusterMembershipV1, ok := clonable.(*propertiesv1.HostClusterMembership)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostClusterMembership' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			yes = hostClusterMembershipV1.Cluster != ""
			return nil
		})
	})
	return yes, xerr
}

// IsGateway tells if the host acts as a gateway for a Subnet
func (rh host) IsGateway(task concurrency.Task) (_ bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return false, fail.InvalidInstanceError()
	}

	var state bool
	xerr = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			state = hnV2.IsGateway
			return nil
		})
	})
	if xerr != nil {
		return false, xerr
	}
	return state, nil
}

// PushStringToFile creates a file 'filename' on remote 'host' with the content 'content'
func (rh host) PushStringToFile(task concurrency.Task, content string, filename string) (xerr fail.Error) {
	return rh.PushStringToFileWithOwnership(task, content, filename, "", "")
}

// PushStringToFileWithOwnership creates a file 'filename' on remote 'host' with the content 'content', and apply ownership
func (rh host) PushStringToFileWithOwnership(task concurrency.Task, content string, filename string, owner, mode string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if content == "" {
		return fail.InvalidParameterError("content", "cannot be empty string")
	}
	if filename == "" {
		return fail.InvalidParameterError("filename", "cannot be empty string")
	}

	hostName := rh.GetName()
	f, xerr := system.CreateTempFileFromString(content, 0600)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to create temporary file")
	}

	to := fmt.Sprintf("%s:%s", hostName, filename)
	deleted := false
	retryErr := retry.WhileUnsuccessful(
		func() error {
			retcode, _, _, innerXErr := rh.Push(task, f.Name(), filename, owner, mode, temporal.GetExecutionTimeout())
			if innerXErr != nil {
				return innerXErr
			}
			if retcode != 0 {
				// If retcode == 1 (general copy error), retry. It may be a temporary network incident
				if retcode == 1 && !deleted {
					// File may exist on target, try to remove it
					if _, _, _, innerXErr = rh.Run(task, "sudo rm -f "+filename, outputs.COLLECT, temporal.GetConnectSSHTimeout(), temporal.GetExecutionTimeout()); innerXErr == nil {
						deleted = true
					}
					return fail.NewError("file may have existing on remote with inappropriate access rights, deleted it and now retrying")
				}
				if system.IsSCPRetryable(retcode) {
					xerr = fail.NewError("failed to copy temporary file to '%s' (retcode: %d=%s)", to, retcode, system.SCPErrorString(retcode))
				}
			}
			return nil
		},
		1*time.Second,
		2*time.Minute,
	)
	_ = os.Remove(f.Name())
	if retryErr != nil {
		if _, ok := retryErr.(*retry.ErrTimeout); ok {
			return fail.Wrap(retryErr, "timeout trying to copy temporary file to '%s'", to)
		}
		return xerr
	}

	cmd := ""
	if owner != "" {
		cmd += `sudo chown ` + owner + ` '` + filename + `' ;`
	}
	if mode != "" {
		cmd += `sudo chmod ` + mode + ` '` + filename + `'`
	}
	if cmd != "" {
		retryErr = retry.WhileUnsuccessful(
			func() error {
				retcode, stdout, _, innerXErr := rh.Run(task, cmd, outputs.COLLECT, temporal.GetConnectionTimeout(), temporal.GetExecutionTimeout())
				if innerXErr != nil {
					// on error, innerXErr already has annotations "retcode" and "stderr", we need to add stdout
					_ = innerXErr.Annotate("stdout", stdout)
					return innerXErr
				}
				if retcode != 0 {
					xerr = fail.NewError("failed to change rights of file '%s' (retcode=%d)", to, retcode)
				}
				return nil
			},
			2*time.Second,
			1*time.Minute,
		)
		if retryErr != nil {
			switch retryErr.(type) {
			case *retry.ErrTimeout:
				return xerr
			default:
				return fail.Wrap(retryErr, "failed to change rights of file '%s' on host '%s'", filename, hostName)
			}
		}
	}
	return nil
}

// GetDefaultSubnet returns the Networking instance corresponding to host default subnet
func (rh host) GetDefaultSubnet(task concurrency.Task) (rs resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nullSubnet(), fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nullSubnet(), fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(hostproperty.NetworkV2) {
			return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				networkV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				rs, innerXErr = LoadSubnet(task, rh.GetService(), "", networkV2.DefaultSubnetID)
				if innerXErr != nil {
					return innerXErr
				}
				return nil
			})
		}
		return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			rs, innerXErr = LoadSubnet(task, rh.GetService(), "", hostNetworkV2.DefaultSubnetID)
			if innerXErr != nil {
				return innerXErr
			}
			return nil
		})
	})
	if xerr != nil {
		return nullSubnet(), xerr
	}

	return rs, nil
}

// ToProtocol convert an resources.Host to protocol.Host
func (rh host) ToProtocol(task concurrency.Task) (ph *protocol.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	var (
		ahc *abstract.HostCore
		hostSizingV1  *propertiesv1.HostSizing
		hostVolumesV1 *propertiesv1.HostVolumes
		volumes       []string
	)

	publicIP := rh.getPublicIP(task)
	privateIP := rh.getPrivateIP(task)

	xerr = rh.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		var ok bool
		ahc, ok = clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		return props.Inspect(task, hostproperty.SizingV1, func(clonable data.Clonable) fail.Error {
			hostSizingV1, ok = clonable.(*propertiesv1.HostSizing)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String)
			}
			return props.Inspect(task, hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
				hostVolumesV1, ok = clonable.(*propertiesv1.HostVolumes)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String)
				}

				volumes = make([]string, 0, len(hostVolumesV1.VolumesByName))
				for _, v := range hostVolumesV1.VolumesByName {
					volumes = append(volumes, v)
				}
				return nil
			})
		})
	})
	if xerr != nil {
		return ph, xerr
	}

	ph = &protocol.Host{
		Cpu:                 int32(hostSizingV1.AllocatedSize.Cores),
		Disk:                int32(hostSizingV1.AllocatedSize.DiskSize),
		Id:                  ahc.ID,
		PublicIp:            publicIP,
		PrivateIp:           privateIP,
		Name:                ahc.Name,
		PrivateKey:          ahc.PrivateKey,
		Password:            ahc.Password,
		Ram:                 hostSizingV1.AllocatedSize.RAMSize,
		State:               protocol.HostState(ahc.LastState),
		AttachedVolumeNames: volumes,
	}
	return ph, nil
}

// BindSecurityGroup binds a security group to the host; if enabled is true, apply it immediately
func (rh *host) BindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup, enable resources.SecurityGroupActivation) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	return rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// If the Security Group is already bound to the host with the exact same state, consider as a success
			if v, ok := hsgV1.ByID[sgID]; ok && v.Disabled == !bool(enable) {
				return nil
			}

			// Not found, add it
			item := &propertiesv1.SecurityGroupBond{
				ID:       sgID,
				Name:     sg.GetName(),
				Disabled: bool(!enable),
			}
			hsgV1.ByID[sgID] = item
			hsgV1.ByName[item.Name] = item.ID

			// If enabled, apply it
			innerXErr := sg.BindToHost(task, rh, enable, resources.MarkSecurityGroupAsSupplemental)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrDuplicate:
				// already bound, success
				default:
					return innerXErr
				}
			}
			return nil
		})
	})
}

// UnbindSecurityGroup unbinds a security group from the host
func (rh *host) UnbindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	return rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// Check if the security group is listed for the host
			found := false
			for k, v := range hsgV1.ByID {
				if k == sgID {
					if v.FromSubnet {
						return fail.InvalidRequestError("cannot unbind Security Group '%s': inherited from Subnet", sg.GetName())
					}
					found = true
					break
				}
			}
			// If not found, consider request successful
			if !found {
				return nil
			}

			// unbind security group from host on remote service side
			if innerXErr := sg.UnbindFromHost(task, rh); innerXErr != nil {
				return innerXErr
			}

			// found, delete it from properties
			delete(hsgV1.ByID, sgID)
			delete(hsgV1.ByName, sg.GetName())
			return nil

		})
	})
}

// ListSecurityGroups returns a slice of security groups binded to host
func (rh host) ListSecurityGroups(task concurrency.Task, state securitygroupstate.Enum) (list []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var emptySlice []*propertiesv1.SecurityGroupBond
	if rh.IsNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return emptySlice, fail.InvalidParameterError("task", "cannot be nil")
	}

	xerr = rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			list = filterBondsByKind(hsgV1.ByID, state)
			return nil
		})
	})
	if xerr != nil {
		return emptySlice, xerr
	}
	return list, nil
}

// EnableSecurityGroup enables a bound security group to host by applying its rules
func (rh *host) EnableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	svc := rh.GetService()
	return rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			xerr := sg.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				if asg, ok = clonable.(*abstract.SecurityGroup); !ok {
					return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if xerr != nil {
				return xerr
			}

			// First check if the security group is not already registered for the host with the exact same state
			var found bool
			for k := range hsgV1.ByID {
				if k == asg.ID {
					found = true
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not bound to host '%s'", sg.GetName(), rh.GetID())
			}

			if svc.GetCapabilities().CanDisableSecurityGroup {
				if xerr = svc.EnableSecurityGroup(asg); xerr != nil {
					return xerr
				}
			} else {
				// Bind the security group on provider side; if already bound (*fail.ErrDuplicate), consider as a success
				if xerr = sg.GetService().BindSecurityGroupToHost(asg, rh.GetID()); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						// continue
					default:
						return xerr
					}
				}
			}

			// found and updated, update metadata
			hsgV1.ByID[asg.ID].Disabled = false
			return nil
		})
	})
}

// DisableSecurityGroup disables a binded security group to host
func (rh *host) DisableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if sg.IsNull() {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	svc := rh.GetService()
	return rh.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			xerr := sg.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				if asg, ok = clonable.(*abstract.SecurityGroup); !ok {
					return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				return nil
			})
			if xerr != nil {
				return xerr
			}

			// First check if the security group is not already registered for the host with the exact same state
			var found bool
			for k := range hsgV1.ByID {
				if k == asg.ID {
					found = true
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not bound to host '%s'", sg.GetName(), sg.GetID())
			}

			if svc.GetCapabilities().CanDisableSecurityGroup {
				if xerr = svc.DisableSecurityGroup(asg); xerr != nil {
					return xerr
				}
			} else {
				// Bind the security group on provider side; if security group not binded, consider as a success
				if xerr = svc.UnbindSecurityGroupFromHost(asg, rh.GetID()); xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// continue
					default:
						return xerr
					}
				}
			}

			// found, update properties
			hsgV1.ByID[asg.ID].Disabled = true
			return nil
		})
	})
}
