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
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/iaas/stacks"
	"github.com/CS-SI/SafeScale/lib/server/iaas/userdata"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/subnetproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v2"
	"github.com/CS-SI/SafeScale/lib/system"
	"github.com/CS-SI/SafeScale/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/data/cache"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/retry"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

const (
	hostKind = "host"
	// hostsFolderName is the technical name of the container used to store networks info
	hostsFolderName = "hosts"

	// defaultHostSecurityGroupNamePattern = "safescale-sg_host_%s.%s.%s" // safescale-sg_host_<hostname>.<subnet name>.<network name>; should be unique across a tenant
)

// host ...
// follows interface resources.Host
type host struct {
	*core

	lock                          sync.RWMutex
	installMethods                map[uint8]installmethod.Enum
	privateIP, publicIP, accessIP string
	sshProfile                    *system.SSHConfig
}

// NewHost ...
func NewHost(svc iaas.Service) (_ resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := newCore(svc, hostKind, hostsFolderName, &abstract.HostCore{})
	if xerr != nil {
		return nil, xerr
	}

	instance := &host{
		core: coreInstance,
		// lock: concurrency.NewTaskedLock(),
	}
	return instance, nil
}

// nullHost returns a *host corresponding to NullValue
func nullHost() *host {
	return &host{core: nullCore()}
}

// LoadHost ...
func LoadHost(task concurrency.Task, svc iaas.Service, ref string) (rh resources.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task == nil {
		return nullHost(), fail.InvalidParameterCannotBeNilError("task")
	}
	if svc == nil {
		return nullHost(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if ref == "" {
		return nullHost(), fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	if task.Aborted() {
		return nullHost(), fail.AbortedError(nil, "aborted")
	}

	hostCache, xerr := svc.GetCache(hostKind)
	if xerr != nil {
		return nullHost(), xerr
	}

	options := []data.ImmutableKeyValue{
		data.NewImmutableKeyValue("onMiss", func() (cache.Cacheable, fail.Error) {
			rh, innerXErr := NewHost(svc)
			if innerXErr != nil {
				return nil, innerXErr
			}

			// TODO: core.ReadByID() does not check communication failure, side effect of limitations of Stow (waiting for stow replacement by rclone)
			if innerXErr = rh.Read(task, ref); innerXErr != nil {
				return nil, innerXErr
			}

			// deal with legacy
			if xerr = rh.(*host).upgradeIfNeeded(task); xerr != nil {
				switch xerr.(type) {
				case *fail.ErrAlteredNothing:
					// nothing changed, continue
				default:
					return nil, fail.Wrap(xerr, "failed to upgrade Host metadata")
				}
			}

			return rh, nil
		}),
	}

	ce, xerr := hostCache.Get(task, ref, options...)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// rewrite NotFoundError, user does not bother about metadata message
			return nullHost(), fail.NotFoundError("failed to find Host '%s'", ref)
		default:
			return nullHost(), xerr
		}
	}

	if rh = ce.Content().(resources.Host); rh == nil {
		return nil, fail.InconsistentError("nil value found in Host cache for key '%s'", ref)
	}
	_ = ce.LockContent()
	defer func() {
		if xerr != nil {
			_ = ce.UnlockContent()
		}
	}()

	// cache access information only if there was no error
	return rh, rh.(*host).cacheAccessInformation(task)
}

// upgradeIfNeeded upgrades IPAddress properties if needed
func (instance *host) upgradeIfNeeded(task concurrency.Task) fail.Error {
	return instance.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

		return fail.AlteredNothingError()
	})
}

// cacheAccessInformation loads in cache SSH configuration to access host; this information will not change over time
func (instance *host) cacheAccessInformation(task concurrency.Task) fail.Error {
	svc := instance.GetService()
	return instance.Review(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
				instance.privateIP = hnV2.IPv4Addresses[hnV2.DefaultSubnetID]
				if instance.privateIP == "" {
					instance.privateIP = hnV2.IPv6Addresses[hnV2.DefaultSubnetID]
				}
			}
			instance.publicIP = hnV2.PublicIPv4
			if instance.publicIP == "" {
				instance.publicIP = hnV2.PublicIPv6
			}
			if instance.publicIP != "" {
				instance.accessIP = instance.publicIP
			} else {
				instance.accessIP = instance.privateIP
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

					ip := rgw.(*host).unsafeGetAccessIP()
					opUser, opUserErr := getOperatorUsernameFromCfg(svc)
					if opUserErr != nil {
						return opUserErr
					}

					primaryGatewayConfig = &system.SSHConfig{
						PrivateKey: gwahc.PrivateKey,
						Port:       int(gwahc.SSHPort),
						IPAddress:  ip,
						Hostname:   gwahc.Name,
						User:       opUser,
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
						opUser, opUserErr := getOperatorUsernameFromCfg(svc)
						if opUserErr != nil {
							return opUserErr
						}
						secondaryGatewayConfig = &system.SSHConfig{
							PrivateKey: gwahc.PrivateKey,
							Port:       int(gwahc.SSHPort),
							IPAddress:  rgw.(*host).unsafeGetAccessIP(),
							Hostname:   rgw.GetName(),
							User:       opUser,
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

		opUser, opUserErr := getOperatorUsernameFromCfg(svc)
		if opUserErr != nil {
			return opUserErr
		}

		instance.sshProfile = &system.SSHConfig{
			Port:                   int(ahc.SSHPort),
			IPAddress:              instance.accessIP,
			Hostname:               instance.GetName(),
			User:                   opUser,
			PrivateKey:             ahc.PrivateKey,
			GatewayConfig:          primaryGatewayConfig,
			SecondaryGatewayConfig: secondaryGatewayConfig,
		}
		return nil
	})
}

func getOperatorUsernameFromCfg(svc iaas.Service) (string, fail.Error) {
	cfg, xerr := svc.GetConfigurationOptions()
	if xerr != nil {
		return "", xerr
	}

	var userName string
	if anon, ok := cfg.Get("OperatorUsername"); ok {
		userName = anon.(string)
		if userName == "" {
			logrus.Warnf("OperatorUsername is empty, check your tenants.toml file. Using 'safescale' user instead.")
		}
	}
	if userName == "" {
		userName = abstract.DefaultUser
	}

	return userName, nil
}

// isNull tests if instance is nil or empty
func (instance *host) isNull() bool {
	return instance == nil || instance.core.isNull()
}

// carry ...
func (instance *host) carry(task concurrency.Task, clonable data.Clonable) (xerr fail.Error) {
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}
	identifiable, ok := clonable.(data.Identifiable)
	if !ok {
		return fail.InvalidParameterError("clonable", "must also satisfy interface 'data.Identifiable'")
	}

	kindCache, xerr := instance.GetService().GetCache(instance.core.kind)
	if xerr != nil {
		return xerr
	}

	if xerr := kindCache.ReserveEntry(task, identifiable.GetID()); xerr != nil {
		return xerr
	}
	defer func() {
		if xerr != nil {
			if derr := kindCache.FreeEntry(task, identifiable.GetID()); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free %s cache entry for key '%s'", instance.core.kind, identifiable.GetID()))
			}

		}
	}()

	// Note: do not validate parameters, this call will do it
	if xerr := instance.core.Carry(task, clonable); xerr != nil {
		return xerr
	}

	cacheEntry, xerr := kindCache.CommitEntry(task, identifiable.GetID(), instance)
	if xerr != nil {
		return xerr
	}

	cacheEntry.LockContent()

	return nil
}

// Browse walks through host folder and executes a callback for each entries
func (instance *host) Browse(task concurrency.Task, callback func(*abstract.HostCore) fail.Error) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitTraceError(&xerr, "failed to create host")

	instance.lock.RLock()
	defer instance.lock.RLock()

	return instance.core.BrowseFolder(task, func(buf []byte) (innerXErr fail.Error) {
		ahc := abstract.NewHostCore()
		if innerXErr = ahc.Deserialize(buf); innerXErr != nil {
			return innerXErr
		}

		return callback(ahc)
	})
}

// ForceGetState returns the current state of the provider host after reloading metadata
func (instance *host) ForceGetState(task concurrency.Task) (state hoststate.Enum, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	state = hoststate.UNKNOWN
	if instance.isNull() {
		return state, fail.InvalidInstanceError()
	}
	if task == nil {
		return state, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return state, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitTraceError(&xerr, "failed to create host")

	xerr = instance.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
func (instance *host) Reload(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	hostName := instance.GetName()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", hostName).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.Lock()
	defer instance.lock.Unlock()

	if xerr = instance.core.Reload(task); xerr != nil {
		switch xerr.(type) { //nolint
		case *retry.ErrTimeout: // If retry timed out, log it and return error ErrNotFound
			xerr = fail.NotFoundError("metadata of host '%s' not found; host deleted?", hostName)
		default:
			return xerr
		}
	}

	// Request host inspection from provider
	ahf, xerr := instance.GetService().InspectHost(instance.GetID())
	if xerr != nil {
		return xerr
	}

	// Updates the host metadata
	xerr = instance.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

	return instance.cacheAccessInformation(task)
}

// GetState returns the last known state of the host, without forced inspect
func (instance *host) GetState(task concurrency.Task) (state hoststate.Enum) {
	state = hoststate.UNKNOWN
	if instance.isNull() || task == nil {
		return state
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	_ = instance.Review(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
func (instance *host) Create(task concurrency.Task, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements) (_ *userdata.Content, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	hostname := instance.GetName()
	if hostname != "" {
		return nil, fail.NotAvailableError("already carrying host '%s'", hostname)
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", hostReq.ResourceName).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitTraceError(&xerr, "failed to create host")

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.GetService()

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
		hostReq.TemplateID, xerr = instance.findTemplateID(hostDef)
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
			hostReq.DefaultRouteIP = func() string { out, _ := defaultSubnet.(*subnet).unsafeGetDefaultRouteIP(task); return out }()
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
		hostReq.ImageID, xerr = instance.findImageID(&hostDef)
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
		return nil, fail.Wrap(xerr, "failed to create Host '%s'", hostReq.ResourceName)
	}

	defer func() {
		if xerr != nil && !hostReq.KeepOnFailure {
			if derr := svc.DeleteHost(ahf.Core.ID); derr != nil {
				_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete Host '%s'", actionFromError(xerr), ahf.Core.Name))
			}
		}
	}()

	// Make sure ssh port wanted is set
	if hostReq.SSHPort > 0 {
		ahf.Core.SSHPort = hostReq.SSHPort
	} else {
		ahf.Core.SSHPort = 22
	}

	// Creates metadata early to "reserve" host name
	if xerr = instance.carry(task, ahf.Core); xerr != nil {
		return nil, xerr
	}

	defer func() {
		if xerr != nil && !hostReq.KeepOnFailure {
			// Disable abort signal during the clean up
			defer task.DisarmAbortSignal()()

			if derr := instance.core.Delete(task); derr != nil {
				logrus.Errorf("cleaning up on %s, failed to delete host '%s' metadata: %v", actionFromError(xerr), ahf.Core.Name, derr)
				_ = xerr.AddConsequence(derr)
			}
		}
	}()

	xerr = instance.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
		return instance.setSecurityGroups(task, hostReq, defaultSubnet)
	})
	if xerr != nil {
		return nil, xerr
	}
	defer func() {
		// Disable abort signal during the clean up
		defer task.DisarmAbortSignal()()

		instance.undoSetSecurityGroups(task, &xerr, hostReq.KeepOnFailure)
	}()

	if xerr = instance.cacheAccessInformation(task); xerr != nil {
		return nil, xerr
	}

	logrus.Infof("Compute resource created: '%s'", instance.GetName())

	// A host claimed ready by a Cloud provider is not necessarily ready
	// to be used until ssh service is up and running. So we wait for it before
	// claiming host is created
	logrus.Infof("Waiting SSH availability on Host '%s' ...", instance.GetName())

	// FIXME: configurable timeout here
	status, xerr := instance.waitInstallPhase(task, userdata.PHASE1_INIT, time.Duration(0))
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrTimeout:
			return nil, fail.Wrap(xerr, "timeout after Host creation waiting for SSH availability")
		default:
			if abstract.IsProvisioningError(xerr) {
				logrus.Errorf("%+v", xerr)
				return nil, fail.Wrap(xerr, "error provisioning the new host, please check safescaled logs", instance.GetName())
			}
			return nil, xerr
		}
	}

	xerr = instance.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
	if xerr = instance.updateSubnets(task, hostReq); xerr != nil {
		return nil, xerr
	}
	defer func() {
		// Disable abort signal during the clean up
		defer task.DisarmAbortSignal()()

		instance.undoUpdateSubnets(task, hostReq, &xerr)
	}()

	if xerr = instance.finalizeProvisioning(task, userdataContent); xerr != nil {
		return nil, xerr
	}

	logrus.Infof("host '%s' created successfully", instance.GetName())
	return userdataContent, nil
}

// setSecurityGroups sets the Security Groups for the host
func (instance *host) setSecurityGroups(task concurrency.Task, req abstract.HostRequest, defaultSubnet resources.Subnet) fail.Error {
	return instance.properties.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) (innerXErr fail.Error) {
		hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
		if !ok {
			return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		svc := instance.GetService()

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
			if innerXErr = gwsg.BindToHost(task, instance, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to apply Subnet's Security Group for gateway '%s' on host '%s'", gwsg.GetName(), req.ResourceName)
			}

			defer func() {
				if innerXErr != nil && !req.KeepOnFailure {
					// Disable abort signal during the clean up
					defer task.DisarmAbortSignal()()

					if derr := gwsg.UnbindFromHost(task, instance); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group '%s' from Host '%s'", actionFromError(innerXErr), gwsg.GetName(), instance.GetName()))
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
			defer pubipsg.Released(task)

			if innerXErr = pubipsg.BindToHost(task, instance, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
				return fail.Wrap(innerXErr, "failed to apply Subnet's Security Group for gateway '%s' on host '%s'", pubipsg.GetName(), req.ResourceName)
			}

			defer func() {
				if innerXErr != nil && !req.KeepOnFailure {
					// Disable abort signal during the clean up
					defer task.DisarmAbortSignal()()

					if derr := pubipsg.UnbindFromHost(task, instance); derr != nil {
						_ = innerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group '%s' from Host '%s'", actionFromError(innerXErr), pubipsg.GetName(), instance.GetName()))
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
					// Disable abort signal during the clean up
					defer task.DisarmAbortSignal()()

					var (
						sg     resources.SecurityGroup
						derr   error
						errors []error
					)
					for _, v := range req.Subnets {
						subnetInstance, deeperXErr := LoadSubnet(task, svc, "", v.ID)
						if deeperXErr != nil {
							_ = innerXErr.AddConsequence(deeperXErr)
							continue
						}
						defer func(subnetInstance resources.Subnet) {
							subnetInstance.Released(task)
						}(subnetInstance)

						sgName := sg.GetName()
						deeperXErr = subnetInstance.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
							as, ok := clonable.(*abstract.Subnet)
							if !ok {
								return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
							}

							if sg, derr = LoadSecurityGroup(task, svc, as.InternalSecurityGroupID); derr == nil {
								derr = sg.UnbindFromHost(task, instance)
								sg.Released(task)
							}
							if derr != nil {
								errors = append(errors, derr)
							}
							return nil
						})
						if deeperXErr != nil {
							_ = innerXErr.AddConsequence(fail.Wrap(deeperXErr, "cleaning up on failure, failed to unbind Security Group '%s' from Host", sgName))
						}
					}
					if len(errors) > 0 {
						_ = innerXErr.AddConsequence(fail.Wrap(fail.NewErrorList(errors), "failed to unbind Subnets Security Group from host '%s'", sg.GetName(), req.ResourceName))
					}
				}
			}()

			for _, v := range req.Subnets {
				subnetInstance, xerr := LoadSubnet(task, svc, "", v.ID)
				if xerr != nil {
					return xerr
				}
				defer func(subnetInstance resources.Subnet) {
					subnetInstance.Released(task)
				}(subnetInstance)

				xerr = subnetInstance.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					as, ok := clonable.(*abstract.Subnet)
					if !ok {
						return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					if lansg, innerXErr = LoadSecurityGroup(task, svc, as.InternalSecurityGroupID); innerXErr != nil {
						return fail.Wrap(innerXErr, "failed to load Subnet '%s' internal Security Group %s", as.Name, as.InternalSecurityGroupID)
					}
					defer func(sgInstance resources.SecurityGroup) {
						sgInstance.Released(task)
					}(lansg)

					if innerXErr = lansg.BindToHost(task, instance, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
						return fail.Wrap(innerXErr, "failed to apply Subnet '%s' internal Security Group '%s' to host '%s'", as.Name, lansg.GetName(), req.ResourceName)
					}
					return nil
				})
				if xerr != nil {
					return xerr
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
		var an *abstract.Network
		rn, _ := defaultSubnet.(*subnet).unsafeInspectNetwork(task)
		innerXErr = rn.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			var ok bool
			an, ok = clonable.(*abstract.Network)
			if !ok {
				return fail.InconsistentError("'*abstract.Network' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to query Network of Subnet '%s'", defaultSubnet.GetName())
		}

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
			} else if innerXErr = svc.UnbindSecurityGroupFromHost(adsg, instance.GetID()); innerXErr != nil {
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

func (instance *host) undoSetSecurityGroups(task concurrency.Task, errorPtr *fail.Error, keepOnFailure bool) {
	if errorPtr == nil {
		logrus.Errorf("trying to call a cancel function from a nil error; cancel not run")
		return
	}
	if *errorPtr != nil && !keepOnFailure {
		svc := instance.GetService()
		derr := instance.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
						opXErr = sg.UnbindFromHost(task, instance)
					}
					if opXErr != nil {
						errors = append(errors, opXErr)
					}
				}
				if len(errors) > 0 {
					return fail.Wrap(fail.NewErrorList(errors), "cleaning up on %s, failed to unbind Security Groups from Host", actionFromError(*errorPtr))
				}

				return nil
			})
		})
		if derr != nil {
			_ = (*errorPtr).AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to cleanup Security Groups", actionFromError(*errorPtr)))
		}
	}
}

func (instance *host) findTemplateID(hostDef abstract.HostSizingRequirements) (string, fail.Error) {
	svc := instance.GetService()
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

func (instance *host) findImageID(hostDef *abstract.HostSizingRequirements) (string, fail.Error) {
	svc := instance.GetService()
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
func (instance *host) runInstallPhase(task concurrency.Task, phase userdata.Phase, userdataContent *userdata.Content) fail.Error {
	// execute userdata 'final' (phase4) script to final install/configure of the host (no need to reboot)
	content, xerr := userdataContent.Generate(phase)
	if xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil)
	}

	file := fmt.Sprintf("/opt/safescale/var/tmp/user_data.%s.sh", phase)
	if xerr = instance.unsafePushStringToFile(task, string(content), file); xerr != nil {
		return xerr
	}

	if task.Aborted() {
		return fail.AbortedError(nil)
	}

	command := fmt.Sprintf("sudo bash %s; exit $?", file)
	// Executes the script on the remote host
	retcode, _, stderr, xerr := instance.unsafeRun(task, command, outputs.COLLECT, 0, 0)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to apply configuration phase '%s'", phase)
	}
	if retcode != 0 {
		if retcode == 255 {
			return fail.NewError("failed to execute install phase '%s' on host '%s': SSH connection failed", phase, instance.GetName())
		}
		return fail.NewError("failed to execute install phase '%s' on host '%s': %s", phase, instance.GetName(), stderr)
	}
	return nil
}

func (instance *host) waitInstallPhase(task concurrency.Task, phase userdata.Phase, timeout time.Duration) (string, fail.Error) {
	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	sshDefaultTimeout := int(temporal.GetHostTimeout().Minutes())
	if sshDefaultTimeoutCandidate := os.Getenv("SSH_TIMEOUT"); sshDefaultTimeoutCandidate != "" {
		if num, err := strconv.Atoi(sshDefaultTimeoutCandidate); err == nil {
			logrus.Debugf("Using custom timeout of %d minutes", num)
			sshDefaultTimeout = num
		}
	}

	// sshCfg, xerr := instance.GetSSHConfig(task)
	// if xerr != nil {
	// 	return "", xerr
	// }

	// TODO: configurable timeout here
	duration := time.Duration(sshDefaultTimeout) * time.Minute
	status, xerr := instance.sshProfile.WaitServerReady(task, string(phase), time.Duration(sshDefaultTimeout)*time.Minute)
	if xerr != nil {
		switch xerr.(type) { //nolint
		case *fail.ErrTimeout:
			return status, fail.Wrap(xerr.Cause(), "failed to wait for SSH on Host '%s' to be ready after %s (phase %s): %s", instance.GetName(), temporal.FormatDuration(duration), phase, status)
		}
		if abstract.IsProvisioningError(xerr) {
			logrus.Errorf("%+v", xerr)
			return status, fail.Wrap(xerr, "error provisioning Host '%s', please check safescaled logs", instance.GetName())
		}
	}
	return status, xerr
}

// updateSubnets updates subnets on which host is attached and host property HostNetworkV2
func (instance *host) updateSubnets(task concurrency.Task, req abstract.HostRequest) fail.Error {
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// If host is a gateway, do not add it as host attached to the Subnet, it's considered as part of the subnet
	if !req.IsGateway {
		return instance.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hnV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hostID := instance.GetID()
				hostName := instance.GetName()

				for _, as := range req.Subnets {
					rs, innerXErr := LoadSubnet(task, instance.core.GetService(), "", as.ID)
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
func (instance *host) undoUpdateSubnets(task concurrency.Task, req abstract.HostRequest, errorPtr *fail.Error) {
	if errorPtr != nil && *errorPtr != nil && !req.IsGateway && !req.KeepOnFailure {
		// Without this,the undo will not be able to complete in case it's called on an abort...
		defer task.DisarmAbortSignal()()

		xerr := instance.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hsV1, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hostID := instance.GetID()
				hostName := instance.GetName()

				for _, as := range req.Subnets {
					rs, innerXErr := LoadSubnet(task, instance.core.GetService(), "", as.ID)
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
			_ = (*errorPtr).AddConsequence(fail.Wrap(xerr, "cleaning up on %s, failed to remove Host relationships with Subnets", actionFromError(xerr)))
		}
	}
}

func (instance *host) finalizeProvisioning(task concurrency.Task, userdataContent *userdata.Content) fail.Error {
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	// Reset userdata script for Host from Cloud Provider metadata service (if stack is able to do so)
	if xerr := instance.GetService().ClearHostStartupScript(instance.GetID()); xerr != nil {
		return xerr
	}

	// Executes userdata.PHASE2_NETWORK_AND_SECURITY script to configure subnet and security
	if xerr := instance.runInstallPhase(task, userdata.PHASE2_NETWORK_AND_SECURITY, userdataContent); xerr != nil {
		return xerr
	}

	// Update Keypair of the Host with the one set in HostRequest
	xerr := instance.Alter(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
	if xerr = instance.cacheAccessInformation(task); xerr != nil {
		return xerr
	}

	// Reboot host
	command := "sudo systemctl reboot"
	if _, _, _, xerr = instance.unsafeRun(task, command, outputs.COLLECT, temporal.GetContextTimeout(), temporal.GetHostTimeout()); xerr != nil {
		return xerr
	}

	if _, xerr = instance.waitInstallPhase(task, userdata.PHASE2_NETWORK_AND_SECURITY, 0); xerr != nil {
		return xerr
	}

	// if host is not a gateway, executes userdata.PHASE4/5 scripts to fix possible system issues and finalize host creation
	// For a gateway, userdata.PHASE3 to 5 have to be run explicitly (cf. operations/subnet.go)
	if !userdataContent.IsGateway {
		// execute userdata.PHASE4_SYSTEM_FIXES script to fix possible misconfiguration in system
		if xerr = instance.runInstallPhase(task, userdata.PHASE4_SYSTEM_FIXES, userdataContent); xerr != nil {
			return xerr
		}

		// Reboot host
		command = "sudo systemctl reboot"
		if _, _, _, xerr = instance.unsafeRun(task, command, outputs.COLLECT, 0, 0); xerr != nil {
			return xerr
		}

		if _, xerr = instance.waitInstallPhase(task, userdata.PHASE4_SYSTEM_FIXES, 0); xerr != nil {
			return xerr
		}

		// execute userdata.PHASE5_FINAL script to final install/configure of the host (no need to reboot)
		if xerr = instance.runInstallPhase(task, userdata.PHASE5_FINAL, userdataContent); xerr != nil {
			return xerr
		}

		if _, xerr = instance.waitInstallPhase(task, userdata.PHASE5_FINAL, temporal.GetHostTimeout()); xerr != nil {
			switch xerr.(type) { //nolint
			case *fail.ErrTimeout:
				return fail.Wrap(xerr, "timeout creating a host")
			}
			if abstract.IsProvisioningError(xerr) {
				logrus.Errorf("%+v", xerr)
				return fail.Wrap(xerr, "error provisioning the new host, please check safescaled logs", instance.GetName())
			}
			return xerr
		}
	}
	return nil
}

// WaitSSHReady waits until SSH responds successfully
func (instance *host) WaitSSHReady(task concurrency.Task, timeout time.Duration) (_ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return "", fail.InvalidInstanceError()
	}
	if task == nil {
		return "", fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.waitInstallPhase(task, userdata.PHASE5_FINAL, timeout)
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
				// Disable abort signal during the clean up
				defer task.DisarmAbortSignal()()

				if derr := rn.Delete(task); derr != nil {
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
	if rs == nil {
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
				// Disable abort signal during the clean up
				defer task.DisarmAbortSignal()()

				if derr := rs.Delete(task); derr != nil {
					_ = xerr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to delete subnet '%s'", actionFromError(xerr), abstract.SingleHostSubnetName))
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
func (instance *host) Delete(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.Unlock()

	xerr = instance.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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

	return instance.relaxedDeleteHost(task)
}

// relaxedDeleteHost is the method that really deletes a host, being a gateway or not
func (instance *host) relaxedDeleteHost(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	svc := instance.GetService()
	var shares map[string]*propertiesv1.HostShare
	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
						instance, inErr := LoadHost(task, svc, hostID)
						if inErr == nil {
							instance.Released(task)
							return fail.NotAvailableError("host '%s' exports %d share%s and at least one share is mounted", instance.GetName(), shareCount, strprocess.Plural(uint(shareCount)))
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
				return fail.NotAvailableError("host '%s' has %d volume%s attached", instance.GetName(), nAttached, strprocess.Plural(uint(nAttached)))
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	xerr = instance.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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

				defer func(instance resources.Share) {
					instance.Released(task)
				}(rshare)

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
			defer func(shareInstance resources.Share) {
				shareInstance.Released(task)
			}(rs)

			loopErr = rs.Unmount(task, instance)
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
			hostID := instance.GetID()
			// hostName := instance.GetName()

			var errors []error
			for k := range hostNetworkV2.SubnetsByID {
				if !hostNetworkV2.IsGateway && k != hostNetworkV2.DefaultSubnetID {
					rs, loopErr := LoadSubnet(task, svc, "", k)
					if loopErr == nil {
						defer func(instance resources.Subnet) {
							instance.Released(task)
						}(rs)

						loopErr = rs.AbandonHost(task, hostID)
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
			}
			if len(errors) > 0 {
				return fail.Wrap(fail.NewErrorList(errors), "failed to update metadata for Subnets of Host")
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Unbind Security Groups from Host
		innerXErr = props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Unbind Security Groups from Host
			var errors []error
			for _, v := range hsgV1.ByID {
				rsg, derr := LoadSecurityGroup(task, svc, v.ID)
				if derr == nil {
					defer func(instance resources.SecurityGroup) {
						instance.Released(task)
					}(rsg)

					derr = rsg.UnbindFromHost(task, instance)
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

		// Delete host
		waitForDeletion := true
		innerXErr = retry.WhileUnsuccessfulDelay1Second(
			func() error {
				if derr := svc.DeleteHost(instance.GetID()); derr != nil {
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
					state, stateErr := svc.GetHostState(instance.GetID())
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
				switch innerXErr.(type) { //nolint
				case *retry.ErrStopRetry:
					innerXErr = fail.ConvertError(innerXErr.Cause())
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
	})
	if xerr != nil {
		return xerr
	}

	// Deletes metadata from Object Storage
	if xerr = instance.core.Delete(task); xerr != nil {
		// If entry not found, considered as success
		if _, ok := xerr.(*fail.ErrNotFound); !ok {
			return xerr
		}
	}

	// newHost := nullHost()
	// *instance = *newHost
	return nil
}

// GetSSHConfig loads SSH configuration for host from metadata
//
// FIXME: verify that system.SSHConfig carries data about secondary getGateway
func (instance *host) GetSSHConfig(task concurrency.Task) (_ *system.SSHConfig, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.sshProfile, nil
}

// Run tries to execute command 'cmd' on the host
func (instance *host) Run(task concurrency.Task, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return 0, "", "", fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, "", "", fail.InvalidParameterCannotBeNilError("task")
	}
	if cmd == "" {
		return 0, "", "", fail.InvalidParameterError("cmd", "cannot be empty string")
	}

	if task.Aborted() {
		return 0, "", "", fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(cmd='%s', outs=%s)", outs.String()).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeRun(task, cmd, outs, connectionTimeout, executionTimeout)
}

// Pull downloads a file from Host
func (instance *host) Pull(task concurrency.Task, target, source string, timeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return 0, "", "", fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, "", "", fail.InvalidParameterCannotBeNilError("task")
	}
	if target == "" {
		return 0, "", "", fail.InvalidParameterCannotBeEmptyStringError("target")
	}
	if source == "" {
		return 0, "", "", fail.InvalidParameterCannotBeEmptyStringError("source")
	}

	if task.Aborted() {
		return 0, "", "", fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(target=%s,source=%s)", target, source).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	// // retrieve ssh config to perform some commands
	// ssh, xerr := instance.GetSSHConfig(task)
	// if xerr != nil {
	// 	return 0, "", "", xerr
	// }

	// FIXME: reintroduce timeout on ssh.
	// if timeout < temporal.GetHostTimeout() {
	// 	timeout = temporal.GetHostTimeout()
	// }
	var (
		retcode        int
		stdout, stderr string
	)
	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			var innerXErr fail.Error
			if retcode, stdout, stderr, innerXErr = instance.sshProfile.Copy(task, target, source, false); innerXErr != nil {
				return innerXErr
			}
			switch retcode { //nolint
			case 1: // FIXME: Check errorcodes
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
func (instance *host) Push(task concurrency.Task, source, target, owner, mode string, timeout time.Duration) (_ int, _ string, _ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return 0, "", "", fail.InvalidInstanceError()
	}
	if task == nil {
		return 0, "", "", fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return 0, "", "", fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(source=%s, target=%s, owner=%s, mode=%s)", source, target, owner, mode).Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafePush(task, source, target, owner, mode, timeout)
}

// GetShare returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
func (instance *host) GetShare(task concurrency.Task, shareRef string) (_ *propertiesv1.HostShare, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if shareRef == "" {
		return nil, fail.InvalidParameterError("shareRef", "cannot be empty string")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(shareRef=%s)", shareRef).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RLock()

	var (
		hostShare *propertiesv1.HostShare
		// ok        bool
	)
	err := instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if item, ok := sharesV1.ByID[shareRef]; ok {
				hostShare = item.Clone().(*propertiesv1.HostShare)
				return nil
			}
			if item, ok := sharesV1.ByName[shareRef]; ok {
				hostShare = sharesV1.ByID[item].Clone().(*propertiesv1.HostShare)
				return nil
			}
			return fail.NotFoundError("share '%s' not found in server '%s' metadata", shareRef, instance.GetName())
		})
	})
	if err != nil {
		return nil, err
	}

	return hostShare, nil
}

// GetVolumes returns information about volumes attached to the host
func (instance *host) GetVolumes(task concurrency.Task) (_ *propertiesv1.HostVolumes, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetVolumes(task)
}

// Start starts the host
func (instance *host) Start(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.Unlock()

	hostName := instance.GetName()
	hostID := instance.GetID()

	svc := instance.GetService()
	if xerr = svc.StartHost(hostID); xerr != nil {
		return xerr
	}

	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			return svc.WaitHostState(hostID, hoststate.STARTED, temporal.GetHostTimeout())
		},
		5*time.Minute,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAborted:
			if cerr := fail.ConvertError(xerr.Cause()); cerr != nil {
				return cerr
			}
			return xerr
		case *retry.ErrTimeout:
			return fail.Wrap(xerr, "timeout waiting host '%s' to be started", hostName)
		default:
			return xerr
		}
	}
	return nil
}

// Stop stops the host
func (instance *host) Stop(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.Unlock()

	hostName := instance.GetName()
	hostID := instance.GetID()

	svc := instance.GetService()
	if xerr = svc.StopHost(hostID); xerr != nil {
		return xerr
	}

	xerr = retry.WhileUnsuccessfulDelay5Seconds(
		func() error {
			if task.Aborted() {
				return fail.AbortedError(nil, "aborted")
			}

			return svc.WaitHostState(hostID, hoststate.STOPPED, temporal.GetHostTimeout())
		},
		// FIXME: static value
		5*time.Minute,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAborted:
			if cerr := fail.ConvertError(xerr.Cause()); cerr != nil {
				return cerr
			}
			return xerr
		case *retry.ErrTimeout:
			return fail.Wrap(xerr, "timeout waiting host '%s' to be stopped", hostName)
		default:
			return xerr
		}
	}
	return nil
}

// Reboot reboots the host
func (instance *host) Reboot(task concurrency.Task) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	if xerr := instance.Stop(task); xerr != nil {
		return xerr
	}
	return instance.Start(task)
}

// Resize ...
// not yet implemented
func (instance *host) Resize(task concurrency.Task, hostSize abstract.HostSizingRequirements) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	return fail.NotImplementedError("Host.Resize() not yet implemented")
}

// GetPublicIP returns the public IP address of the host
func (instance *host) GetPublicIP(task concurrency.Task) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if instance.isNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task == nil {
		return ip, fail.InvalidParameterCannotBeNilError("task")
	}
	if task.Aborted() {
		return ip, fail.AbortedError(nil, "aborted")
	}

	if ip = instance.unsafeGetPublicIP(); ip == "" {
		return ip, fail.NotFoundError("no public IP associated with Host '%s'", instance.GetName())
	}
	return ip, nil
}

// GetPrivateIP returns the private IP of the host on its default Networking
func (instance *host) GetPrivateIP(task concurrency.Task) (_ string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return "", fail.InvalidInstanceError()
	}
	if task == nil {
		return "", fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return "", fail.AbortedError(nil, "aborted")
	}

	return instance.unsafeGetPrivateIP(), nil
}

// GetPrivateIPOnSubnet returns the private IP of the host on its default Subnet
func (instance *host) GetPrivateIPOnSubnet(task concurrency.Task, subnetID string) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if instance.isNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task == nil {
		return ip, fail.InvalidParameterError("task", "cannot be nil")
	}
	if subnetID = strings.TrimSpace(subnetID); subnetID == "" {
		return ip, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	if task.Aborted() {
		return ip, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", subnetID).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		if props.Lookup(hostproperty.NetworkV2) {
			return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				if ip, ok = hostNetworkV2.IPv4Addresses[subnetID]; !ok {
					return fail.InvalidRequestError("host '%s' does not have an IP address on subnet '%s'", instance.GetName(), subnetID)
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
				return fail.InvalidRequestError("host '%s' does not have an IP address on subnet '%s'", instance.GetName(), subnetID)
			}
			return nil
		})
	})
	return ip, xerr
}

// GetAccessIP returns the IP to reach the host
func (instance *host) GetAccessIP(task concurrency.Task) (ip string, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	ip = ""
	if instance.isNull() {
		return ip, fail.InvalidInstanceError()
	}
	if task == nil {
		return ip, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return ip, fail.AbortedError(nil, "aborted")
	}

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetAccessIP(), nil
}

// GetShares returns the information about the shares hosted by the host
func (instance *host) GetShares(task concurrency.Task) (shares *propertiesv1.HostShares, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	shares = &propertiesv1.HostShares{}
	if instance.isNull() {
		return shares, fail.InvalidInstanceError()
	}
	if task == nil {
		return shares, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return shares, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			hostSharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			shares = hostSharesV1.Clone().(*propertiesv1.HostShares)
			return nil
		})
	})
	return shares, xerr
}

// GetMounts returns the information abouts the mounts of the host
func (instance *host) GetMounts(task concurrency.Task) (mounts *propertiesv1.HostMounts, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	mounts = nil
	if instance.isNull() {
		return mounts, fail.InvalidInstanceError()
	}
	if task == nil {
		return mounts, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return mounts, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafeGetMounts(task)
}

// IsClusterMember returns true if the host is member of a cluster
func (instance *host) IsClusterMember(task concurrency.Task) (yes bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	yes = false
	if instance.isNull() {
		return yes, fail.InvalidInstanceError()
	}
	if task == nil {
		return yes, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return yes, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (instance *host) IsGateway(task concurrency.Task) (_ bool, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return false, fail.InvalidInstanceError()
	}
	if task == nil {
		return false, fail.InvalidParameterCannotBeNilError("task")
	}

	if task.Aborted() {
		return false, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var state bool
	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (instance *host) PushStringToFile(task concurrency.Task, content string, filename string) (xerr fail.Error) {
	return instance.PushStringToFileWithOwnership(task, content, filename, "", "")
}

// PushStringToFileWithOwnership creates a file 'filename' on remote 'host' with the content 'content', and apply ownership
func (instance *host) PushStringToFileWithOwnership(task concurrency.Task, content string, filename string, owner, mode string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if content == "" {
		return fail.InvalidParameterError("content", "cannot be empty string")
	}
	if filename == "" {
		return fail.InvalidParameterError("filename", "cannot be empty string")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(content, filename='%s', ownner=%s, mode=%s", filename, owner, mode).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	return instance.unsafePushStringToFileWithOwnership(task, content, filename, owner, mode)
}

// GetDefaultSubnet returns the Networking instance corresponding to host default subnet
func (instance *host) GetDefaultSubnet(task concurrency.Task) (rs resources.Subnet, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nullSubnet(), fail.InvalidInstanceError()
	}
	if task == nil {
		return nullSubnet(), fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return nullSubnet(), fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) (innerXErr fail.Error) {
		if props.Lookup(hostproperty.NetworkV2) {
			return props.Inspect(task, hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				networkV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				rs, innerXErr = LoadSubnet(task, instance.GetService(), "", networkV2.DefaultSubnetID)
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
			rs, innerXErr = LoadSubnet(task, instance.GetService(), "", hostNetworkV2.DefaultSubnetID)
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
func (instance *host) ToProtocol(task concurrency.Task) (ph *protocol.Host, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	var (
		ahc           *abstract.HostCore
		hostSizingV1  *propertiesv1.HostSizing
		hostVolumesV1 *propertiesv1.HostVolumes
		volumes       []string
	)

	publicIP := instance.unsafeGetPublicIP()
	privateIP := instance.unsafeGetPrivateIP()

	xerr = instance.Inspect(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (instance *host) BindSecurityGroup(task concurrency.Task, rsg resources.SecurityGroup, enable resources.SecurityGroupActivation) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if rsg == nil {
		return fail.InvalidParameterCannotBeNilError("rsg")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(rsg='%s', enable=%v", rsg.GetName(), enable).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := rsg.GetID()
			// If the Security Group is already bound to the host with the exact same state, consider as a success
			if v, ok := hsgV1.ByID[sgID]; ok && v.Disabled == !bool(enable) {
				return nil
			}

			// Not found, add it
			item := &propertiesv1.SecurityGroupBond{
				ID:       sgID,
				Name:     rsg.GetName(),
				Disabled: bool(!enable),
			}
			hsgV1.ByID[sgID] = item
			hsgV1.ByName[item.Name] = item.ID

			// If enabled, apply it
			if innerXErr := rsg.BindToHost(task, instance, enable, resources.MarkSecurityGroupAsSupplemental); innerXErr != nil {
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
func (instance *host) UnbindSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if sg == nil {
		return fail.InvalidParameterCannotBeNilError("sg")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	sgName := sg.GetName()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(sg='%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.Unlock()

	return instance.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID := sg.GetID()
			// Check if the security group is listed for the host
			found := false
			for k, v := range hsgV1.ByID {
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if k == sgID {
					if v.FromSubnet {
						return fail.InvalidRequestError("cannot unbind Security Group '%s': inherited from Subnet", sgName)
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
			if innerXErr := sg.UnbindFromHost(task, instance); innerXErr != nil {
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
func (instance *host) ListSecurityGroups(task concurrency.Task, state securitygroupstate.Enum) (list []*propertiesv1.SecurityGroupBond, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	var emptySlice []*propertiesv1.SecurityGroupBond
	if instance.isNull() {
		return emptySlice, fail.InvalidInstanceError()
	}
	if task == nil {
		return emptySlice, fail.InvalidParameterError("task", "cannot be nil")
	}

	if task.Aborted() {
		return emptySlice, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(state=%s)", state.String()).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.RLock()
	defer instance.lock.RUnlock()

	xerr = instance.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
func (instance *host) EnableSecurityGroup(task concurrency.Task, sg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}

	if sg == nil {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	sgName := sg.GetName()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(sg='%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.GetService()
	return instance.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
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
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if k == asg.ID {
					found = true
					break
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not bound to host '%s'", sgName, instance.GetID())
			}

			if svc.GetCapabilities().CanDisableSecurityGroup {
				if xerr = svc.EnableSecurityGroup(asg); xerr != nil {
					return xerr
				}
			} else {
				// Bind the security group on provider side; if already bound (*fail.ErrDuplicate), consider as a success
				if xerr = sg.GetService().BindSecurityGroupToHost(asg, instance.GetID()); xerr != nil {
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
func (instance *host) DisableSecurityGroup(task concurrency.Task, rsg resources.SecurityGroup) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if rsg == nil {
		return fail.InvalidParameterError("rsg", "cannot be nil")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	sgName := rsg.GetName()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(rsg='%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()
	// defer fail.OnExitLogError(&err, tracer.TraceMessage())

	instance.lock.Lock()
	defer instance.lock.Unlock()

	svc := instance.GetService()
	return instance.Alter(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			xerr := rsg.Inspect(task, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
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
				if task.Aborted() {
					return fail.AbortedError(nil, "aborted")
				}

				if k == asg.ID {
					found = true
					break
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not bound to host '%s'", sgName, rsg.GetID())
			}

			if svc.GetCapabilities().CanDisableSecurityGroup {
				if xerr = svc.DisableSecurityGroup(asg); xerr != nil {
					return xerr
				}
			} else {
				// Bind the security group on provider side; if security group not binded, consider as a success
				if xerr = svc.UnbindSecurityGroupFromHost(asg, instance.GetID()); xerr != nil {
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
