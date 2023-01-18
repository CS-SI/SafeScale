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

package operations

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/labelproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/networkproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/subnetproperty"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/consts"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/operations/converters"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	netretry "github.com/CS-SI/SafeScale/v22/lib/utils/net"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

const (
	hostKind = "host"
	// hostsFolderName is the technical name of the container used to store networks info
	hostsFolderName = "hosts"
)

// Host ...
// follows interface resources.Host
type Host struct {
	*MetadataCore
}

// NewHost ...
func NewHost(svc iaas.Service) (_ *Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	coreInstance, xerr := NewCore(svc, hostKind, hostsFolderName, &abstract.HostCore{})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Host{
		MetadataCore: coreInstance,
	}
	return instance, nil
}

// onHostCacheMiss is called when host 'ref' is not found in cache
func onHostCacheMiss(inctx context.Context, svc iaas.Service, ref string) (data.Identifiable, fail.Error) {
	defer elapsed(inctx, fmt.Sprintf("onHostCacheMiss of %s", ref))()
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		a    data.Identifiable
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ data.Identifiable, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			hostInstance, innerXErr := NewHost(svc)
			if innerXErr != nil {
				return nil, innerXErr
			}

			serialized, xerr := hostInstance.Sdump(ctx)
			if xerr != nil {
				return nil, xerr
			}

			incrementExpVar("host.load.hits")
			incrementExpVar("newhost.cache.read")

			if innerXErr = hostInstance.Read(ctx, ref); innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					return nil, fail.NotFoundError("host '%s' not found", ref)
				default:
					return nil, innerXErr
				}
			}

			var does bool
			if does, innerXErr = hostInstance.Exists(ctx); innerXErr == nil {
				if !does {
					return nil, fail.NotFoundError("host '%s' does not exist", ref)
				}
			}

			afterSerialized, xerr := hostInstance.Sdump(ctx)
			if xerr != nil {
				return nil, xerr
			}

			if strings.Compare(serialized, afterSerialized) == 0 {
				return nil, fail.NotFoundError("something is very wrong, either read or updateCachedInformation should have failed: %s", serialized)
			}

			return hostInstance, nil
		}()
		chRes <- result{ga, gerr}
	}()
	select {
	case res := <-chRes:
		return res.a, res.rErr
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return nil, fail.ConvertError(inctx.Err())
	}
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Host) Exists(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	defer elapsed(ctx, fmt.Sprintf("Exist of %s", instance.name.Load().(string)))()
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.ConvertError(err)
	}

	_, xerr := instance.Service().InspectHost(ctx, theID)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			return false, nil
		default:
			return false, xerr
		}
	}

	return true, nil
}

// updateCachedInformation loads in cache SSH configuration to access host; this information will not change over time
func (instance *Host) updateCachedInformation(ctx context.Context) (sshapi.Connector, fail.Error) {
	defer elapsed(ctx, fmt.Sprintf("updateCachedInformation of %s", instance.name.Load().(string)))()
	svc := instance.Service()

	opUser, opUserErr := getOperatorUsernameFromCfg(ctx, svc)
	if opUserErr != nil {
		return nil, opUserErr
	}

	var conn sshapi.Connector

	xerr := instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		var primaryGatewayConfig, secondaryGatewayConfig sshapi.Config
		innerXErr := props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// During upgrade, hnV2.DefaultSubnetID may be empty string, do not execute the following code in this case
			// Do not execute iff Host is single or is a gateway
			if !hnV2.Single && !hnV2.IsGateway && hnV2.DefaultSubnetID != "" {
				subnetInstance, xerr := LoadSubnet(ctx, svc, "", hnV2.DefaultSubnetID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				gwInstance, xerr := subnetInstance.InspectGateway(ctx, true)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				gwErr := gwInstance.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					gwahc, ok := clonable.(*abstract.HostCore)
					if !ok {
						return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					castedGW, ok := gwInstance.(*Host)
					if !ok {
						return fail.InconsistentError("failed to cast gwInstance to '*Host'")
					}

					ip, inXErr := castedGW.GetAccessIP(ctx)
					if inXErr != nil {
						return inXErr
					}

					primaryGatewayConfig = ssh.NewConfig(gwahc.Name, ip, int(gwahc.SSHPort), opUser, gwahc.PrivateKey, 0, "", nil, nil)
					return nil
				})
				if gwErr != nil {
					return gwErr
				}

				// Secondary gateway may not exist...
				gwInstance, xerr = subnetInstance.InspectGateway(ctx, false)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// continue
						debug.IgnoreError2(ctx, xerr)
					default:
						return xerr
					}
				} else {
					gwErr = gwInstance.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
						gwahc, ok := clonable.(*abstract.HostCore)
						if !ok {
							return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
						}

						castedGW, ok := gwInstance.(*Host)
						if !ok {
							return fail.InconsistentError("failed to cast gwInstance to '*Host'")
						}

						ip, inXErr := castedGW.GetAccessIP(ctx)
						if inXErr != nil {
							return inXErr
						}

						secondaryGatewayConfig = ssh.NewConfig(gwInstance.GetName(), ip, int(gwahc.SSHPort), opUser, gwahc.PrivateKey, 0, "", nil, nil)
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

		gaip, innerXErr := instance.GetAccessIP(ctx)
		if innerXErr != nil {
			return innerXErr
		}

		cfg := ssh.NewConfig(instance.GetName(), gaip, int(ahc.SSHPort), opUser, ahc.PrivateKey, 0, "", primaryGatewayConfig, secondaryGatewayConfig)
		aconn, innerXErr := sshfactory.NewConnector(cfg)
		if innerXErr != nil {
			return innerXErr
		}

		conn = aconn
		return nil
	})

	if xerr != nil {
		return nil, xerr
	}

	return conn, nil
}

func getOperatorUsernameFromCfg(ctx context.Context, svc iaas.Service) (string, fail.Error) {
	cfg, xerr := svc.GetConfigurationOptions(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	var userName string
	if anon, ok := cfg.Get("OperatorUsername"); ok {
		userName, ok = anon.(string)
		if ok {
			if userName == "" {
				logrus.WithContext(ctx).Warnf("OperatorUsername is empty, check your tenants.toml file. Using 'safescale' user instead.")
			}
		}
	}
	if userName == "" {
		userName = abstract.DefaultUser
	}

	return userName, nil
}

// IsNull ...
func (instance *Host) IsNull() bool {
	return instance == nil || instance.MetadataCore == nil || valid.IsNil(instance.MetadataCore)
}

// carry ...
func (instance *Host) carry(ctx context.Context, clonable data.Clonable) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) {
		if instance.MetadataCore.IsTaken() {
			return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
		}
	}
	if clonable == nil {
		return fail.InvalidParameterCannotBeNilError("clonable")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.MetadataCore.Carry(ctx, clonable)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through Host MetadataFolder and executes a callback for each entry
func (instance *Host) Browse(ctx context.Context, callback func(*abstract.HostCore) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if callback == nil {
		return fail.InvalidParameterCannotBeNilError("callback")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()

	// instance.RLock()
	// defer instance.RUnlock()

	return instance.MetadataCore.BrowseFolder(ctx, func(buf []byte) (innerXErr fail.Error) {
		ahc := abstract.NewHostCore()
		var inErr fail.Error
		if inErr = ahc.Deserialize(buf); inErr != nil {
			return inErr
		}

		return callback(ahc)
	})
}

// ForceGetState returns the current state of the provider Host then alter metadata
func (instance *Host) ForceGetState(ctx context.Context) (state hoststate.Enum, ferr fail.Error) {
	defer elapsed(ctx, fmt.Sprintf("ForceGetState of %s", instance.name.Load().(string)))()
	defer fail.OnPanic(&ferr)

	state = hoststate.Unknown
	if valid.IsNil(instance) {
		return state, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return state, fail.InvalidParameterCannotBeNilError("ctx")
	}

	hid, err := instance.GetID()
	if err != nil {
		return state, fail.ConvertError(err)
	}

	state, xerr := instance.Service().GetHostState(ctx, hid)
	if xerr != nil {
		return state, xerr
	}

	previousState, xerr := instance.GetState(ctx)
	if xerr != nil {
		return state, xerr
	}

	if state != previousState {
		xerr = instance.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
			ahc, ok := clonable.(*abstract.HostCore)
			if !ok {
				return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			ahc.LastState = state
			return nil
		})
		if xerr != nil {
			return hoststate.Unknown, xerr
		}
	}

	return state, nil
}

// Reload reloads Host from metadata and current Host state on provider state
func (instance *Host) Reload(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	return instance.unsafeReload(ctx)
}

// unsafeReload reloads Host from metadata and current Host state on provider state
func (instance *Host) unsafeReload(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := instance.MetadataCore.Reload(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout: // If retry timed out, log it and return error ErrNotFound
			return fail.NotFoundError("metadata of Host '%s' not found; Host deleted?", instance.GetName())
		default:
			return xerr
		}
	}

	hid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	// Request Host inspection from provider
	ahf, xerr := instance.Service().InspectHost(ctx, hid)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cache, xerr := instance.Service().GetCache(ctx)
	if xerr != nil {
		return xerr
	}

	if cache != nil {
		hid, err := instance.GetID()
		if err != nil {
			return fail.ConvertError(err)
		}

		thing, err := cache.Get(ctx, hid)
		if err != nil || thing == nil { // usually notfound
			err = cache.Set(ctx, hid, instance, &store.Options{Expiration: 120 * time.Minute})
			if err != nil {
				return fail.ConvertError(err)
			}
			time.Sleep(50 * time.Millisecond) // consolidate cache.Set
		} else if _, ok := thing.(*Host); !ok {
			return fail.NewError("cache stored the wrong type")
		}
	}

	// Updates the Host metadata
	xerr = instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' received", reflect.TypeOf(clonable).String())
		}

		changed := false
		if ahc.LastState != ahf.CurrentState {
			ahf.CurrentState = ahc.LastState
			changed = true
		}

		innerXErr := props.Alter(hostproperty.SizingV2, func(clonable data.Clonable) fail.Error {
			hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			allocated := converters.HostEffectiveSizingFromAbstractToPropertyV2(ahf.Sizing)
			if !reflect.DeepEqual(*allocated, *hostSizingV2.AllocatedSize) {
				*hostSizingV2.AllocatedSize = *allocated
				changed = true
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Updates Host property propertiesv1.HostNetworking from "ground" (Cloud Provider side)
		innerXErr = props.Alter(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if len(ahf.Networking.IPv4Addresses) > 0 {
				hnV2.IPv4Addresses = ahf.Networking.IPv4Addresses
			}
			if len(ahf.Networking.IPv6Addresses) > 0 {
				hnV2.IPv6Addresses = ahf.Networking.IPv6Addresses
			}
			if len(ahf.Networking.SubnetsByID) > 0 {
				hnV2.SubnetsByID = ahf.Networking.SubnetsByID
			}
			if len(ahf.Networking.SubnetsByName) > 0 {
				hnV2.SubnetsByName = ahf.Networking.SubnetsByName
			}
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAlteredNothing:
			return nil
		default:
			return xerr
		}
	}

	return nil
}

// GetState returns the last known state of the Host, without forced inspect
func (instance *Host) GetState(ctx context.Context) (hoststate.Enum, fail.Error) {
	state := hoststate.Unknown
	if valid.IsNil(instance) {
		return state, fail.InvalidInstanceError()
	}

	xerr := instance.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ahc, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		state = ahc.LastState
		return nil
	})
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	return state, nil
}

// Create creates a new Host and its metadata
// If the metadata is already carrying a Host, returns fail.ErrNotAvailable
// In case of error occurring after Host resource creation, 'instance' still contains ID of the Host created. This can be used to
// defer Host deletion in case of error
func (instance *Host) Create(inctx context.Context, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements, extra interface{}) (_ *userdata.Content, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// note: do not test IsNull() here, it's expected to be IsNull() actually
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance.MetadataCore) {
		if instance.MetadataCore.IsTaken() {
			return nil, fail.InconsistentError("already carrying information")
		}
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		ct  *userdata.Content
		err fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)

		a, err := instance.implCreate(ctx, hostReq, hostDef, extra)
		chRes <- result{
			ct:  a,
			err: err,
		}
	}()

	select {
	case res := <-chRes: // if it works return the result
		if res.ct == nil && res.err == nil {
			return nil, fail.NewError("creation failed unexpectedly")
		}
		return res.ct, res.err
	case <-ctx.Done():
		<-chRes // wait for cleanup
		return nil, fail.ConvertError(ctx.Err())
	case <-inctx.Done(): // if not because parent context was canceled
		<-chRes // wait for cleanup
		return nil, fail.Wrap(inctx.Err(), "canceled by parent")
	}
}

func (instance *Host) implCreate(
	ctx context.Context, hostReq abstract.HostRequest, hostDef abstract.HostSizingRequirements, extra interface{},
) (_ *userdata.Content, _ fail.Error) {
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(%s)", hostReq.ResourceName).WithStopwatch().Entering()
	defer tracer.Exiting()

	type result struct {
		ct  *userdata.Content
		err fail.Error
	}

	chRes := make(chan result)
	go func() {
		defer close(chRes)

		gres, _ := func() (_ result, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			svc := instance.Service()

			// Check if Host exists and is managed bySafeScale
			hc, xerr := LoadHost(ctx, svc, hostReq.ResourceName)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreError2(ctx, xerr)
				default:
					ar := result{nil, fail.Wrap(xerr, "failed to check if Host '%s' already exists", hostReq.ResourceName)}
					return ar, ar.err
				}
			} else {
				if does, xerr := hc.Exists(ctx); xerr == nil {
					if !does {
						logrus.WithContext(ctx).Debugf("Either metadata corruption or cache not properly invalidated")
					} else {
						ar := result{nil, fail.DuplicateError("'%s' already exists", hostReq.ResourceName)}
						return ar, ar.err
					}
				}
			}

			// Check if Host exists but is not managed by SafeScale
			// FIXME: OPP Another mistake, we are not looking for the managed tag
			_, xerr = svc.InspectHost(ctx, abstract.NewHostCore().SetName(hostReq.ResourceName))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreError2(ctx, xerr)
				default:
					ar := result{nil, fail.Wrap(xerr, "failed to check if Host resource name '%s' is already used", hostReq.ResourceName)}
					return ar, ar.err
				}
			} else {
				ar := result{nil, fail.DuplicateError("found an existing Host named '%s' (but not managed by SafeScale)", hostReq.ResourceName)}
				return ar, ar.err
			}

			// select new template based on hostDef and hostReq
			{
				newHostDef := hostDef
				if newHostDef.Template == "" {
					newHostDef.Template = hostReq.TemplateRef
					if hostReq.TemplateID != "" {
						newHostDef.Template = hostReq.TemplateID
					}
				}
				tmpl, xerr := svc.FindTemplateBySizing(ctx, newHostDef)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, fail.NotFoundErrorWithCause(xerr, nil, "failed to find template to match requested sizing")}
					return ar, ar.err
				}

				hostDef.Template = tmpl.ID
				hostReq.TemplateRef = tmpl.Name
			}

			hostReq.TemplateID = hostDef.Template

			// If hostDef.Image is not explicitly defined, find an image ID corresponding to the content of hostDef.ImageRef
			imageQuery := hostDef.Image
			if imageQuery == "" {
				imageQuery = hostReq.ImageRef
				if imageQuery == "" { // if ImageRef also empty, use defaults
					imageQuery = consts.DEFAULTOS
				}

				hostReq.ImageRef, hostReq.ImageID, xerr = determineImageID(ctx, svc, imageQuery)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.err
				}
			}
			hostDef.Image = hostReq.ImageID

			// identify default Subnet
			var (
				defaultSubnet                  resources.Subnet
				undoCreateSingleHostNetworking func() fail.Error
			)
			if hostReq.Single {
				defaultSubnet, undoCreateSingleHostNetworking, xerr = createSingleHostNetworking(ctx, svc, hostReq)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.err
				}

				defer func() {
					ferr = debug.InjectPlannedFail(ferr)
					if ferr != nil && !hostReq.KeepOnFailure {
						derr := undoCreateSingleHostNetworking()
						if derr != nil {
							_ = ferr.AddConsequence(derr)
						}
					}
				}()

				xerr = defaultSubnet.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					as, ok := clonable.(*abstract.Subnet)
					if !ok {
						return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					hostReq.Subnets = append(hostReq.Subnets, as)
					hostReq.SecurityGroupIDs = map[string]struct{}{
						as.PublicIPSecurityGroupID: {},
						as.GWSecurityGroupID:       {},
					}
					hostReq.PublicIP = true
					return nil
				})
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.err
				}
			} else {
				// By convention, default subnet is the first of the list
				as := hostReq.Subnets[0]
				defaultSubnet, xerr = LoadSubnet(ctx, svc, "", as.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.err
				}

				if !hostReq.IsGateway && hostReq.DefaultRouteIP == "" {
					s, ok := defaultSubnet.(*Subnet)
					if !ok {
						ar := result{nil, fail.InconsistentError("failed to cast 'defaultSubnet' to '*Subnet'")}
						return ar, ar.err
					}
					hostReq.DefaultRouteIP, xerr = s.unsafeGetDefaultRouteIP(ctx)
					if xerr != nil {
						ar := result{nil, xerr}
						return ar, ar.err
					}
				}

				// list IDs of Security Groups to apply to Host
				if len(hostReq.SecurityGroupIDs) == 0 {
					hostReq.SecurityGroupIDs = make(map[string]struct{}, len(hostReq.Subnets)+1)
					for _, v := range hostReq.Subnets {
						hostReq.SecurityGroupIDs[v.InternalSecurityGroupID] = struct{}{}
					}

					opts, xerr := svc.GetConfigurationOptions(ctx)
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						ar := result{nil, xerr}
						return ar, ar.err
					}

					anon, ok := opts.Get("UseNATService")
					useNATService := ok && anon.(bool)
					if hostReq.PublicIP || useNATService {
						xerr = defaultSubnet.Inspect(ctx,
							func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
								as, ok := clonable.(*abstract.Subnet)
								if !ok {
									return fail.InconsistentError(
										"*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String(),
									)
								}

								if as.PublicIPSecurityGroupID != "" {
									hostReq.SecurityGroupIDs[as.PublicIPSecurityGroupID] = struct{}{}
								}
								return nil
							},
						)
						xerr = debug.InjectPlannedFail(xerr)
						if xerr != nil {
							ar := result{nil, fail.Wrap(xerr, "failed to consult details of Subnet '%s'", defaultSubnet.GetName())}
							return ar, ar.err
						}
					}
				}
			}

			var ahf *abstract.HostFull
			var userdataContent *userdata.Content

			defer func() {
				if ferr != nil && !hostReq.KeepOnFailure {
					if ahf.IsConsistent() {
						aname, aid := ahf.Core.Name, ahf.Core.ID
						logrus.WithContext(ctx).Debugf("Trying to delete failed instance: %s, %s", ahf.Core.Name, ahf.Core.ID)
						if derr := svc.DeleteHost(cleanupContextFrom(ctx), ahf.Core.ID); derr != nil {
							logrus.WithContext(ctx).Errorf(
								"cleaning up on %s, failed to delete Host '%s' instance: %v", ActionFromError(ferr), ahf.Core.Name,
								derr,
							)
							_ = ferr.AddConsequence(derr)
						}

						theID, _ := instance.GetID()

						if derr := instance.MetadataCore.Delete(cleanupContextFrom(ctx)); derr != nil {
							logrus.WithContext(ctx).Errorf(
								"cleaning up on %s, failed to delete Host '%s' metadata: %v", ActionFromError(ferr), ahf.Core.Name,
								derr,
							)
							_ = ferr.AddConsequence(derr)
						}

						if ka, err := instance.Service().GetCache(ctx); err == nil {
							if ka != nil {
								if theID != "" {
									_ = ka.Delete(ctx, fmt.Sprintf("%T/%s", instance, theID))
								}
							}
						}

						logrus.WithContext(ctx).Debugf("Now the instance: %s, %s, should be deleted", aname, aid)
					} else {
						logrus.WithContext(ctx).Debugf("We should NOT trust consistency")
					}
				}
			}()

			// instruct Cloud Provider to create host
			defaultSubnetID, err := defaultSubnet.GetID()
			if err != nil {
				ar := result{nil, fail.ConvertError(err)}
				return ar, ar.err
			}
			ahf, userdataContent, xerr = svc.CreateHost(ctx, hostReq, extra)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				if _, ok := xerr.(*fail.ErrInvalidRequest); ok {
					ar := result{nil, xerr}
					return ar, ar.err
				}
				ar := result{nil, fail.Wrap(xerr, "failed to create Host '%s'", hostReq.ResourceName)}
				return ar, ar.err
			}

			// Make sure ssh port wanted is set
			if !userdataContent.IsGateway {
				if hostReq.SSHPort > 0 {
					ahf.Core.SSHPort = hostReq.SSHPort
				} else {
					ahf.Core.SSHPort = 22
				}
			} else {
				userdataContent.SSHPort = strconv.Itoa(int(hostReq.SSHPort))
				ahf.Core.SSHPort = hostReq.SSHPort
			}

			// Creates metadata early to "reserve" Host name
			xerr = instance.carry(ctx, ahf.Core)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					if ahf.IsConsistent() {
						if ahf.Core.LastState != hoststate.Deleted {
							logrus.WithContext(cleanupContextFrom(ctx)).Warnf("Marking instance '%s' as failed", ahf.GetName())
							derr := instance.Alter(cleanupContextFrom(ctx), func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
								ahc, ok := clonable.(*abstract.HostCore)
								if !ok {
									return fail.InconsistentError(
										"'*abstract.HostCore' expected, '%s' received", reflect.TypeOf(clonable).String(),
									)
								}

								ahc.LastState = hoststate.Failed
								ahc.ProvisioningState = hoststate.Failed
								return nil
							})
							if derr != nil {
								_ = ferr.AddConsequence(derr)
							} else {
								logrus.WithContext(cleanupContextFrom(ctx)).Warnf("Instance now should be in failed state")
							}
						}
					}
				}
			}()

			xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
				innerXErr := props.Alter(hostproperty.SizingV2, func(clonable data.Clonable) fail.Error {
					hostSizingV2, ok := clonable.(*propertiesv2.HostSizing)
					if !ok {
						return fail.InconsistentError("'*propertiesv2.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					hostSizingV2.AllocatedSize = converters.HostEffectiveSizingFromAbstractToPropertyV2(ahf.Sizing)
					hostSizingV2.RequestedSize = converters.HostSizingRequirementsFromAbstractToPropertyV2(hostDef)
					hostSizingV2.Template = hostReq.TemplateRef
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				// Sets Host extension DescriptionV1
				innerXErr = props.Alter(hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
					hostDescriptionV1, ok := clonable.(*propertiesv1.HostDescription)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostDescription' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					_, err := hostDescriptionV1.Replace(converters.HostDescriptionFromAbstractToPropertyV1(*ahf.Description))
					if err != nil {
						return fail.Wrap(err)
					}
					creator := ""
					hostname, err := os.Hostname()
					if err != nil {
						return fail.Wrap(err)
					}
					if curUser, err := user.Current(); err != nil {
						creator = "unknown@" + hostname
					} else {
						creator = curUser.Username
						if hostname != "" {
							creator += "@" + hostname
						}
						if curUser.Name != "" {
							creator += " (" + curUser.Name + ")"
						}
					}
					hostDescriptionV1.Creator = creator
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				// Updates Host property propertiesv2.HostNetworking
				return props.Alter(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
					hnV2, ok := clonable.(*propertiesv2.HostNetworking)
					if !ok {
						return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					hnV2.DefaultSubnetID = defaultSubnetID
					hnV2.IsGateway = hostReq.IsGateway
					hnV2.Single = hostReq.Single
					hnV2.PublicIPv4 = ahf.Networking.PublicIPv4
					hnV2.PublicIPv6 = ahf.Networking.PublicIPv6
					hnV2.SubnetsByID = ahf.Networking.SubnetsByID
					hnV2.SubnetsByName = ahf.Networking.SubnetsByName
					hnV2.IPv4Addresses = ahf.Networking.IPv4Addresses
					hnV2.IPv6Addresses = ahf.Networking.IPv6Addresses
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			xerr = instance.setSecurityGroups(ctx, hostReq, defaultSubnet)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}
			defer func() {
				derr := instance.undoSetSecurityGroups(cleanupContextFrom(ctx), &ferr, hostReq.KeepOnFailure)
				if derr != nil {
					logrus.WithContext(ctx).Warnf(derr.Error())
				}
			}()

			logrus.WithContext(ctx).Infof("Compute resource '%s' (%s) created", ahf.Core.Name, ahf.Core.ID)

			safe := false

			// Fix for Stein
			{
				st, xerr := svc.GetProviderName()
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.err
				}
				if st != "ovh" {
					safe = true
				}
			}

			if cfg, xerr := svc.GetConfigurationOptions(ctx); xerr == nil {
				if aval, ok := cfg.Get("Safe"); ok {
					if val, ok := aval.(bool); ok {
						safe = val
					}
				}
			}

			if !safe {
				xerr = svc.ChangeSecurityGroupSecurity(ctx, true, false, hostReq.Subnets[0].Network, "")
				if xerr != nil {
					ar := result{nil, xerr}
					return ar, ar.err
				}
			}

			timings, xerr := svc.Timings()
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			// A Host claimed ready by a Cloud provider is not necessarily ready
			// to be used until ssh service is up and running. So we wait for it before
			// claiming Host is created
			logrus.WithContext(ctx).Infof("Waiting SSH availability on Host '%s' ...", hostReq.ResourceName)

			maybePackerFailure := false
			status, xerr := instance.waitInstallPhase(ctx, userdata.PHASE1_INIT, timings.HostBootTimeout())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrTimeout:
					maybePackerFailure = true
				default:
					if abstract.IsProvisioningError(xerr) {
						ar := result{nil, fail.Wrap(xerr, "error provisioning the new Host '%s', please check safescaled logs", hostReq.ResourceName)}
						return ar, ar.err
					}
					ar := result{nil, xerr}
					return ar, ar.err
				}
			}

			for numReboots := 0; numReboots < 2; numReboots++ { // 2 reboots at most
				if maybePackerFailure {
					logrus.WithContext(ctx).Infof("Hard Rebooting the host %s", hostReq.ResourceName)
					hostID, err := instance.GetID()
					if err != nil {
						ar := result{nil, fail.ConvertError(err)}
						return ar, ar.err
					}

					xerr = svc.RebootHost(ctx, hostID)
					if xerr != nil {
						ar := result{nil, xerr}
						return ar, ar.err
					}

					status, xerr = instance.waitInstallPhase(ctx, userdata.PHASE1_INIT, timings.HostBootTimeout())
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrTimeout:
							if numReboots == 1 {
								ar := result{nil, fail.Wrap(xerr, "timeout after Host creation waiting for SSH availability")}
								return ar, ar.err
							} else {
								continue
							}
						default:
							if abstract.IsProvisioningError(xerr) {
								ar := result{nil, fail.Wrap(xerr, "error provisioning the new Host '%s', please check safescaled logs", hostReq.ResourceName)}
								return ar, ar.err
							}
							ar := result{nil, xerr}
							return ar, ar.err
						}
					} else {
						break
					}
				}
			}

			xerr = instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
				// update Host system property
				return props.Alter(hostproperty.SystemV1, func(clonable data.Clonable) fail.Error {
					systemV1, ok := clonable.(*propertiesv1.HostSystem)
					if !ok {
						return fail.InconsistentError("'*propertiesv1.HostSystem' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					parts := strings.Split(status, ",")
					if len(parts) >= 3 {
						systemV1.Type = parts[1]
						systemV1.Flavor = parts[2]
					}
					systemV1.Image = hostReq.ImageID
					return nil
				})
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			// -- Updates Host link with subnets --
			xerr = instance.updateSubnets(ctx, hostReq)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					instance.undoUpdateSubnets(cleanupContextFrom(ctx), hostReq, &ferr)
				}
			}()

			// Set ssh port from given one (applied after netsec setup)
			if userdataContent.IsGateway {
				userdataContent.SSHPort = strconv.Itoa(int(hostReq.SSHPort))
			}

			xerr = instance.finalizeProvisioning(ctx, hostReq, userdataContent)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			// Unbind default security group if needed
			networkInstance, xerr := defaultSubnet.InspectNetwork(ctx)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			nid, err := networkInstance.GetID()
			if err != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			xerr = instance.unbindDefaultSecurityGroupIfNeeded(ctx, nid)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				ar := result{nil, xerr}
				return ar, ar.err
			}

			var trueState hoststate.Enum
			hostID, err := instance.GetID()
			if err != nil {
				ar := result{nil, fail.ConvertError(err)}
				return ar, ar.err
			}

			trueState, err = svc.GetHostState(ctx, hostID)
			if err != nil {
				ar := result{nil, fail.ConvertError(err)}
				return ar, ar.err
			}
			if trueState == hoststate.Error {
				ar := result{nil, fail.ConvertError(fmt.Errorf("broken machine"))}
				return ar, ar.err
			}

			if !valid.IsNil(ahf) {
				if !valid.IsNil(ahf.Core) {
					logrus.WithContext(ctx).Debugf("Marking instance '%s' as started", hostReq.ResourceName)
					rerr := instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
						ahc, ok := clonable.(*abstract.HostCore)
						if !ok {
							return fail.InconsistentError(
								"'*abstract.HostCore' expected, '%s' received", reflect.TypeOf(clonable).String(),
							)
						}

						ahc.LastState = hoststate.Started
						return nil
					})
					if rerr != nil {
						ar := result{userdataContent, rerr}
						return ar, ar.err
					}
				}
			}

			logrus.WithContext(ctx).Infof("Host '%s' created successfully", hostReq.ResourceName)
			ar := result{userdataContent, nil}
			return ar, nil
		}()
		chRes <- gres
	}() // nolint

	select {
	case res := <-chRes: // if it works return the result
		return res.ct, res.err
	case <-ctx.Done(): // if not because parent context was canceled
		<-chRes // wait for cleanup
		return nil, fail.Wrap(ctx.Err(), "canceled by parent")
	}
}

func determineImageID(ctx context.Context, svc iaas.Service, imageRef string) (string, string, fail.Error) {
	if imageRef == "" {
		cfg, xerr := svc.GetConfigurationOptions(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return "", "", xerr
		}

		imageRef = cfg.GetString("DefaultImage")
		if imageRef == "" {
			return "", "", fail.InconsistentError("DefaultImage cannot be empty")
		}
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return "", "", xerr
	}

	var img *abstract.Image
	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			rimg, innerXErr := svc.SearchImage(ctx, imageRef)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrNotFound:
					return retry.StopRetryError(innerXErr)
				case *fail.ErrInvalidParameter:
					return retry.StopRetryError(innerXErr)
				default:
					return innerXErr
				}
			}
			img = rimg
			return nil
		},
		timings.SmallDelay(),
		timings.OperationTimeout(),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			imgs, xerr := svc.ListImages(ctx, true)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return "", "", fail.Wrap(xerr, "failure listing images")
			}

			for _, v := range imgs {
				if strings.Compare(v.ID, imageRef) == 0 {
					logrus.WithContext(ctx).Tracef("exact match by ID, ignoring jarowinkler results")
					img = v
					break
				}
			}
		default:
			debug.IgnoreError2(ctx, xerr)
		}
	}

	if img == nil {
		return "", "", fail.Wrap(xerr, "failed to find image ID corresponding to '%s' to use on compute resource", imageRef)
	}

	if img.ID == "" {
		return "", "", fail.Wrap(xerr, "failed to find image ID corresponding to '%s' to use on compute resource, with img '%v'", imageRef, img)
	}

	return imageRef, img.ID, nil
}

// setSecurityGroups sets the Security Groups for the host
func (instance *Host) setSecurityGroups(ctx context.Context, req abstract.HostRequest, defaultSubnet resources.Subnet) fail.Error {
	svc := instance.Service()
	if req.Single {
		hostID, err := instance.GetID()
		if err != nil {
			return fail.ConvertError(err)
		}
		for k := range req.SecurityGroupIDs {
			if k != "" {
				logrus.WithContext(ctx).Infof("Binding security group with id %s to host %s", k, hostID)
				xerr := svc.BindSecurityGroupToHost(ctx, k, hostID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}
		}
		return nil
	}

	xerr := instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SecurityGroupsV1, func(clonable data.Clonable) (finnerXErr fail.Error) {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// get default Subnet core data
			var (
				defaultAbstractSubnet *abstract.Subnet
				defaultSubnetID       string
			)
			innerXErr := defaultSubnet.Inspect(ctx,
				func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
					var ok bool
					defaultAbstractSubnet, ok = clonable.(*abstract.Subnet)
					if !ok {
						return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}

					defaultSubnetID = defaultAbstractSubnet.ID
					return nil
				},
			)
			if innerXErr != nil {
				return innerXErr
			}

			var gwsg, pubipsg, lansg resources.SecurityGroup

			// Apply Security Group for gateways in default Subnet
			if req.IsGateway && defaultAbstractSubnet.GWSecurityGroupID != "" {
				gwsg, innerXErr = LoadSecurityGroup(ctx, svc, defaultAbstractSubnet.GWSecurityGroupID)
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to query Subnet '%s' Security Group '%s'", defaultSubnet.GetName(), defaultAbstractSubnet.GWSecurityGroupID)
				}

				innerXErr = gwsg.BindToHost(ctx, instance, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental)
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to apply Subnet's GW Security Group for gateway '%s' on Host '%s'", gwsg.GetName(), req.ResourceName)
				}

				defer func() {
					if finnerXErr != nil && !req.KeepOnFailure {
						derr := gwsg.UnbindFromHost(cleanupContextFrom(ctx), instance)
						if derr != nil {
							_ = finnerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group '%s' from Host '%s'", ActionFromError(finnerXErr), gwsg.GetName(), req.ResourceName))
						}
					}
				}()

				gwid, err := gwsg.GetID()
				if err != nil {
					return fail.ConvertError(err)
				}

				item := &propertiesv1.SecurityGroupBond{
					ID:         gwid,
					Name:       gwsg.GetName(),
					Disabled:   false,
					FromSubnet: true,
				}
				hsgV1.ByID[item.ID] = item
				hsgV1.ByName[item.Name] = item.ID
			}

			// Apply Security Group for hosts with public IP in default Subnet
			if (req.IsGateway || req.PublicIP) && defaultAbstractSubnet.PublicIPSecurityGroupID != "" {
				pubipsg, innerXErr = LoadSecurityGroup(ctx, svc, defaultAbstractSubnet.PublicIPSecurityGroupID)
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to query Subnet '%s' Security Group with ID %s", defaultSubnet.GetName(), defaultAbstractSubnet.PublicIPSecurityGroupID)
				}

				innerXErr = pubipsg.BindToHost(ctx, instance, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental)
				if innerXErr != nil {
					return fail.Wrap(innerXErr, "failed to apply Subnet's Public Security Group for gateway '%s' on Host '%s'", pubipsg.GetName(), req.ResourceName)
				}

				defer func() {
					if finnerXErr != nil && !req.KeepOnFailure {
						derr := pubipsg.UnbindFromHost(cleanupContextFrom(ctx), instance)
						if derr != nil {
							_ = finnerXErr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to unbind Security Group '%s' from Host '%s'", ActionFromError(finnerXErr), pubipsg.GetName(), req.ResourceName))
						}
					}
				}()

				pubID, err := pubipsg.GetID()
				if err != nil {
					return fail.ConvertError(err)
				}

				item := &propertiesv1.SecurityGroupBond{
					ID:         pubID,
					Name:       pubipsg.GetName(),
					Disabled:   false,
					FromSubnet: true,
				}
				hsgV1.ByID[item.ID] = item
				hsgV1.ByName[item.Name] = item.ID
			}

			// Apply internal Security Group of each other subnets
			defer func() {
				if finnerXErr != nil && !req.KeepOnFailure {
					var (
						sg   resources.SecurityGroup
						derr error
						errs []error
					)
					for _, v := range req.Subnets {
						if v.ID == defaultSubnetID {
							continue
						}

						subnetInstance, deeperXErr := LoadSubnet(cleanupContextFrom(ctx), svc, "", v.ID)
						if deeperXErr != nil {
							_ = innerXErr.AddConsequence(deeperXErr)
							continue
						}

						sgName := sg.GetName()
						deeperXErr = subnetInstance.Inspect(cleanupContextFrom(ctx), func(
							clonable data.Clonable, _ *serialize.JSONProperties,
						) fail.Error {
							abstractSubnet, ok := clonable.(*abstract.Subnet)
							if !ok {
								return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
							}

							if abstractSubnet.InternalSecurityGroupID != "" {
								sg, derr = LoadSecurityGroup(cleanupContextFrom(ctx), svc, abstractSubnet.InternalSecurityGroupID)
								if derr != nil {
									errs = append(errs, derr)
								} else {
									derr = sg.UnbindFromHost(cleanupContextFrom(ctx), instance)
									if derr != nil {
										errs = append(errs, derr)
									}
								}
							}
							return nil
						})
						if deeperXErr != nil {
							_ = finnerXErr.AddConsequence(fail.Wrap(deeperXErr, "cleaning up on failure, failed to unbind Security Group '%s' from Host", sgName))
						}
					}
					if len(errs) > 0 {
						_ = finnerXErr.AddConsequence(fail.Wrap(fail.NewErrorList(errs), "failed to unbind Subnets Security Group from Host '%s'", sg.GetName(), req.ResourceName))
					}
				}
			}()

			for _, v := range req.Subnets {
				// Do not try to bind defaultSubnet on gateway, because this code is running under a lock on defaultSubnet in this case, and this will lead to deadlock
				// (binding of gateway on defaultSubnet is done inside Subnet.Create() call)
				if req.IsGateway && v.ID == defaultSubnetID {
					continue
				}

				otherSubnetInstance, innerXErr := LoadSubnet(ctx, svc, "", v.ID)
				innerXErr = debug.InjectPlannedFail(innerXErr)
				if innerXErr != nil {
					return innerXErr
				}

				var otherAbstractSubnet *abstract.Subnet
				innerXErr = otherSubnetInstance.Inspect(ctx, func(
					clonable data.Clonable, _ *serialize.JSONProperties,
				) fail.Error {
					var ok bool
					otherAbstractSubnet, ok = clonable.(*abstract.Subnet)
					if !ok {
						return fail.InconsistentError("'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String())
					}
					_ = otherAbstractSubnet

					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				safe := false

				// Fix for Stein
				{
					st, xerr := svc.GetProviderName()
					if xerr != nil {
						return xerr
					}
					if st != "ovh" {
						safe = true
					}
				}

				if cfg, xerr := svc.GetConfigurationOptions(ctx); xerr == nil {
					if aval, ok := cfg.Get("Safe"); ok {
						if val, ok := aval.(bool); ok {
							safe = val
						}
					}
				}

				if otherAbstractSubnet.InternalSecurityGroupID != "" {
					lansg, innerXErr = LoadSecurityGroup(ctx, svc, otherAbstractSubnet.InternalSecurityGroupID)
					if innerXErr != nil {
						return fail.Wrap(innerXErr, "failed to load Subnet '%s' internal Security Group %s", otherAbstractSubnet.Name, otherAbstractSubnet.InternalSecurityGroupID)
					}

					if !safe {
						innerXErr = svc.ChangeSecurityGroupSecurity(ctx, false, true, otherAbstractSubnet.Network, "")
						if innerXErr != nil {
							return fail.Wrap(innerXErr, "failed to change security group")
						}
					}

					innerXErr = lansg.BindToHost(ctx, instance, resources.SecurityGroupEnable, resources.MarkSecurityGroupAsSupplemental)
					if innerXErr != nil {
						return fail.Wrap(innerXErr, "failed to apply Subnet '%s' internal Security Group '%s' to Host '%s'", otherAbstractSubnet.Name, lansg.GetName(), req.ResourceName)
					}

					if !safe {
						innerXErr = svc.ChangeSecurityGroupSecurity(ctx, true, false, otherAbstractSubnet.Network, "")
						if innerXErr != nil {
							return fail.Wrap(innerXErr, "failed to change security group")
						}
					}

					langID, err := lansg.GetID()
					if err != nil {
						return fail.ConvertError(err)
					}

					// register security group in properties
					item := &propertiesv1.SecurityGroupBond{
						ID:         langID,
						Name:       lansg.GetName(),
						Disabled:   false,
						FromSubnet: true,
					}
					hsgV1.ByID[item.ID] = item
					hsgV1.ByName[item.Name] = item.ID
				}

			}

			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	return nil
}

func (instance *Host) undoSetSecurityGroups(ctx context.Context, errorPtr *fail.Error, keepOnFailure bool) fail.Error {
	if errorPtr == nil {
		return fail.NewError("trying to call a cancel function from a nil error; cancel not run")
	}

	if *errorPtr != nil && !keepOnFailure {
		svc := instance.Service()
		derr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(
				hostproperty.SecurityGroupsV1, func(clonable data.Clonable) (innerXErr fail.Error) {
					hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv1.HostSecurityGroups' expected, '%s' provided",
							reflect.TypeOf(clonable).String(),
						)
					}

					var (
						opXErr fail.Error
						sg     resources.SecurityGroup
						errs   []error
					)

					// unbind security groups
					for _, v := range hsgV1.ByName {
						if sg, opXErr = LoadSecurityGroup(ctx, svc, v); opXErr != nil {
							errs = append(errs, opXErr)
						} else {
							opXErr = sg.UnbindFromHost(ctx, instance)
							if opXErr != nil {
								errs = append(errs, opXErr)
							}
						}
					}
					if len(errs) > 0 {
						return fail.Wrap(fail.NewErrorList(errs), "cleaning up on %s, failed to unbind Security Groups from Host", ActionFromError(*errorPtr))
					}

					return nil
				},
			)
		})
		if derr != nil {
			_ = (*errorPtr).AddConsequence(
				fail.Wrap(
					derr, "cleaning up on %s, failed to cleanup Security Groups", ActionFromError(*errorPtr),
				),
			)
		}
	}
	return nil
}

// UnbindDefaultSecurityGroupIfNeeded unbinds "default" Security Group from Host if it is bound
func (instance *Host) unbindDefaultSecurityGroupIfNeeded(ctx context.Context, networkID string) fail.Error {
	svc := instance.Service()

	hostID, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	sgName, err := svc.GetDefaultSecurityGroupName(ctx)
	if err != nil {
		return fail.ConvertError(err)
	}
	if sgName != "" {
		adsg, innerXErr := svc.InspectSecurityGroupByName(ctx, networkID, sgName)
		if innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// ignore this error
				debug.IgnoreError2(ctx, innerXErr)
			default:
				return innerXErr
			}
		} else if innerXErr = svc.UnbindSecurityGroupFromHost(ctx, adsg, hostID); innerXErr != nil {
			switch innerXErr.(type) {
			case *fail.ErrNotFound:
				// Consider a security group not found as a successful unbind
				debug.IgnoreError2(ctx, innerXErr)
			default:
				return fail.Wrap(innerXErr, "failed to unbind Security Group '%s' from Host", sgName)
			}
		}
	}
	return nil
}

func (instance *Host) thePhaseDoesSomething(_ context.Context, phase userdata.Phase, userdataContent *userdata.Content) bool {
	// assume yes
	result := true

	// render content
	content, xerr := userdataContent.Generate(phase)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return true
	}

	fullCt := string(content)
	if !strings.Contains(fullCt, "# ---- Main") {
		return true
	}

	if !strings.Contains(fullCt, "# ---- EndMain") {
		return true
	}

	// TODO: Remove blank lines to simplify this test
	if strings.Contains(fullCt, "# ---- Main\n# ---- EndMain") {
		result = false
	}

	if strings.Contains(fullCt, "# ---- Main\n\n# ---- EndMain") {
		result = false
	}

	if strings.Contains(fullCt, "# ---- Main\n\n\n# ---- EndMain") {
		result = false
	}

	return result
}

func (instance *Host) thePhaseReboots(_ context.Context, phase userdata.Phase, userdataContent *userdata.Content) bool {
	// render content
	content, xerr := userdataContent.Generate(phase)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return true
	}

	fullCt := string(content)
	return strings.Contains(fullCt, "# ---- REBOOT")
}

// runInstallPhase uploads then starts script corresponding to phase 'phase'
func (instance *Host) runInstallPhase(ctx context.Context, phase userdata.Phase, userdataContent *userdata.Content, timeout time.Duration) (ferr fail.Error) {
	defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Starting install phase %s on '%s'...", phase, instance.GetName()), fmt.Sprintf("Ending phase %s on '%s' with err '%s' ...", phase, instance.GetName(), ferr))()

	content, xerr := userdataContent.Generate(phase)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	file := fmt.Sprintf("%s/user_data.%s.sh", utils.TempFolder, phase)
	xerr = instance.unsafePushStringToFileWithOwnership(ctx, string(content), file, userdataContent.Username, "755")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	rounds := 10
	for {
		select {
		case <-ctx.Done():
			return fail.ConvertError(ctx.Err())
		default:
		}

		rc, _, _, xerr := instance.unsafeRun(ctx, "sudo sync", outputs.COLLECT, 0, 10*time.Second)
		if xerr != nil {
			rounds--
			continue
		}

		if rc == 126 {
			logrus.WithContext(ctx).Debugf("Text busy happened")
		}

		if rc == 0 {
			break
		}

		if rc != 126 || rounds == 0 {
			if rc == 126 {
				return fail.NewError("Text busy killed the script")
			}
		}

		rounds--
	}

	command := getCommand(ctx, file)

	// Executes the script on the remote Host
	retcode, stdout, stderr, xerr := instance.unsafeRun(ctx, command, outputs.COLLECT, 0, timeout)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to apply configuration phase '%s'", phase)
	}
	if retcode != 0 {
		// build new error
		problem := fail.NewError("failed to execute install phase '%s' on Host '%s'", phase, instance.GetName())
		problem.Annotate("retcode", retcode)
		problem.Annotate("stdout", stdout)
		problem.Annotate("stderr", stderr)

		if abstract.IsProvisioningError(problem) {
			// Rewrite stdout, probably has too much information
			if stdout != "" {
				lastMsg := ""
				lines := strings.Split(stdout, "\n")
				for _, line := range lines {
					if strings.Contains(line, "+ echo '") {
						lastMsg = line
					}
				}

				if len(lastMsg) > 0 {
					problem = fail.NewError(
						"failed to execute install phase '%s' on Host '%s': %s", phase, instance.GetName(),
						lastMsg[8:len(lastMsg)-1],
					)
				}
			}

			if stderr != "" {
				lastMsg := ""
				lines := strings.Split(stderr, "\n")
				for _, line := range lines {
					if strings.Contains(line, "+ echo '") {
						lastMsg = line
					}
				}

				if len(lastMsg) > 0 {
					problem = fail.NewError(
						"failed to execute install phase '%s' on Host '%s': %s", phase, instance.GetName(),
						lastMsg[8:len(lastMsg)-1],
					)
				}
			}
		}

		return problem
	}
	return nil
}

func (instance *Host) waitInstallPhase(inctx context.Context, phase userdata.Phase, timeout time.Duration) (_ string, rerr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type result struct {
		rTr  string
		rErr fail.Error
	}
	chRes := make(chan result)
	go func() {
		defer close(chRes)
		defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Waiting install phase %s on '%s'...", phase, instance.GetName()), fmt.Sprintf("Finish Waiting install phase %s on '%s' with err '%s' ...", phase, instance.GetName(), rerr))()

		sshDefaultTimeout := timeout
		duration := sshDefaultTimeout

		sshCfg, xerr := instance.GetSSHConfig(ctx)
		if xerr != nil {
			chRes <- result{"", xerr}
			return
		}

		sshProfile, xerr := sshfactory.NewConnector(sshCfg)
		if xerr != nil {
			chRes <- result{"", xerr}
			return
		}

		status, xerr := sshProfile.WaitServerReady(ctx, string(phase), duration)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry:
				chRes <- result{status, fail.Wrap(fail.Cause(xerr), "stopping retries")}
				return
			case *fail.ErrTimeout:
				chRes <- result{status, fail.Wrap(
					fail.Cause(xerr), "failed to wait for SSH on Host '%s' to be ready after %s (phase %s): %s",
					instance.GetName(), temporal.FormatDuration(duration), phase, status,
				)}
				return
			default:
			}
			if abstract.IsProvisioningError(xerr) {
				stdout := ""
				stderr := ""

				if astdout, ok := xerr.Annotation("stdout"); ok {
					if val, ok := astdout.(string); ok {
						stdout = val
					}
				}
				if astderr, ok := xerr.Annotation("stderr"); ok {
					if val, ok := astderr.(string); ok {
						stderr = val
					}
				}

				// Rewrite stdout, probably has too much information
				if stdout != "" {
					lastMsg := ""
					lines := strings.Split(stdout, "\n")
					for _, line := range lines {
						if strings.Contains(line, "+ echo '") {
							lastMsg = line
						}
					}

					if len(lastMsg) > 0 {
						xerr = fail.NewError(
							"failed to execute install phase '%s' on Host '%s': %s", phase, instance.GetName(),
							lastMsg[8:len(lastMsg)-1],
						)
					}
				}

				if stderr != "" {
					lastMsg := ""
					lines := strings.Split(stderr, "\n")
					for _, line := range lines {
						if strings.Contains(line, "+ echo '") {
							lastMsg = line
						}
					}

					if len(lastMsg) > 0 {
						xerr = fail.NewError(
							"failed to execute install phase '%s' on Host '%s': %s", phase, instance.GetName(),
							lastMsg[8:len(lastMsg)-1],
						)
					}
				}
			}
		}
		chRes <- result{status, xerr}

	}()
	select {
	case <-time.After(timeout):
		return "", fail.TimeoutError(fmt.Errorf("failed to wait for SSH on Host '%s' to be ready (phase %s)", instance.GetName(), phase), timeout)
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return "", fail.ConvertError(ctx.Err())
	case <-inctx.Done():
		return "", fail.ConvertError(inctx.Err())
	}
}

// updateSubnets updates subnets on which host is attached and host property HostNetworkV2
func (instance *Host) updateSubnets(ctx context.Context, req abstract.HostRequest) fail.Error {
	// If Host is a gateway or is single, do not add it as Host attached to the Subnet, it's considered as part of the subnet
	if !req.IsGateway && !req.Single {
		xerr := instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
				hnV2, ok := clonable.(*propertiesv2.HostNetworking)
				if !ok {
					return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				hostID, err := instance.GetID()
				if err != nil {
					return fail.ConvertError(err)
				}
				hostName := instance.GetName()
				svc := instance.Service()
				for _, as := range req.Subnets {
					rs, innerXErr := LoadSubnet(ctx, svc, "", as.ID)
					if innerXErr != nil {
						return innerXErr
					}

					innerXErr = rs.Alter(ctx, func(clonable data.Clonable, properties *serialize.JSONProperties) fail.Error {
						return properties.Alter(subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
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
		if xerr != nil {
			return xerr
		}
	}
	return nil
}

// undoUpdateSubnets removes what updateSubnets have done
func (instance *Host) undoUpdateSubnets(inctx context.Context, req abstract.HostRequest, errorPtr *fail.Error) {
	ctx := inctx

	if errorPtr != nil && *errorPtr != nil && !req.IsGateway && !req.Single && !req.KeepOnFailure {
		xerr := instance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Alter(
				hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
					hsV1, ok := clonable.(*propertiesv2.HostNetworking)
					if !ok {
						return fail.InconsistentError(
							"'*propertiesv2.HostNetworking' expected, '%s' provided",
							reflect.TypeOf(clonable).String(),
						)
					}

					hostID, err := instance.GetID()
					if err != nil {
						return fail.ConvertError(err)
					}
					hostName := instance.GetName()
					svc := instance.Service()
					for _, as := range req.Subnets {
						subnetInstance, innerXErr := LoadSubnet(ctx, svc, "", as.ID)
						if innerXErr != nil {
							return innerXErr
						}

						innerXErr = subnetInstance.Alter(ctx,
							func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
								return props.Alter(
									subnetproperty.HostsV1, func(clonable data.Clonable) fail.Error {
										subnetHostsV1, ok := clonable.(*propertiesv1.SubnetHosts)
										if !ok {
											return fail.InconsistentError(
												"'*propertiesv1.SubnetHosts' expected, '%s' provided",
												reflect.TypeOf(clonable).String(),
											)
										}

										delete(subnetHostsV1.ByID, hostID)
										delete(subnetHostsV1.ByName, hostName)
										return nil
									},
								)
							},
						)
						if innerXErr != nil {
							return innerXErr
						}

						delete(hsV1.SubnetsByID, as.ID)
						delete(hsV1.SubnetsByName, as.ID)
					}
					return nil
				},
			)
		})
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			_ = (*errorPtr).AddConsequence(
				fail.Wrap(
					xerr, "cleaning up on %s, failed to remove Host relationships with Subnets", ActionFromError(xerr),
				),
			)
		}
	}
}

func (instance *Host) finalizeProvisioning(ctx context.Context, hr abstract.HostRequest, userdataContent *userdata.Content) fail.Error {
	// Reset userdata script for Host from Cloud Provider metadata service (if stack is able to do so)
	svc := instance.Service()

	hostID, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	xerr := svc.ClearHostStartupScript(ctx, hostID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	if userdataContent.Debug {
		if _, err := os.Stat("/tmp/tss"); !errors.Is(err, os.ErrNotExist) {
			_, _, _, xerr = instance.unsafePush(ctx, "/tmp/tss", fmt.Sprintf("/home/%s/tss", userdataContent.Username), userdataContent.Username, "755", 10*time.Second)
			if xerr != nil {
				debug.IgnoreError2(ctx, xerr)
			}
		}
	}

	// Executes userdata.PHASE2_NETWORK_AND_SECURITY script to configure networking and security
	xerr = instance.runInstallPhase(ctx, userdata.PHASE2_NETWORK_AND_SECURITY, userdataContent, getPhase2Timeout(timings))
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// Update Keypair of the Host with the final one
	xerr = instance.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
		ah, ok := clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		ah.PrivateKey = userdataContent.FinalPrivateKey
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to update Keypair of machine '%s'", hr.ResourceName)
	}

	if inBackground() {
		_, xerr = instance.waitInstallPhase(ctx, userdata.PHASE2_NETWORK_AND_SECURITY, timings.HostOperationTimeout()+timings.HostBootTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	waitingTime := temporal.MaxTimeout(24*timings.RebootTimeout()/10, timings.HostCreationTimeout())
	// If the script doesn't reboot, we force a reboot
	if !instance.thePhaseReboots(ctx, userdata.PHASE2_NETWORK_AND_SECURITY, userdataContent) {
		logrus.WithContext(ctx).Infof("finalizing Host provisioning of '%s': rebooting", hr.ResourceName)

		// Reboot Host
		xerr = instance.Reboot(ctx, true)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		time.Sleep(timings.RebootTimeout())
	}

	_, xerr = instance.waitInstallPhase(ctx, userdata.PHASE2_NETWORK_AND_SECURITY, 90*time.Second) // FIXME: It should be 1:30 min tops, 2*reboot time
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	// if Host is not a gateway, executes userdata.PHASE4/5 scripts
	// to fix possible system issues and finalize Host creation.
	// For a gateway, userdata.PHASE3 to 5 have to be run explicitly (cf. operations/subnet.go)
	if !userdataContent.IsGateway {
		if instance.thePhaseDoesSomething(ctx, userdata.PHASE4_SYSTEM_FIXES, userdataContent) {
			// execute userdata.PHASE4_SYSTEM_FIXES script to fix possible misconfiguration in system
			xerr = instance.runInstallPhase(ctx, userdata.PHASE4_SYSTEM_FIXES, userdataContent, getPhase4Timeout(timings))
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				theCause := fail.ConvertError(fail.Cause(xerr))
				if _, ok := theCause.(*fail.ErrTimeout); !ok || valid.IsNil(theCause) {
					return xerr
				}

				debug.IgnoreError2(ctx, xerr)
			}

			// Reboot Host
			logrus.WithContext(ctx).Infof("finalizing Host provisioning of '%s' (not-gateway): rebooting", hr.ResourceName)
			xerr = instance.Reboot(ctx, true)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			time.Sleep(timings.RebootTimeout())

			_, xerr = instance.waitInstallPhase(ctx, userdata.PHASE4_SYSTEM_FIXES, waitingTime)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		} else {
			logrus.WithContext(ctx).Debugf("Nothing to do for the phase '%s'", userdata.PHASE4_SYSTEM_FIXES)
		}

		// execute userdata.PHASE5_FINAL script to finalize install/configure of the Host (no need to reboot)
		xerr = instance.runInstallPhase(ctx, userdata.PHASE5_FINAL, userdataContent, waitingTime)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		_, xerr = instance.waitInstallPhase(ctx, userdata.PHASE5_FINAL, timings.HostOperationTimeout())
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) { // nolint
			case *retry.ErrStopRetry:
				return fail.Wrap(xerr, "stopping retries")
			case *fail.ErrTimeout:
				return fail.Wrap(xerr, "timeout creating a Host")
			}
			if abstract.IsProvisioningError(xerr) {
				logrus.WithContext(ctx).Errorf("%+v", xerr)
				return fail.Wrap(
					xerr, "error provisioning the new Host, please check safescaled logs", hr.ResourceName,
				)
			}
			return xerr
		}
	}
	return nil
}

// WaitSSHReady waits until SSH responds successfully
func (instance *Host) WaitSSHReady(ctx context.Context, timeout time.Duration) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).Entering()
	defer tracer.Exiting()

	return instance.waitInstallPhase(ctx, userdata.PHASE5_FINAL, timeout)
}

// createSingleHostNetwork creates Single-Host Network and Subnet
func createSingleHostNetworking(ctx context.Context, svc iaas.Service, singleHostRequest abstract.HostRequest) (_ resources.Subnet, _ func() fail.Error, ferr fail.Error) {
	// Build network name
	cfg, xerr := svc.GetConfigurationOptions(ctx)
	if xerr != nil {
		return nil, nil, xerr
	}

	bucketName := cfg.GetString("MetadataBucketName")
	if bucketName == "" {
		return nil, nil, fail.InconsistentError("missing service configuration option 'MetadataBucketName'")
	}

	// Trim and TrimPrefix don't do the same thing
	networkName := fmt.Sprintf("sfnet-%s", strings.TrimPrefix(bucketName, objectstorage.BucketNamePrefix+"-"))

	// Create network if needed
	networkInstance, xerr := LoadNetwork(ctx, svc, networkName)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			networkInstance, xerr = NewNetwork(svc)
			if xerr != nil {
				return nil, nil, xerr
			}

			request := abstract.NetworkRequest{
				Name:          networkName,
				CIDR:          abstract.SingleHostNetworkCIDR,
				KeepOnFailure: true,
			}
			xerr = networkInstance.Create(ctx, request)
			if xerr != nil {
				// handle a particular case of *fail.ErrDuplicate...
				switch cerr := xerr.(type) {
				case *fail.ErrDuplicate:
					value, found := cerr.Annotation("managed")
					if found && value != nil {
						managed, ok := value.(bool)
						if ok && !managed {
							return nil, nil, xerr
						}
					}
				default:
				}
				// ... otherwise, try to get Network that is created by another goroutine
				switch xerr.(type) {
				case *fail.ErrDuplicate, *fail.ErrNotAvailable:
					// If these errors occurred, another goroutine is running to create the same Network, so wait for it
					networkInstance, xerr = LoadNetwork(ctx, svc, networkName)
					if xerr != nil {
						return nil, nil, xerr
					}
				default:
					return nil, nil, xerr
				}
			}
		default:
			return nil, nil, xerr
		}
	}

	nid, err := networkInstance.GetID()
	if err != nil {
		return nil, nil, fail.ConvertError(err)
	}

	// Check if Subnet exists
	var (
		subnetRequest abstract.SubnetRequest
		cidrIndex     uint
	)
	subnetInstance, xerr := LoadSubnet(ctx, svc, nid, singleHostRequest.ResourceName)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			subnetInstance, xerr = NewSubnet(svc)
			if xerr != nil {
				return nil, nil, xerr
			}

			var (
				subnetCIDR string
			)

			subnetCIDR, cidrIndex, xerr = ReserveCIDRForSingleHost(ctx, networkInstance)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, nil, xerr
			}

			var dnsServers []string
			opts, xerr := svc.GetConfigurationOptions(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
				default:
					return nil, nil, xerr
				}
			} else if servers := strings.TrimSpace(opts.GetString("DNSServers")); servers != "" {
				dnsServers = strings.Split(servers, ",")
			}

			subnetRequest.Name = singleHostRequest.ResourceName
			subnetRequest.NetworkID, err = networkInstance.GetID()
			if err != nil {
				return nil, nil, fail.ConvertError(err)
			}
			subnetRequest.IPVersion = ipversion.IPv4
			subnetRequest.CIDR = subnetCIDR
			subnetRequest.DNSServers = dnsServers
			subnetRequest.HA = false

			xerr = subnetInstance.CreateSubnetWithoutGateway(ctx, subnetRequest)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, nil, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && !singleHostRequest.KeepOnFailure {
					derr := subnetInstance.Delete(cleanupContextFrom(ctx))
					if derr != nil {
						_ = ferr.AddConsequence(
							fail.Wrap(
								derr, "cleaning up on failure, failed to delete Subnet '%s'",
								singleHostRequest.ResourceName,
							),
						)
					}
				}
			}()

			// Sets the CIDR index in instance metadata
			xerr = subnetInstance.Alter(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				as, ok := clonable.(*abstract.Subnet)
				if !ok {
					return fail.InconsistentError(
						"'*abstract.Subnet' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}

				as.SingleHostCIDRIndex = cidrIndex
				return nil
			})
			if xerr != nil {
				return nil, nil, xerr
			}
		default:
			return nil, nil, xerr
		}
	} else {
		return nil, nil, fail.DuplicateError("there is already a Subnet named '%s'", singleHostRequest.ResourceName)
	}

	undoFunc := func() fail.Error {
		var errs []error
		if !singleHostRequest.KeepOnFailure {
			derr := subnetInstance.Delete(cleanupContextFrom(ctx))
			if derr != nil {
				errs = append(
					errs, fail.Wrap(
						derr, "cleaning up on failure, failed to delete Subnet '%s'", singleHostRequest.ResourceName,
					),
				)
			}
			derr = FreeCIDRForSingleHost(cleanupContextFrom(ctx), networkInstance, cidrIndex)
			if derr != nil {
				errs = append(
					errs, fail.Wrap(
						derr, "cleaning up on failure, failed to free CIDR slot in Network '%s'",
						networkInstance.GetName(),
					),
				)
			}
		}
		if len(errs) > 0 {
			return fail.NewErrorList(errs)
		}
		return nil
	}

	return subnetInstance, undoFunc, nil
}

// Delete deletes a Host with its metadata and updates subnet links
func (instance *Host) Delete(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	defer func() {
		// drop the cache when we are done creating the cluster
		if ka, err := instance.Service().GetCache(context.Background()); err == nil {
			if ka != nil {
				_ = ka.Clear(context.Background())
			}
		}
	}()

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).Entering()
	defer tracer.Exiting()

	xerr := instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Do not remove a Host that is a gateway
		return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			if hostNetworkV2.IsGateway {
				return fail.NotAvailableError("cannot delete Host, it's a gateway that can only be deleted through its Subnet")
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.RelaxedDeleteHost(cleanupContextFrom(ctx))
	return xerr
}

// RelaxedDeleteHost is the method that really deletes a host, being a gateway or not
func (instance *Host) RelaxedDeleteHost(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	svc := instance.Service()
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	cache, xerr := instance.Service().GetCache(ctx)
	if xerr != nil {
		return xerr
	}

	var shares map[string]*propertiesv1.HostShare
	xerr = instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// Do not remove a Host having shared folders that are currently remotely mounted
		innerXErr := props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
			sharesV1, ok := clonable.(*propertiesv1.HostShares)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
			}

			shares = sharesV1.ByID
			shareCount := len(shares)
			for _, hostShare := range shares {
				count := len(hostShare.ClientsByID)
				if count > 0 {
					// clients found, checks if these clients already exists...
					for _, hostID := range hostShare.ClientsByID {
						instance, inErr := LoadHost(ctx, svc, hostID)
						if inErr != nil {
							debug.IgnoreError2(ctx, inErr)
							continue
						}
						return fail.NotAvailableError("Host '%s' exports %d share%s and at least one share is mounted", instance.GetName(), shareCount, strprocess.Plural(uint(shareCount)))
					}
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Do not delete a Host with Bucket mounted
		innerXErr = props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounbts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			nMounted := len(hostMountsV1.BucketMounts)
			if nMounted > 0 {
				return fail.NotAvailableError("Host '%s' has %d Bucket%s mounted", instance.GetName(), nMounted, strprocess.Plural(uint(nMounted)))
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Do not delete a Host with Volumes attached
		return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok := clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String(),
				)
			}

			nAttached := len(hostVolumesV1.VolumesByID)
			if nAttached > 0 {
				return fail.NotAvailableError("Host '%s' has %d Volume%s attached", instance.GetName(), nAttached,
					strprocess.Plural(uint(nAttached)),
				)
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	hid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	hname := instance.GetName()

	var (
		single         bool
		singleSubnetID string
	)
	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		// If Host has mounted shares, unmounts them before anything else
		var mounts []*propertiesv1.HostShare
		innerXErr := props.Inspect(hostproperty.MountsV1, func(clonable data.Clonable) fail.Error {
			hostMountsV1, ok := clonable.(*propertiesv1.HostMounts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostMounts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			for _, i := range hostMountsV1.RemoteMountsByPath {
				// Retrieve Share data
				shareInstance, loopErr := LoadShare(ctx, svc, i.ShareID)
				if loopErr != nil {
					if _, ok := loopErr.(*fail.ErrNotFound); !ok { // nolint
						return loopErr
					}
					debug.IgnoreError2(ctx, loopErr)
					continue
				}

				// Retrieve data about the server serving the Share
				hostServer, loopErr := shareInstance.GetServer(ctx)
				if loopErr != nil {
					return loopErr
				}

				// Retrieve data about v from its server
				item, loopErr := hostServer.GetShare(ctx, i.ShareID)
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

		// Unmounts tier shares mounted on Host (done outside the previous Host.properties.Reading() section, because
		// Unmount() have to lock for write, and won't succeed while Host.properties.Reading() is running,
		// leading to a deadlock)
		for _, v := range mounts {
			shareInstance, loopErr := LoadShare(ctx, svc, v.ID)
			if loopErr != nil {
				if _, ok := loopErr.(*fail.ErrNotFound); !ok { // nolint
					return loopErr
				}
				debug.IgnoreError2(ctx, loopErr)
				continue
			}

			loopErr = shareInstance.Unmount(ctx, instance)
			if loopErr != nil {
				return loopErr
			}
		}

		// if Host exports shares, delete them
		for _, v := range shares {
			shareInstance, loopErr := LoadShare(ctx, svc, v.Name)
			if loopErr != nil {
				if _, ok := loopErr.(*fail.ErrNotFound); !ok { // nolint
					return loopErr
				}
				debug.IgnoreError2(ctx, loopErr)
				continue
			}

			loopErr = shareInstance.Delete(ctx)
			if loopErr != nil {
				return loopErr
			}
		}

		// Walk through property propertiesv1.HostNetworking to remove the reference to the Host in Subnets
		innerXErr = props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			hostID, err := instance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			single = hostNetworkV2.Single
			if single {
				singleSubnetID = hostNetworkV2.DefaultSubnetID
			}

			if !single {
				var errs []error
				for k := range hostNetworkV2.SubnetsByID {
					if !hostNetworkV2.IsGateway && k != hostNetworkV2.DefaultSubnetID {
						subnetInstance, loopErr := LoadSubnet(ctx, svc, "", k)
						if loopErr != nil {
							logrus.WithContext(ctx).Errorf(loopErr.Error())
							errs = append(errs, loopErr)
							continue
						}

						loopErr = subnetInstance.DetachHost(ctx, hostID)
						if loopErr != nil {
							logrus.WithContext(ctx).Errorf(loopErr.Error())
							errs = append(errs, loopErr)
							continue
						}
					}
				}
				if len(errs) > 0 {
					return fail.Wrap(fail.NewErrorList(errs), "failed to update metadata for Subnets of Host")
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		// Unbind Security Groups from Host
		innerXErr = props.Alter(hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Unbind Security Groups from Host
			var errs []error
			for _, v := range hsgV1.ByID {
				sgInstance, rerr := LoadSecurityGroup(ctx, svc, v.ID)
				if rerr != nil {
					switch rerr.(type) {
					case *fail.ErrNotFound:
						// Consider that a Security Group that cannot be loaded or is not bound as a success
						debug.IgnoreError2(ctx, rerr)
					default:
						errs = append(errs, rerr)
					}
					continue
				}

				rerr = sgInstance.UnbindFromHost(ctx, instance)
				if rerr != nil {
					switch rerr.(type) {
					case *fail.ErrNotFound:
						// Consider that a Security Group that cannot be loaded or is not bound as a success
						debug.IgnoreError2(ctx, rerr)
					default:
						errs = append(errs, rerr)
					}
				}
			}
			if len(errs) > 0 {
				return fail.Wrap(fail.NewErrorList(errs), "failed to unbind some Security Groups")
			}

			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to unbind Security Groups from Host")
		}

		// Unbind labels from Host
		innerXErr = props.Alter(hostproperty.LabelsV1, func(clonable data.Clonable) fail.Error {
			hlV1, ok := clonable.(*propertiesv1.HostLabels)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostLabels' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// Unbind Security Groups from Host
			var errs []error
			for k := range hlV1.ByID {
				labelInstance, rerr := LoadLabel(ctx, svc, k)
				if rerr != nil {
					switch rerr.(type) {
					case *fail.ErrNotFound:
						// Consider that a Security Group that cannot be loaded or is not bound as a success
						debug.IgnoreError2(ctx, rerr)
					default:
						errs = append(errs, rerr)
					}
					continue
				}

				rerr = labelInstance.UnbindFromHost(cleanupContextFrom(ctx), instance)
				if rerr != nil {
					switch rerr.(type) {
					case *fail.ErrNotFound:
						// Consider that a Security Group that cannot be loaded or is not bound as a success
						debug.IgnoreError2(ctx, rerr)
					default:
						errs = append(errs, rerr)
					}
				}
			}
			if len(errs) > 0 {
				return fail.Wrap(fail.NewErrorList(errs), "failed to unbind some Security Groups")
			}

			return nil
		})
		if innerXErr != nil {
			return fail.Wrap(innerXErr, "failed to unbind Security Groups from Host")
		}

		// Delete Host
		waitForDeletion := true
		innerXErr = retry.WhileUnsuccessful(
			func() error {
				select {
				case <-ctx.Done():
					return retry.StopRetryError(ctx.Err())
				default:
				}

				if rerr := svc.DeleteHost(ctx, hid); rerr != nil {
					switch rerr.(type) {
					case *fail.ErrNotFound:
						// A Host not found is considered as a successful deletion
						logrus.WithContext(ctx).Tracef("Host not found, deletion considered as a success")
						debug.IgnoreError2(ctx, rerr)
					default:
						return fail.Wrap(rerr, "cannot delete Host")
					}
					waitForDeletion = false
				}
				return nil
			},
			timings.SmallDelay(),
			timings.HostCleanupTimeout(),
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

		// wait for effective Host deletion
		if waitForDeletion {
			innerXErr = retry.WhileUnsuccessfulWithHardTimeout(
				func() error {
					select {
					case <-ctx.Done():
						return retry.StopRetryError(ctx.Err())
					default:
					}

					state, stateErr := svc.GetHostState(ctx, hid)
					if stateErr != nil {
						switch stateErr.(type) {
						case *fail.ErrNotFound:
							// If Host is not found anymore, consider this as a success
							debug.IgnoreError2(ctx, stateErr)
							return nil
						default:
							return stateErr
						}
					}
					if state == hoststate.Error {
						return fail.NotAvailableError("Host is in state Error")
					}
					return nil
				},
				timings.NormalDelay(),
				timings.OperationTimeout(),
			)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *retry.ErrStopRetry:
					innerXErr = fail.ConvertError(fail.Cause(innerXErr))
					if _, ok := innerXErr.(*fail.ErrNotFound); !ok || valid.IsNil(innerXErr) {
						return innerXErr
					}
					debug.IgnoreError2(ctx, innerXErr)
				case *fail.ErrNotFound:
					debug.IgnoreError2(ctx, innerXErr)
				default:
					return innerXErr
				}
			}
		}

		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	if single {
		// delete its dedicated Subnet
		singleSubnetInstance, xerr := LoadSubnet(ctx, svc, "", singleSubnetID)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		xerr = singleSubnetInstance.Delete(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}
	}

	theID, _ := instance.GetID()

	// Deletes metadata from Object Storage
	xerr = instance.MetadataCore.Delete(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		// If entry not found, considered as a success
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return xerr
		}
		debug.IgnoreError2(ctx, xerr)
		logrus.WithContext(ctx).Tracef("core instance not found, deletion considered as a success")
	}

	if ka, err := instance.Service().GetCache(ctx); err == nil {
		if ka != nil {
			if theID != "" {
				_ = ka.Delete(ctx, fmt.Sprintf("%T/%s", instance, theID))
			}
		}
	}

	if cache != nil {
		_ = cache.Delete(ctx, hid)
		_ = cache.Delete(ctx, hname)
	}

	return nil
}

// GetSSHConfig loads SSH configuration for Host from metadata
func (instance *Host) GetSSHConfig(ctx context.Context) (_ sshapi.Config, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	sshProfile, xerr := instance.updateCachedInformation(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if valid.IsNil(sshProfile) {
		return nil, fail.NotFoundError("failed to find SSH Config of Host '%s'", instance.GetName())
	}

	return sshProfile.Config()
}

// Run tries to execute command 'cmd' on the Host
func (instance *Host) Run(ctx context.Context, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if valid.IsNil(instance) {
		return invalid, "", "", fail.InvalidInstanceError()
	}

	if ctx == nil {
		return invalid, "", "", fail.InvalidParameterCannotBeNilError("ctx")
	}
	if cmd == "" {
		return invalid, "", "", fail.InvalidParameterError("cmd", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(cmd='%s', outs=%s)", outs.String()).Entering()
	defer tracer.Exiting()

	return instance.unsafeRun(ctx, cmd, outs, connectionTimeout, executionTimeout)
}

// Pull downloads a file from Host
func (instance *Host) Pull(ctx context.Context, target, source string, timeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if valid.IsNil(instance) {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return invalid, "", "", fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("target")
	}
	if source == "" {
		return invalid, "", "", fail.InvalidParameterCannotBeEmptyStringError("source")
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return invalid, "", "", xerr
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(target=%s,source=%s)", target, source).Entering()
	defer tracer.Exiting()

	// instance.RLock()
	// defer instance.RUnlock()

	targetName := instance.GetName()

	var state hoststate.Enum
	state, xerr = instance.ForceGetState(ctx)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if state != hoststate.Started {
		return invalid, "", "", fail.InvalidRequestError(fmt.Sprintf("cannot pull anything on '%s', '%s' is NOT started", targetName, targetName))
	}

	var stdout, stderr string
	retcode := -1
	sshCfg, xerr := instance.GetSSHConfig(ctx)
	if xerr != nil {
		return retcode, stdout, stderr, xerr
	}

	sshProfile, xerr := sshfactory.NewConnector(sshCfg)
	if xerr != nil {
		return retcode, stdout, stderr, xerr
	}

	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			iretcode, istdout, istderr, innerXErr := sshProfile.CopyWithTimeout(ctx, target, source, false, timeout)
			if innerXErr != nil {
				return innerXErr
			}
			if iretcode != 0 {
				problem := fail.NewError("copy failed")
				problem.Annotate("stdout", istdout)
				problem.Annotate("stderr", istderr)
				problem.Annotate("retcode", iretcode)
				return problem
			}

			retcode = iretcode
			stdout = istdout
			stderr = istderr

			return nil
		},
		timings.NormalDelay(),
		2*timeout,
	)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrStopRetry:
			return retcode, stdout, stderr, fail.Wrap(fail.Cause(xerr), "stopping retries")
		case *retry.ErrTimeout:
			return retcode, stdout, stderr, fail.Wrap(fail.Cause(xerr), "timeout")
		default:
			return retcode, stdout, stderr, xerr
		}
	}
	return retcode, stdout, stderr, nil
}

// Push uploads a file to Host
func (instance *Host) Push(
	ctx context.Context, source, target, owner, mode string, timeout time.Duration,
) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if valid.IsNil(instance) {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return invalid, "", "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(source=%s, target=%s, owner=%s, mode=%s)", source, target, owner, mode).Entering()
	defer tracer.Exiting()

	// instance.RLock()
	// defer instance.RUnlock()

	return instance.unsafePush(ctx, source, target, owner, mode, timeout)
}

// GetShare returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
func (instance *Host) GetShare(ctx context.Context, shareRef string) (_ *propertiesv1.HostShare, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	var (
		hostShare *propertiesv1.HostShare
		// ok        bool
	)
	err := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(
			hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
				sharesV1, ok := clonable.(*propertiesv1.HostShares)
				if !ok {
					return fail.InconsistentError(
						"'*propertiesv1.HostShares' expected, '%s' provided", reflect.TypeOf(clonable).String(),
					)
				}

				if item, ok := sharesV1.ByID[shareRef]; ok {
					cloned, cerr := item.Clone()
					if cerr != nil {
						return fail.Wrap(cerr)
					}
					hostShare, ok = cloned.(*propertiesv1.HostShare)
					if !ok {
						return fail.InconsistentError("item should be a *propertiesv1.HostShare")
					}
					return nil
				}
				if item, ok := sharesV1.ByName[shareRef]; ok {
					cloned, cerr := sharesV1.ByID[item].Clone()
					if cerr != nil {
						return fail.Wrap(cerr)
					}
					hostShare, ok = cloned.(*propertiesv1.HostShare)
					if !ok {
						return fail.InconsistentError("hostShare should be a *propertiesv1.HostShare")
					}
					return nil
				}
				return fail.NotFoundError(
					"share '%s' not found in server '%s' metadata", shareRef, instance.GetName(),
				)
			},
		)
	})
	err = debug.InjectPlannedFail(err)
	if err != nil {
		return nil, err
	}

	return hostShare, nil
}

// GetVolumes returns information about volumes attached to the Host
func (instance *Host) GetVolumes(ctx context.Context) (_ *propertiesv1.HostVolumes, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	return instance.unsafeGetVolumes(ctx)
}

// Start starts the Host
func (instance *Host) Start(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostName := instance.GetName()
	hostID, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	svc := instance.Service()
	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	xerr = svc.StartHost(ctx, hostID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			hs, err := instance.GetState(ctx)
			if err != nil {
				return err
			}

			if hs != hoststate.Started {
				return fail.NewError("%s not started yet: %s", hostName, hs.String())
			}

			return nil
		},
		timings.NormalDelay(),
		timings.ExecutionTimeout(),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAborted:
			if cerr := fail.ConvertError(fail.Cause(xerr)); cerr != nil {
				return cerr
			}
			return xerr
		case *retry.ErrTimeout:
			return fail.Wrap(xerr, "timeout waiting Host '%s' to be started", hostName)
		default:
			return xerr
		}
	}

	// Now unsafeReload
	xerr = instance.unsafeReload(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Stop stops the Host
func (instance *Host) Stop(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostName := instance.GetName()
	hostID, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	svc := instance.Service()

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	xerr = instance.Sync(ctx)
	if xerr != nil {
		logrus.WithContext(ctx).Debugf("failure trying to sync: %v", xerr)
	}

	xerr = svc.StopHost(ctx, hostID, false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = retry.WhileUnsuccessful(
		func() error {
			select {
			case <-ctx.Done():
				return retry.StopRetryError(ctx.Err())
			default:
			}

			hs, err := instance.GetState(ctx)
			if err != nil {
				return err
			}

			if hs != hoststate.Stopped {
				return fail.NewError("%s not stopped yet: %s", hostName, hs.String())
			}

			return nil
		},
		timings.NormalDelay(),
		timings.ExecutionTimeout(),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAborted:
			if cerr := fail.ConvertError(fail.Cause(xerr)); cerr != nil {
				return cerr
			}
			return xerr
		case *retry.ErrTimeout:
			return fail.Wrap(xerr, "timeout waiting Host '%s' to be stopped", hostName)
		default:
			return xerr
		}
	}

	// Now unsafeReload
	xerr = instance.unsafeReload(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Reboot reboots the Host
func (instance *Host) Reboot(ctx context.Context, soft bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := instance.Sync(ctx)
	if xerr != nil {
		logrus.WithContext(ctx).Debugf("failure trying to sync: %v", xerr)
	}

	if soft {
		xerr := instance.softReboot(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			logrus.WithContext(ctx).Warnf("Soft reboot failed, trying the hard way: %v", xerr)
			xerr = instance.hardReboot(ctx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
			return nil
		}
		return nil
	}

	xerr = instance.hardReboot(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	return nil
}

func (instance *Host) Sync(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	// Sync Host
	logrus.WithContext(ctx).Infof("Host '%s': sync", instance.GetName())
	command := `sync`
	_, _, _, xerr = instance.unsafeRun(ctx, command, outputs.COLLECT, timings.NormalDelay(), 30*time.Second) // nolint
	if xerr != nil {
		logrus.WithContext(ctx).Debugf("there was an error sending the reboot command: %v", xerr)
	}

	return nil
}

func (instance *Host) softReboot(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if debugFlag := os.Getenv("SAFESCALE_DEBUG"); debugFlag == "NoReboot" {
		return nil
	}

	timings, xerr := instance.Service().Timings()
	if xerr != nil {
		return xerr
	}

	waitingTime := 24 * timings.RebootTimeout() / 10 // by default, near 4 min
	minWaitFor := timings.NormalDelay()
	if minWaitFor > waitingTime {
		minWaitFor = waitingTime
	}

	// Reboot Host
	logrus.WithContext(ctx).Infof("Host '%s': rebooting", instance.GetName())
	command := `echo "sleep 4 ; sync ; sudo systemctl reboot" | at now`
	rebootCtx, cancelReboot := context.WithTimeout(ctx, waitingTime)
	defer cancelReboot()
	_, _, _, xerr = instance.unsafeRun(rebootCtx, command, outputs.COLLECT, timings.NormalDelay(), waitingTime) // nolint
	if xerr != nil {
		logrus.WithContext(ctx).Debugf("there was an error sending the reboot command: %v", xerr)
	}

	time.Sleep(minWaitFor)
	return nil
}

// HardReboot reboots the Host
func (instance *Host) hardReboot(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()

	xerr := instance.Stop(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Start(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// GetPublicIP returns the public IP address of the Host
func (instance *Host) GetPublicIP(_ context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	this, err := instance.MetadataCore.properties.UnWrap()
	if err != nil {
		return "", fail.ConvertError(err)
	}
	aclo, err := this[hostproperty.NetworkV2].UnWrap()
	if err != nil {
		return "", fail.ConvertError(err)
	}
	hnV2, _ := aclo.(*propertiesv2.HostNetworking) // nolint

	publicIP := hnV2.PublicIPv4
	if publicIP == "" {
		publicIP = hnV2.PublicIPv6
		if publicIP == "" {
			return "", fail.NotFoundError("failed to find Public IP of Host '%s'", instance.GetName())
		}
	}

	return publicIP, nil
}

// GetPrivateIP returns the private IP of the Host on its default Networking
func (instance *Host) GetPrivateIP(_ context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	this, err := instance.MetadataCore.properties.UnWrap()
	if err != nil {
		return "", fail.ConvertError(err)
	}
	aclo, err := this[hostproperty.NetworkV2].UnWrap()
	if err != nil {
		return "", fail.ConvertError(err)
	}
	hnV2, _ := aclo.(*propertiesv2.HostNetworking) // nolint

	var privateIP string
	if len(hnV2.IPv4Addresses) > 0 {
		privateIP = hnV2.IPv4Addresses[hnV2.DefaultSubnetID]
		if privateIP == "" {
			privateIP = hnV2.IPv6Addresses[hnV2.DefaultSubnetID]
		}
	}

	if privateIP == "" {
		return "", fail.NotFoundError("failed to find Private IP of Host '%s'", instance.GetName())
	}
	return privateIP, nil
}

// GetPrivateIPOnSubnet returns the private IP of the Host on its default Subnet
func (instance *Host) GetPrivateIPOnSubnet(ctx context.Context, subnetID string) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ip := ""
	if valid.IsNil(instance) {
		return ip, fail.InvalidInstanceError()
	}
	if subnetID = strings.TrimSpace(subnetID); subnetID == "" {
		return ip, fail.InvalidParameterError("subnetID", "cannot be empty string")
	}

	// instance.RLock()
	// defer instance.RUnlock()

	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hostNetworkV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			if ip, ok = hostNetworkV2.IPv4Addresses[subnetID]; !ok {
				return fail.InvalidRequestError("Host '%s' does not have an IP address on subnet '%s'", instance.GetName(), subnetID)
			}
			return nil
		})
	})
	return ip, xerr
}

// GetAccessIP returns the IP to reach the Host
func (instance *Host) GetAccessIP(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	publicIP, _ := instance.GetPublicIP(ctx)

	// FIXME: find a better way to handle the use case (adjust SG? something else?)
	// Workaround for a specific use: safescaled inside a cluster, to force access to host using internal IP
	fromInside := os.Getenv("SAFESCALED_FROM_INSIDE")
	if publicIP == "" || fromInside == "true" {
		privIP, xerr := instance.GetPrivateIP(ctx)
		if xerr != nil {
			return "", xerr
		}

		if privIP == "" {
			return "", fail.NotFoundError("failed to find Access IP of Host '%s'", instance.GetName())
		}
		return privIP, nil
	} else {
		if publicIP == "" {
			return "", fail.NotFoundError("failed to find Access IP of Host '%s'", instance.GetName())
		}
		return publicIP, nil
	}
}

// GetShares returns the information about the shares hosted by the Host
func (instance *Host) GetShares(ctx context.Context) (shares *propertiesv1.HostShares, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	shares = &propertiesv1.HostShares{}
	if valid.IsNil(instance) {
		return shares, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SharesV1, func(clonable data.Clonable) fail.Error {
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

// GetMounts returns the information abouts the mounts of the Host
func (instance *Host) GetMounts(ctx context.Context) (mounts *propertiesv1.HostMounts, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	mounts = nil
	if valid.IsNil(instance) {
		return mounts, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	return instance.unsafeGetMounts(ctx)
}

// IsClusterMember returns true if the Host is member of a cluster
func (instance *Host) IsClusterMember(ctx context.Context) (yes bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	yes = false
	if valid.IsNil(instance) {
		return yes, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.ClusterMembershipV1, func(clonable data.Clonable) fail.Error {
			hostClusterMembershipV1, ok := clonable.(*propertiesv1.HostClusterMembership)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv1.HostClusterMembership' expected, '%s' provided",
					reflect.TypeOf(clonable).String(),
				)
			}

			yes = hostClusterMembershipV1.Cluster != ""
			return nil
		})
	})
	return yes, xerr
}

// IsGateway tells if the Host acts as a gateway for a Subnet
func (instance *Host) IsGateway(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	var state bool
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			state = hnV2.IsGateway
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	return state, nil
}

// IsSingle tells if the Host is single
func (instance *Host) IsSingle(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	var state bool
	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.NetworkV2, func(clonable data.Clonable) fail.Error {
			hnV2, ok := clonable.(*propertiesv2.HostNetworking)
			if !ok {
				return fail.InconsistentError("'*propertiesv2.HostNetworking' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}
			state = hnV2.Single
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return false, xerr
	}

	return state, nil
}

// PushStringToFileWithOwnership creates a file 'filename' on remote 'Host' with the content 'content', and apply ownership
func (instance *Host) PushStringToFileWithOwnership(
	ctx context.Context, content string, filename string, owner, mode string,
) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if content == "" {
		return fail.InvalidParameterError("content", "cannot be empty string")
	}
	if filename == "" {
		return fail.InvalidParameterError("filename", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(content, filename='%s', ownner=%s, mode=%s", filename, owner, mode).WithStopwatch().Entering()
	defer tracer.Exiting()

	// instance.RLock()
	// defer instance.RUnlock()

	return instance.unsafePushStringToFileWithOwnership(ctx, content, filename, owner, mode)
}

// GetDefaultSubnet returns the Networking instance corresponding to Host default subnet
func (instance *Host) GetDefaultSubnet(ctx context.Context) (subnetInstance resources.Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	return instance.unsafeGetDefaultSubnet(ctx)
}

// ToProtocol convert a resources.Host to protocol.Host
func (instance *Host) ToProtocol(ctx context.Context) (ph *protocol.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var (
		ahc           *abstract.HostCore
		hostSizingV2  *propertiesv2.HostSizing
		hostVolumesV1 *propertiesv1.HostVolumes
		hostLabelsV1  *propertiesv1.HostLabels
	)

	publicIP, _ := instance.GetPublicIP(ctx)   // There may be no public ip, but the returned value is pertinent in this case, no need to handle error
	privateIP, _ := instance.GetPrivateIP(ctx) // Idem

	xerr := instance.Inspect(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		var ok bool
		ahc, ok = clonable.(*abstract.HostCore)
		if !ok {
			return fail.InconsistentError("'*abstract.HostCore' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		innerXErr := props.Inspect(hostproperty.SizingV2, func(clonable data.Clonable) fail.Error {
			hostSizingV2, ok = clonable.(*propertiesv2.HostSizing)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String)
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(hostproperty.LabelsV1, func(clonable data.Clonable) fail.Error {
			hostLabelsV1, ok = clonable.(*propertiesv1.HostLabels)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSizing' expected, '%s' provided", reflect.TypeOf(clonable).String)
			}

			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(hostproperty.VolumesV1, func(clonable data.Clonable) fail.Error {
			hostVolumesV1, ok = clonable.(*propertiesv1.HostVolumes)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostVolumes' expected, '%s' provided", reflect.TypeOf(clonable).String)
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	volumes := make([]string, 0, len(hostVolumesV1.VolumesByName))
	for k := range hostVolumesV1.VolumesByName {
		volumes = append(volumes, k)
	}

	labels := make([]*protocol.HostLabelResponse, 0, len(hostLabelsV1.ByID))
	svc := instance.Service()
	for k, v := range hostLabelsV1.ByID {
		labelInstance, xerr := LoadLabel(ctx, svc, k)
		if xerr != nil {
			return nil, xerr
		}

		pbLabel, xerr := labelInstance.ToProtocol(ctx, false)
		if xerr != nil {
			return nil, xerr
		}

		item := &protocol.HostLabelResponse{
			Id:           pbLabel.Id,
			Name:         pbLabel.Name,
			HasDefault:   pbLabel.HasDefault,
			DefaultValue: pbLabel.DefaultValue,
			Value:        v,
		}
		labels = append(labels, item)
	}

	var kvlist []*protocol.KeyValue
	hostkvs, err := instance.shielded.UnWrap()
	if err != nil {
		return nil, fail.ConvertError(err)
	}
	casted, ok := hostkvs.(*abstract.HostCore)
	if !ok {
		return nil, fail.InconsistentError("hostkvs should be a HostCore")
	}
	for k, v := range casted.Tags {
		k, v := k, v
		kvlist = append(kvlist, &protocol.KeyValue{
			Key:   k,
			Value: v,
		})
	}

	ph = &protocol.Host{
		Cpu:                 int32(hostSizingV2.AllocatedSize.Cores),
		Disk:                int32(hostSizingV2.AllocatedSize.DiskSize),
		Id:                  ahc.ID,
		PublicIp:            publicIP,
		PrivateIp:           privateIP,
		Name:                ahc.Name,
		PrivateKey:          ahc.PrivateKey,
		Password:            ahc.Password,
		Ram:                 hostSizingV2.AllocatedSize.RAMSize,
		State:               protocol.HostState(ahc.LastState),
		StateLabel:          ahc.LastState.String(),
		CreationDate:        ahc.Tags["CreationDate"],
		AttachedVolumeNames: volumes,
		Template:            hostSizingV2.Template,
		Labels:              labels,
		Kvs:                 kvlist,
	}
	return ph, nil
}

// BindSecurityGroup binds a security group to the Host; if enabled is true, apply it immediately
func (instance *Host) BindSecurityGroup(ctx context.Context, sgInstance resources.SecurityGroup, enable resources.SecurityGroupActivation) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgInstance == nil {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(sgInstance='%s', enable=%v", sgInstance.GetName(), enable).WithStopwatch().Entering()
	defer tracer.Exiting()

	// instance.Lock()
	// defer instance.Unlock()

	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID, err := sgInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			// If the Security Group is already bound to the Host with the exact same state, considered as a success
			item, ok := hsgV1.ByID[sgID]
			if ok && item.Disabled == !bool(enable) {
				return nil
			}

			if !ok { // Not found, update bind metadata of Host
				item = &propertiesv1.SecurityGroupBond{
					ID:   sgID,
					Name: sgInstance.GetName(),
				}
				hsgV1.ByID[sgID] = item
				hsgV1.ByName[item.Name] = item.ID
			}
			item.Disabled = bool(!enable)

			// If enabled, apply it
			sgInstanceImpl, ok := sgInstance.(*SecurityGroup)
			if !ok {
				return fail.InconsistentError("failed to cast sgInstance to '*SecurityGroup")
			}

			innerXErr := sgInstanceImpl.unsafeBindToHost(ctx, instance, enable, resources.MarkSecurityGroupAsSupplemental)
			if innerXErr != nil {
				switch innerXErr.(type) {
				case *fail.ErrDuplicate:
					// already bound, consider as a success
					break
				default:
					return innerXErr
				}
			}
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	return nil
}

// UnbindSecurityGroup unbinds a security group from the Host
func (instance *Host) UnbindSecurityGroup(ctx context.Context, sgInstance resources.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgInstance == nil {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	sgName := sgInstance.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(sgInstance='%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()

	// instance.Lock()
	// defer instance.Unlock()

	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			sgID, err := sgInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			// Check if the security group is listed for the Host
			found := false
			for k, v := range hsgV1.ByID {
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

			// unbind security group from Host on remote service side
			innerXErr := sgInstance.UnbindFromHost(ctx, instance)
			if innerXErr != nil {
				return innerXErr
			}

			// found, delete it from properties
			delete(hsgV1.ByID, sgID)
			delete(hsgV1.ByName, sgInstance.GetName())
			return nil
		})
	})
	if xerr != nil {
		return xerr
	}

	// -- Remove Host referenced in Security Group
	return sgInstance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(securitygroupproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			sghV1, ok := clonable.(*propertiesv1.SecurityGroupHosts)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.SecurityGroupHosts' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			hid, err := instance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			delete(sghV1.ByID, hid)
			delete(sghV1.ByName, instance.GetName())
			return nil
		})
	})
}

// ListSecurityGroups returns a slice of security groups bound to Host
func (instance *Host) ListSecurityGroups(ctx context.Context, state securitygroupstate.Enum) (list []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	// instance.RLock()
	// defer instance.RUnlock()

	xerr := instance.Inspect(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			list = FilterBondsByKind(hsgV1.ByID, state)
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return list, nil
}

// EnableSecurityGroup enables a bound security group to Host by applying its rules
func (instance *Host) EnableSecurityGroup(ctx context.Context, sg resources.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if sg == nil {
		return fail.InvalidParameterError("sg", "cannot be null value of 'SecurityGroup'")
	}

	hid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	sgName := sg.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(sg='%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()

	// instance.Lock()
	// defer instance.Unlock()

	svc := instance.Service()
	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			xerr := sg.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				if asg, ok = clonable.(*abstract.SecurityGroup); !ok {
					return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			// First check if the security group is not already registered for the Host with the exact same state
			var found bool
			for k := range hsgV1.ByID {
				if k == asg.ID {
					found = true
					break
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not bound to Host '%s'", sgName, hid)
			}

			{
				// Bind the security group on provider side; if already bound (*fail.ErrDuplicate), considered as a success
				xerr = svc.BindSecurityGroupToHost(ctx, asg, hid)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrDuplicate:
						debug.IgnoreError2(ctx, xerr)
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
	if xerr != nil {
		return xerr
	}

	return nil
}

// DisableSecurityGroup disables a bound security group to Host
func (instance *Host) DisableSecurityGroup(ctx context.Context, sgInstance resources.SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if sgInstance == nil {
		return fail.InvalidParameterError("sgInstance", "cannot be nil")
	}

	sgName := sgInstance.GetName()
	sgID, err := sgInstance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	hid, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(sgInstance='%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()

	svc := instance.Service()
	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.SecurityGroupsV1, func(clonable data.Clonable) fail.Error {
			hsgV1, ok := clonable.(*propertiesv1.HostSecurityGroups)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostSecurityGroups' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var asg *abstract.SecurityGroup
			xerr := sgInstance.Inspect(ctx, func(clonable data.Clonable, _ *serialize.JSONProperties) fail.Error {
				var ok bool
				if asg, ok = clonable.(*abstract.SecurityGroup); !ok {
					return fail.InconsistentError("'*abstract.SecurityGroup' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}

				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			// First check if the security group is not already registered for the Host with the exact same state
			var found bool
			for k := range hsgV1.ByID {
				if k == asg.ID {
					found = true
					break
				}
			}
			if !found {
				return fail.NotFoundError("security group '%s' is not bound to Host '%s'", sgName, sgID)
			}

			{
				// Bind the security group on provider side; if security group not binded, considered as a success
				xerr = svc.UnbindSecurityGroupFromHost(ctx, asg, hid)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						debug.IgnoreError2(ctx, xerr)
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
	if xerr != nil {
		return xerr
	}

	return nil
}

// ReserveCIDRForSingleHost returns the first available CIDR and its index inside the Network 'network'
func ReserveCIDRForSingleHost(ctx context.Context, networkInstance resources.Network) (_ string, _ uint, ferr fail.Error) {
	var index uint
	xerr := networkInstance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(networkproperty.SingleHostsV1, func(clonable data.Clonable) fail.Error {
			nshV1, ok := clonable.(*propertiesv1.NetworkSingleHosts)
			if !ok {
				return fail.InconsistentError(
					"'*propertiesv1.NetworkSingleHosts' expected, '%s' provided",
					reflect.TypeOf(clonable).String(),
				)
			}

			index = nshV1.ReserveSlot()
			return nil
		})
	})
	if xerr != nil {
		return "", 0, xerr
	}

	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := FreeCIDRForSingleHost(cleanupContextFrom(ctx), networkInstance, index)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to free CIDR slot '%d' in Network '%s'", index, networkInstance.GetName()))
			}
		}
	}()

	_, networkNet, err := net.ParseCIDR(abstract.SingleHostNetworkCIDR)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", 0, fail.Wrap(err, "failed to convert CIDR to net.IPNet")
	}

	result, xerr := netretry.NthIncludedSubnet(*networkNet, propertiesv1.SingleHostsCIDRMaskAddition, index)
	if xerr != nil {
		return "", 0, xerr
	}
	return result.String(), index, nil
}

func getCommand(ctx context.Context, file string) string {
	theType, _ := getDefaultConnectorType()
	switch theType {
	case "cli":
		command := fmt.Sprintf("sudo bash %s; exit $?", file)
		logrus.WithContext(ctx).Debugf("running '%s'", command)
		return command
	default:
		// "sudo -b bash -c 'nohup %s > /dev/null 2>&1 &'"
		command := fmt.Sprintf("sudo -b bash -c 'nohup %s > /dev/null 2>&1 &'", file)
		logrus.WithContext(ctx).Debugf("running '%s'", command)
		return command
	}
}

func getPhase2Timeout(timings temporal.Timings) time.Duration {
	theType, _ := getDefaultConnectorType()
	switch theType {
	case "cli":
		return timings.HostCreationTimeout()
	default:
		return timings.ContextTimeout()
	}
}

func getPhase4Timeout(timings temporal.Timings) time.Duration {
	theType, _ := getDefaultConnectorType()
	switch theType {
	case "cli":
		waitingTime := temporal.MaxTimeout(24*timings.RebootTimeout()/10, timings.HostCreationTimeout())
		return waitingTime
	default:
		return 30 * time.Second
	}
}

func inBackground() bool {
	theType, _ := getDefaultConnectorType()
	switch theType {
	case "cli":
		return false
	default:
		return true
	}
}

// ListLabels lists Labels bound to Host
func (instance *Host) ListLabels(ctx context.Context) (_ map[string]string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()

	var labelsV1 *propertiesv1.HostLabels
	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.LabelsV1, func(clonable data.Clonable) fail.Error {
			var ok bool
			labelsV1, ok = clonable.(*propertiesv1.HostLabels)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostTags' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return labelsV1.ByID, nil
}

// BindLabel binds a Label to Host
func (instance *Host) BindLabel(ctx context.Context, labelInstance resources.Label, value string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if labelInstance == nil {
		return fail.InvalidParameterCannotBeNilError("label")
	}

	labelName := labelInstance.GetName()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "('%s')", labelName).WithStopwatch().Entering()
	defer tracer.Exiting()

	labelID, err := labelInstance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	instanceID, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	// Inform Label we want it bound to Host (updates its metadata)
	xerr := labelInstance.BindToHost(ctx, instance, value)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	defer func() {
		ferr = debug.InjectPlannedFail(ferr)
		if ferr != nil {
			derr := labelInstance.UnbindFromHost(cleanupContextFrom(ctx), instance)
			if derr != nil {
				_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure"))
			}
		}
	}()

	if value == "" {
		value, xerr = labelInstance.DefaultValue(ctx)
		if xerr != nil {
			return xerr
		}
	}

	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.LabelsV1, func(clonable data.Clonable) fail.Error {
			hostLabelsV1, ok := clonable.(*propertiesv1.HostLabels)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostLabels' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// If the host already has this tag, consider it a success
			_, ok = hostLabelsV1.ByID[labelID]
			if !ok {
				hostLabelsV1.ByID[labelID] = value
				hostLabelsV1.ByName[labelName] = value
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	lmap, err := labelToMap(labelInstance, value)
	if err != nil {
		return fail.ConvertError(err)
	}

	svc := instance.Service()
	xerr = svc.UpdateTags(ctx, abstract.HostResource, instanceID, lmap)
	if xerr != nil {
		return xerr
	}

	return nil
}

func labelToMap(labelInstance resources.Label, value string) (map[string]string, error) {
	sad := make(map[string]string)
	k := labelInstance.GetName()
	sad[k] = value

	return sad, nil
}

// UnbindLabel removes a Label from Host
func (instance *Host) UnbindLabel(ctx context.Context, labelInstance resources.Label) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if labelInstance == nil {
		return fail.InvalidParameterCannotBeNilError("labelInstance")
	}

	labelName := labelInstance.GetName()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "('%s')", labelName).WithStopwatch().Entering()
	defer tracer.Exiting()

	instanceID, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	xerr := instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.LabelsV1, func(clonable data.Clonable) fail.Error {
			hostLabelsV1, ok := clonable.(*propertiesv1.HostLabels)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostLabels' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			labelID, err := labelInstance.GetID()
			if err != nil {
				return fail.ConvertError(err)
			}

			// If the host is not bound to this Label, consider it a success
			if _, ok = hostLabelsV1.ByID[labelID]; ok {
				delete(hostLabelsV1.ByID, labelID)
				delete(hostLabelsV1.ByName, labelInstance.GetName())
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = labelInstance.UnbindFromHost(ctx, instance)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	svc := instance.Service()
	xerr = svc.DeleteTags(ctx, abstract.HostResource, instanceID, []string{labelInstance.GetName()})
	if xerr != nil {
		return xerr
	}

	return nil
}

// ResetLabel resets the value of Label bound with Host to default value of Label
func (instance *Host) ResetLabel(ctx context.Context, labelInstance resources.Label) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if labelInstance == nil {
		return fail.InvalidParameterCannotBeNilError("tag")
	}

	defaultValue, xerr := labelInstance.DefaultValue(ctx)
	if xerr != nil {
		return xerr
	}

	return instance.UpdateLabel(ctx, labelInstance, defaultValue)
}

// UpdateLabel resets the value of the Label bound to Host to default value of Label
func (instance *Host) UpdateLabel(ctx context.Context, labelInstance resources.Label, value string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if labelInstance == nil {
		return fail.InvalidParameterCannotBeNilError("labelInstance")
	}

	labelName := labelInstance.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "('%s')", labelName).WithStopwatch().Entering()
	defer tracer.Exiting()

	var alabel *abstract.Label
	hostID, err := instance.GetID()
	if err != nil {
		return fail.ConvertError(err)
	}

	hostName := instance.GetName()
	xerr := labelInstance.Alter(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		var ok bool
		alabel, ok = clonable.(*abstract.Label)
		if !ok {
			return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
		}

		return props.Alter(labelproperty.HostsV1, func(clonable data.Clonable) fail.Error {
			labelHostsV1, ok := clonable.(*propertiesv1.LabelHosts)
			if !ok {
				return fail.InconsistentError("'*abstract.Label' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// If the tag does not have this host, consider it a success
			if _, ok = labelHostsV1.ByID[hostID]; !ok {
				return fail.NotFoundError("failed to find bind of Host %s with Label %s", alabel.Name, hostName)
			}

			labelHostsV1.ByID[hostID] = value
			labelHostsV1.ByName[hostName] = value
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Alter(ctx, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.LabelsV1, func(clonable data.Clonable) fail.Error {
			hostLabelsV1, ok := clonable.(*propertiesv1.HostLabels)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostLabels' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			// If the host is not bound to this Label, consider it a success
			if _, ok = hostLabelsV1.ByID[alabel.ID]; !ok {
				return fail.NotFoundError("failed to find bind of Label %s with Host %s", hostName, alabel.Name)
			}

			hostLabelsV1.ByID[alabel.ID] = value
			hostLabelsV1.ByName[alabel.Name] = value
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}
