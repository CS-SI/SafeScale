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

package resources

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/user"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/eko/gocache/v2/store"
	"github.com/sirupsen/logrus"

	jobapi "github.com/CS-SI/SafeScale/v22/lib/backend/common/job/api"
	iaasapi "github.com/CS-SI/SafeScale/v22/lib/backend/iaas/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/objectstorage"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/providers"
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas/userdata"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/consts"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/converters"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/ipversion"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/labelproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/securitygroupstate"
	sshfactory "github.com/CS-SI/SafeScale/v22/lib/backend/resources/factories/ssh"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/metadata"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	propertiesv2 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v2"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/system/ssh"
	sshapi "github.com/CS-SI/SafeScale/v22/lib/system/ssh/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/result"
	"github.com/CS-SI/SafeScale/v22/lib/utils/retry"
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
type (
	Host struct {
		*metadata.Core[*abstract.HostCore]

		localCache struct {
			sync.RWMutex
			installMethods                sync.Map
			privateIP, publicIP, accessIP string
			sshProfile                    sshapi.Connector
			sshCfg                        sshapi.Config
			once                          bool
		}
	}
)

// NewHost ...
func NewHost(ctx context.Context) (_ *Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	coreInstance, xerr := metadata.NewCore(ctx, metadata.MethodObjectStorage, hostKind, hostsFolderName, abstract.NewEmptyHostCore())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	instance := &Host{
		Core: coreInstance,
	}
	return instance, nil
}

// LoadHost ...
func LoadHost(inctx context.Context, ref string) (*Host, fail.Error) {
	if ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}
	myjob, xerr := jobapi.FromContext(inctx)
	if xerr != nil {
		return nil, xerr
	}
	if valid.IsNull(myjob) {
		return nil, fail.InvalidParameterError("inctx", "missing valid Job")
	}
	if ref == "" {
		return nil, fail.InvalidParameterCannotBeEmptyStringError("ref")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	chRes := make(chan result.Holder[*Host])
	go func() {
		defer close(chRes)
		ga, gerr := func() (_ *Host, ferr fail.Error) {
			defer fail.OnPanic(&ferr)

			// trick to avoid collisions
			var kt *Host
			refcache := fmt.Sprintf("%T/%s", kt, ref)

			cache, xerr := myjob.Service().Cache(ctx)
			if xerr != nil {
				return nil, xerr
			}

			var (
				hostInstance *Host
				inCache      bool
				err          error
			)
			if cache != nil {
				entry, err := cache.Get(ctx, refcache)
				if err == nil {
					hostInstance, err = lang.Cast[*Host](entry)
					if err != nil {
						return nil, fail.Wrap(err)
					}

					inCache = true
					incrementExpVar("newhost.cache.hit")

					// -- reload from metadata storage
					xerr = hostInstance.Core.Reload(ctx)
					if xerr != nil {
						return nil, xerr
					}
				} else {
					logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
				}
			}
			if hostInstance == nil {
				anon, xerr := onHostCacheMiss(ctx, ref)
				if xerr != nil {
					return nil, xerr
				}

				hostInstance, err = lang.Cast[*Host](anon)
				if err != nil {
					return nil, fail.Wrap(err)
				}
			}

			if cache != nil {
				if !inCache {
					// -- add host instance in cache by name
					err := cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hostInstance.GetName()), hostInstance, &store.Options{Expiration: 1 * time.Minute})
					if err != nil {
						return nil, fail.Wrap(err)
					}

					time.Sleep(10 * time.Millisecond) // consolidate cache.Set
					hid, err := hostInstance.GetID()
					if err != nil {
						return nil, fail.Wrap(err)
					}

					// -- add host instance in cache by id
					err = cache.Set(ctx, fmt.Sprintf("%T/%s", kt, hid), hostInstance, &store.Options{Expiration: 1 * time.Minute})
					if err != nil {
						return nil, fail.Wrap(err)
					}

					time.Sleep(10 * time.Millisecond) // consolidate cache.Set

					val, xerr := cache.Get(ctx, refcache)
					if xerr == nil {
						if _, ok := val.(*Host); ok {
							incrementExpVar("newhost.cache.hit")
						} else {
							logrus.WithContext(ctx).Warnf("wrong type of *Host")
						}
					} else {
						logrus.WithContext(ctx).Warnf("cache response: %v", xerr)
					}
				}
			}

			hostTrx, innerErr := newHostTransaction(ctx, hostInstance)
			if innerErr != nil {
				return nil, innerErr
			}
			defer hostTrx.TerminateFromError(ctx, &ferr)

			xerr = hostInstance.updateCachedInformation(ctx, hostTrx)
			if xerr != nil {
				return nil, xerr
			}

			return hostInstance, nil
		}()
		res, _ := result.NewHolder[*Host](
			result.WithPayload(ga),
			result.TagSuccessFromCondition[*Host](ga != nil),
			result.TagCompletedFromError[*Host](gerr),
		)
		chRes <- res
	}()

	select {
	case res := <-chRes:
		p, err := res.Payload()
		if err != nil {
			return nil, fail.Wrap(err)
		}

		return p, fail.Wrap(res.Error())
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return nil, fail.Wrap(inctx.Err())
	}
}

// onHostCacheMiss is called when host 'ref' is not found in cache
func onHostCacheMiss(inctx context.Context, ref string) (_ data.Identifiable, ferr fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	defer fail.OnPanic(&ferr)

	hostInstance, xerr := NewHost(ctx)
	if xerr != nil {
		return nil, xerr
	}

	blank, xerr := NewHost(ctx)
	if xerr != nil {
		return nil, xerr
	}

	xerr = hostInstance.Read(ctx, ref)
	if xerr != nil {
		return nil, xerr
	}

	incrementExpVar("host.load.hits")
	incrementExpVar("newhost.cache.read")

	if strings.Compare(fail.IgnoreError(hostInstance.String()).(string), fail.IgnoreError(blank.String()).(string)) == 0 {
		return nil, fail.NotFoundError("fail to find Host with ref '%s'", ref)
	}

	return hostInstance, nil
}

// Exists checks if the resource actually exists in provider side (not in stow metadata)
func (instance *Host) Exists(ctx context.Context) (bool, fail.Error) {
	theID, err := instance.GetID()
	if err != nil {
		return false, fail.Wrap(err)
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
func (instance *Host) updateCachedInformation(ctx context.Context, hostTrx hostTransaction) fail.Error {
	svc := instance.Service()
	scope := instance.Job().Scope()

	opUser, opUserErr := getOperatorUsernameFromCfg(ctx, svc)
	if opUserErr != nil {
		return opUserErr
	}

	instance.localCache.Lock()
	defer instance.localCache.Unlock()

	return inspectHostMetadata(ctx, hostTrx, func(ahc *abstract.HostCore, props *serialize.JSONProperties) fail.Error {
		var primaryGatewayConfig, secondaryGatewayConfig sshapi.Config
		innerXErr := props.Inspect(hostproperty.NetworkV2, func(p clonable.Clonable) (ferr fail.Error) {
			hnV2, innerErr := lang.Cast[*propertiesv2.HostNetworking](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			if len(hnV2.IPv4Addresses) > 0 {
				instance.localCache.privateIP = hnV2.IPv4Addresses[hnV2.DefaultSubnetID]
				if instance.localCache.privateIP == "" {
					instance.localCache.privateIP = hnV2.IPv6Addresses[hnV2.DefaultSubnetID]
				}
			}
			instance.localCache.publicIP = hnV2.PublicIPv4
			if instance.localCache.publicIP == "" {
				instance.localCache.publicIP = hnV2.PublicIPv6
			}

			// FIXME: find a better way to handle the use case (adjust SG? something else?)
			// Workaround for a specific use: safescaled inside a cluster, to force access to host using internal IP
			fromInside := os.Getenv("SAFESCALED_FROM_INSIDE")
			if instance.localCache.publicIP == "" || fromInside == "true" {
				instance.localCache.accessIP = instance.localCache.privateIP
			} else {
				instance.localCache.accessIP = instance.localCache.publicIP
			}

			// Do not execute if Host is single or is a gateway
			if !hnV2.Single && !hnV2.IsGateway && hnV2.DefaultSubnetID != "" {
				subnetInstance, xerr := LoadSubnet(ctx, "", hnV2.DefaultSubnetID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				subnetTrx, xerr := newSubnetTransaction(ctx, subnetInstance)
				if xerr != nil {
					return xerr
				}
				defer subnetTrx.TerminateFromError(ctx, &ferr)

				gwInstance, xerr := subnetInstance.inspectGateway(ctx, subnetTrx, true)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}

				ip, xerr := gwInstance.GetAccessIP(ctx)
				if xerr != nil {
					return xerr
				}

				gwTrx, xerr := newHostTransaction(ctx, gwInstance)
				if xerr != nil {
					return xerr
				}
				defer gwTrx.TerminateFromError(ctx, &ferr)

				gwErr := inspectHostMetadataAbstract(ctx, gwTrx, func(gwahc *abstract.HostCore) fail.Error {
					primaryGatewayConfig = ssh.NewConfig(gwahc.Name, ip, int(gwahc.SSHPort), opUser, gwahc.PrivateKey, 0, "", nil, nil)
					return nil
				})
				if gwErr != nil {
					return gwErr
				}

				// Secondary gateway may not exist...
				gwInstance, xerr = subnetInstance.inspectGateway(ctx, subnetTrx, false)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					switch xerr.(type) {
					case *fail.ErrNotFound:
						// continue
						debug.IgnoreErrorWithContext(ctx, xerr)
					default:
						return xerr
					}
				} else {
					ip, inXErr := gwInstance.GetAccessIP(ctx)
					if inXErr != nil {
						return inXErr
					}

					gwTrx, xerr := newHostTransaction(ctx, gwInstance)
					if xerr != nil {
						return xerr
					}
					defer gwTrx.TerminateFromError(ctx, &ferr)

					gwErr = inspectHostMetadataAbstract(ctx, gwTrx, func(ahc *abstract.HostCore) fail.Error {
						secondaryGatewayConfig = ssh.NewConfig(gwInstance.GetName(), ip, int(ahc.SSHPort), opUser, ahc.PrivateKey, 0, "", nil, nil)
						return nil
					})
					if gwErr != nil {
						return gwErr
					}
				}
			}

			if svc.Capabilities().UseTerraformer {
				cfg, propXErr := svc.ConfigurationOptions()
				if propXErr != nil {
					return propXErr
				}

				// -- updates terraformer extra subnet in abstract
				subnetList := make([]*abstract.Subnet, 0, len(hnV2.SubnetsByName))
				for k := range hnV2.SubnetsByName {
					if cfg.ProviderNetwork == k {
						// Provider's default network is not listed as not managed by SafeScale...
						continue
					}

					entry, propXErr := scope.AbstractByName(abstract.SubnetKind, k)
					if propXErr != nil {
						switch propXErr.(type) {
						case *fail.ErrNotFound:
							logrus.WithContext(ctx).Errorf("inconsistency detected in metadata: Host '%s' is bound to Subnet '%s', which is not registered in Scope", ahc.Name, k)
							continue
						default:
							return propXErr
						}
					}

					// casted, inspectErr := lang.Cast[*abstract.Subnet](entry)
					// if inspectErr != nil {
					// 	return fail.Wrap(inspectErr)
					// }

					cloned, inspectErr := clonable.CastedClone[*abstract.Subnet](entry /*casted*/)
					if inspectErr != nil {
						return fail.Wrap(inspectErr)
					}

					subnetList = append(subnetList, cloned)
				}
				innerXErr := ahc.AddOptions(
					abstract.WithExtraData("Subnets", subnetList),
					abstract.WithExtraData("PublicIP", hnV2.IsGateway),
				)
				if innerXErr != nil {
					return innerXErr
				}
			}
			return nil
		})

		cfg := ssh.NewConfig(instance.GetName(), instance.localCache.accessIP, int(ahc.SSHPort), opUser, ahc.PrivateKey, 0, "", primaryGatewayConfig, secondaryGatewayConfig)
		conn, innerXErr := sshfactory.NewConnector(cfg)
		if innerXErr != nil {
			return innerXErr
		}

		instance.localCache.sshCfg = cfg
		instance.localCache.sshProfile = conn

		// -- updates available install methods
		var index uint8
		innerXErr = props.Inspect(hostproperty.SystemV1, func(p clonable.Clonable) fail.Error {
			systemV1, innerErr := lang.Cast[*propertiesv1.HostSystem](p)
			if innerErr != nil {
				logrus.WithContext(ctx).Error(fail.Wrap(innerErr))
			}
			if systemV1.Type == "linux" {
				switch systemV1.Flavor {
				case "centos", "redhat":
					index++
					instance.localCache.installMethods.Store(index, installmethod.Yum)
				case "debian":
					fallthrough
				case "ubuntu":
					index++
					instance.localCache.installMethods.Store(index, installmethod.Apt)
				case "fedora", "rhel":
					index++
					instance.localCache.installMethods.Store(index, installmethod.Dnf)
				}
			}
			return nil
		})
		if innerXErr != nil {
			return innerXErr
		}

		index++
		instance.localCache.installMethods.Store(index, installmethod.Bash)
		index++
		instance.localCache.installMethods.Store(index, installmethod.None)

		// -- updates terraformer extra data in abstract
		if svc.Capabilities().UseTerraformer {
			{
				prov, xerr := svc.ProviderDriver()
				if xerr != nil {
					return innerXErr
				}
				castedProv, innerErr := lang.Cast[providers.ReservedForTerraformerUse](prov)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				innerXErr := castedProv.ConsolidateHostSnippet(ahc)
				if innerXErr != nil {
					return innerXErr
				}
			}

			var sgs map[string]string
			innerXErr = props.Inspect(hostproperty.SecurityGroupsV1, func(p clonable.Clonable) fail.Error {
				sgsV1, innerErr := lang.Cast[*propertiesv1.HostSecurityGroups](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				sgs = make(map[string]string, len(sgsV1.ByName))
				for k, v := range sgsV1.ByName {
					sgs[v] = k
				}
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			var (
				template, diskSize string
			)
			innerXErr = props.Inspect(hostproperty.SizingV2, func(p clonable.Clonable) fail.Error {
				hsV2, innerErr := lang.Cast[*propertiesv2.HostSizing](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				template = hsV2.Template
				diskSize = strconv.Itoa(hsV2.AllocatedSize.DiskSize)
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			var image string
			innerXErr = props.Inspect(hostproperty.SystemV1, func(p clonable.Clonable) fail.Error {
				systemV1, innerErr := lang.Cast[*propertiesv1.HostSystem](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				image = systemV1.Image
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			var az string
			innerXErr = props.Inspect(hostproperty.DescriptionV1, func(p clonable.Clonable) fail.Error {
				descV1, innerErr := lang.Cast[*propertiesv1.HostDescription](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				az = descV1.AZ
				return nil
			})
			if innerXErr != nil {
				return innerXErr
			}

			innerXErr = ahc.AddOptions(
				abstract.WithExtraData("SecurityGroupByID", sgs),
				abstract.WithExtraData("Image", image),
				abstract.WithExtraData("Template", template),
				abstract.WithExtraData("DiskSize", diskSize),
				abstract.WithExtraData("AvailabilityZone", az),
			)
			if innerXErr != nil {
				return innerXErr
			}

			// -- register abstract in Scope if needed
			_, innerXErr = instance.Job().Scope().RegisterAbstractIfNeeded(ahc)
			return innerXErr
		}

		return nil
	})
}

func getOperatorUsernameFromCfg(ctx context.Context, svc iaasapi.Service) (string, fail.Error) {
	cfg, xerr := svc.ConfigurationOptions()
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return "", xerr
	}

	userName := cfg.OperatorUsername
	if userName == "" {
		logrus.WithContext(ctx).Warnf("OperatorUsername is empty, check your tenants.toml file. Using 'safescale' user instead.")
		userName = abstract.DefaultUser
	}

	return userName, nil
}

// IsNull ...
func (instance *Host) IsNull() bool {
	return instance == nil || valid.IsNil(instance.Core)
}

func (instance *Host) Clone() (clonable.Clonable, error) {
	if instance == nil {
		return nil, fail.InvalidInstanceError()
	}

	newInstance, err := newBulkHost()
	if err != nil {
		return nil, err
	}

	return newInstance, newInstance.Replace(instance)
}

// newBulkHost ...
func newBulkHost() (*Host, fail.Error) {
	protected, err := abstract.NewHostCore()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	core, err := metadata.NewEmptyCore(abstract.HostKind, protected)
	if err != nil {
		return nil, fail.Wrap(err)
	}

	instance := &Host{Core: core}
	return instance, nil
}

func (instance *Host) Replace(in clonable.Clonable) error {
	if instance == nil {
		return fail.InvalidInstanceError()
	}

	src, err := lang.Cast[*Host](in)
	if err != nil {
		return err
	}

	err = instance.Core.Replace(src.Core)
	if err != nil {
		return err
	}

	instance.localCache.installMethods = sync.Map{}
	src.localCache.installMethods.Range(func(key any, value any) bool {
		instance.localCache.installMethods.Store(key, value)
		return true
	})
	instance.localCache.publicIP = src.localCache.publicIP
	instance.localCache.privateIP = src.localCache.privateIP
	instance.localCache.sshCfg = src.localCache.sshCfg
	instance.localCache.sshProfile = src.localCache.sshProfile
	instance.localCache.accessIP = src.localCache.accessIP
	instance.localCache.once = src.localCache.once

	return nil
}

// Carry ...
func (instance *Host) Carry(ctx context.Context, ahc *abstract.HostCore) (ferr fail.Error) {
	if instance == nil {
		return fail.InvalidInstanceError()
	}
	if !valid.IsNil(instance) && instance.IsTaken() {
		return fail.InvalidInstanceContentError("instance", "is not null value, cannot overwrite")
	}
	if ahc == nil {
		return fail.InvalidParameterCannotBeNilError("ahf")
	}

	// Note: do not validate parameters, this call will do it
	xerr := instance.Core.Carry(ctx, ahc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Job().Scope().RegisterAbstract(ahc)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	return nil
}

// Browse walks through Host Metadata Folder and executes a callback for each entry
func (instance *Host) Browse(ctx context.Context, callback func(*abstract.HostCore) fail.Error) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	// Note: Do not test with Isnull here, as Browse may be used from null value
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

	return instance.BrowseFolder(ctx, func(buf []byte) (innerXErr fail.Error) {
		ahc, _ := abstract.NewHostCore()
		innerXErr = ahc.Deserialize(buf)
		if innerXErr != nil {
			return innerXErr
		}

		return callback(ahc)
	})
}

// ForceGetState returns the current state of the provider Host then alter metadata
func (instance *Host) ForceGetState(ctx context.Context) (state hoststate.Enum, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	state = hoststate.Unknown
	if valid.IsNil(instance) {
		return state, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return state, fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return state, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return hostTrx.ForceGetState(ctx)
}

// Reload reloads Host from metadata and current Host state on provider state
func (instance *Host) Reload(ctx context.Context) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}

	trx, err := newHostTransaction(ctx, instance)
	if err != nil {
		return fail.Wrap(err)
	}
	defer trx.TerminateFromError(ctx, &ferr)

	return instance.reload(ctx, trx)
}

// GetState returns the last known state of the Host, without forced inspect
func (instance *Host) GetState(ctx context.Context) (_ hoststate.Enum, ferr fail.Error) {
	state := hoststate.Unknown
	if valid.IsNil(instance) {
		return state, fail.InvalidInstanceError()
	}

	trx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return state, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	xerr = inspectHostMetadataAbstract(ctx, trx, func(ahc *abstract.HostCore) fail.Error {
		state = ahc.LastState
		return nil
	})
	if xerr != nil {
		return hoststate.Unknown, xerr
	}

	return state, nil
}

// Review returns a view of the Host, without forced inspect
func (instance *Host) Review(ctx context.Context) (_ *abstract.HostCore, _ *serialize.JSONProperties, ferr fail.Error) {
	if valid.IsNil(instance) {
		return nil, nil, fail.InvalidInstanceError()
	}

	trx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, nil, xerr
	}
	defer trx.TerminateFromError(ctx, &ferr)

	var (
		propsClone *serialize.JSONProperties
		state      *abstract.HostCore
	)
	xerr = inspectHostMetadata(ctx, trx, func(ahc *abstract.HostCore, props *serialize.JSONProperties) fail.Error {
		// Note: ahc is a clone so no need to clone here
		state = ahc

		var innerErr error
		// FIXME: check if props is not already a clone...
		propsClone, innerErr = clonable.CastedClone[*serialize.JSONProperties](props)
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		return nil
	})
	if xerr != nil {
		return nil, nil, xerr
	}

	netInfo, xerr := propertiesv2.NewHostNetworkingFromProperty(propsClone)
	if xerr != nil {
		return nil, nil, xerr
	}

	logrus.WithContext(ctx).Debugf("%s", spew.Sdump(netInfo))
	return state, propsClone, nil
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
	if !valid.IsNil(instance.Core) && instance.IsTaken() {
		return nil, fail.InconsistentError("already carrying information")
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type localresult struct {
		ct  *userdata.Content
		err fail.Error
	}

	chRes := make(chan localresult)
	go func() {
		defer close(chRes)

		ud, gerr := func() (_ *userdata.Content, ferr fail.Error) {
			defer fail.OnPanic(&ferr)
			svc := instance.Service()

			// Check if Host exists and is managed bySafeScale
			_, xerr := LoadHost(ctx, hostReq.ResourceName)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					return nil, fail.Wrap(xerr, "failed to check if Host '%s' already exists", hostReq.ResourceName)
				}
			} else {
				return nil, fail.DuplicateError("'%s' already exists", hostReq.ResourceName)
			}

			// Check if Host exists but is not managed by SafeScale
			ahc, xerr := abstract.NewHostCore(abstract.WithName(hostReq.ResourceName))
			if xerr != nil {
				return nil, xerr
			}

			_, xerr = svc.InspectHost(ctx, ahc)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrNotFound:
					// continue
					debug.IgnoreErrorWithContext(ctx, xerr)
				default:
					return nil, fail.Wrap(xerr, "failed to check if Host resource name '%s' is already used", hostReq.ResourceName)
				}
			} else {
				return nil, fail.DuplicateError("found an existing Host named '%s' (but not managed by SafeScale)", hostReq.ResourceName)
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
					return nil, fail.NotFoundErrorWithCause(xerr, nil, "failed to find template to match requested sizing")
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
					return nil, xerr
				}
			}
			hostDef.Image = hostReq.ImageID

			// identify default Subnet
			var (
				defaultSubnet                  *Subnet
				undoCreateSingleHostNetworking func() fail.Error
			)
			if hostReq.Single {
				defaultSubnet, undoCreateSingleHostNetworking, xerr = createSingleHostNetworking(ctx, hostReq)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return nil, xerr
				}

				defer func() {
					ferr = debug.InjectPlannedFail(ferr)
					if ferr != nil && hostReq.CleanOnFailure() {
						derr := undoCreateSingleHostNetworking()
						if derr != nil {
							_ = ferr.AddConsequence(derr)
						}
					}
				}()

				defaultSubnetTrx, xerr := newSubnetTransaction(ctx, defaultSubnet)
				if xerr != nil {
					return nil, xerr
				}
				defer defaultSubnetTrx.TerminateFromError(ctx, &ferr)

				xerr = inspectSubnetMetadataAbstract(ctx, defaultSubnetTrx, func(as *abstract.Subnet) fail.Error {
					hostReq.Subnets = append(hostReq.Subnets, as)
					// hostReq.SecurityGroupByID = map[string]string{
					// 	as.PublicIPSecurityGroupID: as.PublicIPSecurityGroupName,
					// 	as.GWSecurityGroupID:       as.GWSecurityGroupName,
					// }
					hostReq.PublicIP = true
					return nil
				})
				if xerr != nil {
					return nil, xerr
				}
			} else {
				// By convention, default subnet is the first of the list
				as := hostReq.Subnets[0]
				if as == nil {
					return nil, fail.InvalidParameterError("hostReq.Subnet[0] cannot be nil")
				}

				defaultSubnet, xerr = LoadSubnet(ctx, "", as.ID)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return nil, xerr
				}

				defaultSubnetTrx, xerr := newSubnetTransaction(ctx, defaultSubnet)
				if xerr != nil {
					return nil, xerr
				}
				defer defaultSubnetTrx.TerminateFromError(ctx, &ferr)

				if !hostReq.IsGateway && hostReq.DefaultRouteIP == "" {
					hostReq.DefaultRouteIP, xerr = defaultSubnetTrx.GetDefaultRouteIP(ctx)
					if xerr != nil {
						return nil, xerr
					}
				}

				// // list IDs of Security Groups to apply to Host
				// if len(hostReq.SecurityGroupByID) == 0 {
				// 	hostReq.SecurityGroupByID = make(map[string]string, len(hostReq.Subnets)+1)
				// 	for _, v := range hostReq.Subnets {
				// 		hostReq.SecurityGroupByID[v.InternalSecurityGroupID] = v.InternalSecurityGroupName
				// 	}
				//
				// 	opts, xerr := svc.ConfigurationOptions()
				// 	xerr = debug.InjectPlannedFail(xerr)
				// 	if xerr != nil {
				// 		return nil, xerr
				// 	}
				//
				// 	if hostReq.PublicIP || opts.UseNATService {
				// 		xerr = inspectSubnetMetadataAbstract(ctx, defaultSubnetTrx, func(as *abstract.Subnet) fail.Error {
				// 			if as.PublicIPSecurityGroupID != "" {
				// 				hostReq.SecurityGroupByID[as.PublicIPSecurityGroupID] = as.PublicIPSecurityGroupName
				// 			}
				// 			return nil
				// 		})
				// 		xerr = debug.InjectPlannedFail(xerr)
				// 		if xerr != nil {
				// 			return nil, fail.Wrap(xerr, "failed to consult details of Subnet '%s'", defaultSubnet.GetName())
				// 		}
				// 	}
				// }
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil && hostReq.CleanOnFailure() && ahc != nil && ahc.IsConsistent() {
					derr := svc.DeleteHost(cleanupContextFrom(ctx), ahc)
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete Host '%s'", ActionFromError(ferr), ahc.Name))
					}
					ahc.LastState = hoststate.Deleted
				}
			}()

			// instruct Cloud Provider to create host
			defaultSubnetID, err := defaultSubnet.GetID()
			if err != nil {
				return nil, fail.Wrap(err)
			}

			defaultSubnetTrx, xerr := newSubnetTransaction(ctx, defaultSubnet)
			if xerr != nil {
				return nil, xerr
			}
			defer defaultSubnetTrx.TerminateFromError(ctx, &ferr)

			ahf, userdataContent, xerr := svc.CreateHost(ctx, hostReq, extra)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				switch xerr.(type) {
				case *fail.ErrInvalidRequest:
					return nil, xerr
				default:
					return nil, fail.Wrap(xerr, "failed to create Host '%s'", hostReq.ResourceName)
				}
			}

			defer func() {
				if ferr != nil && hostReq.CleanOnFailure() {
					derr := svc.DeleteHost(ctx, ahf)
					if derr != nil {
						logrus.WithContext(ctx).Errorf("cleaning up on %s, failed to Delete Host '%s': %v", ActionFromError(ferr), ahf.Name, derr)
						_ = ferr.AddConsequence(derr)
					}
				}
			}()

			// Make sure ssh port wanted is set
			if !userdataContent.IsGateway {
				if hostReq.SSHPort > 0 {
					ahf.SSHPort = hostReq.SSHPort
				} else {
					ahf.SSHPort = 22
				}
			} else {
				userdataContent.SSHPort = strconv.Itoa(int(hostReq.SSHPort))
				ahf.SSHPort = hostReq.SSHPort
			}

			// Creates metadata early to "reserve" Host name
			xerr = instance.Carry(ctx, ahf.HostCore)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// Starting from here, using metadata.Transaction
			hostTrx, xerr := newHostTransaction(ctx, instance)
			if xerr != nil {
				return nil, xerr
			}
			defer hostTrx.TerminateFromError(ctx, &ferr)

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					ctx := cleanupContextFrom(ctx)
					if ahf.IsConsistent() && ahf.LastState != hoststate.Deleted {
						logrus.WithContext(ctx).Warnf("Marking instance '%s' as FAILED", ahf.GetName())
						derr := alterHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
							ahc.LastState = hoststate.Failed
							ahc.ProvisioningState = hoststate.Failed
							return nil
						})
						if derr != nil {
							_ = ferr.AddConsequence(derr)
						} else {
							derr = hostTrx.Commit(ctx)
							if derr != nil {
								_ = ferr.AddConsequence(derr)
							} else {
								logrus.WithContext(ctx).Warnf("Instance now should be in FAILED state")
							}
						}
					}

					if hostReq.CleanOnFailure() {
						hostTrx.SilentTerminate(ctx)
						derr := instance.Core.Delete(ctx)
						if derr != nil {
							_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on %s, failed to Delete metadata of Host '%s'", ActionFromError(derr), hostReq.ResourceName))
						}
					}
				}
			}()

			xerr = alterHostMetadataProperties(ctx, hostTrx, func(props *serialize.JSONProperties) fail.Error {
				innerXErr := props.Alter(hostproperty.SizingV2, func(p clonable.Clonable) fail.Error {
					hostSizingV2, innerErr := lang.Cast[*propertiesv2.HostSizing](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
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
				innerXErr = props.Alter(hostproperty.DescriptionV1, func(p clonable.Clonable) fail.Error {
					hostDescriptionV1, innerErr := lang.Cast[*propertiesv1.HostDescription](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
					}

					innerErr = hostDescriptionV1.Replace(converters.HostDescriptionFromAbstractToPropertyV1(*ahf.Description))
					if innerErr != nil {
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
					hostDescriptionV1.AZ = ahf.Description.AZ
					return nil
				})
				if innerXErr != nil {
					return innerXErr
				}

				// Updates Host property propertiesv2.HostNetworking
				return props.Alter(hostproperty.NetworkV2, func(p clonable.Clonable) fail.Error {
					hnV2, innerErr := lang.Cast[*propertiesv2.HostNetworking](p)
					if innerErr != nil {
						return fail.Wrap(innerErr)
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
				return nil, xerr
			}

			xerr = hostTrx.Commit(ctx)
			if xerr != nil {
				return nil, xerr
			}

			xerr = instance.updateCachedInformation(ctx, hostTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			xerr = hostTrx.SetSecurityGroups(ctx, hostReq, defaultSubnetTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}
			defer func() {
				derr := hostTrx.UndoSetSecurityGroups(cleanupContextFrom(ctx), &ferr, hostReq.KeepOnFailure)
				if derr != nil {
					logrus.WithContext(ctx).Warnf(derr.Error())
				}
			}()

			logrus.WithContext(ctx).Infof("Compute resource '%s' (%s) created", ahf.Name, ahf.ID)

			safe := false

			// Fix for Stein
			{
				st, xerr := svc.ProviderName()
				if xerr != nil {
					return nil, xerr
				}
				if st != "ovh" {
					safe = true
				}
			}

			if cfg, xerr := svc.ConfigurationOptions(); xerr == nil {
				safe = cfg.Safe
			}

			if !safe {
				xerr = svc.ChangeSecurityGroupSecurity(ctx, true, false, hostReq.Subnets[0].Network, "")
				if xerr != nil {
					return nil, xerr
				}
			}

			timings, xerr := svc.Timings()
			if xerr != nil {
				return nil, xerr
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
						return nil, fail.Wrap(xerr, "error provisioning the new Host '%s', please check safescaled logs", hostReq.ResourceName)
					}

					return nil, xerr
				}
			}

			for numReboots := 0; numReboots < 2; numReboots++ { // 2 reboots at most
				if maybePackerFailure {
					logrus.WithContext(ctx).Warningf("Hard Rebooting the host %s", hostReq.ResourceName)

					xerr = svc.RebootHost(ctx, ahf)
					if xerr != nil {
						return nil, xerr
					}

					status, xerr = instance.waitInstallPhase(ctx, userdata.PHASE1_INIT, timings.HostBootTimeout())
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						switch xerr.(type) {
						case *fail.ErrTimeout:
							if numReboots == 1 {
								return nil, fail.Wrap(xerr, "timeout after Host creation waiting for SSH availability")
							} else {
								continue
							}
						default:
							if abstract.IsProvisioningError(xerr) {
								return nil, fail.Wrap(xerr, "error provisioning the new Host '%s', please check safescaled logs", hostReq.ResourceName)
							}

							return nil, xerr
						}
					} else {
						break
					}
				}
			}

			xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.SystemV1, func(systemV1 *propertiesv1.HostSystem) fail.Error {
				parts := strings.Split(status, ",")
				if len(parts) >= 3 {
					systemV1.Type = parts[1]
					systemV1.Flavor = parts[2]
				}
				systemV1.Image = hostReq.ImageID
				return nil
			})
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// -- Updates Host link with subnets --
			xerr = hostTrx.UpdateSubnets(ctx, hostReq)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			defer func() {
				ferr = debug.InjectPlannedFail(ferr)
				if ferr != nil {
					hostTrx.UndoUpdateSubnets(cleanupContextFrom(ctx), hostReq, &ferr)
				}
			}()

			// Set ssh port from given one (applied after netsec setup)
			if userdataContent.IsGateway {
				userdataContent.SSHPort = strconv.Itoa(int(hostReq.SSHPort))
			}

			xerr = instance.finalizeProvisioning(ctx, hostTrx, userdataContent)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			// Unbind default security group if needed
			networkInstance, xerr := defaultSubnet.InspectNetwork(ctx)
			if xerr != nil {
				return nil, xerr
			}

			nid, err := networkInstance.GetID()
			if err != nil {
				return nil, xerr
			}

			xerr = hostTrx.UnbindDefaultSecurityGroupIfNeeded(ctx, nid)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, xerr
			}

			hostID, err := instance.GetID()
			if err != nil {
				return nil, fail.Wrap(err)
			}

			trueState, err := svc.GetHostState(ctx, hostID)
			if err != nil {
				return nil, fail.Wrap(err)
			}
			if trueState == hoststate.Error {
				return nil, fail.Wrap(fmt.Errorf("broken machine"))
			}

			if !valid.IsNil(ahf) && !valid.IsNil(ahf.HostCore) {
				logrus.WithContext(ctx).Debugf("Marking instance '%s' as started", hostReq.ResourceName)
				rerr := alterHostMetadataAbstract(ctx, hostTrx, func(ahc *abstract.HostCore) fail.Error {
					ahc.LastState = hoststate.Started
					return nil
				})
				if rerr != nil {
					return userdataContent, rerr
				}
			}

			logrus.WithContext(ctx).Infof("Host '%s' created successfully", hostReq.ResourceName)
			return userdataContent, nil
		}()

		chRes <- localresult{ud, gerr}
	}() // nolint

	select {
	case res := <-chRes: // if it works return the localresult
		if res.ct == nil && res.err == nil {
			return nil, fail.NewError("creation failed unexpectedly")
		}

		return res.ct, res.err
	case <-ctx.Done():
		return nil, fail.Wrap(ctx.Err())
	case <-inctx.Done(): // if not because parent context was canceled
		return nil, fail.Wrap(inctx.Err(), "canceled by parent")
	}
}

func determineImageID(ctx context.Context, svc iaasapi.Service, imageRef string) (string, string, fail.Error) {
	if imageRef == "" {
		cfg, xerr := svc.ConfigurationOptions()
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return "", "", xerr
		}

		imageRef = cfg.DefaultImage
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
			debug.IgnoreErrorWithContext(ctx, xerr)
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

func (instance *Host) thePhaseDoesSomething(_ context.Context, phase userdata.Phase, userdataContent *userdata.Content) bool {
	// assume yes
	localresult := true

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
		localresult = false
	}

	if strings.Contains(fullCt, "# ---- Main\n\n# ---- EndMain") {
		localresult = false
	}

	if strings.Contains(fullCt, "# ---- Main\n\n\n# ---- EndMain") {
		localresult = false
	}

	return localresult
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
	defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Starting install phase %s on '%s'...", phase, instance.GetName()), fmt.Sprintf("Ending phase %s on '%s' with err '%v' ...", phase, instance.GetName(), ferr))()

	instance.localCache.RLock()
	notok := instance.localCache.sshProfile == nil
	instance.localCache.RUnlock() // nolint
	if notok {
		return fail.InvalidInstanceContentError("instance.sshProfile", "cannot be nil")
	}
	incrementExpVar("host.cache.hit")

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
			return fail.Wrap(ctx.Err())
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
					problem = fail.NewError("failed to execute install phase '%s' on Host '%s': %s", phase, instance.GetName(), lastMsg[8:len(lastMsg)-1])
				}
			}
		}

		return problem
	}
	return nil
}

func (instance *Host) waitInstallPhase(inctx context.Context, phase userdata.Phase, timeout time.Duration) (string, fail.Error) {
	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	type localresult struct {
		rTr  string
		rErr fail.Error
	}
	chRes := make(chan localresult)
	go func() {
		defer close(chRes)

		var xerr fail.Error
		defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Waiting install phase %s on '%s'...", phase, instance.GetName()), fmt.Sprintf("Finish Waiting install phase %s on '%s' with err '%v' ...", phase, instance.GetName(), xerr))()

		sshDefaultTimeout := timeout
		duration := sshDefaultTimeout

		var (
			sshCfg     sshapi.Config
			sshProfile sshapi.Connector
			status     string
		)
		sshCfg, xerr = instance.GetSSHConfig(ctx)
		if xerr != nil {
			chRes <- localresult{"", xerr}
			return
		}

		sshProfile, xerr = sshfactory.NewConnector(sshCfg)
		if xerr != nil {
			chRes <- localresult{"", xerr}
			return
		}

		status, xerr = sshProfile.WaitServerReady(ctx, string(phase), duration)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *retry.ErrStopRetry:
				xerr = fail.Wrap(fail.Cause(xerr), "stopping retries")
				chRes <- localresult{status, xerr}
				return
			case *fail.ErrTimeout:
				xerr = fail.Wrap(fail.Cause(xerr), "failed to wait for SSH on Host '%s' to be ready after %s (phase %s): %s", instance.GetName(), temporal.FormatDuration(duration), phase, status)
				chRes <- localresult{status, xerr}
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
						xerr = fail.NewError("failed to execute install phase '%s' on Host '%s': %s", phase, instance.GetName(), lastMsg[8:len(lastMsg)-1])
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
						xerr = fail.NewError("failed to execute install phase '%s' on Host '%s': %s", phase, instance.GetName(), lastMsg[8:len(lastMsg)-1])
					}
				}
			}
		}
		chRes <- localresult{status, xerr}
	}()

	select {
	case <-time.After(timeout):
		return "", fail.TimeoutError(fmt.Errorf("failed to wait for SSH on Host '%s' to be ready (phase %s)", instance.GetName(), phase), timeout)
	case res := <-chRes:
		return res.rTr, res.rErr
	case <-ctx.Done():
		return "", fail.Wrap(ctx.Err())
	case <-inctx.Done():
		return "", fail.Wrap(inctx.Err())
	}
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
func createSingleHostNetworking(ctx context.Context, singleHostRequest abstract.HostRequest) (_ *Subnet, _ func() fail.Error, ferr fail.Error) {
	myjob, xerr := jobapi.FromContext(ctx)
	if xerr != nil {
		return nil, nil, xerr
	}

	// Build network name
	cfg, xerr := myjob.Service().ConfigurationOptions()
	if xerr != nil {
		return nil, nil, xerr
	}

	bucketName := cfg.MetadataBucketName
	if bucketName == "" {
		return nil, nil, fail.InconsistentError("missing service configuration option 'MetadataBucketName'")
	}

	// Trim and TrimPrefix don't do the same thing
	networkName := fmt.Sprintf("sfnet-%s", strings.TrimPrefix(bucketName, objectstorage.BucketNamePrefix+"-"))

	// Create network if needed
	networkInstance, xerr := LoadNetwork(ctx, networkName)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			networkInstance, xerr = NewNetwork(ctx)
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
					networkInstance, xerr = LoadNetwork(ctx, networkName)
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
		return nil, nil, fail.Wrap(err)
	}

	networkTrx, xerr := newNetworkTransaction(ctx, networkInstance)
	if xerr != nil {
		return nil, nil, xerr
	}
	defer networkTrx.TerminateFromError(ctx, &ferr)

	// Check if Subnet exists
	var (
		subnetRequest abstract.SubnetRequest
		cidrIndex     uint
	)
	subnetInstance, xerr := LoadSubnet(ctx, nid, singleHostRequest.ResourceName)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			subnetInstance, xerr = NewSubnet(ctx)
			if xerr != nil {
				return nil, nil, xerr
			}

			var (
				subnetCIDR string
			)

			subnetCIDR, cidrIndex, xerr = reserveCIDRForSingleHost(ctx, networkTrx)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return nil, nil, xerr
			}

			dnsServers := cfg.DNSServers
			subnetRequest.Name = singleHostRequest.ResourceName
			subnetRequest.NetworkID, err = networkInstance.GetID()
			if err != nil {
				return nil, nil, fail.Wrap(err)
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
				if ferr != nil && singleHostRequest.CleanOnFailure() {
					derr := subnetInstance.Delete(cleanupContextFrom(ctx))
					if derr != nil {
						_ = ferr.AddConsequence(fail.Wrap(derr, "cleaning up on failure, failed to Delete Subnet '%s'", singleHostRequest.ResourceName))
					}
				}
			}()

			subnetTrx, xerr := newSubnetTransaction(ctx, subnetInstance)
			if xerr != nil {
				return nil, nil, xerr
			}
			defer subnetTrx.TerminateFromError(ctx, &ferr)

			// Sets the CIDR index in instance metadata
			xerr = alterSubnetMetadataAbstract(ctx, subnetTrx, func(as *abstract.Subnet) fail.Error {
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
		if singleHostRequest.CleanOnFailure() {
			ctx := cleanupContextFrom(ctx)
			derr := subnetInstance.Delete(ctx)
			if derr != nil {
				errs = append(errs, fail.Wrap(derr, "cleaning up on failure, failed to Delete Subnet '%s'", singleHostRequest.ResourceName))
			}
			derr = networkTrx.FreeCIDRForSingleHost(ctx, cidrIndex)
			if derr != nil {
				errs = append(errs, fail.Wrap(derr, "cleaning up on failure, failed to free CIDR slot in Network '%s'", networkInstance.GetName()))
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

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).Entering()
	defer tracer.Exiting()

	// Do not remove a Host that is a gateway
	isGateway, xerr := instance.IsGateway(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}
	if isGateway {
		return fail.NotAvailableError("cannot Delete Host, it's a gateway that can only be deleted through its Subnet")
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	xerr = hostTrx.RelaxedDeleteHost(ctx, instance.localCache.sshProfile)
	if xerr != nil {
		return xerr
	}

	// Need to explicitly terminate host transaction to be able to Delete metadata (dead-lock otherwise)
	hostTrx.SilentTerminate(ctx)

	// Deletes metadata from Object Storage
	xerr = instance.Core.Delete(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		// If entry not found, considered as a success
		if _, ok := xerr.(*fail.ErrNotFound); !ok || valid.IsNil(xerr) {
			return xerr
		}

		debug.IgnoreErrorWithContext(ctx, xerr)
		logrus.WithContext(ctx).Tracef("core instance not found, deletion considered as a success")
	}

	return nil
}

// GetSSHConfig loads SSH configuration for Host from metadata
func (instance *Host) GetSSHConfig(ctx context.Context) (_ sshapi.Config, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	xerr = instance.refreshLocalCacheIfNeeded(ctx, hostTrx)
	if xerr != nil {
		return nil, xerr
	}

	instance.localCache.RLock()
	sshProfile := instance.localCache.sshProfile
	instance.localCache.RUnlock() // nolint
	if valid.IsNil(sshProfile) {
		return nil, fail.NotFoundError("failed to find SSH Config of Host '%s'", instance.GetName())
	}
	incrementExpVar("host.cache.hit")

	return sshProfile.Config()
}

// Run tries to execute command 'cmd' on the Host
func (instance *Host) Run(ctx context.Context, cmd string, outs outputs.Enum, connectionTimeout, executionTimeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	const invalid = -1

	if valid.IsNil(instance) {
		return invalid, "", "", fail.InvalidInstanceError()
	}
	instance.localCache.RLock()
	notok := instance.localCache.sshProfile == nil
	instance.localCache.RUnlock() // nolint
	if notok {
		return invalid, "", "", fail.InvalidInstanceContentError("instance.sshProfile", "cannot be nil")
	}
	incrementExpVar("host.cache.hit")

	if ctx == nil {
		return invalid, "", "", fail.InvalidParameterCannotBeNilError("ctx")
	}
	if cmd == "" {
		return invalid, "", "", fail.InvalidParameterError("cmd", "cannot be empty string")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(cmd='%s', outs=%s)", outs.String()).Entering()
	defer tracer.Exiting()

	targetName := instance.GetName()

	state, xerr := instance.GetState(ctx)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if state != hoststate.Started {
		return invalid, "", "", fail.InvalidRequestError(fmt.Sprintf("cannot run anything on '%s', '%s' is NOT started", targetName, targetName))
	}

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
	state, xerr = instance.GetState(ctx)
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
func (instance *Host) Push(ctx context.Context, source, target, owner, mode string, timeout time.Duration) (_ int, _ string, _ string, ferr fail.Error) {
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

	targetName := instance.GetName()

	state, xerr := instance.GetState(ctx)
	if xerr != nil {
		return invalid, "", "", xerr
	}

	if state != hoststate.Started {
		return invalid, "", "", fail.InvalidRequestError(fmt.Sprintf("cannot push anything on '%s', '%s' is NOT started: %s", targetName, targetName, state.String()))
	}

	return instance.unsafePush(ctx, source, target, owner, mode, timeout)
}

// GetShare returns a clone of the propertiesv1.HostShare corresponding to share 'shareRef'
func (instance *Host) GetShare(ctx context.Context, shareRef string) (_ *propertiesv1.HostShare, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	var (
		hostShare *propertiesv1.HostShare
		// ok        bool
	)
	err := inspectHostMetadataProperty(ctx, hostTrx, hostproperty.SharesV1, func(sharesV1 *propertiesv1.HostShares) fail.Error {
		var innerErr error
		item, ok := sharesV1.ByID[shareRef]
		if ok {
			hostShare, innerErr = clonable.CastedClone[*propertiesv1.HostShare](item)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return nil
		}

		id, ok := sharesV1.ByName[shareRef]
		if ok {
			hostShare, innerErr = clonable.CastedClone[*propertiesv1.HostShare](sharesV1.ByID[id])
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			return nil
		}

		return fail.NotFoundError("share '%s' not found in server '%s' metadata", shareRef, instance.GetName())
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

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return hostTrx.GetVolumes(ctx)
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
		return fail.Wrap(err)
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

			return svc.WaitHostState(ctx, hostID, hoststate.Started, timings.HostOperationTimeout())
		},
		timings.NormalDelay(),
		timings.ExecutionTimeout(),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAborted:
			if cerr := fail.Wrap(fail.Cause(xerr)); cerr != nil {
				return cerr
			}
			return xerr
		case *retry.ErrTimeout:
			return fail.Wrap(xerr, "timeout waiting Host '%s' to be started", hostName)
		default:
			return xerr
		}
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	// Now reload
	xerr = instance.reload(ctx, hostTrx)
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
		return fail.Wrap(err)
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

			return svc.WaitHostState(ctx, hostID, hoststate.Stopped, timings.HostOperationTimeout())
		},
		timings.NormalDelay(),
		timings.ExecutionTimeout(),
	)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrAborted:
			if cerr := fail.Wrap(fail.Cause(xerr)); cerr != nil {
				return cerr
			}
			return xerr
		case *retry.ErrTimeout:
			return fail.Wrap(xerr, "timeout waiting Host '%s' to be stopped", hostName)
		default:
			return xerr
		}
	}

	// Now reload
	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	xerr = instance.reload(ctx, hostTrx)
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

	state, xerr := instance.ForceGetState(ctx)
	if xerr != nil {
		return fail.Wrap(xerr, "there was an error retrieving machine state")
	}

	if state != hoststate.Started {
		return fail.NewError("if the machine is not started sync won't work: %s", state.String())
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

// Resize ...
// not yet implemented
func (instance *Host) Resize(ctx context.Context, hostSize abstract.HostSizingRequirements) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host")).WithStopwatch().Entering()
	defer tracer.Exiting()

	return fail.NotImplementedError("Host.Resize() not yet implemented") // FIXME: Technical debt
}

// GetPublicIP returns the public IP address of the Host
func (instance *Host) GetPublicIP(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	xerr = instance.refreshLocalCacheIfNeeded(ctx, hostTrx)
	if xerr != nil {
		return "", xerr
	}

	instance.localCache.RLock()
	ip := instance.localCache.publicIP
	instance.localCache.RUnlock() // nolint
	if ip == "" {
		return "", fail.NotFoundError("failed to find Public IP of Host '%s'", instance.GetName())
	}
	incrementExpVar("host.cache.hit")

	return ip, nil
}

// GetPrivateIP returns the private IP of the Host on its default Networking
func (instance *Host) GetPrivateIP(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	xerr = instance.refreshLocalCacheIfNeeded(ctx, hostTrx)
	if xerr != nil {
		return "", xerr
	}

	instance.localCache.RLock()
	ip := instance.localCache.privateIP
	instance.localCache.RUnlock() // nolint
	if ip == "" {
		return "", fail.NotFoundError("failed to find Private IP of Host '%s'", instance.GetName())
	}
	incrementExpVar("host.cache.hit")

	return ip, nil
}

// GetPrivateIPOnSubnet returns the private IP of the Host on its default Subnet
func (instance *Host) GetPrivateIPOnSubnet(ctx context.Context, subnetRef string) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	ip := ""
	if valid.IsNil(instance) {
		return ip, fail.InvalidInstanceError()
	}
	if subnetRef = strings.TrimSpace(subnetRef); subnetRef == "" {
		return ip, fail.InvalidParameterCannotBeEmptyStringError("subnetRef")
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return ip, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return ip, inspectHostMetadataProperty(ctx, hostTrx, hostproperty.NetworkV2, func(hostNetworkV2 *propertiesv2.HostNetworking) fail.Error {
		var ok bool
		ip, ok = hostNetworkV2.IPv4Addresses[subnetRef]
		if !ok {
			id, ok := hostNetworkV2.SubnetsByName[subnetRef]
			if ok {
				ip, ok = hostNetworkV2.IPv4Addresses[id]
			}
		}
		if !ok {
			return fail.InvalidRequestError("Host '%s' does not have an IP address on Subnet '%s'", instance.GetName(), subnetRef)
		}

		return nil
	})
}

// GetAccessIP returns the IP to reach the Host
func (instance *Host) GetAccessIP(ctx context.Context) (_ string, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	xerr = instance.refreshLocalCacheIfNeeded(ctx, hostTrx)
	if xerr != nil {
		return "", xerr
	}

	instance.localCache.RLock()
	ip := instance.localCache.accessIP
	instance.localCache.RUnlock() // nolint
	if ip == "" {
		return "", fail.NotFoundError("failed to find Access IP of Host '%s'", instance.GetName())
	}
	incrementExpVar("host.cache.hit")

	return ip, nil
}

// GetShares returns the information about the shares hosted by the Host
func (instance *Host) GetShares(ctx context.Context) (shares *propertiesv1.HostShares, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	shares = &propertiesv1.HostShares{}
	if valid.IsNil(instance) {
		return shares, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return shares, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return shares, inspectHostMetadataProperty(ctx, hostTrx, hostproperty.SharesV1, func(hostSharesV1 *propertiesv1.HostShares) fail.Error {
		shares = hostSharesV1
		return nil
	})
}

// GetMounts returns the information abouts the mounts of the Host
func (instance *Host) GetMounts(ctx context.Context) (mounts *propertiesv1.HostMounts, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	mounts = nil
	if valid.IsNil(instance) {
		return mounts, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return hostTrx.GetMounts(ctx)
}

// IsClusterMember returns true if the Host is member of a cluster
func (instance *Host) IsClusterMember(ctx context.Context) (yes bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	yes = false
	if valid.IsNil(instance) {
		return yes, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return yes, inspectHostMetadataProperty(ctx, hostTrx, hostproperty.ClusterMembershipV1, func(hostClusterMembershipV1 *propertiesv1.HostClusterMembership) fail.Error {
		yes = hostClusterMembershipV1.Cluster != ""
		return nil
	})
}

// IsGateway tells if the Host acts as a gateway for a Subnet
func (instance *Host) IsGateway(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	var state bool
	return state, inspectHostMetadataProperty(ctx, hostTrx, hostproperty.NetworkV2, func(hnV2 *propertiesv2.HostNetworking) fail.Error {
		state = hnV2.IsGateway
		return nil
	})
}

// IsSingle tells if the Host is single
func (instance *Host) IsSingle(ctx context.Context) (_ bool, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	var state bool
	return state, inspectHostMetadataProperty(ctx, hostTrx, hostproperty.NetworkV2, func(hnV2 *propertiesv2.HostNetworking) fail.Error {
		state = hnV2.Single
		return nil
	})
}

// PushStringToFile creates a file 'filename' on remote 'Host' with the content 'content'
func (instance *Host) PushStringToFile(ctx context.Context, content string, filename string) (ferr fail.Error) {
	return instance.PushStringToFileWithOwnership(ctx, content, filename, "", "")
}

// PushStringToFileWithOwnership creates a file 'filename' on remote 'Host' with the content 'content', and apply ownership
func (instance *Host) PushStringToFileWithOwnership(ctx context.Context, content string, filename string, owner, mode string) (ferr fail.Error) {
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

	targetName := instance.GetName()
	state, xerr := instance.GetState(ctx)
	if xerr != nil {
		return xerr
	}

	if state != hoststate.Started {
		return fail.InvalidRequestError(fmt.Sprintf("cannot push anything on '%s', '%s' is NOT started: %s", targetName, targetName, state.String()))
	}

	return instance.unsafePushStringToFileWithOwnership(ctx, content, filename, owner, mode)
}

// GetDefaultSubnet returns the Networking instance corresponding to Host default subnet
func (instance *Host) GetDefaultSubnet(ctx context.Context) (_ *Subnet, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return hostTrx.GetDefaultSubnet(ctx)
}

// ToProtocol convert a resources.Host to protocol.Host
func (instance *Host) ToProtocol(ctx context.Context) (ph *protocol.Host, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	var (
		abstractHostCore *abstract.HostCore
		hostSizingV2     *propertiesv2.HostSizing
		hostVolumesV1    *propertiesv1.HostVolumes
		hostLabelsV1     *propertiesv1.HostLabels
	)

	publicIP, _ := instance.GetPublicIP(ctx)   // There may be no public ip, but the returned value is pertinent in this case, no need to handle error
	privateIP, _ := instance.GetPrivateIP(ctx) // Idem

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	xerr = inspectHostMetadata(ctx, hostTrx, func(ahc *abstract.HostCore, props *serialize.JSONProperties) fail.Error {
		abstractHostCore = ahc
		innerXErr := props.Inspect(hostproperty.SizingV2, func(p clonable.Clonable) fail.Error {
			var innerErr error
			hostSizingV2, innerErr = lang.Cast[*propertiesv2.HostSizing](p)
			return fail.Wrap(innerErr)
		})
		if innerXErr != nil {
			return innerXErr
		}

		innerXErr = props.Inspect(hostproperty.LabelsV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			hostLabelsV1, innerErr = lang.Cast[*propertiesv1.HostLabels](p)
			return fail.Wrap(innerErr)
		})
		if innerXErr != nil {
			return innerXErr
		}

		return props.Inspect(hostproperty.VolumesV1, func(p clonable.Clonable) fail.Error {
			var innerErr error
			hostVolumesV1, innerErr = lang.Cast[*propertiesv1.HostVolumes](p)
			return fail.Wrap(innerErr)
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
	for k, v := range hostLabelsV1.ByID {
		labelInstance, xerr := LoadLabel(ctx, k)
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

	ph = &protocol.Host{
		Cpu:                 int32(hostSizingV2.AllocatedSize.Cores),
		Disk:                int32(hostSizingV2.AllocatedSize.DiskSize),
		Id:                  abstractHostCore.ID,
		PublicIp:            publicIP,
		PrivateIp:           privateIP,
		Name:                abstractHostCore.Name,
		PrivateKey:          abstractHostCore.PrivateKey,
		Password:            abstractHostCore.Password,
		Ram:                 hostSizingV2.AllocatedSize.RAMSize,
		State:               protocol.HostState(abstractHostCore.LastState),
		StateLabel:          abstractHostCore.LastState.String(),
		CreationDate:        abstractHostCore.Tags["CreationDate"],
		AttachedVolumeNames: volumes,
		Template:            hostSizingV2.Template,
		Labels:              labels,
	}
	return ph, nil
}

// BindSecurityGroup binds a security group to the Host; if enabled is true, apply it immediately
func (instance *Host) BindSecurityGroup(ctx context.Context, sgInstance *SecurityGroup, enable SecurityGroupActivation) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer fail.OnExitLogError(ctx, &ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if sgInstance == nil {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(sg='%s', enable=%v)", sgInstance.GetName(), enable).WithStopwatch().Entering()
	defer tracer.Exiting()

	sgID, err := sgInstance.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	// If the Security Group is already bound to the Host with the exact same state, considered as a success
	xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) fail.Error {
		item, ok := hsgV1.ByID[sgID]
		if !ok {
			// No entry for bind, create one
			item = &propertiesv1.SecurityGroupBond{
				ID:   sgID,
				Name: sgInstance.GetName(),
			}
			hsgV1.ByID[sgID] = item
			hsgV1.ByName[item.Name] = item.ID
		}
		item.Disabled = bool(!enable)
		return nil
	})
	if xerr != nil {
		return xerr
	}

	return sgTrx.BindToHost(ctx, hostTrx, enable, MarkSecurityGroupAsSupplemental)
}

// UnbindSecurityGroup unbinds a security group from the Host
func (instance *Host) UnbindSecurityGroup(ctx context.Context, sgInstance *SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer fail.OnExitLogError(ctx, &ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if valid.IsNil(sgInstance) {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	sgName := sgInstance.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(sgInstance='%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) fail.Error {
		sgID, innerErr := sgInstance.GetID()
		if innerErr != nil {
			return fail.Wrap(innerErr)
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

		// found, Delete it from properties
		delete(hsgV1.ByID, sgID)
		delete(hsgV1.ByName, sgTrx.GetName())
		return nil
	})
	if xerr != nil {
		return xerr
	}

	// unbind security group from Host on remote service side
	xerr = sgTrx.UnbindFromHost(ctx, hostTrx)
	if xerr != nil {
		return xerr
	}

	// -- Remove Host referenced in Security Group
	return alterSecurityGroupMetadataProperty(ctx, sgTrx, securitygroupproperty.HostsV1, func(sghV1 *propertiesv1.SecurityGroupHosts) fail.Error {
		hostID, innerErr := hostTrx.GetID()
		if innerErr != nil {
			return fail.Wrap(innerErr)
		}

		delete(sghV1.ByID, hostID)
		delete(sghV1.ByName, hostTrx.GetName())
		return nil
	})
}

// ListSecurityGroups returns a slice of security groups bound to Host
func (instance *Host) ListSecurityGroups(ctx context.Context, state securitygroupstate.Enum) (list []*propertiesv1.SecurityGroupBond, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []*propertiesv1.SecurityGroupBond
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return emptySlice, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return list, inspectHostMetadataProperty(ctx, hostTrx, hostproperty.SecurityGroupsV1, func(hsgV1 *propertiesv1.HostSecurityGroups) fail.Error {
		list = FilterBondsByKind(hsgV1.ByID, state)
		return nil
	})
}

// EnableSecurityGroup enables a bound security group to Host by applying its rules
func (instance *Host) EnableSecurityGroup(ctx context.Context, sgInstance *SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if valid.IsNil(sgInstance) {
		return fail.InvalidParameterError("sgInstance", "cannot be null value of 'SecurityGroup'")
	}

	sgName := sgInstance.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "(%s)", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	return hostTrx.EnableSecurityGroup(ctx, sgTrx)
}

// DisableSecurityGroup disables a bound security group to Host
func (instance *Host) DisableSecurityGroup(ctx context.Context, sgInstance *SecurityGroup) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterError("ctx", "cannot be nil")
	}
	if valid.IsNil(sgInstance) {
		return fail.InvalidParameterCannotBeNilError("sgInstance")
	}

	sgName := sgInstance.GetName()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "('%s')", sgName).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	sgTrx, xerr := newSecurityGroupTransaction(ctx, sgInstance)
	if xerr != nil {
		return xerr
	}
	defer sgTrx.TerminateFromError(ctx, &ferr)

	return hostTrx.DisableSecurityGroup(ctx, sgTrx)
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
		return timings.HostOperationTimeout()
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

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	var labelsV1 *propertiesv1.HostLabels
	return labelsV1.ByID, alterHostMetadataProperty(ctx, hostTrx, hostproperty.LabelsV1, func(p *propertiesv1.HostLabels) fail.Error {
		labelsV1 = p
		return nil
	})
}

// BindLabel binds a Label to Host
func (instance *Host) BindLabel(ctx context.Context, labelInstance *Label, value string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if labelInstance == nil {
		return fail.InvalidParameterCannotBeNilError("Label")
	}

	labelName := labelInstance.GetName()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.host"), "('%s')", labelName).WithStopwatch().Entering()
	defer tracer.Exiting()

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	labelTrx, xerr := newLabelTransaction(ctx, labelInstance)
	if xerr != nil {
		return xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	labelID, err := labelTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	hostID, err := hostTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	// Inform Label we want it bound to Host (updates its metadata)
	xerr = labelTrx.BindToHost(ctx, hostTrx, value)
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

	xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.LabelsV1, func(hostLabelsV1 *propertiesv1.HostLabels) fail.Error {
		// If the host already has this tag, consider it a success
		_, ok := hostLabelsV1.ByID[labelID]
		if !ok {
			hostLabelsV1.ByID[labelID] = value
			hostLabelsV1.ByName[labelName] = value
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	lmap, err := labelToMap(labelInstance)
	if err != nil {
		return fail.Wrap(err)
	}

	svc := instance.Service()
	xerr = svc.UpdateTags(ctx, abstract.HostResource, hostID, lmap)
	if xerr != nil {
		return xerr
	}

	return nil
}

// labelToMap ...
func labelToMap(labelInstance *Label) (map[string]string, error) {
	if labelInstance == nil {
		return nil, fail.InvalidParameterCannotBeNilError("labelInstance")
	}

	sad := make(map[string]string)
	k := labelInstance.GetName()
	v, err := labelInstance.DefaultValue(context.Background())
	if err != nil {
		return nil, err
	}
	sad[k] = v

	return sad, nil
}

// UnbindLabel removes a Label from Host
func (instance *Host) UnbindLabel(ctx context.Context, labelInstance *Label) (ferr fail.Error) {
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

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	labelTrx, xerr := newLabelTransaction(ctx, labelInstance)
	if xerr != nil {
		return xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	hostID, err := hostTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	labelID, err := labelTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.LabelsV1, func(hostLabelsV1 *propertiesv1.HostLabels) fail.Error {
		// If the host is not bound to this Label, consider it a success
		_, found := hostLabelsV1.ByID[labelID]
		if found {
			delete(hostLabelsV1.ByID, labelID)
			delete(hostLabelsV1.ByName, labelInstance.GetName())
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = labelTrx.UnbindFromHost(ctx, hostTrx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	xerr = instance.Service().DeleteTags(ctx, abstract.HostResource, hostID, []string{labelInstance.GetName()})
	if xerr != nil {
		return xerr
	}

	return nil
}

// ResetLabel resets the value of Label bound with Host to default value of Label
func (instance *Host) ResetLabel(ctx context.Context, labelInstance *Label) (ferr fail.Error) {
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
func (instance *Host) UpdateLabel(ctx context.Context, labelInstance *Label, value string) (ferr fail.Error) {
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
		return fail.Wrap(err)
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	labelTrx, xerr := newLabelTransaction(ctx, labelInstance)
	if xerr != nil {
		return xerr
	}
	defer labelTrx.TerminateFromError(ctx, &ferr)

	hostName := instance.GetName()
	xerr = alterLabelMetadata(ctx, labelTrx, func(al *abstract.Label, props *serialize.JSONProperties) fail.Error {
		alabel = al
		return props.Alter(labelproperty.HostsV1, func(p clonable.Clonable) fail.Error {
			labelHostsV1, innerErr := lang.Cast[*propertiesv1.LabelHosts](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			// If the tag does not have this host, consider it a success
			_, ok := labelHostsV1.ByID[hostID]
			if !ok {
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

	return alterHostMetadataProperty(ctx, hostTrx, hostproperty.LabelsV1, func(hostLabelsV1 *propertiesv1.HostLabels) fail.Error {
		// If the host is not bound to this Label, consider it a success
		_, ok := hostLabelsV1.ByID[alabel.ID]
		if !ok {
			return fail.NotFoundError("failed to find bind of Label %s with Host %s", hostName, alabel.Name)
		}

		hostLabelsV1.ByID[alabel.ID] = value
		hostLabelsV1.ByName[alabel.Name] = value
		return nil
	})
}

// GetDomain returns the domain used to fully qualify the host name for DNS queries (for example)
func (instance *Host) GetDomain(ctx context.Context) (_ string, ferr fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return "", xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	domain := ""
	xerr = inspectHostMetadataProperty(ctx, hostTrx, hostproperty.DescriptionV1, func(hostDescriptionV1 *propertiesv1.HostDescription) fail.Error {
		domain = hostDescriptionV1.Domain
		if domain != "" {
			domain = "." + domain
		}
		return nil
	})
	if xerr != nil {
		return "", xerr
	}

	return domain, nil
}

// refreshLocalCacheIfNeeded refreshes instance.localCache if instance.localCache.PrivateIP == ""
func (instance *Host) refreshLocalCacheIfNeeded(ctx context.Context, hostTrx hostTransaction) fail.Error {
	instance.localCache.RLock()
	doRefresh := instance.localCache.privateIP == ""
	instance.localCache.RUnlock() // nolint
	if doRefresh {
		xerr := instance.updateCachedInformation(ctx, hostTrx)
		if xerr != nil {
			return xerr
		}
	} else {
		incrementExpVar("host.cache.hit")
	}
	return nil
}

func (instance *Host) finalizeProvisioning(ctx context.Context, hostTrx hostTransaction, userdataContent *userdata.Content) (ferr fail.Error) {
	if ctx == nil {
		return fail.InvalidInstanceError()
	}
	if hostTrx == nil {
		return fail.InvalidParameterCannotBeNilError("hostTrx")
	}
	if userdataContent == nil {
		return fail.InvalidParameterCannotBeNilError("userdataContent")
	}

	defer fail.OnExitLogError(ctx, &ferr)

	// Reset userdata script for Host from Cloud Provider metadata service (if stack is able to do so)
	svc := instance.Service()
	hostName := hostTrx.GetName()
	hostID, err := hostTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	xerr := svc.ClearHostStartupScript(ctx, hostID)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	timings, xerr := svc.Timings()
	if xerr != nil {
		return xerr
	}

	if userdataContent.Debug {
		if _, err := os.Stat("/tmp/tss"); !errors.Is(err, os.ErrNotExist) {
			_, _, _, xerr = instance.Push(ctx, "/tmp/tss", fmt.Sprintf("/home/%s/tss", userdataContent.Username), userdataContent.Username, "755", 10*time.Second)
			if xerr != nil {
				debug.IgnoreErrorWithContext(ctx, xerr)
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
	xerr = alterHostMetadataAbstract(ctx, hostTrx, func(ah *abstract.HostCore) fail.Error {
		ah.PrivateKey = userdataContent.FinalPrivateKey
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return fail.Wrap(xerr, "failed to update Keypair of machine '%s'", hostName)
	}

	xerr = hostTrx.Commit(ctx)
	if xerr != nil {
		return xerr
	}

	xerr = instance.updateCachedInformation(ctx, hostTrx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
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
		logrus.WithContext(ctx).Infof("finalizing Host provisioning of '%s': rebooting", hostName)

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
				theCause := fail.Wrap(fail.Cause(xerr))
				if _, ok := theCause.(*fail.ErrTimeout); !ok || valid.IsNil(theCause) {
					return xerr
				}

				debug.IgnoreErrorWithContext(ctx, xerr)
			}

			// Reboot Host
			logrus.WithContext(ctx).Infof("finalizing Host provisioning of '%s' (not-gateway): rebooting", hostName)
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
					xerr, "error provisioning the new Host, please check safescaled logs", hostName,
				)
			}
			return xerr
		}
	}
	return nil
}

// reload reloads Host from metadata and current Host state on provider state
func (instance *Host) reload(ctx context.Context, hostTrx hostTransaction) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	xerr := instance.Core.Reload(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *retry.ErrTimeout: // If retry timed out, log it and return error ErrNotFound
			return fail.NotFoundError("metadata of Host '%s' not found; Host deleted?", instance.GetName())
		default:
			return xerr
		}
	}

	hid, err := hostTrx.GetID()
	if err != nil {
		return fail.Wrap(err)
	}

	// Request Host inspection from provider
	ahf, xerr := instance.Service().InspectHost(ctx, hid)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	cache, xerr := instance.Service().Cache(ctx)
	if xerr != nil {
		return xerr
	}

	if cache != nil {
		hid, err := instance.GetID()
		if err != nil {
			return fail.Wrap(err)
		}

		thing, err := cache.Get(ctx, hid)
		if err != nil || thing == nil { // usually notfound
			err = cache.Set(ctx, hid, instance, &store.Options{Expiration: 1 * time.Minute})
			if err != nil {
				return fail.Wrap(err)
			}

			time.Sleep(10 * time.Millisecond) // consolidate cache.Set
		} else if _, ok := thing.(*Host); !ok {
			return fail.NewError("cache stored the wrong type")
		}
	}

	// Updates the Host metadata
	xerr = alterHostMetadata(ctx, hostTrx, func(ahc *abstract.HostCore, props *serialize.JSONProperties) fail.Error {
		changed := false
		if ahc.LastState != ahf.CurrentState {
			ahf.CurrentState = ahc.LastState
			changed = true
		}

		innerXErr := props.Alter(hostproperty.SizingV2, func(p clonable.Clonable) fail.Error {
			hostSizingV2, innerErr := lang.Cast[*propertiesv2.HostSizing](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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
		innerXErr = props.Alter(hostproperty.NetworkV2, func(p clonable.Clonable) fail.Error {
			hnV2, innerErr := lang.Cast[*propertiesv2.HostNetworking](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
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

	return instance.updateCachedInformation(ctx, hostTrx)
}
