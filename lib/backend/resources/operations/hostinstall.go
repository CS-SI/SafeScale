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

package operations

import (
	"context"
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/clonable"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/lang"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// AddFeature handles 'safescale host feature add <host name or id> <feature name>'
func (instance *Host) AddFeature(ctx context.Context, name string, vars data.Map[string, any], settings resources.FeatureSettings) (outcomes resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.host"), "(%s)", name).Entering()
	defer tracer.Exiting()

	targetName := instance.GetName()

	state, xerr := instance.GetState(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if state != hoststate.Started {
		return nil, fail.InvalidRequestError(fmt.Sprintf("cannot install feature on '%s', '%s' is NOT started", targetName, targetName))
	}

	feat, xerr := NewFeature(ctx, instance.Scope(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	outcomes, xerr = func() (resources.Results, fail.Error) {
		// /!\ Do not cross references in alter, it makes deadlock
		outcomes, xerr := feat.Add(ctx, instance, vars, settings)
		if xerr != nil {
			return outcomes, xerr
		}
		xerr = instance.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			// updates HostFeatures property for host
			return props.Alter(hostproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
				hostFeaturesV1, innerErr := lang.Cast[*propertiesv1.HostFeatures](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				requires, innerXErr := feat.Dependencies(ctx)
				if innerXErr != nil {
					return innerXErr
				}

				nif := propertiesv1.NewHostInstalledFeature()
				nif.HostContext = true
				if requires != nil {
					nif.Requires = requires
				}

				hostFeaturesV1.Installed[name] = nif
				return nil
			})
		})
		return outcomes, xerr
	}()

	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	return outcomes, nil
}

// CheckFeature ...
func (instance *Host) CheckFeature(ctx context.Context, name string, vars data.Map[string, any], settings resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	tracer := debug.NewTracerFromCtx(ctx, tracing.ShouldTrace("resources.host"), "(%s)", name).Entering()
	defer tracer.Exiting()

	feat, xerr := NewFeature(ctx, instance.Scope(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Check(ctx, instance, vars, settings)
}

// DeleteFeature handles 'safescale host delete-feature <host name> <feature name>'
func (instance *Host) DeleteFeature(inctx context.Context, name string, vars data.Map[string, any], settings resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if inctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("inctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	ctx, cancel := context.WithCancel(inctx)
	defer cancel()

	tracer := debug.NewTracerFromCtx(ctx, false /*tracing.ShouldTrace("resources.host") || tracing.ShouldTrace("resources.feature"), */, "(%s)", name).Entering()
	defer tracer.Exiting()

	targetName := instance.GetName()

	state, xerr := instance.GetState(ctx)
	if xerr != nil {
		return nil, xerr
	}

	if state != hoststate.Started {
		return nil, fail.InvalidRequestError(fmt.Sprintf("cannot delete feature on '%s', '%s' is NOT started", targetName, targetName))
	}

	feat, xerr := NewFeature(ctx, instance.Scope(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = func() fail.Error {
		outcomes, innerXErr := feat.Remove(ctx, instance, vars, settings)
		if innerXErr != nil {
			return fail.NewError(innerXErr, nil, "error uninstalling feature '%s' on '%s'", name, instance.GetName())
		}
		if !outcomes.Successful() {
			msg := fmt.Sprintf("failed to delete feature '%s' from host '%s'", name, instance.GetName())
			tracer.Trace(strprocess.Capitalize(msg) + ":\n" + outcomes.AllErrorMessages())
			return fail.NewError(msg)
		}
		return instance.Alter(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
			// updates HostFeatures property for host
			return props.Alter(hostproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
				hostFeaturesV1, innerErr := lang.Cast[*propertiesv1.HostFeatures](p)
				if innerErr != nil {
					return fail.Wrap(innerErr)
				}

				delete(hostFeaturesV1.Installed, name)
				return nil
			})
		})
	}()
	return nil, xerr
}

// TargetType returns the type of the target.
// satisfies install.Targetable interface.
func (instance *Host) TargetType() featuretargettype.Enum {
	if valid.IsNil(instance) {
		return featuretargettype.Unknown
	}

	return featuretargettype.Host
}

// InstallMethods returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = highest preference)
// satisfies interface install.Targetable
func (instance *Host) InstallMethods(_ context.Context) (map[uint8]installmethod.Enum, fail.Error) {
	if valid.IsNil(instance) {
		return map[uint8]installmethod.Enum{}, fail.InvalidInstanceError()
	}

	out := make(map[uint8]installmethod.Enum)
	instance.localCache.RLock()
	defer instance.localCache.RUnlock()
	instance.localCache.installMethods.Range(func(k, v interface{}) bool {
		var ok bool
		out[k.(uint8)], ok = v.(installmethod.Enum)
		return ok
	})
	return out, nil
}

// RegisterFeature registers an installed Feature in metadata of Host
func (instance *Host) RegisterFeature(ctx context.Context, feat resources.Feature, requiredBy resources.Feature, clusterContext bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if feat == nil {
		return fail.InvalidParameterCannotBeNilError("feat")
	}

	return instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
			featuresV1, innerErr := lang.Cast[*propertiesv1.HostFeatures](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			item, ok := featuresV1.Installed[feat.GetName()]
			if !ok {
				requirements, innerXErr := feat.Dependencies(ctx)
				if innerXErr != nil {
					return innerXErr
				}

				item = propertiesv1.NewHostInstalledFeature()
				if requirements != nil {
					item.Requires = requirements
				}
				item.HostContext = !clusterContext

				featuresV1.Installed[feat.GetName()] = item
			}
			if item != nil {
				if !valid.IsNil(requiredBy) {
					if item.RequiredBy != nil {
						item.RequiredBy[requiredBy.GetName()] = struct{}{}
					} else {
						item.RequiredBy = make(map[string]struct{})
						item.RequiredBy[requiredBy.GetName()] = struct{}{}
					}
				}
			}

			return nil
		})
	})
}

// UnregisterFeature unregisters a Feature from Cluster metadata
func (instance *Host) UnregisterFeature(ctx context.Context, feat string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if ctx == nil {
		return fail.InvalidParameterCannotBeNilError("ctx")
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	return instance.Alter(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
			featuresV1, innerErr := lang.Cast[*propertiesv1.HostFeatures](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			delete(featuresV1.Installed, feat)
			for _, v := range featuresV1.Installed {
				delete(v.RequiredBy, feat)
			}
			return nil
		})
	})
}

// ListEligibleFeatures returns a slice of features eligible to Cluster
func (instance *Host) ListEligibleFeatures(ctx context.Context) (_ []resources.Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []resources.Feature
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	return filterEligibleFeatures(ctx, instance, allWithEmbedded)
}

// ListInstalledFeatures returns a slice of installed features
func (instance *Host) ListInstalledFeatures(ctx context.Context) (_ []resources.Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []resources.Feature
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	list, _ := instance.InstalledFeatures(ctx)
	out := make([]resources.Feature, 0, len(list))
	for _, v := range list {
		item, xerr := NewFeature(ctx, instance.Scope(), v)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return emptySlice, xerr
		}

		out = append(out, item)
	}
	return out, nil
}

// InstalledFeatures returns a slice of installed features
// satisfies interface resources.Targetable
func (instance *Host) InstalledFeatures(ctx context.Context) ([]string, fail.Error) {
	if valid.IsNull(instance) {
		return []string{}, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return []string{}, fail.InvalidParameterCannotBeNilError("ctx")
	}

	var out []string
	xerr := instance.Review(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
			featuresV1, innerErr := lang.Cast[*propertiesv1.HostFeatures](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			for k := range featuresV1.Installed {
				out = append(out, k)
			}
			return nil
		})
	})
	if xerr != nil {
		return []string{}, xerr
	}
	return out, nil
}

// ComplementFeatureParameters configures parameters that are appropriate for the target
// satisfies interface install.Targetable
func (instance *Host) ComplementFeatureParameters(ctx context.Context, v data.Map[string, any]) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if v == nil {
		return fail.InvalidParameterCannotBeNilError("v")
	}

	// FIXME: Bug mitigation
	if _, ok := v["DefaultRouteIP"]; !ok { // FIXME: Hardcoded stuff everywhere !!
		v["DefaultRouteIP"] = ""
	}

	v["ShortHostname"] = instance.GetName()
	domain := ""

	xerr := instance.Review(ctx, func(p clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.DescriptionV1, func(p clonable.Clonable) fail.Error {
			hostDescriptionV1, innerErr := lang.Cast[*propertiesv1.HostDescription](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			domain = hostDescriptionV1.Domain
			if domain != "" {
				domain = "." + domain
			}
			return nil
		})
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["Hostname"] = instance.GetName() + domain
	v["HostIP"], xerr = instance.GetPrivateIP(ctx)
	if xerr != nil {
		return xerr
	}

	v["PublicIP"], xerr = instance.GetPublicIP(ctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// Host may not have Public IP, ignore this error
			debug.IgnoreError(xerr)
		default:
			return xerr
		}
	}

	if _, ok := v["Username"]; !ok {
		config, xerr := instance.Service().ConfigurationOptions()
		if xerr != nil {
			return xerr
		}

		v["Username"] = config.OperatorUsername
		if v["username"] == "" {
			v["Username"] = abstract.DefaultUser
		}
	}

	subnetInstance, xerr := instance.unsafeGetDefaultSubnet(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	isGateway, xerr := instance.IsGateway(ctx)
	if xerr != nil {
		return xerr
	}
	v["HostIsGateway"] = isGateway

	single, xerr := instance.IsSingle(ctx)
	if xerr != nil {
		return xerr
	}
	if single {
		v["PrimaryGatewayIP"] = ""
		v["GatewayIP"] = "" // legacy
		v["PrimaryPublicIP"] = ""

		v["SecondaryGatewayIP"] = ""
		v["SecondaryPublicIP"] = ""

		v["DefaultRouteIP"] = ""
	} else {
		gwInstance, xerr := subnetInstance.InspectGateway(ctx, true)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		v["PrimaryGatewayIP"], xerr = gwInstance.GetPrivateIP(ctx)
		if xerr != nil {
			return xerr
		}

		v["GatewayIP"] = v["PrimaryGatewayIP"] // legacy
		v["PrimaryPublicIP"], xerr = gwInstance.GetPublicIP(ctx)
		if xerr != nil {
			return xerr
		}

		gwInstance, xerr = subnetInstance.InspectGateway(ctx, false)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				v["SecondaryGatewayIP"] = ""
				v["SecondaryPublicIP"] = ""
				debug.IgnoreError(xerr)
			default:
				return xerr
			}
		} else {
			v["SecondaryGatewayIP"], xerr = gwInstance.GetPrivateIP(ctx)
			if xerr != nil {
				return xerr
			}

			v["SecondaryPublicIP"], xerr = gwInstance.GetPublicIP(ctx)
			if xerr != nil {
				return xerr
			}
		}

		v["EndpointIP"], xerr = subnetInstance.GetEndpointIP(ctx)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return xerr
		}

		v["PublicIP"] = v["EndpointIP"]
	}

	// Some Cluster-related values that need to exist
	v["ClusterFlavor"] = ""
	v["ClusterAdminUsername"] = ""
	v["ClusterAdminPassword"] = ""

	return nil
}

// IsFeatureInstalled ...
func (instance *Host) IsFeatureInstalled(ctx context.Context, name string) (found bool, ferr fail.Error) {
	found = false
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return false, fail.InvalidParameterError("name", "cannot be empty string")
	}

	return found, instance.Inspect(ctx, func(_ clonable.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.FeaturesV1, func(p clonable.Clonable) fail.Error {
			featuresV1, innerErr := lang.Cast[*propertiesv1.HostFeatures](p)
			if innerErr != nil {
				return fail.Wrap(innerErr)
			}

			_, found = featuresV1.Installed[name]
			return nil
		})
	})
}
