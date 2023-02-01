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
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/abstract"
	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// AddFeature handles 'safescale host feature add <host name or id> <feature name>'
func (instance *Host) AddFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (outcomes rscapi.Results, ferr fail.Error) {
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

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	feat, xerr := NewFeature(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	outcomes, xerr = func() (rscapi.Results, fail.Error) {
		// /!\ Do not cross references in alter, it makes deadlock
		outcomes, xerr := feat.Add(ctx, instance, vars, opts...)
		if xerr != nil {
			return outcomes, xerr
		}
		// updates HostFeatures property for host
		xerr = alterHostMetadataProperty(ctx, hostTrx, hostproperty.FeaturesV1, func(hostFeaturesV1 *propertiesv1.HostFeatures) fail.Error {
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
		return outcomes, xerr
	}()

	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	return outcomes, nil
}

// CheckFeature ...
func (instance *Host) CheckFeature(ctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (_ rscapi.Results, ferr fail.Error) {
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

	feat, xerr := NewFeature(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Check(ctx, instance, vars, opts...)
}

// DeleteFeature handles 'safescale host delete-feature <host name> <feature name>'
func (instance *Host) DeleteFeature(inctx context.Context, name string, vars data.Map[string, any], opts ...options.Option) (_ rscapi.Results, ferr fail.Error) {
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

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	feat, xerr := NewFeature(ctx, name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = func() fail.Error {
		outcomes, innerXErr := feat.Remove(ctx, instance, vars, opts...)
		if innerXErr != nil {
			return fail.NewError(innerXErr, nil, "error uninstalling feature '%s' on '%s'", name, instance.GetName())
		}

		if !outcomes.IsSuccessful() {
			msg := fmt.Sprintf("failed to delete feature '%s' from host '%s'", name, instance.GetName())
			tracer.Trace(strprocess.Capitalize(msg) + ":\n" + outcomes.ErrorMessage())
			return fail.NewError(msg)
		}

		// updates HostFeatures property for host
		return alterHostMetadataProperty(ctx, hostTrx, hostproperty.FeaturesV1, func(hostFeaturesV1 *propertiesv1.HostFeatures) fail.Error {
			delete(hostFeaturesV1.Installed, name)
			return nil
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
func (instance *Host) RegisterFeature(ctx context.Context, feat *Feature, requiredBy *Feature, clusterContext bool) (ferr fail.Error) {
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

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return alterHostMetadataProperty(ctx, hostTrx, hostproperty.FeaturesV1, func(featuresV1 *propertiesv1.HostFeatures) fail.Error {
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
		if item != nil && !valid.IsNil(requiredBy) {
			if item.RequiredBy != nil {
				item.RequiredBy[requiredBy.GetName()] = struct{}{}
			} else {
				item.RequiredBy = make(map[string]struct{})
				item.RequiredBy[requiredBy.GetName()] = struct{}{}
			}
		}

		return nil
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

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return alterHostMetadataProperty(ctx, hostTrx, hostproperty.FeaturesV1, func(featuresV1 *propertiesv1.HostFeatures) fail.Error {
		delete(featuresV1.Installed, feat)
		for _, v := range featuresV1.Installed {
			delete(v.RequiredBy, feat)
		}
		return nil
	})
}

// ListEligibleFeatures returns a slice of features eligible to Cluster
func (instance *Host) ListEligibleFeatures(ctx context.Context) (_ []*Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []*Feature
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	return filterEligibleFeatures(ctx, instance, allWithEmbedded)
}

// ListInstalledFeatures returns a slice of installed features
func (instance *Host) ListInstalledFeatures(ctx context.Context) (_ []*Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []*Feature
	if valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	list, _ := instance.InstalledFeatures(ctx)
	out := make([]*Feature, 0, len(list))
	for _, v := range list {
		item, xerr := NewFeature(ctx, v)
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
func (instance *Host) InstalledFeatures(ctx context.Context) (_ []string, ferr fail.Error) {
	if valid.IsNull(instance) {
		return []string{}, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return []string{}, fail.InvalidParameterCannotBeNilError("ctx")
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return nil, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	var out []string
	xerr = inspectHostMetadataProperty(ctx, hostTrx, hostproperty.FeaturesV1, func(featuresV1 *propertiesv1.HostFeatures) fail.Error {
		for k := range featuresV1.Installed {
			out = append(out, k)
		}
		return nil
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

	isGateway, xerr := instance.IsGateway(ctx)
	if xerr != nil {
		return xerr
	}

	v["HostIP"], xerr = instance.GetPrivateIP(ctx)
	if xerr != nil {
		return xerr
	}

	v["PublicIP"], xerr = instance.GetPublicIP(ctx)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// Host may not have Public IP, ignore this error
			debug.IgnoreErrorWithContext(ctx, xerr)
		default:
			return xerr
		}
	}

	single, xerr := instance.IsSingle(ctx)
	if xerr != nil {
		return xerr
	}

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	// FIXME: Bug mitigation
	if _, ok := v["DefaultRouteIP"]; !ok { // FIXME: Hardcoded stuff everywhere !!
		v["DefaultRouteIP"] = ""
	}

	v["ShortHostname"] = instance.GetName()
	domain := ""

	xerr = inspectHostMetadataProperty(ctx, hostTrx, hostproperty.DescriptionV1, func(hostDescriptionV1 *propertiesv1.HostDescription) fail.Error {
		domain = hostDescriptionV1.Domain
		if domain != "" {
			domain = "." + domain
		}
		return nil
	})
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	v["Hostname"] = hostTrx.GetName() + domain
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

	v["HostIsGateway"] = isGateway

	subnetInstance, xerr := instance.trxGetDefaultSubnet(ctx, hostTrx)
	xerr = debug.InjectPlannedFail(xerr)
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
				debug.IgnoreErrorWithContext(ctx, xerr)
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

	hostTrx, xerr := newHostTransaction(ctx, instance)
	if xerr != nil {
		return false, xerr
	}
	defer hostTrx.TerminateFromError(ctx, &ferr)

	return found, inspectHostMetadataProperty(ctx, hostTrx, hostproperty.FeaturesV1, func(featuresV1 *propertiesv1.HostFeatures) fail.Error {
		_, found = featuresV1.Installed[name]
		return nil
	})
}
