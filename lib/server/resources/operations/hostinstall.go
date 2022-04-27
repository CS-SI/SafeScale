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
	"reflect"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/hoststate"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installmethod"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/strprocess"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// AddFeature handles 'safescale host feature add <host name or id> <feature name>'
func (instance *Host) AddFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (outcomes resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", name).Entering()
	defer tracer.Exiting()

	targetName := instance.GetName()

	var state hoststate.Enum
	state, xerr = instance.GetState()
	if xerr != nil {
		return nil, xerr
	}

	if state != hoststate.Started {
		return nil, fail.InvalidRequestError(fmt.Sprintf("cannot install feature on '%s', '%s' is NOT started", targetName, targetName))
	}

	feat, xerr := NewFeature(task.Context(), instance.Service(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		var innerXErr fail.Error
		outcomes, innerXErr = feat.Add(task.Context(), instance, vars, settings)
		if innerXErr != nil {
			return innerXErr
		}

		// updates HostFeatures property for host
		return props.Alter(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("expected '*propertiesv1.HostFeatures', received '%s'", reflect.TypeOf(clonable))
			}

			requires, innerXErr := feat.Dependencies()
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
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	return outcomes, nil
}

// CheckFeature ...
func (instance *Host) CheckFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", name).Entering()
	defer tracer.Exiting()

	feat, xerr := NewFeature(task.Context(), instance.Service(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return feat.Check(task.Context(), instance, vars, settings)
}

// DeleteFeature handles 'safescale host delete-feature <host name> <feature name>'
func (instance *Host) DeleteFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	task, xerr := concurrency.TaskFromContextOrVoid(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, false /*tracing.ShouldTrace("resources.host") || tracing.ShouldTrace("resources.feature"), */, "(%s)", name).Entering()
	defer tracer.Exiting()

	targetName := instance.GetName()

	var state hoststate.Enum
	state, xerr = instance.GetState()
	if xerr != nil {
		return nil, xerr
	}

	if state != hoststate.Started {
		return nil, fail.InvalidRequestError(fmt.Sprintf("cannot delete feature on '%s', '%s' is NOT started", targetName, targetName))
	}

	feat, xerr := NewFeature(task.Context(), instance.Service(), name)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.Alter(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		outcomes, innerXErr := feat.Remove(task.Context(), instance, vars, settings)
		if innerXErr != nil {
			return fail.NewError(innerXErr, nil, "error uninstalling feature '%s' on '%s'", name, instance.GetName())
		}

		if !outcomes.Successful() {
			msg := fmt.Sprintf("failed to delete feature '%s' from host '%s'", name, instance.GetName())
			tracer.Trace(strprocess.Capitalize(msg) + ":\n" + outcomes.AllErrorMessages())
			return fail.NewError(msg)
		}

		// updates HostFeatures property for host
		return props.Alter(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("expected '*propertiesv1.HostFeatures', provided '%s'", reflect.TypeOf(clonable))
			}

			delete(hostFeaturesV1.Installed, name)
			return nil
		})
	})
	return nil, xerr
}

// TargetType returns the type of the target.
// satisfies install.Targetable interface.
func (instance *Host) TargetType() featuretargettype.Enum {
	if instance == nil || valid.IsNil(instance) {
		return featuretargettype.Unknown
	}

	return featuretargettype.Host
}

// InstallMethods returns a list of installation methods usable on the target, ordered from upper to lower preference (1 = highest preference)
// satisfies interface install.Targetable
func (instance *Host) InstallMethods() (map[uint8]installmethod.Enum, fail.Error) {
	if instance == nil || valid.IsNil(instance) {
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
func (instance *Host) RegisterFeature(feat resources.Feature, requiredBy resources.Feature, clusterContext bool) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if feat == nil {
		return fail.InvalidParameterCannotBeNilError("feat")
	}

	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var item *propertiesv1.HostInstalledFeature
			if item, ok = featuresV1.Installed[feat.GetName()]; !ok {
				requirements, innerXErr := feat.Dependencies()
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
func (instance *Host) UnregisterFeature(feat string) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	return instance.Alter(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
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
	if instance == nil || valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	// FIXME: 'allWithEmbedded' should be passed as parameter...
	return filterEligibleFeatures(ctx, instance, allWithEmbedded)
}

// ListInstalledFeatures returns a slice of installed features
func (instance *Host) ListInstalledFeatures(ctx context.Context) (_ []resources.Feature, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	var emptySlice []resources.Feature
	if instance == nil || valid.IsNil(instance) {
		return emptySlice, fail.InvalidInstanceError()
	}

	// instance.lock.RLock()
	// defer instance.lock.RUnlock()

	list := instance.InstalledFeatures()
	out := make([]resources.Feature, 0, len(list))
	for _, v := range list {
		item, xerr := NewFeature(ctx, instance.Service(), v)
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
func (instance *Host) InstalledFeatures() []string {
	if instance == nil {
		return []string{}
	}

	var out []string
	xerr := instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			for k := range featuresV1.Installed {
				out = append(out, k)
			}
			return nil
		})
	})
	if xerr != nil {
		logrus.Error(xerr.Error())
		return []string{}
	}
	return out
}

// ComplementFeatureParameters configures parameters that are appropriate for the target
// satisfies interface install.Targetable
func (instance *Host) ComplementFeatureParameters(ctx context.Context, v data.Map) (ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return fail.InvalidInstanceError()
	}
	if v == nil {
		return fail.InvalidParameterCannotBeNilError("v")
	}

	v["ShortHostname"] = instance.GetName()
	domain := ""

	xerr := instance.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
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
		config, xerr := instance.Service().GetConfigurationOptions()
		if xerr != nil {
			return xerr
		}
		if v["Username"], ok = config.Get("OperatorUsername"); !ok {
			v["Username"] = abstract.DefaultUser
		}
	}

	subnetInstance, xerr := instance.unsafeGetDefaultSubnet(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return xerr
	}

	single, xerr := instance.IsSingle()
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

	return nil
}

// IsFeatureInstalled ...
func (instance *Host) IsFeatureInstalled(name string) (found bool, ferr fail.Error) {
	found = false
	defer fail.OnPanic(&ferr)

	if instance == nil || valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return false, fail.InvalidParameterError("name", "cannot be empty string")
	}

	return found, instance.Inspect(func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("`propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found = featuresV1.Installed[name]
			return nil
		})
	})
}
