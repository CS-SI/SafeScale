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
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/abstract"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/serialize"
	"github.com/CS-SI/SafeScale/lib/utils/strprocess"
	"github.com/sirupsen/logrus"
)

// AddFeature handles 'safescale host feature add <host name or id> <feature name>'
func (instance *host) AddFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (outcomes resources.Results, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", name).Entering()
	defer tracer.Exiting()

	feat, xerr := NewFeature(task, instance.GetService(), name)
	if xerr != nil {
		return nil, xerr
	}

	xerr = instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		var innerXErr fail.Error
		outcomes, innerXErr = feat.Add(instance, vars, settings)
		if innerXErr != nil {
			return innerXErr
		}

		// updates HostFeatures property for host
		return props.Alter(/*task, */hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
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
func (instance *host) CheckFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.host"), "(%s)", name).Entering()
	defer tracer.Exiting()

	feat, xerr := NewFeature(task, instance.GetService(), name)
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

	return feat.Check(instance, vars, settings)
}

// DeleteFeature handles 'safescale host delete-feature <host name> <feature name>'
func (instance *host) DeleteFeature(ctx context.Context, name string, vars data.Map, settings resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("featureName", "cannot be empty string")
	}

	if task.Aborted() {
		return nil, fail.AbortedError(nil, "aborted")
	}

	tracer := debug.NewTracer(task, false /*Trace.IPAddress, */, "(%s)", name).Entering()
	defer tracer.Exiting()

	feat, xerr := NewFeature(task, instance.GetService(), name)
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

	xerr = instance.Alter(/*task,  */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		outcomes, innerXErr := feat.Remove(instance, vars, settings)
		if innerXErr != nil {
			return fail.NewError(innerXErr, nil, "error uninstalling feature '%s' on '%s'", name, instance.GetName())
		}

		if !outcomes.Successful() {
			msg := fmt.Sprintf("failed to delete feature '%s' from host '%s'", name, instance.GetName())
			tracer.Trace(strprocess.Capitalize(msg) + ":\n" + outcomes.AllErrorMessages())
			return fail.NewError(msg)
		}

		// updates HostFeatures property for host
		return props.Alter(/*task, */hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
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
func (instance *host) TargetType() featuretargettype.Enum {
	if instance.isNull() {
		return featuretargettype.UNKNOWN
	}

	return featuretargettype.HOST
}

// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
// satisfies interface install.Targetable
func (instance *host) InstallMethods(ctx context.Context) map[uint8]installmethod.Enum {
	// FIXME: Return error
	if instance.isNull() {
		logrus.Error(fail.InvalidInstanceError().Error())
		return map[uint8]installmethod.Enum{}
	}
	if task == nil {
		logrus.Error(fail.InvalidParameterCannotBeNilError("task").Error())
		return map[uint8]installmethod.Enum{}
	}

	if task.Aborted() {
		logrus.Error(fail.AbortedError(nil, "aborted").Error())
		return map[uint8]installmethod.Enum{}
	}

	if instance.installMethods == nil {
		instance.installMethods = map[uint8]installmethod.Enum{}

		_ = instance.Inspect(/*task, */func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			// props, inErr := instance.properties(task)
			// if inErr != nil {
			// 	return inErr
			// }

			// Ignore error in this special case; will fallback to use bash method if cannot determine operating system type and flavor
			var index uint8
			_ = props.Inspect(/*task, */hostproperty.SystemV1, func(clonable data.Clonable) fail.Error {
				systemV1, ok := clonable.(*propertiesv1.HostSystem)
				if !ok {
					logrus.Error(fail.InconsistentError("'*propertiesv1.HostSystem' expected, '%s' provided", reflect.TypeOf(clonable).String()))
				}
				if systemV1.Type == "linux" {
					switch systemV1.Flavor {
					case "centos", "redhat":
						index++
						instance.installMethods[index] = installmethod.Yum
					case "debian":
						fallthrough
					case "ubuntu":
						index++
						instance.installMethods[index] = installmethod.Apt
					case "fedora", "rhel":
						index++
						instance.installMethods[index] = installmethod.Dnf
					}
				}
				return nil
			})
			index++
			instance.installMethods[index] = installmethod.Bash
			index++
			instance.installMethods[index] = installmethod.None
			return nil
		})
	}
	return instance.installMethods
}

// RegisterFeature registers an installed Feature in metadata of Host
func (instance *host) RegisterFeature(ctx context.Context, feat resources.Feature, requiredBy resources.Feature, clusterContext bool) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if feat == nil {
		return fail.InvalidParameterCannotBeNilError("feat")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.Alter(/*task,  */func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(/*task, */hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("'*propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			var item *propertiesv1.HostInstalledFeature
			if item, ok = featuresV1.Installed[feat.GetName()]; !ok {
				requirements, innerXErr := feat.GetRequirements()
				if innerXErr != nil {
					return innerXErr
				}
				item = propertiesv1.NewHostInstalledFeature()
				item.Requires = requirements
				item.HostContext = !clusterContext
				featuresV1.Installed[feat.GetName()] = item
			}
			if rf, ok := requiredBy.(*feature); ok && !rf.isNull() {
				item.RequiredBy[rf.GetName()] = struct{}{}
			}
			return nil
		})
	})
}

// UnregisterFeature unregisters a Feature from Cluster metadata
func (instance *host) UnregisterFeature(ctx context.Context, feat string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	return instance.Alter(/*task,  */func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(/*task, */hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
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

// InstalledFeatures returns a list of installed features
// satisfies interface install.Targetable
func (instance *host) InstalledFeatures(ctx context.Context) []string {
	var list []string
	return list
}

// ComplementFeatureParameters configures parameters that are appropriate for the target
// satisfies interface install.Targetable
func (instance *host) ComplementFeatureParameters(ctx context.Context, v data.Map) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterCannotBeNilError("task")
	}
	if v == nil {
		return fail.InvalidParameterCannotBeNilError("v")
	}

	if task.Aborted() {
		return fail.AbortedError(nil, "aborted")
	}

	v["ShortHostname"] = instance.GetName()
	domain := ""
	xerr = instance.Review(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(/*task, */hostproperty.DescriptionV1, func(clonable data.Clonable) fail.Error {
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

	v["Hostname"] = instance.GetName() + domain

	v["HostIP"] = instance.privateIP
	v["PublicIP"] = instance.publicIP

	if _, ok := v["Username"]; !ok {
		v["Username"] = abstract.DefaultUser
	}

	rs, xerr := instance.unsafeGetDefaultSubnet(task)
	if xerr != nil {
		return xerr
	}

	rgw, xerr := rs.InspectGateway(task, true)
	if xerr != nil {
		return xerr
	}
	defer rgw.Released()

	v["PrimaryGatewayIP"] = rgw.(*host).privateIP
	v["GatewayIP"] = v["PrimaryGatewayIP"] // legacy
	v["PrimaryPublicIP"] = rgw.(*host).publicIP

	if rgw, xerr = rs.InspectGateway(task, false); xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotFound:
			// continue
		default:
			return xerr
		}
	} else {
		defer rgw.Released()

		v["SecondaryGatewayIP"] = rgw.(*host).privateIP
		v["SecondaryPublicIP"] = rgw.(*host).publicIP
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

// IsFeatureInstalled ...
func (instance *host) IsFeatureInstalled(ctx context.Context, name string) (found bool, xerr fail.Error) {
	found = false
	defer fail.OnPanic(&xerr)

	if instance.isNull() {
		return false, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return false, fail.InvalidParameterError("name", "cannot be empty string")
	}

	return found, instance.Inspect(/*task, */func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(/*task, */hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("``ropertoesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found = featuresV1.Installed[name]
			return nil
		})
	})
}
