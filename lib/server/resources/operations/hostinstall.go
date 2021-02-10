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

	"github.com/sirupsen/logrus"

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
)

// AddFeature handles 'safescale host feature add <host name or id> <feature name>'
func (rh *host) AddFeature(task concurrency.Task, name string, vars data.Map, settings resources.FeatureSettings) (outcomes resources.Results, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
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
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
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
	if task == nil {
		return nil, fail.InvalidParameterCannotBeNilError("task")
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
func (rh host) TargetType() featuretargettype.Enum {
	if rh.IsNull() {
		return featuretargettype.UNKNOWN
	}
	return featuretargettype.HOST
}

// InstallMethods returns a list of installation methods useable on the target, ordered from upper to lower preference (1 = highest preference)
// satisfies interface install.Targetable
func (rh host) InstallMethods(task concurrency.Task) map[uint8]installmethod.Enum {
	if rh.IsNull() {
		logrus.Error(fail.InvalidInstanceError().Error())
		return map[uint8]installmethod.Enum{}
	}
	if task == nil {
		logrus.Error(fail.InvalidParameterCannotBeNilError("task").Error())
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
			index++
			rh.installMethods[index] = installmethod.None
			return nil
		})
	}
	return rh.installMethods
}

// RegisterFeature registers an installed Feature in metadata of Host
func (rh *host) RegisterFeature(task concurrency.Task, feat resources.Feature, requiredBy resources.Feature) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task == nil {
		return fail.InvalidParameterError("task", "cannot be nil")
	}
	if feat == nil {
		return fail.InvalidParameterError("feat", "cannot be nil")
	}

	return rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
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
				featuresV1.Installed[feat.GetName()] = item
			}
			if rf, ok := requiredBy.(*feature); ok && !rf.IsNull() {
				item.RequiredBy[rf.GetName()] = struct{}{}
			}
			return nil
		})
	})
}

// UnregisterFeature unregisters a Feature from Cluster metadata
func (rh *host) UnregisterFeature(task concurrency.Task, feat string) (xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return fail.InvalidInstanceError()
	}
	if task.IsNull() {
		return fail.InvalidParameterError("task", "cannot be null value of 'concurrency.Task'")
	}
	if feat == "" {
		return fail.InvalidParameterError("feat", "cannot be empty string")
	}

	return rh.Alter(task, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Alter(task, hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
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

// IsFeatureInstalled ...
func (rh *host) IsFeatureInstalled(task concurrency.Task, name string) (found bool, xerr fail.Error) {
	found = false
	defer fail.OnPanic(&xerr)

	if rh.IsNull() {
		return false, fail.InvalidInstanceError()
	}
	if name = strings.TrimSpace(name); name == "" {
		return false, fail.InvalidParameterError("name", "cannot be empty string")
	}

	return found, rh.Inspect(task, func(_ data.Clonable, props *serialize.JSONProperties) fail.Error {
		return props.Inspect(task, hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
			featuresV1, ok := clonable.(*propertiesv1.HostFeatures)
			if !ok {
				return fail.InconsistentError("``ropertoesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
			}

			_, found = featuresV1.Installed[name]
			return nil
		})
	})
}
