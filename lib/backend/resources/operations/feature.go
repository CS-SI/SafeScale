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
	"fmt"
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hostproperty"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/hoststate"
	propertiesv1 "github.com/CS-SI/SafeScale/v22/lib/backend/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/serialize"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/protocol"
	"github.com/CS-SI/SafeScale/v22/lib/utils/cli/enums/outputs"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v22/lib/utils/temporal"
	"github.com/CS-SI/SafeScale/v22/lib/utils/valid"
)

// Feature contains the information about a FeatureFile to be installed
type Feature struct {
	file       *FeatureFile
	installers map[installmethod.Enum]Installer // defines the installers available for the Feature
	svc        iaas.Service                     // is the iaas.Service to use to interact with Cloud Provider

	machines map[string]resources.Host

	conditionedParameters ConditionedFeatureParameters
}

// NewFeature searches for a spec file name 'name' and initializes a new Feature object
// with its content
// error contains :
//   - fail.ErrNotFound if no Feature is found by its name
//   - fail.ErrSyntax if Feature found contains syntax error
func NewFeature(ctx context.Context, svc iaas.Service, name string) (_ resources.Feature, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	select {
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	default:
	}

	featureFileInstance, xerr := LoadFeatureFile(ctx, svc, name, false)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	featureInstance := &Feature{
		file:     featureFileInstance,
		machines: make(map[string]resources.Host),
		svc:      svc,
	}
	return featureInstance, nil
}

// NewEmbeddedFeature searches for an embedded featured named 'name' and initializes a new Feature object
// with its content
func NewEmbeddedFeature(ctx context.Context, svc iaas.Service, name string) (_ resources.Feature, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	select {
	case <-ctx.Done():
		return nil, fail.ConvertError(ctx.Err())
	default:
	}

	featureFileInstance, xerr := LoadFeatureFile(ctx, svc, name, true)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	featureInstance := &Feature{
		file: featureFileInstance,
		svc:  svc,
	}

	return featureInstance, nil
}

// IsNull tells if the instance represents a null value
func (instance *Feature) IsNull() bool {
	return instance == nil || instance.file == nil
}

// Clone ...
// satisfies interface data.Clonable
func (instance *Feature) Clone() (data.Clonable, error) {
	res := &Feature{}
	return res.Replace(instance)
}

// Replace ...
// satisfies interface data.Clonable
// may panic
func (instance *Feature) Replace(p data.Clonable) (data.Clonable, error) {
	if instance == nil || p == nil {
		return nil, fail.InvalidInstanceError()
	}

	src, ok := p.(*Feature)
	if !ok {
		return nil, fmt.Errorf("p is not a *Feature")
	}

	*instance = *src
	instance.installers = make(map[installmethod.Enum]Installer, len(src.installers))
	for k, v := range src.installers {
		instance.installers[k] = v
	}
	return instance, nil
}

// GetName returns the display name of the Feature, with error handling
func (instance *Feature) GetName() string {
	return instance.file.displayName
}

// GetID ...
func (instance *Feature) GetID() (string, error) {
	if instance == nil {
		return "", fmt.Errorf("invalid instance")
	}
	return instance.GetName(), nil
}

// GetFilename returns the filename of the Feature definition, with error handling
func (instance *Feature) GetFilename(ctx context.Context) (string, fail.Error) {
	if valid.IsNil(instance) {
		return "", fail.InvalidInstanceError()
	}

	return instance.file.fileName, nil
}

// GetDisplayFilename returns the filename of the Feature definition, beautifulled, with error handling
func (instance *Feature) GetDisplayFilename(ctx context.Context) string {
	if valid.IsNil(instance) {
		return ""
	}
	return instance.file.displayFileName
}

// InstanciateInstallerOfMethod instantiates the right installer corresponding to the method
func (instance *Feature) InstanciateInstallerOfMethod(m installmethod.Enum) Installer {
	if instance.IsNull() {
		return nil
	}

	var installer Installer
	switch m {
	case installmethod.Bash:
		installer = newBashInstaller()
	case installmethod.None:
		installer = newNoneInstaller()
	}
	return installer
}

// Specs returns a copy of the spec file (we don't want external use to modify Feature.specs)
func (instance *Feature) Specs() *viper.Viper {
	if valid.IsNil(instance) {
		return &viper.Viper{}
	}

	return instance.file.Specs()
}

// Applicable tells if the Feature is installable on the target
func (instance *Feature) Applicable(ctx context.Context, tg resources.Targetable) (bool, fail.Error) {
	if valid.IsNil(instance) {
		return false, fail.InvalidInstanceError()
	}

	// 1st check Feature is suitable for target
	switch tg.TargetType() {
	case featuretargettype.Cluster:
		casted, ok := tg.(*Cluster)
		if !ok {
			return false, fail.InconsistentError("failed to cast target as '*Cluster'")
		}
		flavor, xerr := casted.GetFlavor(ctx)
		if xerr != nil {
			return false, fail.Wrap(xerr, "failed to get Cluster Flavor")
		}
		if _, ok := instance.file.suitableFor[flavor.String()]; !ok {
			return false, nil
		}

	case featuretargettype.Host:
		if _, ok := instance.file.suitableFor["host"]; !ok {
			return false, nil
		}
	}

	// 2nd in case of a cluster, check cluster sizing requirements
	switch tg.TargetType() {
	case featuretargettype.Cluster:
		// FIXME: implement this
	default:
	}

	// 2nd check there is an install method the target can use
	methods, xerr := tg.InstallMethods(ctx)
	if xerr != nil {
		return false, xerr
	}

	for _, k := range methods {
		installer := instance.InstanciateInstallerOfMethod(k)
		if installer != nil {
			return true, nil
		}
	}
	return false, nil
}

// Check if Feature is installed on target
// Check is ok if error is nil and Results.Successful() is true
func (instance *Feature) Check(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)
	defer elapsed(ctx, "Feature.Check")()

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}

	featureName := instance.GetName()
	targetName := target.GetName()
	targetType := strings.ToLower(target.TargetType().String())
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	// -- passive check if feature is installed on target
	switch target.(type) { // nolint
	case resources.Host:
		var found bool
		castedTarget, ok := target.(*Host)
		if !ok {
			return &results{}, fail.InconsistentError("failed to cast target to '*Host'")
		}

		xerr := castedTarget.Review(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
				hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				_, found = hostFeaturesV1.Installed[instance.GetName()]
				return nil
			})
		})
		if xerr == nil {
			if found {
				outcomes := &results{}
				_ = outcomes.Add(featureName, &unitResults{
					targetName: &stepResult{
						complete: true,
						success:  true,
					},
				})
				return outcomes, nil
			}
		} else {
			debug.IgnoreError2(ctx, xerr)
		}
	case resources.Cluster:
		var found bool
		castedTarget, ok := target.(*Cluster)
		if !ok {
			return &results{}, fail.InconsistentError("failed to cast target to '*Host'")
		}

		xerr := castedTarget.Review(ctx, func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(clusterproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
				clufea, ok := clonable.(*propertiesv1.ClusterFeatures)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.ClusterFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				_, found = clufea.Installed[instance.GetName()]
				return nil
			})
		})
		if xerr == nil {
			if found {
				outcomes := &results{}
				_ = outcomes.Add(featureName, &unitResults{
					targetName: &stepResult{
						complete: true,
						success:  true,
					},
				})
				return outcomes, nil
			}
		} else {
			debug.IgnoreError2(ctx, xerr)
		}
	}

	switch ata := target.(type) {
	case resources.Host:
		state, xerr := ata.ForceGetState(ctx)
		if xerr != nil {
			return nil, xerr
		}

		if state != hoststate.Started {
			return nil, fail.InvalidRequestError(fmt.Sprintf("cannot check feature on '%s', '%s' is NOT started", targetName, targetName))
		}
	default:
	}

	// -- fall back to active check
	installer, xerr := instance.determineInstallerForTarget(ctx, target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.WithContext(ctx).Debugf("Checking if Feature '%s' is installed on %s '%s'...\n", featureName, targetType, targetName)

	// Inits and checks target parameters
	myV, xerr := instance.prepareParameters(ctx, v, target)
	if xerr != nil {
		return nil, xerr
	}

	r, xerr := installer.Check(ctx, instance, target, myV, s)
	if xerr != nil {
		return nil, xerr
	}

	return r, xerr
}

// prepareConditionedParameters builds a map of strings with final value set, picking it from externals if provided (otherwise, default value is set)
// Returned error may be:
//   - nil: everything went well
//   - fail.InvalidRequestError: a required parameter is missing (value not provided in externals and no default value defined)
func (instance Feature) prepareParameters(ctx context.Context, externals data.Map, target resources.Targetable) (data.Map, fail.Error) {
	defer elapsed(ctx, "prepareParameters")()
	xerr := instance.conditionParameters(ctx, externals, target)
	if xerr != nil {
		return nil, xerr
	}

	// Inits target specific parameters
	myV := instance.conditionedParameters.ToMap()
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return myV, nil
}

// conditionParameters inits if needed the Feature parameters conditioned for final use
// Returned error may be:
//   - nil: everything went well
//   - fail.InvalidRequestError: a required parameter is missing (value not provided in externals and no default value defined)
func (instance *Feature) conditionParameters(ctx context.Context, externals data.Map, target resources.Targetable) fail.Error {
	defer elapsed(ctx, "conditionParameters")()
	if instance.conditionedParameters == nil {
		var xerr fail.Error
		instance.conditionedParameters = make(ConditionedFeatureParameters)
		for k, v := range instance.file.parameters {
			var item ConditionedFeatureParameter
			value, ok := externals[k].(string)
			if ok {
				item, xerr = NewConditionedFeatureParameter(v, &value)
			} else {
				value, ok := externals[instance.GetName()+":"+k].(string)
				if ok {
					item, xerr = NewConditionedFeatureParameter(v, &value)
				} else {
					item, xerr = NewConditionedFeatureParameter(v, nil)
				}
			}
			if xerr != nil {
				return xerr
			}

			instance.conditionedParameters[k] = item

			if _, ok := instance.file.versionControl[k]; ok {
				value, xerr := instance.controlledParameter(ctx, k, target)
				if xerr != nil {
					logrus.WithContext(ctx).Error(xerr.Error())
				} else {
					item.controlled = true
					item.currentValue = value
				}
			}

		}
	}

	return nil
}

// determineInstallerForTarget isolates the available installer to use for target (one that is define in the file and applicable on target)
func (instance *Feature) determineInstallerForTarget(ctx context.Context, target resources.Targetable, action string) (_ Installer, ferr fail.Error) {
	methods, xerr := target.InstallMethods(ctx)
	if xerr != nil {
		return nil, xerr
	}

	var installer Installer
	w := instance.file.installers
	for _, v := range methods {
		meth := v
		if _, ok := w[strings.ToLower(meth.String())]; ok {
			installer = instance.InstanciateInstallerOfMethod(meth)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fail.NotAvailableError("failed to find a way to %s '%s'", action, instance.GetName())
	}
	return installer, nil
}

// Add installs the Feature on the target
// Installs succeeds if error == nil and Results.Successful() is true
func (instance *Feature) Add(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}

	featureName := instance.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()

	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()

	defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Starting addition of Feature '%s' on %s '%s'...", featureName, targetType, targetName), fmt.Sprintf("Ending addition of Feature '%s' on %s '%s' with err '%s'", featureName, targetType, targetName, ferr))()

	installer, xerr := instance.determineInstallerForTarget(ctx, target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Inits and checks target parameters
	myV, xerr := instance.prepareParameters(ctx, v, target)
	if xerr != nil {
		return nil, xerr
	}

	if !s.AddUnconditionally {
		results, xerr := instance.Check(ctx, target, v, s)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to check Feature '%s'", featureName)
		}

		if results.Successful() {
			logrus.WithContext(ctx).Infof("Feature '%s' is already installed.", featureName)
			return results, nil
		}
	}

	if !s.SkipFeatureRequirements {
		xerr = instance.installRequirements(ctx, target, v, s)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to install dependencies")
		}
	}

	results, xerr := installer.Add(ctx, instance, target, myV, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = registerOnSuccessfulHostsInCluster(ctx, instance.svc, target, instance, nil, results)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = target.RegisterFeature(ctx, instance, nil, target.TargetType() == featuretargettype.Cluster)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return results, nil
}

// Remove uninstalls the Feature from the target
func (instance *Feature) Remove(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}

	featureName := instance.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()
	tracer := debug.NewTracer(ctx, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(ctx, &ferr, tracer.TraceMessage(""))

	var (
		results resources.Results
		// installer Installer
	)

	installer, xerr := instance.determineInstallerForTarget(ctx, target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer temporal.NewStopwatch().OnExitLogInfo(ctx, fmt.Sprintf("Starting removal of Feature '%s' from %s '%s'", featureName, targetType, targetName), fmt.Sprintf("Ending removal of Feature '%s' from %s '%s'", featureName, targetType, targetName))()

	// Inits and checks target parameters
	myV, xerr := instance.prepareParameters(ctx, v, target)
	if xerr != nil {
		return nil, xerr
	}

	results, xerr = installer.Remove(ctx, instance, target, myV, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return results, xerr
	}

	xerr = unregisterOnSuccessfulHostsInCluster(ctx, instance.svc, target, instance, results)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = target.UnregisterFeature(ctx, instance.GetName())
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return results, nil
}

// Dependencies returns a list of features needed as dependencies
func (instance *Feature) Dependencies(ctx context.Context) (map[string]struct{}, fail.Error) {
	if valid.IsNil(instance) {
		return nil, fail.InvalidInstanceError()
	}

	return instance.file.getDependencies(), nil
}

// ClusterSizingRequirements returns the cluster sizing requirements for all flavors
// FIXME: define a type to return instead of a map[string]interface{}
func (instance *Feature) ClusterSizingRequirements() (map[string]interface{}, fail.Error) {
	if instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if instance.file == nil {
		return nil, fail.InvalidInstanceContentError("instance.file", "cannot be nil")
	}

	return instance.file.getClusterSizingRequirements(), nil
}

// ClusterSizingRequirementsForFlavor returns the cluster sizing requirements for specified flavors
// returns:
//   - nil, nil: no sizing requirements defined for the flavor
//   - map[string]interface{}, nil: sizing requirements defined for the flavor
//   - nil, *fail.ErrInvalidInstance: called from a null valued instance
//
// FIXME: define a type to return instead of a map[string]interface{}
func (instance *Feature) ClusterSizingRequirementsForFlavor(flavor string) (map[string]interface{}, fail.Error) {
	if instance.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if instance.file == nil {
		return nil, fail.InvalidInstanceContentError("instance.file", "cannot be nil")
	}

	return instance.file.getClusterSizingRequirementsForFlavor(flavor), nil
}

// installRequirements walks through dependencies and installs them if needed
func (instance *Feature) installRequirements(ctx context.Context, t resources.Targetable, v data.Map, s resources.FeatureSettings) fail.Error {
	requirements := instance.file.getDependencies()
	if len(requirements) > 0 {
		{
			msgHead := fmt.Sprintf("Checking dependencies of Feature '%s'", instance.GetName())
			var msgTail string
			switch t.TargetType() {
			case featuretargettype.Host:
				msgTail = fmt.Sprintf("on host '%s'", t.GetName())
			case featuretargettype.Node:
				msgTail = fmt.Sprintf("on cluster node '%s'", t.GetName())
			case featuretargettype.Cluster:
				msgTail = fmt.Sprintf("on cluster '%s'", t.GetName())
			}
			logrus.WithContext(ctx).Debugf("%s %s...", msgHead, msgTail)
		}

		targetIsCluster := t.TargetType() == featuretargettype.Cluster
		for requirement := range requirements {
			needed, xerr := NewFeature(ctx, instance.svc, requirement)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to find required Feature '%s'", requirement)
			}

			results, xerr := needed.Check(ctx, t, v, s)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to check required Feature '%s' for Feature '%s'", requirement, instance.GetName())
			}

			if !results.Successful() {
				results, xerr := needed.Add(ctx, t, v, s)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to install required Feature '%s'", requirement)
				}

				if !results.Successful() {
					return fail.NewError("failed to install required Feature '%s':\n%s", requirement, results.AllErrorMessages())
				}

				// Register the needed Feature as a requirement for instance
				xerr = t.RegisterFeature(ctx, needed, instance, targetIsCluster)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}
		}
	}
	return nil
}

func registerOnSuccessfulHostsInCluster(ctx context.Context, svc iaas.Service, target resources.Targetable, installed resources.Feature, requiredBy resources.Feature, results resources.Results) fail.Error {
	if target.TargetType() == featuretargettype.Cluster {
		// Walk through results and register Feature in successful hosts
		successfulHosts := map[string]struct{}{}
		for _, k := range results.Keys() {
			r := results.ResultsOfKey(k)
			for _, l := range r.Keys() {
				s := r.ResultOfKey(l)
				if s != nil {
					if s.Successful() {
						successfulHosts[l] = struct{}{}
					}
				}
			}
		}
		for k := range successfulHosts {
			host, xerr := LoadHost(ctx, svc, k)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = host.RegisterFeature(ctx, installed, requiredBy, true)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

func unregisterOnSuccessfulHostsInCluster(ctx context.Context, svc iaas.Service, target resources.Targetable, installed resources.Feature, results resources.Results) fail.Error {
	if target.TargetType() == featuretargettype.Cluster {
		// Walk through results and register Feature in successful hosts
		successfulHosts := map[string]struct{}{}
		for _, k := range results.Keys() {
			r := results.ResultsOfKey(k)
			for _, l := range r.Keys() {
				s := r.ResultOfKey(l)
				if s != nil {
					if s.Successful() {
						successfulHosts[l] = struct{}{}
					}
				}
			}
		}
		for k := range successfulHosts {
			host, xerr := LoadHost(ctx, svc, k)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = host.UnregisterFeature(ctx, installed.GetName())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

// ToProtocol converts a Feature to *protocol.FeatureResponse
func (instance Feature) ToProtocol(ctx context.Context) *protocol.FeatureResponse {
	out := &protocol.FeatureResponse{
		Name:     instance.GetName(),
		FileName: instance.GetDisplayFilename(ctx),
	}
	return out
}

// ListParametersWithControl returns a slice of parameter names that have control script
func (instance Feature) ListParametersWithControl(ctx context.Context) []string {
	out := make([]string, 0, len(instance.file.versionControl))
	for k := range instance.file.versionControl {
		out = append(out, k)
	}
	return out
}

// controlledParameter ...
func (instance Feature) controlledParameter(ctx context.Context, p string, target resources.Targetable) (string, fail.Error) {
	if ctx == nil {
		return "", fail.InvalidParameterCannotBeNilError("ctx")
	}
	if p == "" {
		return "", fail.InvalidParameterCannotBeEmptyStringError("p")
	}
	if target == nil {
		return "", fail.InvalidParameterCannotBeNilError("target")
	}

	if cc, ok := instance.file.versionControl[p]; ok {
		var host resources.Host
		switch target.TargetType() {
		case featuretargettype.Host, featuretargettype.Node:
			host, ok = target.(resources.Host)
			if !ok {
				return "", fail.InconsistentError("failed to cast target to 'resources.Host'")
			}
		case featuretargettype.Cluster:
			var xerr fail.Error
			cluster, ok := target.(*Cluster)
			if !ok {
				return "", fail.InconsistentError("failed to cast target to 'resources.Host'")
			}

			host, xerr = cluster.FindAvailableMaster(ctx)
			if xerr != nil {
				return "", xerr
			}
		}

		cmd, xerr := replaceVariablesInString(cc, data.Map{"ParameterValue": instance.conditionedParameters[p].currentValue})
		if xerr != nil {
			return "", xerr
		}

		timings, xerr := instance.svc.Timings()
		if xerr != nil {
			return "", xerr
		}

		retcode, stdout, stderr, xerr := host.Run(ctx, cmd, outputs.COLLECT, timings.ConnectionTimeout(), timings.ExecutionTimeout())
		if xerr != nil {
			return "", xerr
		}
		if retcode != 0 {
			msg := fmt.Sprintf("failed to control value of parameter '%s'", p)
			if stderr != "" {
				msg += fmt.Sprintf(" (%s)", stderr)
			}
			return "", fail.ExecutionError(nil, msg)
		}

		return stdout, nil
	}

	return "", fail.NotFoundError("no way to control the value of parameter '%s'", p)
}

// ExtractFeatureParameters convert a slice of string in format a=b into a map index on 'a' with value 'b'
func ExtractFeatureParameters(params []string) data.Map {
	out := data.NewMap()
	for _, v := range params {
		splitted := strings.Split(v, "=")
		if len(splitted) > 1 {
			out[splitted[0]] = splitted[1]
		} else {
			out[splitted[0]] = ""
		}
	}
	return out
}

// featureFilter represents the filter to apply on Features
type featureFilter string

const (
	embeddedOnly    featureFilter = "embedded"
	allWithEmbedded featureFilter = "all"
	withoutEmbedded featureFilter = "withoutEmbedded"
)

// filterEligibleFeatures lists the available features than can be installed on target
func filterEligibleFeatures(ctx context.Context, target resources.Targetable, filter featureFilter) ([]resources.Feature, fail.Error) {
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}

	// walk through the folders that may contain Feature files
	list, xerr := walkInsideFeatureFileFolders(ctx, filter)
	if xerr != nil {
		return nil, xerr
	}

	var out []resources.Feature
	for _, v := range list {
		entry, xerr := NewFeature(ctx, target.Service(), v)
		if xerr != nil {
			switch xerr.(type) {
			case *fail.ErrNotFound:
				// ignore a feature file not found; weird, but fs may have changed (will be handled properly later with fswatcher)
			case *fail.ErrSyntax:
				// When a syntax error occurs, log but do not fail
				logrus.WithContext(ctx).Error(fail.Wrap(xerr, "failed to load Feature '%s'", v))
				continue
			default:
				return nil, xerr
			}
		}

		ok, xerr := entry.Applicable(ctx, target)
		if xerr != nil {
			return nil, xerr
		}
		if ok {
			out = append(out, entry)
		}
	}

	return out, nil

}
