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
	"io/ioutil"
	"reflect"
	"strings"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/v21/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data/serialize"
	"github.com/CS-SI/SafeScale/v21/lib/utils/valid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/v21/lib/protocol"
	"github.com/CS-SI/SafeScale/v21/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v21/lib/utils"
	"github.com/CS-SI/SafeScale/v21/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/v21/lib/utils/data"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
	"github.com/CS-SI/SafeScale/v21/lib/utils/temporal"
)

// Feature contains the information about an installable Feature
type Feature struct {
	displayName     string                           // is the name of the service
	fileName        string                           // is the name of the specification file
	displayFileName string                           // is the 'beautiful' name of the specification file
	embedded        bool                             // tells if the Feature is embedded in deploy
	installers      map[installmethod.Enum]Installer // defines the installers available for the Feature
	specs           *viper.Viper                     // is the Viper instance containing Feature specification
	svc             iaas.Service                     // is the iaas.Service to use to interact with Cloud Provider
}

func newFeature(displayName string, fileName string, displayFileName string, embedded bool, installers map[installmethod.Enum]Installer, specs *viper.Viper, svc iaas.Service) *Feature {
	return &Feature{displayName: displayName, fileName: fileName, displayFileName: displayFileName, embedded: embedded, installers: installers, specs: specs, svc: svc}
}

// FeatureNullValue returns a *Feature corresponding to a null value
func FeatureNullValue() *Feature {
	return newFeature("", "", "", false, make(map[installmethod.Enum]Installer), nil, nil)
}

// ListFeatures lists all features suitable for hosts or clusters
func ListFeatures(svc iaas.Service, suitableFor string) (_ []interface{}, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}

	var (
		cfgFiles []interface{}
		paths    []string
	)
	features := allEmbeddedFeaturesMap
	paths = append(paths, utils.AbsPathify("$HOME/.safescale/features"))
	paths = append(paths, utils.AbsPathify("$HOME/.config/safescale/features"))
	paths = append(paths, utils.AbsPathify("/etc/safescale/features"))

	for _, path := range paths {
		files, err := ioutil.ReadDir(path)
		if err != nil {
			debug.IgnoreError(err)
			continue
		}
		for _, f := range files {
			if strings.HasSuffix(strings.ToLower(f.Name()), ".yml") {
				feat, xerr := NewFeature(svc, strings.Replace(strings.ToLower(f.Name()), ".yml", "", 1))
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					debug.IgnoreError(xerr) // Don't hide errors
					continue
				}
				casted, ok := feat.(*Feature)
				if !ok {
					logrus.Warnf("feat should be a *Feature") // FIXME: This should be an error
					continue
				}
				if _, ok := allEmbeddedFeaturesMap[casted.displayName]; !ok {
					allEmbeddedFeaturesMap[casted.displayName] = casted
				}
			}
		}
	}

	for _, feat := range features {
		switch suitableFor {
		case "host":
			yamlKey := "feature.suitableFor.host"
			if feat.Specs().IsSet(yamlKey) {
				value := strings.ToLower(feat.Specs().GetString(yamlKey))
				if value == "ok" || value == "yes" || value == "true" || value == "1" {
					cfgFiles = append(cfgFiles, feat.fileName)
				}
			}
		case "cluster":
			yamlKey := "feature.suitableFor.cluster"
			if feat.Specs().IsSet(yamlKey) {
				values := strings.Split(strings.ToLower(feat.Specs().GetString(yamlKey)), ",")
				if values[0] == "all" || values[0] == "k8s" || values[0] == "boh" {
					cfg := struct {
						FeatureName    string   `json:"feature"`
						ClusterFlavors []string `json:"available-cluster-flavors"`
					}{feat.displayName, []string{}}

					cfg.ClusterFlavors = append(cfg.ClusterFlavors, values...)

					cfgFiles = append(cfgFiles, cfg)
				}
			}
		default:
			return nil, fail.SyntaxError("unknown parameter value: %s (should be 'host' or 'cluster')", suitableFor)
		}
	}

	return cfgFiles, nil
}

// NewFeature searches for a spec file name 'name' and initializes a new Feature object
// with its content
// error contains :
//    - fail.ErrNotFound if no Feature is found by its name
//    - fail.ErrSyntax if Feature found contains syntax error
func NewFeature(svc iaas.Service, name string) (_ resources.Feature, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("./features")
	v.AddConfigPath("./.safescale/features")
	v.AddConfigPath("$HOME/.safescale/features")
	v.AddConfigPath("$HOME/.config/safescale/features")
	v.AddConfigPath("/etc/safescale/features")
	v.SetConfigName(name)

	casted := FeatureNullValue()
	err := v.ReadInConfig()
	err = debug.InjectPlannedError(err)
	if err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			// Failed to find a spec file on filesystem, trying with embedded ones
			var ok bool
			if _, ok = allEmbeddedFeaturesMap[name]; !ok {
				return nil, fail.NotFoundError("failed to find a Feature named '%s'", name)
			}

			cloned, cerr := allEmbeddedFeaturesMap[name].Clone()
			if cerr != nil {
				return nil, fail.Wrap(cerr)
			}

			casted, ok = cloned.(*Feature)
			if !ok {
				return nil, fail.NewError("embedded feature should be a *Feature")
			}
			casted.displayFileName = name + ".yml [embedded]"

		default:
			return nil, fail.SyntaxError("failed to read the specification file of Feature called '%s': %s", name, err.Error())
		}
	} else if v.IsSet("feature") {
		casted = newFeature(name, v.ConfigFileUsed(), v.ConfigFileUsed(), false, make(map[installmethod.Enum]Installer), v, nil)
	}

	logrus.Tracef("loaded feature '%s' (%s)", casted.GetDisplayFilename(), casted.GetFilename())

	// if we can log the sha256 of the feature, do it
	filename := v.ConfigFileUsed()
	if filename != "" {
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		logrus.Tracef("loaded feature %s:SHA256:%s", name, getSHA256Hash(string(content)))
	}

	casted.svc = svc

	return casted, nil
}

// NewEmbeddedFeature searches for an embedded featured named 'name' and initializes a new Feature object
// with its content
func NewEmbeddedFeature(svc iaas.Service, name string) (_ resources.Feature, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	casted := FeatureNullValue()
	if _, ok := allEmbeddedFeaturesMap[name]; !ok {
		return casted, fail.NotFoundError("failed to find a Feature named '%s'", name)
	}

	cloned, cerr := allEmbeddedFeaturesMap[name].Clone()
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	var ok bool
	casted, ok = cloned.(*Feature)
	if !ok {
		return nil, fail.NewError("feature is not a *Feature")
	}
	casted.svc = svc

	// if we can log the sha256 of the feature, do it
	if casted.fileName != "" {
		content, err := ioutil.ReadFile(casted.fileName)
		if err != nil {
			return nil, fail.ConvertError(err)
		}
		logrus.Tracef("loaded feature %s:SHA256:%s", name, getSHA256Hash(string(content)))
	}

	casted.fileName += " [embedded]"

	return casted, nil
}

// IsNull tells if the instance represents a null value
func (instance *Feature) IsNull() bool {
	return instance == nil || instance.displayName == ""
}

// Clone ...
// satisfies interface data.Clonable
func (instance *Feature) Clone() (data.Clonable, error) {
	res := FeatureNullValue()
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
	if valid.IsNil(instance) {
		return ""
	}
	return instance.displayName
}

// GetID ...
func (instance *Feature) GetID() string {
	if valid.IsNil(instance) {
		return ""
	}
	return instance.GetName()
}

// GetFilename returns the filename of the Feature definition, with error handling
func (instance *Feature) GetFilename() string {
	if valid.IsNil(instance) {
		return ""
	}

	return instance.fileName
}

// GetDisplayFilename returns the filename of the Feature definition, beautifulled, with error handling
func (instance *Feature) GetDisplayFilename() string {
	if valid.IsNil(instance) {
		return ""
	}
	return instance.displayFileName
}

// installerOfMethod instanciates the right installer corresponding to the method
func (instance *Feature) installerOfMethod(m installmethod.Enum) Installer {
	if valid.IsNil(instance) {
		return nil
	}
	var installer Installer
	switch m {
	case installmethod.Bash:
		installer = newBashInstaller()
	case installmethod.Apt:
		installer = NewAptInstaller()
	case installmethod.Yum:
		installer = NewYumInstaller()
	case installmethod.Dnf:
		installer = NewDnfInstaller()
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
	roSpecs := *instance.specs
	return &roSpecs
}

// Applicable tells if the Feature is installable on the target
func (instance *Feature) Applicable(t resources.Targetable) bool {
	if valid.IsNil(instance) {
		return false
	}

	methods := t.InstallMethods()
	for _, k := range methods {
		installer := instance.installerOfMethod(k)
		if installer != nil {
			return true
		}
	}
	return false
}

// Check if Feature is installed on target
// Check is ok if error is nil and Results.Successful() is true
func (instance *Feature) Check(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
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

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
	}

	featureName := instance.GetName()
	targetName := target.GetName()
	targetType := strings.ToLower(target.TargetType().String())
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	// -- passive check if feature is installed on target
	switch target.(type) { // nolint
	case resources.Host:
		var found bool
		castedTarget, ok := target.(*Host)
		if !ok {
			return &results{}, fail.InconsistentError("failed to cast target to '*Host'")
		}

		xerr = castedTarget.Review(func(clonable data.Clonable, props *serialize.JSONProperties) fail.Error {
			return props.Inspect(hostproperty.FeaturesV1, func(clonable data.Clonable) fail.Error {
				hostFeaturesV1, ok := clonable.(*propertiesv1.HostFeatures)
				if !ok {
					return fail.InconsistentError("'*propertiesv1.HostFeatures' expected, '%s' provided", reflect.TypeOf(clonable).String())
				}
				_, found = hostFeaturesV1.Installed[instance.GetName()]
				return nil
			})
		})
		if xerr != nil {
			return nil, xerr
		}
		if found {
			outcomes := &results{}
			_ = outcomes.Add(featureName, &unitResults{
				targetName: &stepResult{
					completed: true,
					success:   true,
				},
			})
			return outcomes, nil
		}
	}

	// -- fall back to active check
	installer, xerr := instance.findInstallerForTarget(target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("Checking if Feature '%s' is installed on %s '%s'...\n", featureName, targetType, targetName)
	myV, cerr := v.FakeClone()
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// // Checks required parameters have their values
	// xerr = checkRequiredParameters(*instance, myV)
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return nil, xerr
	// }
	//
	r, xerr := installer.Check(ctx, instance, target, myV, s)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: restore Feature check using iaas.ResourceCache
	// _ = checkCache.ForceSet(cacheKey, results)
	return r, xerr
}

// findInstallerForTarget isolates the available installer to use for target (one that is define in the file and applicable on target)
func (instance *Feature) findInstallerForTarget(target resources.Targetable, action string) (installer Installer, ferr fail.Error) {
	methods := target.InstallMethods()
	w := instance.specs.GetStringMap("feature.install")
	for i := uint8(1); i <= uint8(len(methods)); i++ {
		meth := methods[i]
		if _, ok := w[strings.ToLower(meth.String())]; ok {
			if installer = instance.installerOfMethod(meth); installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fail.NotAvailableError("failed to find a way to %s '%s'", action, instance.GetName())
	}
	return installer, nil
}

// checkRequiredParameters Check if required parameters defined in specification file have been set in 'v'
func checkRequiredParameters(f Feature, v data.Map) fail.Error {
	if f.specs.IsSet("feature.parameters") {
		params := f.specs.GetStringSlice("feature.parameters")
		for _, p := range params {
			if p == "" {
				continue
			}

			splitted := strings.Split(p, "=")
			if _, ok := v[splitted[0]]; !ok {
				if len(splitted) == 1 {
					return fail.InvalidRequestError("missing value for parameter '%s'", p)
				}

				v[splitted[0]] = splitted[1]
			}
		}
	}
	return nil
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

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
	}

	featureName := instance.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting addition of Feature '%s' on %s '%s'...", featureName, targetType, targetName),
		fmt.Sprintf("Ending addition of Feature '%s' on %s '%s'", featureName, targetType, targetName),
	)()

	installer, xerr := instance.findInstallerForTarget(target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// 'v' may be updated by concurrent tasks, so use copy of it
	myV, cerr := v.FakeClone()
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// // Checks required parameters have value
	// xerr = checkRequiredParameters(*instance, myV)
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return nil, xerr
	// }

	if !s.AddUnconditionally {
		results, xerr := instance.Check(ctx, target, v, s)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to check Feature '%s'", featureName)
		}

		if results.Successful() {
			logrus.Infof("Feature '%s' is already installed.", featureName)
			return results, nil
		}
	}

	if !s.SkipFeatureRequirements {
		xerr = instance.installRequirements(ctx, target, v, s)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to install requirements")
		}
	}

	results, xerr := installer.Add(ctx, instance, target, myV, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = registerOnSuccessfulHostsInCluster(instance.svc, target, instance, nil, results)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: restore Feature check cache using iaas.ResourceCache
	// _ = checkCache.ForceSet(featureName()+"@"+targetName, results)

	return results, target.RegisterFeature(instance, nil, target.TargetType() == featuretargettype.Cluster)
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

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		switch xerr.(type) {
		case *fail.ErrNotAvailable:
			task, xerr = concurrency.VoidTask()
			if xerr != nil {
				return nil, xerr
			}
		default:
			return nil, xerr
		}
	}

	featureName := instance.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&ferr, tracer.TraceMessage(""))

	var (
		results resources.Results
		// installer Installer
	)

	installer, xerr := instance.findInstallerForTarget(target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting removal of Feature '%s' from %s '%s'", featureName, targetType, targetName),
		fmt.Sprintf("Ending removal of Feature '%s' from %s '%s'", featureName, targetType, targetName),
	)()

	// 'v' may be updated by parallel tasks, so use copy of it
	myV, cerr := v.FakeClone()
	if cerr != nil {
		return nil, fail.Wrap(cerr)
	}

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// // Checks required parameters have value
	// xerr = checkRequiredParameters(*instance, myV)
	// xerr = debug.InjectPlannedFail(xerr)
	// if xerr != nil {
	// 	return nil, xerr
	// }

	results, xerr = installer.Remove(ctx, instance, target, myV, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return results, xerr
	}

	xerr = unregisterOnSuccessfulHostsInCluster(instance.svc, target, instance, results)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return results, target.UnregisterFeature(instance.GetName())
}

const yamlKey = "feature.requirements.features"

// GetRequirements returns a list of features needed as requirements
func (instance *Feature) GetRequirements() (map[string]struct{}, fail.Error) {
	emptyMap := map[string]struct{}{}
	if valid.IsNil(instance) {
		return emptyMap, fail.InvalidInstanceError()
	}

	out := make(map[string]struct{}, len(instance.specs.GetStringSlice(yamlKey)))
	for _, r := range instance.specs.GetStringSlice(yamlKey) {
		out[r] = struct{}{}
	}
	return out, nil
}

// installRequirements walks through requirements and installs them if needed
func (instance *Feature) installRequirements(ctx context.Context, t resources.Targetable, v data.Map, s resources.FeatureSettings) fail.Error {
	if instance.specs.IsSet(yamlKey) {
		{
			msgHead := fmt.Sprintf("Checking requirements of Feature '%s'", instance.GetName())
			var msgTail string
			switch t.TargetType() {
			case featuretargettype.Host:
				msgTail = fmt.Sprintf("on host '%s'", t.(data.Identifiable).GetName())
			case featuretargettype.Node:
				msgTail = fmt.Sprintf("on cluster node '%s'", t.(data.Identifiable).GetName())
			case featuretargettype.Cluster:
				msgTail = fmt.Sprintf("on cluster '%s'", t.(data.Identifiable).GetName())
			}
			logrus.Debugf("%s %s...", msgHead, msgTail)
		}

		targetIsCluster := t.TargetType() == featuretargettype.Cluster

		// clone FeatureSettings to set DoNotUpdateHostMetadataInClusterContext
		for _, requirement := range instance.specs.GetStringSlice(yamlKey) {
			needed, xerr := NewFeature(instance.svc, requirement)
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
				xerr = t.RegisterFeature(needed, instance, targetIsCluster)
				xerr = debug.InjectPlannedFail(xerr)
				if xerr != nil {
					return xerr
				}
			}
		}

	}
	return nil
}

func registerOnSuccessfulHostsInCluster(svc iaas.Service, target resources.Targetable, installed resources.Feature, requiredBy resources.Feature, results resources.Results) fail.Error {
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
			host, xerr := LoadHost(svc, k)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = host.RegisterFeature(installed, requiredBy, true)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

func unregisterOnSuccessfulHostsInCluster(svc iaas.Service, target resources.Targetable, installed resources.Feature, results resources.Results) fail.Error {
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
			host, xerr := LoadHost(svc, k)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}

			xerr = host.UnregisterFeature(installed.GetName())
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

// ToProtocol converts a Feature to *protocol.FeatureResponse
func (instance Feature) ToProtocol() *protocol.FeatureResponse {
	out := &protocol.FeatureResponse{
		Name:     instance.GetName(),
		FileName: instance.GetDisplayFilename(),
	}
	return out
}

// ExtractFeatureParameters convert a slice of string in format a=b into a map index on 'a' with value 'b'
func ExtractFeatureParameters(params []string) data.Map {
	out := data.Map{}
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
