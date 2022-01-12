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

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/hostproperty"
	propertiesv1 "github.com/CS-SI/SafeScale/lib/server/resources/properties/v1"
	"github.com/CS-SI/SafeScale/lib/utils/data/serialize"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/lib/protocol"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/debug/tracing"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Feature contains the information about an installable Feature
type Feature struct {
	displayName     string                           // is the name of the service
	fileName        string                           // is the name of the specification file
	displayFileName string                           // is the 'beautifulled' name of the specification file
	embedded        bool                             // tells if the Feature is embedded in deploy
	installers      map[installmethod.Enum]Installer // defines the installers available for the Feature
	specs           *viper.Viper                     // is the Viper instance containing Feature specification
	// task            concurrency.Task                 // is theTask that will trigger all Feature operations
	svc iaas.Service // is the iaas.Service to use to interact with Cloud Provider
}

// FeatureNullValue returns a *Feature corresponding to a null value
func FeatureNullValue() *Feature {
	return &Feature{}
}

// ListFeatures lists all features suitable for hosts or clusters
func ListFeatures(svc iaas.Service, suitableFor string) (_ []interface{}, xerr fail.Error) {
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
		if err == nil {
			for _, f := range files {
				if strings.HasSuffix(strings.ToLower(f.Name()), ".yml") {
					feat, xerr := NewFeature(svc, strings.Replace(strings.ToLower(f.Name()), ".yml", "", 1))
					xerr = debug.InjectPlannedFail(xerr)
					if xerr != nil {
						logrus.Warn(xerr) // Don't hide errors
						continue
					}
					casted, ok := feat.(*Feature)
					if !ok {
						logrus.Warnf("feat should be a *Feature")
						continue
					}
					if _, ok := allEmbeddedFeaturesMap[casted.displayName]; !ok {
						allEmbeddedFeaturesMap[casted.displayName] = casted
					}
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
func NewFeature(svc iaas.Service, name string) (_ resources.Feature, xerr fail.Error) {
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
			xerr = nil
			var ok bool
			if _, ok = allEmbeddedFeaturesMap[name]; !ok {
				return nil, fail.NotFoundError("failed to find a Feature named '%s'", name)
			}

			casted, ok = allEmbeddedFeaturesMap[name].Clone().(*Feature)
			if !ok {
				return nil, fail.NewError("embedded feature should be a *Feature")
			}
			casted.displayFileName = name + ".yml [embedded]"
			xerr = nil // FIXME: This function uses a bad error handling practice, when we have an error, return the error, don't reassign it

		default:
			xerr = fail.SyntaxError("failed to read the specification file of Feature called '%s': %s", name, err.Error())
		}
	} else if v.IsSet("feature") {
		casted = &Feature{
			fileName:        v.ConfigFileUsed(),
			displayFileName: v.ConfigFileUsed(),
			displayName:     name,
			specs:           v,
		}
		xerr = nil
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

	return casted, xerr
}

// NewEmbeddedFeature searches for an embedded featured named 'name' and initializes a new Feature object
// with its content
func NewEmbeddedFeature(svc iaas.Service, name string) (_ resources.Feature, xerr fail.Error) {
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
	var ok bool
	casted, ok = allEmbeddedFeaturesMap[name].Clone().(*Feature)
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
func (f *Feature) IsNull() bool {
	return f == nil || f.displayName == ""
}

// Clone ...
// satisfies interface data.Clonable
func (f *Feature) Clone() data.Clonable {
	res := &Feature{}
	return res.Replace(f)
}

// Replace ...
// satisfies interface data.Clonable
// may panic
func (f *Feature) Replace(p data.Clonable) data.Clonable {
	// Do not test with IsNull(), it's allowed to clone a null value...
	if f == nil || p == nil {
		return f
	}

	// FIXME: Replace should also return an error
	src, _ := p.(*Feature) // nolint
	// VPL: Not used yet, need to think if we should return an error or panic, or something else
	// src, ok := p.(*Feature)
	// if !ok {
	// 	panic("failed to cast p to '*Feature'")
	// }
	*f = *src
	f.installers = make(map[installmethod.Enum]Installer, len(src.installers))
	for k, v := range src.installers {
		f.installers[k] = v
	}
	return f
}

// GetName returns the display name of the Feature, with error handling
func (f *Feature) GetName() string {
	if f.IsNull() {
		return ""
	}
	return f.displayName
}

// GetID ...
func (f *Feature) GetID() string {
	return f.GetName()
}

// GetFilename returns the filename of the Feature definition, with error handling
func (f *Feature) GetFilename() string {
	if f.IsNull() {
		return ""
	}

	return f.fileName
}

// GetDisplayFilename returns the filename of the Feature definition, beautifulled, with error handling
func (f *Feature) GetDisplayFilename() string {
	if f.IsNull() {
		return ""
	}
	return f.displayFileName
}

// installerOfMethod instanciates the right installer corresponding to the method
func (f *Feature) installerOfMethod(m installmethod.Enum) Installer {
	if f.IsNull() {
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
func (f *Feature) Specs() *viper.Viper {
	if f.IsNull() {
		return &viper.Viper{}
	}
	roSpecs := *f.specs
	return &roSpecs
}

// Applyable tells if the Feature is installable on the target
func (f *Feature) Applyable(t resources.Targetable) bool {
	if f.IsNull() {
		return false
	}

	methods := t.InstallMethods()
	for _, k := range methods {
		installer := f.installerOfMethod(k)
		if installer != nil {
			return true
		}
	}
	return false
}

// Check if Feature is installed on target
// Check is ok if error is nil and Results.Successful() is true
func (f *Feature) Check(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	if f.IsNull() {
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

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := strings.ToLower(target.TargetType().String())
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

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
				_, found = hostFeaturesV1.Installed[f.GetName()]
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
	installer, xerr := f.findInstallerForTarget(target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("Checking if Feature '%s' is installed on %s '%s'...\n", featureName, targetType, targetName)
	myV := v.Clone()

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have their values
	xerr = checkParameters(*f, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	r, xerr := installer.Check(ctx, f, target, myV, s)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: restore Feature check using iaas.ResourceCache
	// _ = checkCache.ForceSet(cacheKey, results)
	return r, xerr
}

// findInstallerForTarget isolates the available installer to use for target (one that is define in the file and applicable on target)
func (f *Feature) findInstallerForTarget(target resources.Targetable, action string) (installer Installer, xerr fail.Error) {
	methods := target.InstallMethods()
	w := f.specs.GetStringMap("feature.install")
	for i := uint8(1); i <= uint8(len(methods)); i++ {
		meth := methods[i]
		if _, ok := w[strings.ToLower(meth.String())]; ok {
			if installer = f.installerOfMethod(meth); installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fail.NotAvailableError("failed to find a way to %s '%s'", action, f.GetName())
	}
	return installer, nil
}

// Check if required parameters defined in specification file have been set in 'v'
func checkParameters(f Feature, v data.Map) fail.Error {
	if f.specs.IsSet("feature.parameters") {
		params := f.specs.GetStringSlice("feature.parameters")
		for _, k := range params {
			splitted := strings.Split(k, "=")
			if _, ok := v[splitted[0]]; !ok {
				if len(splitted) == 1 {
					return fail.InvalidRequestError("missing value for parameter '%s'", k)
				}
				v[splitted[0]] = strings.Join(splitted[1:], "=")
			}
		}
	}
	return nil
}

// Add installs the Feature on the target
// Installs succeeds if error == nil and Results.Successful() is true
func (f *Feature) Add(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, ferr fail.Error) {
	defer fail.OnPanic(&ferr)

	if f.IsNull() {
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

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting addition of Feature '%s' on %s '%s'...", featureName, targetType, targetName),
		fmt.Sprintf("Ending addition of Feature '%s' on %s '%s'", featureName, targetType, targetName),
	)()

	installer, xerr := f.findInstallerForTarget(target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// 'v' may be updated by concurrent tasks, so use copy of it
	myV := v.Clone()

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have value
	xerr = checkParameters(*f, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if !s.AddUnconditionally {
		results, xerr := f.Check(ctx, target, v, s)
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
		xerr = f.installRequirements(ctx, target, v, s)
		xerr = debug.InjectPlannedFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to install requirements")
		}
	}

	results, xerr := installer.Add(ctx, f, target, myV, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = registerOnSuccessfulHostsInCluster(f.svc, target, f, nil, results)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: restore Feature check cache using iaas.ResourceCache
	// _ = checkCache.ForceSet(featureName()+"@"+targetName, results)

	return results, target.RegisterFeature(f, nil, target.TargetType() == featuretargettype.Cluster)
}

// Remove uninstalls the Feature from the target
func (f *Feature) Remove(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	if f.IsNull() {
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

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.feature"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	var (
		results resources.Results
		// installer Installer
	)

	installer, xerr := f.findInstallerForTarget(target, "check")
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting removal of Feature '%s' from %s '%s'", featureName, targetType, targetName),
		fmt.Sprintf("Ending removal of Feature '%s' from %s '%s'", featureName, targetType, targetName),
	)()

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := v.Clone()

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have value
	xerr = checkParameters(*f, myV)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	results, xerr = installer.Remove(ctx, f, target, myV, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return results, xerr
	}

	xerr = unregisterOnSuccessfulHostsInCluster(f.svc, target, f, results)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return results, target.UnregisterFeature(f.GetName())
}

const yamlKey = "feature.requirements.features"

// GetRequirements returns a list of features needed as requirements
func (f *Feature) GetRequirements() (map[string]struct{}, fail.Error) {
	emptyMap := map[string]struct{}{}
	if f.IsNull() {
		return emptyMap, fail.InvalidInstanceError()
	}

	out := make(map[string]struct{}, len(f.specs.GetStringSlice(yamlKey)))
	for _, r := range f.specs.GetStringSlice(yamlKey) {
		out[r] = struct{}{}
	}
	return out, nil
}

// installRequirements walks through requirements and installs them if needed
func (f *Feature) installRequirements(ctx context.Context, t resources.Targetable, v data.Map, s resources.FeatureSettings) fail.Error {
	if f.specs.IsSet(yamlKey) {
		{
			msgHead := fmt.Sprintf("Checking requirements of Feature '%s'", f.GetName())
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
		for _, requirement := range f.specs.GetStringSlice(yamlKey) {
			needed, xerr := NewFeature(f.svc, requirement)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to find required Feature '%s'", requirement)
			}

			results, xerr := needed.Check(ctx, t, v, s)
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to check required Feature '%s' for Feature '%s'", requirement, f.GetName())
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

				// Register the needed Feature as a requirement for f
				xerr = t.RegisterFeature(needed, f, targetIsCluster)
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
			if xerr == nil {
				xerr = host.RegisterFeature(installed, requiredBy, true)
			}
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
			if xerr == nil {
				xerr = host.UnregisterFeature(installed.GetName())
			}
			xerr = debug.InjectPlannedFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

// ToProtocol converts a Feature to *protocol.FeatureResponse
func (f Feature) ToProtocol() *protocol.FeatureResponse {
	out := &protocol.FeatureResponse{
		Name:     f.GetName(),
		FileName: f.GetDisplayFilename(),
	}
	return out
}
