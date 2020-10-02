/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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
	"io/ioutil"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/featuretargettype"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/debug"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// feature contains the information about an installable feature
type feature struct {
	// displayName is the name of the service
	displayName string
	// fileName is the name of the specification file
	fileName string
	// displayFileName is the 'beautifulled' name of the specification file
	displayFileName string
	// embedded tells if the feature is embedded in deploy
	embedded bool
	// Installers defines the installers available for the feature
	installers map[installmethod.Enum]Installer
	// Dependencies lists other feature(s) (by name) needed by this one
	// dependencies []string
	// Management contains a string map of data that could be used to manage the feature (if it makes sense)
	// This could be used to explain to GetService object how to manage the feature, to react as a service
	// Management map[string]interface{}
	// specs is the Viper instance containing feature specification
	specs *viper.Viper
	task  concurrency.Task
}

func nullFeature() *feature {
	return &feature{}
}

// ListFeatures lists all features suitable for hosts or clusters
func ListFeatures(task concurrency.Task, suitableFor string) ([]interface{}, fail.Error) {
	if task.IsNull() {
		return nil, fail.InvalidInstanceError()
	}

	features := allEmbeddedFeaturesMap
	var cfgFiles []interface{}

	var paths []string
	paths = append(paths, utils.AbsPathify("$HOME/.safescale/features"))
	paths = append(paths, utils.AbsPathify("$HOME/.config/safescale/features"))
	paths = append(paths, utils.AbsPathify("/etc/safescale/features"))

	for _, path := range paths {
		files, err := ioutil.ReadDir(path)
		if err == nil {
			for _, f := range files {
				if strings.HasSuffix(strings.ToLower(f.Name()), ".yml") {
					feat, xerr := NewFeature(task, strings.Replace(strings.ToLower(f.Name()), ".yml", "", 1))
					if xerr != nil {
						logrus.Error(xerr) // FIXME: Don't hide errors
						continue
					}
					casted := feat.(*feature)
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
				if values[0] == "all" || values[0] == "dcos" || values[0] == "k8s" || values[0] == "boh" || values[0] == "swarm" || values[0] == "ohpc" {
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
//    - fail.ErrNotFound if no feature is found by its name
//    - fail.ErrSyntax if feature found contains syntax error
func NewFeature(task concurrency.Task, name string) (_ resources.Feature, xerr fail.Error) {
	if task.IsNull() {
		return nullFeature(), fail.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nullFeature(), fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale/features")
	v.AddConfigPath("$HOME/.config/safescale/features")
	v.AddConfigPath("/etc/safescale/features")
	v.SetConfigName(name)

	casted := nullFeature()
	err := v.ReadInConfig()
	if err != nil {
		switch err.(type) {
		case viper.ConfigFileNotFoundError:
			// Failed to find a spec file on filesystem, trying with embedded ones
			xerr = nil
			var ok bool
			if _, ok = allEmbeddedFeaturesMap[name]; !ok {
				xerr = fail.NotFoundError("failed to find a feature named '%s'", name)
			} else {
				casted = allEmbeddedFeaturesMap[name].Clone().(*feature)
				casted.task = task
				casted.displayFileName = name + ".yml [embedded]"
				xerr = nil
			}
		default:
			xerr = fail.SyntaxError("failed to read the specification file of feature called '%s': %s", name, err.Error())
		}
	} else if v.IsSet("feature") {
		casted = &feature{
			fileName:        v.ConfigFileUsed(),
			displayFileName: v.ConfigFileUsed(),
			displayName:     name,
			specs:           v,
			task:            task,
		}
		xerr = nil
	}
	return casted, xerr
}

// NewEmbeddedFeature searches for an embedded featured named 'name' and initializes a new Feature object
// with its content
func NewEmbeddedFeature(task concurrency.Task, name string) (_ resources.Feature, xerr fail.Error) {
	if task.IsNull() {
		return nullFeature(), fail.InvalidParameterError("task", "cannot be nil")
	}
	if name == "" {
		return nullFeature(), fail.InvalidParameterError("name", "cannot be empty string")
	}

	tracer := debug.NewTracer(task, true, "").WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	casted := nullFeature()
	if _, ok := allEmbeddedFeaturesMap[name]; !ok {
		return casted, fail.NotFoundError("failed to find a feature named '%s'", name)
	}
	casted = allEmbeddedFeaturesMap[name].Clone().(*feature)
	casted.task = task
	casted.fileName += " [embedded]"
	return casted, nil
}

// IsNull tells if the instance represents a null value
func (f *feature) IsNull() bool {
	return f == nil || f.displayName == ""
}

// Clone ...
// satisfies interface data.Clonable
func (f *feature) Clone() data.Clonable {
	if f.IsNull() {
		return f
	}
	res := &feature{}
	return res.Replace(f)
}

// Replace ...
// satisfies interface data.Clonable
func (f *feature) Replace(p data.Clonable) data.Clonable {
	if f.IsNull() {
		return f
	}

	src := p.(*feature)
	*f = *src
	f.installers = make(map[installmethod.Enum]Installer, len(src.installers))
	for k, v := range src.installers {
		f.installers[k] = v
	}
	return f
}

// GetName returns the display name of the feature, with error handling
func (f feature) GetName() string {
	if f.IsNull() {
		return ""
	}
	return f.displayName
}

// GetID ...
func (f feature) GetID() string {
	return f.GetName()
}

// GetFilename returns the filename of the feature definition, with error handling
func (f feature) GetFilename() string {
	if f.IsNull() {
		return ""
	}
	return f.fileName
}

// GetDisplayFilename returns the filename of the feature definition, beautifulled, with error handling
func (f feature) GetDisplayFilename() string {
	if f.IsNull() {
		return ""
	}
	return f.displayFileName
}

// installerOfMethod instanciates the right installer corresponding to the method
func (f feature) installerOfMethod(m installmethod.Enum) Installer {
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
	}
	return installer
}

// Specs returns a copy of the spec file (we don't want external use to modify Feature.specs)
func (f feature) Specs() *viper.Viper {
	if f.IsNull() {
		return &viper.Viper{}
	}
	roSpecs := *f.specs
	return &roSpecs
}

// Applyable tells if the feature is installable on the target
func (f *feature) Applyable(t resources.Targetable) bool {
	if f.IsNull() {
		return false
	}
	methods := t.InstallMethods(f.task)
	for _, k := range methods {
		installer := f.installerOfMethod(k)
		if installer != nil {
			return true
		}
	}
	return false
}

// Check if feature is installed on target
// Check is ok if error is nil and Results.Successful() is true
func (f feature) Check(target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	if f.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if target == nil {
		return nil, fail.InvalidParameterError("target", "cannot be nil")
	}

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()

	tracer := debug.NewTracer(f.task, true, "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	// cacheKey := f.DisplayName() + "@" + t.GetName()
	// if anon, ok := checkCache.Get(cacheKey); ok {
	// 	return anon.(Results), nil
	// }

	methods := target.InstallMethods(f.task)
	var installer Installer
	for _, meth := range methods {
		if f.specs.IsSet("feature.install." + strings.ToLower(meth.String())) {
			installer = f.installerOfMethod(meth)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fail.NewError("failed to find a way to check '%s'", featureName)
	}

	logrus.Debugf("Checking if feature '%s' is installed on %s '%s'...\n", featureName, targetType, targetName)

	// 'v' may be updated by parallel tasks, so use copy of it
	// myV := make(data.Map, len(v))
	// for key, value := range v {
	// 	myV[key] = value
	// }
	myV := v.Clone()

	// Inits target parameters
	if xerr = target.ComplementFeatureParameters(f.task, myV); xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have their values
	if xerr = checkParameters(f, myV); xerr != nil {
		return nil, xerr
	}

	r, xerr := installer.Check(&f, target, myV, s)
	// _ = checkCache.ForceSet(cacheKey, results)
	return r, xerr
}

// Check if required parameters defined in specification file have been set in 'v'
func checkParameters(f feature, v data.Map) fail.Error {
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

// Add installs the feature on the target
// Installs succeeds if error == nil and Results.Successful() is true
func (f feature) Add(target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	if f.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if target == nil {
		return nil, fail.InvalidParameterError("target", "cannot be nil")
	}

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()

	tracer := debug.NewTracer(f.task, true, "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	methods := target.InstallMethods(f.task)
	var (
		installer Installer
		i         uint8
	)
	for i = 1; i <= uint8(len(methods)); i++ {
		meth := methods[i]
		if f.specs.IsSet("feature.install." + strings.ToLower(meth.String())) {
			installer = f.installerOfMethod(meth)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fail.NotAvailableError("failed to find a way to install '%s'", featureName)
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting addition of feature '%s' on %s '%s'...", featureName, targetType, targetName),
		fmt.Sprintf("Ending addition of feature '%s' on %s '%s'", featureName, targetType, targetName),
	)()

	// 'v' may be updated by parallel tasks, so use copy of it
	// myV := make(data.Map, len(v))
	// for key, value := range v {
	// 	myV[key] = value
	// }
	myV := v.Clone()

	// Inits target parameters
	if xerr = target.ComplementFeatureParameters(f.task, myV); xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have value
	if xerr = checkParameters(f, myV); xerr != nil {
		return nil, xerr
	}

	if !s.AddUnconditionally {
		results, xerr := f.Check(target, v, s)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to check feature '%s'", featureName)
		}
		if results.Successful() {
			logrus.Infof("Feature '%s' is already installed.", featureName)
			return results, nil
		}
	}

	if !s.SkipFeatureRequirements {
		if xerr = f.installRequirements(target, v, s); xerr != nil {
			return nil, fail.Wrap(xerr, "failed to install requirements")
		}
	}
	results, xerr := installer.Add(&f, target, myV, s)
	if xerr != nil {
		return nil, xerr
	}
	// _ = checkCache.ForceSet(featureName()+"@"+targetName, results)
	return results, xerr
}

// Remove uninstalls the feature from the target
func (f feature) Remove(target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	if f.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	if target == nil {
		return nil, fail.InvalidParameterError("target", "cannot be nil")
	}

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()

	tracer := debug.NewTracer(f.task, true, "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	var (
		results   resources.Results
		installer Installer
	)
	methods := target.InstallMethods(f.task)
	for _, meth := range methods {
		if f.specs.IsSet("feature.install." + strings.ToLower(meth.String())) {
			installer = f.installerOfMethod(meth)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fail.NotAvailableError("failed to find a way to uninstall '%s'", featureName)
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting removal of feature '%s' from %s '%s'", featureName, targetType, targetName),
		fmt.Sprintf("Ending removal of feature '%s' from %s '%s'", featureName, targetType, targetName),
	)()

	// 'v' may be updated by parallel tasks, so use copy of it
	// myV := make(data.Map, len(v))
	// for key, value := range v {
	// 	myV[key] = value
	// }
	myV := v.Clone()

	// // Inits implicit parameters
	// err = f.setImplicitParameters(t, myV)
	// Inits target parameters
	if xerr = target.ComplementFeatureParameters(f.task, myV); xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have value
	if xerr = checkParameters(f, myV); xerr != nil {
		return nil, xerr
	}

	results, xerr = installer.Remove(&f, target, myV, s)
	// if xerr == nil {
	// 	checkCache.Reset(f.DisplayName() + "@" + targetName)
	// }
	return results, xerr
}

// GetRequirements returns a list of features needed as requirements
func (f *feature) GetRequirements() ([]string, fail.Error) {
	if f.IsNull() {
		return nil, fail.InvalidInstanceError()
	}
	return nil, fail.NotImplementedError("GetRequirements() is not yet implemented")
}

// installRequirements walks through requirements and installs them if needed
func (f *feature) installRequirements(t resources.Targetable, v data.Map, s resources.FeatureSettings) fail.Error {
	yamlKey := "feature.requirements.features"
	if f.specs.IsSet(yamlKey) {
		{
			msgHead := fmt.Sprintf("Checking requirements of feature '%s'", f.GetName())
			var msgTail string
			switch t.TargetType() {
			case featuretargettype.HOST:
				msgTail = fmt.Sprintf("on host '%s'", t.(data.Identifiable).GetName())
			case featuretargettype.NODE:
				msgTail = fmt.Sprintf("on cluster node '%s'", t.(data.Identifiable).GetName())
			case featuretargettype.CLUSTER:
				msgTail = fmt.Sprintf("on cluster '%s'", t.(data.Identifiable).GetName())
			}
			logrus.Debugf("%s %s...", msgHead, msgTail)
		}
		for _, requirement := range f.specs.GetStringSlice(yamlKey) {
			needed, xerr := NewFeature(f.task, requirement)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to find required feature '%s'", requirement)
			}
			results, xerr := needed.Check(t, v, s)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to check required feature '%s' for feature '%s'", requirement, f.GetName())
			}
			if !results.Successful() {
				results, xerr := needed.Add(t, v, s)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to install required feature '%s'", requirement)
				}
				if !results.Successful() {
					return fail.NewError("failed to install required feature '%s':\n%s", requirement, results.AllErrorMessages())
				}
			}
		}
	}
	return nil
}
