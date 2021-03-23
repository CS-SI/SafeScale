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
	"context"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/errcontrol"
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

// feature contains the information about an installable feature
type feature struct {
	displayName     string                           // is the name of the service
	fileName        string                           // is the name of the specification file
	displayFileName string                           // is the 'beautifulled' name of the specification file
	embedded        bool                             // tells if the feature is embedded in deploy
	installers      map[installmethod.Enum]Installer // defines the installers available for the feature
	specs           *viper.Viper                     // is the Viper instance containing feature specification
	// task            concurrency.Task                 // is theTask that will trigger all feature operations
	svc iaas.Service // is the iaas.Service to use to interact with Cloud Provider
}

func nullFeature() *feature {
	return &feature{}
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
					xerr = errcontrol.CrasherFail(xerr)
					if xerr != nil {
						logrus.Warn(xerr) // Don't hide errors
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
func NewFeature(svc iaas.Service, name string) (_ resources.Feature, xerr fail.Error) {
	if svc == nil {
		return nullFeature(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nullFeature(), fail.InvalidParameterError("name", "cannot be empty string")
	}

	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale/features")
	v.AddConfigPath("$HOME/.config/safescale/features")
	v.AddConfigPath("/etc/safescale/features")
	v.SetConfigName(name)

	casted := nullFeature()
	err := v.ReadInConfig()
	err = errcontrol.Crasher(err)
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
		}
		xerr = nil
	}

	casted.svc = svc

	return casted, xerr
}

// NewEmbeddedFeature searches for an embedded featured named 'name' and initializes a new Feature object
// with its content
func NewEmbeddedFeature(svc iaas.Service, name string) (_ resources.Feature, xerr fail.Error) {
	if svc == nil {
		return nullFeature(), fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nullFeature(), fail.InvalidParameterError("name", "cannot be empty string")
	}

	casted := nullFeature()
	if _, ok := allEmbeddedFeaturesMap[name]; !ok {
		return casted, fail.NotFoundError("failed to find a feature named '%s'", name)
	}
	casted = allEmbeddedFeaturesMap[name].Clone().(*feature)
	casted.svc = svc
	casted.fileName += " [embedded]"
	return casted, nil
}

// isNull tells if the instance represents a null value
func (f *feature) isNull() bool {
	return f == nil || f.displayName == ""
}

// Clone ...
// satisfies interface data.Clonable
func (f *feature) Clone() data.Clonable {
	res := &feature{}
	return res.Replace(f)
}

// Replace ...
// satisfies interface data.Clonable
func (f *feature) Replace(p data.Clonable) data.Clonable {
	// Do not test with isNull(), it's allowed to clone a null value...
	if f == nil || p == nil {
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
func (f *feature) GetName() string {
	if f.isNull() {
		return ""
	}
	return f.displayName
}

// GetID ...
func (f *feature) GetID() string {
	return f.GetName()
}

// GetFilename returns the filename of the feature definition, with error handling
func (f *feature) GetFilename() string {
	if f.isNull() {
		return ""
	}

	return f.fileName
}

// GetDisplayFilename returns the filename of the feature definition, beautifulled, with error handling
func (f *feature) GetDisplayFilename() string {
	if f.isNull() {
		return ""
	}
	return f.displayFileName
}

// installerOfMethod instanciates the right installer corresponding to the method
func (f *feature) installerOfMethod(m installmethod.Enum) Installer {
	if f.isNull() {
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
func (f *feature) Specs() *viper.Viper {
	if f.isNull() {
		return &viper.Viper{}
	}
	roSpecs := *f.specs
	return &roSpecs
}

// Applyable tells if the feature is installable on the target
func (f *feature) Applyable(t resources.Targetable) bool {
	if f.isNull() {
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

// Check if feature is installed on target
// Check is ok if error is nil and Results.Successful() is true
func (f *feature) Check(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	if f.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := strings.ToLower(target.TargetType().String())
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.features"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	installer, xerr := f.findInstallerForTarget(target, "check")
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	logrus.Debugf("Checking if feature '%s' is installed on %s '%s'...\n", featureName, targetType, targetName)
	myV := v.Clone()

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have their values
	xerr = checkParameters(*f, myV)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	r, xerr := installer.Check(ctx, f, target, myV, s)

	// FIXME: restore feature check using iaas.ResourceCache
	// _ = checkCache.ForceSet(cacheKey, results)
	return r, xerr
}

// findInstallerForTarget isolates the available installer to use for target (one that is define in the file and applicable on target)
func (f *feature) findInstallerForTarget(target resources.Targetable, action string) (installer Installer, xerr fail.Error) {
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
func (f *feature) Add(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	defer fail.OnPanic(&xerr)

	if f.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()

	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.features"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting addition of feature '%s' on %s '%s'...", featureName, targetType, targetName),
		fmt.Sprintf("Ending addition of feature '%s' on %s '%s'", featureName, targetType, targetName),
	)()

	installer, xerr := f.findInstallerForTarget(target, "check")
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// 'v' may be updated by concurrent tasks, so use copy of it
	myV := v.Clone()

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have value
	xerr = checkParameters(*f, myV)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	if !s.AddUnconditionally {
		results, xerr := f.Check(ctx, target, v, s)
		xerr = errcontrol.CrasherFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to check feature '%s'", featureName)
		}

		if results.Successful() {
			logrus.Infof("Feature '%s' is already installed.", featureName)
			return results, nil
		}
	}

	if !s.SkipFeatureRequirements {
		xerr = f.installRequirements(ctx, target, v, s)
		xerr = errcontrol.CrasherFail(xerr)
		if xerr != nil {
			return nil, fail.Wrap(xerr, "failed to install requirements")
		}
	}

	results, xerr := installer.Add(ctx, f, target, myV, s)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	xerr = registerOnSuccessfulHostsInCluster(f.svc, target, f, nil, results)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// FIXME: restore feature check cache using iaas.ResourceCache
	// _ = checkCache.ForceSet(featureName()+"@"+targetName, results)

	return results, target.RegisterFeature(f, nil, target.TargetType() == featuretargettype.Cluster)
}

// Remove uninstalls the feature from the target
func (f *feature) Remove(ctx context.Context, target resources.Targetable, v data.Map, s resources.FeatureSettings) (_ resources.Results, xerr fail.Error) {
	if f.isNull() {
		return nil, fail.InvalidInstanceError()
	}
	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if target == nil {
		return nil, fail.InvalidParameterCannotBeNilError("target")
	}

	task, xerr := concurrency.TaskFromContext(ctx)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	featureName := f.GetName()
	targetName := target.GetName()
	targetType := target.TargetType().String()
	tracer := debug.NewTracer(task, tracing.ShouldTrace("resources.features"), "(): '%s' on %s '%s'", featureName, targetType, targetName).WithStopwatch().Entering()
	defer tracer.Exiting()
	defer fail.OnExitLogError(&xerr, tracer.TraceMessage(""))

	var (
		results resources.Results
		// installer Installer
	)

	installer, xerr := f.findInstallerForTarget(target, "check")
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	defer temporal.NewStopwatch().OnExitLogInfo(
		fmt.Sprintf("Starting removal of feature '%s' from %s '%s'", featureName, targetType, targetName),
		fmt.Sprintf("Ending removal of feature '%s' from %s '%s'", featureName, targetType, targetName),
	)()

	// 'v' may be updated by parallel tasks, so use copy of it
	myV := v.Clone()

	// Inits target parameters
	xerr = target.ComplementFeatureParameters(ctx, myV)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	// Checks required parameters have value
	xerr = checkParameters(*f, myV)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	results, xerr = installer.Remove(ctx, f, target, myV, s)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return results, xerr
	}

	xerr = unregisterOnSuccessfulHostsInCluster(f.svc, target, f, results)
	xerr = errcontrol.CrasherFail(xerr)
	if xerr != nil {
		return nil, xerr
	}

	return results, target.UnregisterFeature(f.GetName())
}

const yamlKey = "feature.requirements.features"

// GetRequirements returns a list of features needed as requirements
func (f *feature) GetRequirements() (map[string]struct{}, fail.Error) {
	emptyMap := map[string]struct{}{}
	if f.isNull() {
		return emptyMap, fail.InvalidInstanceError()
	}

	out := make(map[string]struct{}, len(f.specs.GetStringSlice(yamlKey)))
	for _, r := range f.specs.GetStringSlice(yamlKey) {
		out[r] = struct{}{}
	}
	return out, nil
}

// installRequirements walks through requirements and installs them if needed
func (f *feature) installRequirements(ctx context.Context, t resources.Targetable, v data.Map, s resources.FeatureSettings) fail.Error {
	if f.specs.IsSet(yamlKey) {
		{
			msgHead := fmt.Sprintf("Checking requirements of feature '%s'", f.GetName())
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
			xerr = errcontrol.CrasherFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to find required feature '%s'", requirement)
			}

			results, xerr := needed.Check(ctx, t, v, s)
			xerr = errcontrol.CrasherFail(xerr)
			if xerr != nil {
				return fail.Wrap(xerr, "failed to check required Feature '%s' for Feature '%s'", requirement, f.GetName())
			}

			if !results.Successful() {
				results, xerr := needed.Add(ctx, t, v, s)
				xerr = errcontrol.CrasherFail(xerr)
				if xerr != nil {
					return fail.Wrap(xerr, "failed to install required feature '%s'", requirement)
				}

				if !results.Successful() {
					return fail.NewError("failed to install required feature '%s':\n%s", requirement, results.AllErrorMessages())
				}

				// Register the needed feature as a requirement for f
				xerr = t.RegisterFeature(needed, f, targetIsCluster)
				xerr = errcontrol.CrasherFail(xerr)
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
		// Walk through results and register feature in successful hosts
		successfulHosts := map[string]struct{}{}
		for _, k := range results.Keys() {
			r := results.ResultsOfKey(k)
			for _, l := range r.Keys() {
				if s := r.ResultOfKey(l); s.Successful() {
					successfulHosts[l] = struct{}{}
				}
			}
		}
		for k := range successfulHosts {
			host, xerr := LoadHost(svc, k)
			if xerr == nil {
				xerr = host.RegisterFeature(installed, requiredBy, true)
			}
			xerr = errcontrol.CrasherFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

func unregisterOnSuccessfulHostsInCluster(svc iaas.Service, target resources.Targetable, installed resources.Feature, results resources.Results) fail.Error {
	if target.TargetType() == featuretargettype.Cluster {
		// Walk through results and register feature in successful hosts
		successfulHosts := map[string]struct{}{}
		for _, k := range results.Keys() {
			r := results.ResultsOfKey(k)
			for _, l := range r.Keys() {
				if s := r.ResultOfKey(l); s.Successful() {
					successfulHosts[l] = struct{}{}
				}
			}
		}
		for k := range successfulHosts {
			host, xerr := LoadHost(svc, k)
			if xerr == nil {
				xerr = host.UnregisterFeature(installed.GetName())
			}
			xerr = errcontrol.CrasherFail(xerr)
			if xerr != nil {
				return xerr
			}
		}
	}
	return nil
}

// ToProtocol converts a feature to *protocol.FeatureResponse
func (f feature) ToProtocol() *protocol.FeatureResponse {
	out := &protocol.FeatureResponse{
		Name:     f.GetName(),
		FileName: f.GetDisplayFilename(),
	}
	return out
}
