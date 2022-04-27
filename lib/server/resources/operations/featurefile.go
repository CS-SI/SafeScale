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
	"io/fs"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/farmergreg/rfsnotify"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"gopkg.in/fsnotify.v1"

	"github.com/CS-SI/SafeScale/v22/lib/server/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data/observer"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

var (
	featureFileController = make(map[string]interface{})
	featureFileFolders    = []string{
		"$HOME/.safescale/features",
		"$HOME/.config/safescale/features",
		"/etc/safescale/features",
	}
	cwdFeatureFileFolders = []string{
		".",
		"./features",
		"./.safescale/features",
	}
)

// FeatureFile contains the information about an installable Feature
type FeatureFile struct {
	displayName               string                       // is the name of the feature
	fileName                  string                       // is the name of the specification file
	displayFileName           string                       // is the 'pretty' name of the specification file
	embedded                  bool                         // tells if the Feature is embedded in SafeScale
	specs                     *viper.Viper                 // is the Viper instance containing Feature file content
	observersLock             *sync.RWMutex                // lock to access field 'observers'
	observers                 map[string]observer.Observer // contains the Observers of the FeatureFile
	suitableFor               map[string]struct{}          // tells for what the Feature is suitable
	parameters                map[string]FeatureParameter  // contains all the parameters defined in Feature file
	versionControl            map[string]string            // contains the templated bash code to determine version of a component used in the FeatureFile
	dependencies              map[string]struct{}          // contains the list of features required to install the Feature described by the file
	clusterSizingRequirements map[string]interface{}       // contains the cluster sizing requirements to allow install
	installers                map[string]interface{}
}

func newFeatureFile(fileName, displayName string, embedded bool, specs *viper.Viper) *FeatureFile {
	instance := &FeatureFile{
		parameters:      map[string]FeatureParameter{},
		versionControl:  map[string]string{},
		observersLock:   &sync.RWMutex{},
		observers:       map[string]observer.Observer{},
		fileName:        fileName,
		displayName:     displayName,
		displayFileName: fileName,
		embedded:        embedded,
		specs:           specs,
	}
	if embedded {
		instance.displayFileName += " [embedded]"
	}
	return instance
}

// IsNull tells if the instance represents a null value
func (ff *FeatureFile) IsNull() bool {
	return ff == nil || ff.displayName == ""
}

// Clone ...
// satisfies interface data.Clonable
func (ff *FeatureFile) Clone() (data.Clonable, error) {
	return newFeatureFile("", "", false, nil).Replace(ff)
}

// Replace ...
// satisfies interface data.Clonable
// may panic
func (ff *FeatureFile) Replace(p data.Clonable) (data.Clonable, error) {
	// Do not test with IsNull(), it's allowed to clone a null value...
	if ff == nil || p == nil {
		return ff, nil
	}

	// FIXME: Replace should also return an error
	src, ok := p.(*FeatureFile) // nolint
	if !ok {
		return ff, fail.InvalidParameterError("p", "must be a '*FeatureFile'")
	}

	// VPL: Not used yet, need to think if we should return an error or panic, or something else
	// src, ok := p.(*Feature)
	// if !ok {
	// 	panic("failed to cast p to '*Feature'")
	// }
	ff.displayName = src.displayName
	ff.fileName = src.fileName
	ff.displayFileName = src.displayFileName
	ff.specs = src.specs // Note: using same pointer here is wanted; do not raise an alert in UT on this
	ff.embedded = src.embedded
	for k, v := range src.observers {
		ff.observers[k] = v
	}
	return ff, nil
}

// GetName returns the display name of the Feature, with error handling
func (ff *FeatureFile) GetName() string {
	if ff.IsNull() {
		return ""
	}

	return ff.displayName
}

// GetID ...
func (ff *FeatureFile) GetID() string {
	return ff.GetName()
}

// Filename returns the filename of the Feature definition, with error handling
func (ff *FeatureFile) Filename() string {
	if ff.IsNull() {
		return ""
	}

	return ff.fileName
}

// DisplayFilename returns the filename of the Feature definition, beautifulled, with error handling
func (ff *FeatureFile) DisplayFilename() string {
	if ff.IsNull() {
		return ""
	}
	return ff.displayFileName
}

// Specs returns a copy of the spec file (we don't want external use to modify Feature.specs)
func (ff *FeatureFile) Specs() *viper.Viper {
	if ff.IsNull() {
		return &viper.Viper{}
	}

	roSpecs := *(ff.specs)
	return &roSpecs
}

// Released is used to tell cache that the instance has been used and will not be anymore.
// Helps the cache handler to know when a cached item can be removed from cache (if needed)
// Note: Does nothing for now, prepared for future use
// satisfies interface data.Cacheable
func (ff *FeatureFile) Released() error {
	if ff == nil || ff.IsNull() {
		return fail.InvalidInstanceError()
	}

	ff.observersLock.RLock()
	defer ff.observersLock.RUnlock()

	for _, v := range ff.observers {
		v.MarkAsFreed(ff.displayName)
	}
	return nil
}

// Destroyed is used to tell cache that the instance has been deleted and MUST be removed from cache.
// Note: Does nothing for now, prepared for future use
// satisfies interface data.Cacheable
func (ff *FeatureFile) Destroyed() error {
	if ff == nil || ff.IsNull() {
		return fail.InvalidInstanceError()
	}

	ff.observersLock.RLock()
	defer ff.observersLock.RUnlock()

	for _, v := range ff.observers {
		v.MarkAsDeleted(ff.displayName)
	}
	return nil
}

// AddObserver ...
// satisfies interface data.Observable
func (ff *FeatureFile) AddObserver(o observer.Observer) error {
	if ff == nil || ff.IsNull() {
		return fail.InvalidInstanceError()
	}
	if o == nil {
		return fail.InvalidParameterError("o", "cannot be nil")
	}

	ff.observersLock.Lock()
	defer ff.observersLock.Unlock()

	if pre, ok := ff.observers[o.GetID()]; ok {
		if pre == o {
			return fail.DuplicateError("there is already an Observer identified by '%s'", o.GetID())
		}
		return nil
	}

	ff.observers[o.GetID()] = o
	return nil
}

// NotifyObservers sends a signal to all registered Observers to notify change
// Satisfies interface data.Observable
func (ff *FeatureFile) NotifyObservers() error {
	if ff == nil || ff.IsNull() {
		return fail.InvalidInstanceError()
	}

	ff.observersLock.RLock()
	defer ff.observersLock.RUnlock()

	for _, v := range ff.observers {
		v.SignalChange(ff.displayName)
	}
	return nil
}

// RemoveObserver ...
func (ff *FeatureFile) RemoveObserver(name string) error {
	if ff == nil || ff.IsNull() {
		return fail.InvalidInstanceError()
	}
	if name == "" {
		return fail.InvalidParameterCannotBeEmptyStringError("name")
	}

	ff.observersLock.Lock()
	defer ff.observersLock.Unlock()

	delete(ff.observers, name)
	return nil
}

// LoadFeatureFile searches for a spec file named 'name' and initializes a new FeatureFile object
// with its content
// 'xerr' may contain:
//    - nil: everything worked as expected
//    - fail.ErrNotFound: no FeatureFile is found with the name
//    - fail.ErrSyntax: FeatureFile contains syntax error
func LoadFeatureFile(ctx context.Context, svc iaas.Service, name string, embeddedOnly bool) (_ *FeatureFile, ferr fail.Error) {
	if svc == nil {
		return nil, fail.InvalidParameterCannotBeNilError("svc")
	}
	if name == "" {
		return nil, fail.InvalidParameterError("name", "cannot be empty string")
	}

	cacheMissLoader := func() (data.Identifiable, fail.Error) { return onFeatureFileCacheMiss(svc, name, embeddedOnly) }
	anon, xerr := cacheMissLoader()
	if xerr != nil {
		return nil, xerr
	}

	featureFileInstance, ok := anon.(*FeatureFile)
	if !ok {
		return nil, fail.InconsistentError("cache content for key '%s' is not a resources.Feature", name)
	}
	if featureFileInstance == nil {
		return nil, fail.InconsistentError("nil value found in Feature cache for key '%s'", name)
	}

	return featureFileInstance, nil
}

// onFeatureFileCacheMiss is called when host 'ref' is not found in cache
func onFeatureFileCacheMiss(_ iaas.Service, name string, embeddedOnly bool) (data.Identifiable, fail.Error) {
	var (
		newInstance *FeatureFile
		xerr        fail.Error
	)

	if embeddedOnly {
		newInstance, xerr = findEmbeddedFeatureFile(name)
		if xerr != nil {
			return nil, xerr
		}

		logrus.Tracef("Loaded Feature '%s' (%s)", newInstance.DisplayFilename(), newInstance.Filename())
	} else {
		v := viper.New()
		setViperConfigPathes(v)
		v.SetConfigName(name)
		err := v.ReadInConfig()
		err = debug.InjectPlannedError(err)
		if err != nil {
			switch err.(type) {
			case viper.ConfigFileNotFoundError:
				newInstance, xerr = findEmbeddedFeatureFile(name)
				if xerr != nil {
					return nil, xerr
				}

			default:
				return nil, fail.SyntaxError("failed to read the specification file of Feature called '%s': %s", name, err.Error())
			}
		} else {
			if !v.IsSet("feature") {
				return nil, fail.SyntaxError("missing keyword 'feature' at the beginning of the file")
			}

			newInstance = newFeatureFile(v.ConfigFileUsed(), name, false, v)
		}

		logrus.Tracef("Loaded Feature '%s' (%s)", newInstance.DisplayFilename(), newInstance.Filename())

		// if we can log the sha256 of the feature, do it
		filename := v.ConfigFileUsed()
		if filename != "" {
			content, err := ioutil.ReadFile(filename)
			if err != nil {
				return nil, fail.ConvertError(err)
			}

			logrus.Tracef("Loaded Feature '%s' SHA256:%s", name, getSHA256Hash(string(content)))
		}
	}

	xerr = newInstance.parse()
	if xerr != nil {
		return nil, xerr
	}

	return newInstance, nil
}

// findEmbeddedFeatureFile returns the instance of the embedded feature called 'name', if it exists
func findEmbeddedFeatureFile(name string) (*FeatureFile, fail.Error) {
	if _, ok := allEmbeddedFeaturesMap[name]; !ok {
		return nil, fail.NotFoundError("failed to find an embedded Feature named '%s'", name)
	}

	clone, err := allEmbeddedFeaturesMap[name].Clone()
	if err != nil {
		return nil, fail.Wrap(err)
	}

	newInstance, ok := clone.(*FeatureFile)
	if !ok {
		return nil, fail.NewError("embedded feature should be a *Feature")
	}

	newInstance.displayFileName = name + ".yml [embedded]"
	return newInstance, nil
}

// parse reads the content of the file, init parameter list and signals errors
func (ff *FeatureFile) parse() fail.Error {
	if ff.IsNull() {
		return fail.InvalidInstanceError()
	}

	xerr := ff.parseSuitableFor()
	if xerr != nil {
		return xerr
	}

	xerr = ff.parseFeatureRequirements()
	if xerr != nil {
		return xerr
	}

	xerr = ff.parseParameters()
	if xerr != nil {
		return xerr
	}

	xerr = ff.parseInstallers()
	if xerr != nil {
		return xerr
	}

	return nil
}

// parseSuitableFor parses the field suitableFor
func (ff *FeatureFile) parseSuitableFor() fail.Error {
	const (
		yamlRootKey = "feature.suitableFor"
	)

	var (
		flavorBOH      clusterflavor.Enum = clusterflavor.BOH
		flavorK8S      clusterflavor.Enum = clusterflavor.K8S
		flavorBOHLabel                    = flavorBOH.String()
		flavorK8SLabel                    = flavorK8S.String()
	)

	out := map[string]struct{}{}
	if ff.specs.IsSet(yamlRootKey) {
		fields := ff.specs.GetStringMap(yamlRootKey)
		for k, v := range fields {
			switch strings.ToLower(k) {
			case "host":
				if _, ok := v.(bool); ok {
					if v.(bool) {
						out["host"] = struct{}{}
					}
				} else if _, ok := v.(string); ok {
					switch strings.ToLower(v.(string)) {
					case "yes", "y", "ok", "1", "true":
						out["host"] = struct{}{}
					}
				} else {
					return fail.SyntaxError("unexpected value for key '%s.host'", yamlRootKey)
				}

			case "cluster":
				if _, ok := v.(bool); ok {
					if v.(bool) {
						out[flavorBOHLabel] = struct{}{}
						out[flavorK8SLabel] = struct{}{}
					}
				} else if _, ok := v.(string); ok {
					splitted := strings.Split(v.(string), ",")
					for _, v := range splitted {
						if v == "all" {
							out[flavorBOHLabel] = struct{}{}
							out[flavorK8SLabel] = struct{}{}
						} else {
							flavor, err := clusterflavor.Parse(v)
							if err != nil {
								return fail.ConvertError(err)
							}
							out[flavor.String()] = struct{}{}
						}
					}
				}

			default:
				return fail.SyntaxError("unhandled key '%s.%s'", yamlRootKey, v.(string))
			}
		}
	}

	// if there are no information in suitableFor, the feature is suitable for everything
	if len(out) == 0 {
		out = map[string]struct{}{
			"host":         {},
			flavorBOHLabel: {},
			flavorK8SLabel: {},
		}
	}

	ff.suitableFor = out

	return nil
}

// parseFeatureRequirements parses the dependencies key
func (ff *FeatureFile) parseFeatureRequirements() fail.Error {
	const yamlRootKey = "feature.requirements.features"

	if ff.specs.IsSet(yamlRootKey) {
		fields := ff.specs.GetStringSlice(yamlRootKey)
		out := make(map[string]struct{}, len(fields))
		for _, r := range fields {
			out[r] = struct{}{}
		}

		ff.dependencies = out
	} else {
		ff.dependencies = map[string]struct{}{}
	}

	return nil
}

// parseClusterSizingRequirements reads 'feature.dependencies.clusterSizing' from file content
func (ff *FeatureFile) parseClusterSizingRequirements() fail.Error {
	const yamlRootKey = "feature.requirements.clusterSizing"

	if !ff.specs.IsSet(yamlRootKey) {
		ff.clusterSizingRequirements = map[string]interface{}{}
		return nil
	}

	ff.clusterSizingRequirements = ff.specs.GetStringMap(yamlRootKey)
	return nil
}

// parseParameters parses the parameters and populates 'FeatureFile.parameters'
func (ff *FeatureFile) parseParameters() fail.Error {
	const (
		yamlRootKey    = "feature.parameters"
		nameKey        = "name"
		descriptionKey = "description"
		valueKey       = "value"
		controlKey     = "control"
	)

	if ff.specs.IsSet(yamlRootKey) {
		params, ok := ff.specs.Get(yamlRootKey).([]interface{})
		if !ok {
			return fail.SyntaxError("unsupported content for keyword '%s': must be a list of string or struct", yamlRootKey)
		}

		for k, p := range params {
			switch p := p.(type) {
			case string:
				if p == "" {
					continue
				}

				splitted := strings.Split(p, "=")
				name := splitted[0]

				hasDefaultValue := len(splitted) > 1
				var defaultValue string
				if hasDefaultValue {
					defaultValue = splitted[1]
				}
				newParam, xerr := NewFeatureParameter(name, "", hasDefaultValue, defaultValue, false, "")
				if xerr != nil {
					return xerr
				}

				if len(ff.parameters) == 0 {
					ff.parameters = map[string]FeatureParameter{}
				}
				ff.parameters[name] = newParam

			case map[interface{}]interface{}:
				casted := data.ToMapStringOfString(p)
				name, ok := casted[nameKey]
				if !ok {
					return fail.SyntaxError("missing 'name' field in entry #%d of keyword 'feature.parameters'", k+1)
				}
				if strings.ContainsAny(name, "=:") {
					return fail.SyntaxError("field 'name' cannot contain '=' or ':' in entry #%d", k+1)
				}

				description, _ := casted[descriptionKey] // nolint
				value, hasDefaultValue := casted[valueKey]
				valueControlCode, hasValueControl := casted[controlKey]
				newParam, xerr := NewFeatureParameter(name, description, hasDefaultValue, value, hasValueControl, valueControlCode)
				if xerr != nil {
					return xerr
				}

				if len(ff.parameters) == 0 {
					ff.parameters = map[string]FeatureParameter{}
				}
				ff.parameters[name] = newParam

			default:
				return fail.SyntaxError("unsupported content for keyword 'feature.parameters': must be a list of string or struct")
			}
		}
	}

	return nil
}

// parseInstallers reads 'feature.install' keyword and split up each triplet (installer method/action/step)
func (ff *FeatureFile) parseInstallers() fail.Error {
	const yamlRootKey = "feature.install"

	w := ff.specs.GetStringMap(yamlRootKey)
	out := make(map[string]interface{}, len(w))
	for k, v := range w {
		out[k] = v
	}
	ff.installers = out

	// Does nothing yet, need to review step handling to differentiate a step definition and a step realization
	return nil
}

// getDependencies returns a copy of dependencies defined in FeatureFile
func (ff FeatureFile) getDependencies() map[string]struct{} {
	out := make(map[string]struct{}, len(ff.dependencies))
	for k := range ff.dependencies {
		out[k] = struct{}{}
	}
	return out
}

// getClusterSizingRequirements returns the list of cluster sizing requirements by cluster flavor
func (ff FeatureFile) getClusterSizingRequirements() map[string]interface{} {
	out := make(map[string]interface{}, len(ff.clusterSizingRequirements))
	for k, v := range ff.clusterSizingRequirements {
		out[k] = v
	}
	return out
}

// getClusterSizingRequirementsForFlavor returns the list of cluster sizing requirements of a specific cluster flavor
func (ff FeatureFile) getClusterSizingRequirementsForFlavor(flavor string) map[string]interface{} {
	if flavor != "" {
		anon, ok := ff.clusterSizingRequirements[flavor]
		if ok {
			sizing, ok := anon.(map[string]interface{})
			if ok {
				out := make(map[string]interface{}, len(sizing))
				for k, v := range ff.clusterSizingRequirements {
					out[k] = v
				}
				return out
			}
		}
	}

	return nil
}

// getInsideFeatureFileFolders returns a list of folders to watch into
func getFeatureFileFolders(useCWD bool) []string {
	length := len(featureFileFolders)
	if useCWD {
		length += len(cwdFeatureFileFolders)
	}
	out := make([]string, 0, length)

	// get current dir
	cwd, _ := os.Getwd()

	// get homedir
	home := os.Getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}

	for k := range featureFileFolders {
		if strings.HasPrefix(featureFileFolders[k], "$HOME") {
			if home != "" {
				featureFileFolders[k] = home + strings.TrimPrefix(featureFileFolders[k], "$HOME")
			} else {
				continue
			}
		} else if strings.HasPrefix(featureFileFolders[k], ".") {
			if cwd != "" {
				featureFileFolders[k] = cwd + strings.TrimPrefix(featureFileFolders[k], ".")
			} else {
				continue
			}
		}

		out = append(out, featureFileFolders[k])
	}

	if useCWD {
		for k := range cwdFeatureFileFolders {
			if strings.HasPrefix(cwdFeatureFileFolders[k], "$HOME") {
				if home != "" {
					cwdFeatureFileFolders[k] = home + strings.TrimPrefix(cwdFeatureFileFolders[k], "$HOME")
				} else {
					continue
				}
			} else if strings.HasPrefix(cwdFeatureFileFolders[k], ".") {
				if cwd != "" {
					cwdFeatureFileFolders[k] = cwd + strings.TrimPrefix(cwdFeatureFileFolders[k], ".")
				} else {
					continue
				}
			}

			out = append(out, cwdFeatureFileFolders[k])
		}
	}

	return out
}

// walkInsideFeatureFileFolders walks inside folders where Feature Files may be found and returns a list of Feature names
func walkInsideFeatureFileFolders(filter featureFilter) ([]string, fail.Error) {
	var out []string
	switch filter {
	case allWithEmbedded, embeddedOnly:
		for _, v := range allEmbeddedFeatures {
			out = append(out, v.GetName())
		}
	}

	switch filter {
	case allWithEmbedded, withoutEmbedded:
		for _, v := range getFeatureFileFolders(false) {
			err := filepath.Walk(v, func(walkPath string, fi os.FileInfo, err error) error {
				if err != nil {
					switch casted := err.(type) {
					case *fs.PathError:
						switch casted.Err {
						case NOTFOUND:
							// entry not found, ignore it
							debug.IgnoreError(err)
							return nil
						default:
						}
					default:
					}
					logrus.Error(err)
					return err
				}

				if !fi.IsDir() {
					name := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSuffix(walkPath, path.Ext(walkPath)), v), "/")
					if name != "" {
						out = append(out, name)
					}
				}
				return nil
			})
			if err != nil {
				return nil, fail.ConvertError(err)
			}
		}
	}

	return out, nil
}

// setViperConfgigPathes ...
func setViperConfigPathes(v *viper.Viper) {
	if v != nil {
		folders := getFeatureFileFolders(false)
		for _, i := range folders {
			v.AddConfigPath(i)
		}
	}
}

// watchFeatureFileFolders watches folders that may contain Feature Files and react to changes (invalidating cache entry
// already loaded)
func watchFeatureFileFolders(ctx context.Context) error {
	watcher, err := rfsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer func() { _ = watcher.Close() }()

	done := make(chan bool)
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				onFeatureFileEvent(ctx, watcher, event)

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				logrus.Error("Feature File watcher returned an error: ", err)
			}
		}
	}()

	for _, v := range getFeatureFileFolders(false) {
		err = addPathToWatch(watcher, v)
		if err != nil {
			return err
		}
	}

	<-done
	return nil
}

func addPathToWatch(w *rfsnotify.RWatcher, path string) error {
	err := w.AddRecursive(path)
	if err != nil {
		switch casted := err.(type) {
		case *fs.PathError:
			switch casted.Err {
			case NOTFOUND:
				// folder not found, ignore it
				debug.IgnoreError(err)
				return nil
			default:
				logrus.Error(err)
				return err
			}
		default:
			logrus.Error(err)
			return err
		}
	}

	logrus.Debugf("adding monitoring of folder '%s' for Feature file changes", path)
	return nil
}

// onFeatureFileEvent reacts to filesystem change event
func onFeatureFileEvent(ctx context.Context, w *rfsnotify.RWatcher, e fsnotify.Event) {
	switch {
	case e.Op&fsnotify.Chmod == fsnotify.Chmod:
		fallthrough
	case e.Op&fsnotify.Remove == fsnotify.Remove:
		fallthrough
	case e.Op&fsnotify.Rename == fsnotify.Rename:
		fallthrough
	case e.Op&fsnotify.Write == fsnotify.Write:
		relativeName := reduceFilename(e.Name)
		stat, err := os.Stat(e.Name)
		if err == nil {
			if stat.IsDir() {
				// If the fs object is a folder, do nothing more
				return
			}

			// If the fs object is a file and is still readable, do nothing more
			if e.Op&fsnotify.Chmod == fsnotify.Chmod {
				fd, err := os.Open(e.Name)
				if err == nil {
					_ = fd.Close()
					return
				}
			}
		}

		// invalidate only .yml/.yaml files from cache
		extension := path.Ext(relativeName)
		if extension != ".yml" && extension != ".yaml" {
			return
		}

		// From here, we need to invalidate cache entry, either because content has changed or file have been removed/renamed or updated
		featureName := strings.TrimPrefix(strings.TrimSuffix(relativeName, extension), "/")
		if len(featureName) != len(relativeName) {
			delete(featureFileController, featureName)
		}

	case e.Op&fsnotify.Create == fsnotify.Create:
		// If the object created is a path, add it to RWatcher (if it's a file, nothing more to do, cache miss will
		// do the necessary in time
		fi, err := os.Stat(e.Name)
		if err == nil && fi.IsDir() {
			_ = w.AddRecursive(e.Name)
		}
	}
}

// reduceFilename removes the absolute part of 'name' corresponding to folder
func reduceFilename(name string) string {
	folders := getFeatureFileFolders(false)
	last := name
	for _, v := range folders {
		if strings.HasPrefix(name, v) {
			reduced := strings.TrimPrefix(name, v)
			if len(reduced) < len(last) {
				last = reduced
			}
		}
	}
	return strings.TrimLeft(last, "/")
}

// StartFeatureFileWatcher inits the watcher of Feature File changes
func StartFeatureFileWatcher() {
	// Starts go routine watching changes in Feature File folders
	go func() {
		err := watchFeatureFileFolders(context.Background())
		if err != nil {
			logrus.Error(err)
		}
	}()
}
