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
	"github.com/CS-SI/SafeScale/v22/lib/backend/iaas"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/clusterflavor"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var (
	featureFileFolders = []string{
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
	displayName               string                      // is the name of the feature
	fileName                  string                      // is the name of the specification file
	displayFileName           string                      // is the 'pretty' name of the specification file
	embedded                  bool                        // tells if the Feature is embedded in SafeScale
	specs                     *viper.Viper                // is the Viper instance containing Feature file content
	suitableFor               map[string]struct{}         // tells for what the Feature is suitable
	parameters                map[string]FeatureParameter // contains all the parameters defined in Feature file
	versionControl            map[string]string           // contains the templated bash code to determine version of a component used in the FeatureFile
	dependencies              map[string]struct{}         // contains the list of features required to install the Feature described by the file
	clusterSizingRequirements map[string]interface{}      // contains the cluster sizing requirements to allow install
	installers                map[string]interface{}
}

func newFeatureFile(fileName, displayName string, embedded bool, specs *viper.Viper) *FeatureFile {
	instance := &FeatureFile{
		parameters:      map[string]FeatureParameter{},
		versionControl:  map[string]string{},
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

	src, ok := p.(*FeatureFile)
	if !ok {
		return ff, fail.InvalidParameterError("p", "must be a '*FeatureFile'")
	}

	ff.displayName = src.displayName
	ff.fileName = src.fileName
	ff.displayFileName = src.displayFileName
	ff.specs = src.specs // Note: using same pointer here is wanted; do not raise an alert in UT on this
	ff.embedded = src.embedded
	return ff, nil
}

// GetName returns the display name of the Feature, with error handling
func (ff *FeatureFile) GetName() string {
	return ff.displayName
}

// GetID ...
func (ff *FeatureFile) GetID() (string, error) {
	if ff == nil {
		return "", fmt.Errorf("invalid instance")
	}
	return ff.GetName(), nil
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

		logrus.WithContext(context.Background()).Tracef("Loaded Feature '%s' (%s)", newInstance.DisplayFilename(), newInstance.Filename())
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

		logrus.WithContext(context.Background()).Tracef("Loaded Feature '%s' (%s)", newInstance.DisplayFilename(), newInstance.Filename())

		// if we can log the sha256 of the feature, do it
		filename := v.ConfigFileUsed()
		if filename != "" {
			content, err := os.ReadFile(filename)
			if err != nil {
				return nil, fail.ConvertError(err)
			}

			logrus.WithContext(context.Background()).Tracef("Loaded Feature '%s' SHA256:%s", name, getSHA256Hash(string(content)))
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
func walkInsideFeatureFileFolders(ctx context.Context, filter featureFilter) ([]string, fail.Error) {
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
							debug.IgnoreError2(ctx, err)
							return nil
						default:
						}
					default:
					}
					logrus.WithContext(ctx).Error(err)
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
