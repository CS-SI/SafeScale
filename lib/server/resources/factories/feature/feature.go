/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package feature

import (
    "github.com/CS-SI/SafeScale/lib/server/resources"
    "github.com/CS-SI/SafeScale/lib/server/resources/operations"
    "github.com/CS-SI/SafeScale/lib/utils/concurrency"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
)

// // ErrorList lists all features suitable for hosts
// func ErrorList() ([]interface{}, error) {
// 	cfgFiles := mapset.NewSet()

// 	captured := mapset.NewSet()

// 	var paths []string
// 	paths = append(paths, utils.AbsPathify("$HOME/.safescale/features"))
// 	paths = append(paths, utils.AbsPathify("$HOME/.config/safescale/features"))
// 	paths = append(paths, utils.AbsPathify("/etc/safescale/features"))

// 	for _, path := range paths {
// 		files, err := ioutil.ReadDir(path)
// 		if err == nil {
// 			for _, f := range files {
// 				if isCfgFile := strings.HasSuffix(strings.ToLower(f.GetName()), ".yml"); isCfgFile == true {
// 					cfgFiles.Add(strings.Replace(strings.ToLower(f.GetName()), ".yml", "", 1))
// 				}
// 			}
// 		}
// 	}
// 	for _, feat := range operations.GetAllEmbeddedFeatures() {
// 		yamlKey := "feature.suitableFor.host"

// 		if !captured.Contains(feat.GetName()) {
// 			ok := false
// 			if feat.GetSpecs().IsSet(yamlKey) {
// 				value := strings.ToLower(feat.GetSpecs().GetString(yamlKey))
// 				ok = value == "ok" || value == "yes" || value == "true" || value == "1"
// 			}
// 			if ok {
// 				cfgFiles.Add(feat.GetFilename())
// 			}

// 			captured.Add(feat.GetName())
// 		}
// 	}

// 	return cfgFiles.ToSlice(), nil
// }

// New searches for a spec file name 'name' and initializes a new Feature object
// with its content
func New(task concurrency.Task, name string) (resources.Feature, error) {
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    if name == "" {
        return nil, fail.InvalidParameterError("name", "can't be empty string!")
    }

    feat, err := operations.NewFeature(task, name)
    if err != nil {
        if _, ok := err.(*fail.ErrNotFound); !ok {
            return nil, err
        }

        // Failed to find a spec file on filesystem, trying with embedded ones
        feat, err = operations.NewEmbeddedFeature(task, name)
        if err != nil {
            return nil, err
        }
    }
    return feat, nil
}

// NewEmbedded searches for an embedded feature called 'name' and initializes a new Feature object
// with its content
func NewEmbedded(task concurrency.Task, name string) (resources.Feature, error) {
    if task.IsNull() {
        return nil, fail.InvalidParameterError("task", "cannot be nil")
    }
    if name == "" {
        return nil, fail.InvalidParameterError("name", "canno't be empty string!")
    }

    return operations.NewEmbeddedFeature(task, name)
}
