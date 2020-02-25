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

package operations

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
)

// bashInstaller is an installer using script to add and remove a feature
type bashInstaller struct{}

func (i *bashInstaller) GetName() string {
	return "script"
}

// Check checks if the feature is installed, using the check script in Specs
func (i *bashInstaller) Check(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, error) {
	if f == nil {
		return nil, scerr.InvalidParameterError("f", "cannot be nil")
	}
	if t == nil {
		return nil, scerr.InvalidParameterError("t", "cannot be nil")
	}

	yamlKey := "feature.install.bash.check"
	if !f.SafeGetSpecs().IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s): no key '%s' found`
		return nil, fmt.Errorf(msg, f.SafeGetName(), f.SafeGetDisplayFilename(), yamlKey)
	}

	worker, err := newWorker(f, t, installmethod.Bash, installaction.Check, nil)
	if err != nil {
		return nil, err
	}

	err = worker.CanProceed(s)
	if err != nil {
		logrus.Error(err.Error())
		return nil, err
	}
	return worker.Proceed(v, s)
}

// Add installs the feature using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *bashInstaller) Add(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, error) {
	if f == nil {
		return nil, scerr.InvalidParameterError("f", "cannot be nil")
	}
	if t == nil {
		return nil, scerr.InvalidParameterError("t", "cannot be nil")
	}

	// Determining if install script is defined in specification file
	if !f.SafeGetSpecs().IsSet("feature.install.bash.add") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.add' found`
		return nil, fmt.Errorf(msg, f.SafeGetName(), f.SafeGetDisplayFilename())
	}

	worker, err := newWorker(f, t, installmethod.Bash, installaction.Add, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		logrus.Println(err.Error())
		return nil, err
	}
	if !worker.ConcernsCluster() {
		if _, ok := v["Username"]; !ok {
			v["Username"] = "safescale"
		}
	}
	return worker.Proceed(v, s)
}

// Remove uninstalls the feature
func (i *bashInstaller) Remove(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, error) {
	if f == nil {
		return nil, scerr.InvalidParameterError("f", "cannot be nil")
	}
	if t == nil {
		return nil, scerr.InvalidParameterError("t", "cannot be nil")
	}

	if !f.SafeGetSpecs().IsSet("feature.install.bash.remove") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.remove' found`
		return nil, fmt.Errorf(msg, f.SafeGetName(), f.SafeGetDisplayFilename())
	}

	worker, err := newWorker(f, t, installmethod.Bash, installaction.Remove, nil)
	if err != nil {
		return nil, err
	}
	err = worker.CanProceed(s)
	if err != nil {
		logrus.Println(err.Error())
		return nil, err
	}

	// if t.GetTargetType() != featuretargettype.CLUSTER {
	// 	if _, ok := v["Username"]; !ok {
	// 		v["Username"] = "safescale"
	// 	}
	// }
	return worker.Proceed(v, s)
}

// NewBashInstaller creates a new instance of Installer using script
func NewBashInstaller() Installer {
	return &bashInstaller{}
}
