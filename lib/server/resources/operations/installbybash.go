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
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// bashInstaller is an installer using script to add and remove a feature
type bashInstaller struct{}

// Check checks if the feature is installed, using the check script in Specs
func (i *bashInstaller) Check(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, xerr fail.Error) {
	r = nil
	defer fail.OnPanic(&xerr)

	if f == nil {
		return nil, fail.InvalidParameterCannotBeNilError("f")
	}
	if t == nil {
		return nil, fail.InvalidParameterCannotBeNilError("t")
	}

	yamlKey := "feature.install.bash.check"
	if !f.(*feature).Specs().IsSet(yamlKey) {
		msg := `syntax error in feature '%s' specification file (%s): no key '%s' found`
		return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename(), yamlKey)
	}

	w, xerr := newWorker(f, t, installmethod.Bash, installaction.Check, nil)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = w.CanProceed(s); xerr != nil {
		logrus.Error(xerr.Error())
		return nil, xerr
	}

	if r, xerr = w.Proceed(v, s); xerr != nil {
		xerr = fail.Wrap(xerr, "failed to check if Feature '%s' is installed on %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, xerr
}

// Add installs the feature using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *bashInstaller) Add(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, xerr fail.Error) {
	r = nil
	defer fail.OnPanic(&xerr)

	if f == nil {
		return nil, fail.InvalidParameterCannotBeNilError("f")
	}
	if t == nil {
		return nil, fail.InvalidParameterCannotBeNilError("t")
	}

	// Determining if install script is defined in specification file
	if !f.(*feature).Specs().IsSet("feature.install.bash.add") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.add' found`
		return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename())
	}

	w, xerr := newWorker(f, t, installmethod.Bash, installaction.Add, nil)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = w.CanProceed(s); xerr != nil {
		logrus.Info(xerr.Error())
		return nil, xerr
	}

	if !w.ConcernsCluster() {
		if _, ok := v["Username"]; !ok {
			v["Username"] = "safescale"
		}
	}

	if r, xerr = w.Proceed(v, s); xerr != nil {
		xerr = fail.Wrap(xerr, "failed to add Feature '%s' on %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, xerr
}

// Remove uninstalls the feature
func (i *bashInstaller) Remove(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, xerr fail.Error) {
	r = nil
	defer fail.OnPanic(&xerr)

	if f == nil {
		return nil, fail.InvalidParameterCannotBeNilError("f")
	}
	if t == nil {
		return nil, fail.InvalidParameterCannotBeNilError("t")
	}

	if !f.(*feature).Specs().IsSet("feature.install.bash.remove") {
		msg := `syntax error in feature '%s' specification file (%s):
				no key 'feature.install.bash.remove' found`
		return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename())
	}

	w, xerr := newWorker(f, t, installmethod.Bash, installaction.Remove, nil)
	if xerr != nil {
		return nil, xerr
	}

	if xerr = w.CanProceed(s); xerr != nil {
		logrus.Info(xerr.Error())
		return nil, xerr
	}

	if r, xerr = w.Proceed(v, s); xerr != nil {
		xerr = fail.Wrap(xerr, "failed to remove Feature '%s' from %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, xerr
}

// newBashInstaller creates a new instance of Installer using script
func newBashInstaller() Installer {
	return &bashInstaller{}
}
