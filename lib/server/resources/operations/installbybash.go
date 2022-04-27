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

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// bashInstaller is an installer using script to add and remove a Feature
type bashInstaller struct{}

// Check checks if the Feature is installed, using the check script in Specs
func (i *bashInstaller) Check(ctx context.Context, f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, ferr fail.Error) {
	r = nil
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if f == nil {
		return nil, fail.InvalidParameterCannotBeNilError("f")
	}
	if t == nil {
		return nil, fail.InvalidParameterCannotBeNilError("t")
	}

	yamlKey := "feature.install.bash.check"
	if !f.(*Feature).Specs().IsSet(yamlKey) {
		msg := `syntax error in Feature '%s' specification file (%s): no key '%s' found`
		return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename(), yamlKey)
	}

	w, xerr := newWorker(f, t, installmethod.Bash, installaction.Check, nil)
	if xerr != nil {
		return nil, xerr
	}
	defer w.Terminate()

	xerr = w.CanProceed(ctx, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Error(xerr.Error())
		return nil, xerr
	}

	r, xerr = w.Proceed(ctx, v, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return r, fail.Wrap(xerr, "failed to check if Feature '%s' is installed on %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, nil
}

// Add installs the Feature using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *bashInstaller) Add(ctx context.Context, f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, ferr fail.Error) {
	r = nil
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if f == nil {
		return nil, fail.InvalidParameterCannotBeNilError("f")
	}
	if t == nil {
		return nil, fail.InvalidParameterCannotBeNilError("t")
	}

	// Determining if install script is defined in specification file
	if !f.(*Feature).Specs().IsSet("feature.install.bash.add") {
		msg := `syntax error in Feature '%s' specification file (%s):
				no key 'feature.install.bash.add' found`
		return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename())
	}

	w, xerr := newWorker(f, t, installmethod.Bash, installaction.Add, nil)
	if xerr != nil {
		return nil, xerr
	}
	defer w.Terminate()

	xerr = w.CanProceed(ctx, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Info(xerr.Error())
		return nil, xerr
	}

	if !w.ConcernsCluster() {
		if _, ok := v["Username"]; !ok {
			v["Username"] = "safescale"
		}
	}

	r, xerr = w.Proceed(ctx, v, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return r, fail.Wrap(xerr, "failed to add Feature '%s' on %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, nil
}

// Remove uninstalls the Feature
func (i *bashInstaller) Remove(ctx context.Context, f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, ferr fail.Error) {
	r = nil
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if f == nil {
		return nil, fail.InvalidParameterCannotBeNilError("f")
	}
	if t == nil {
		return nil, fail.InvalidParameterCannotBeNilError("t")
	}

	if !f.(*Feature).Specs().IsSet("feature.install.bash.remove") {
		msg := `syntax error in Feature '%s' specification file (%s):
				no key 'feature.install.bash.remove' found`
		return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename())
	}

	w, xerr := newWorker(f, t, installmethod.Bash, installaction.Remove, nil)
	if xerr != nil {
		return nil, xerr
	}
	defer w.Terminate()

	xerr = w.CanProceed(ctx, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Info(xerr.Error())
		return nil, xerr
	}

	r, xerr = w.Proceed(ctx, v, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return r, fail.Wrap(xerr, "failed to remove Feature '%s' from %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, nil
}

// newBashInstaller creates a new instance of Installer using script
func newBashInstaller() Installer {
	return &bashInstaller{}
}
