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

	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/v22/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// noneInstaller is an installer using script to add and remove a Feature
type noneInstaller struct{}

// Check checks if the Feature is installed
func (i *noneInstaller) Check(_ context.Context, f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, ferr fail.Error) {
	r = nil
	defer fail.OnPanic(&ferr)

	if f == nil {
		return nil, fail.InvalidParameterError("f", "cannot be null value of 'resources.Feature'")
	}
	if t == nil {
		return nil, fail.InvalidParameterCannotBeNilError("t")
	}

	// Forge a completed but unsuccessful results
	out := &results{
		t.GetName(): &unitResults{
			"none": &stepResult{
				completed: true,
				success:   false,
			},
		},
	}
	return out, nil
}

// Add installs the Feature using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *noneInstaller) Add(ctx context.Context, f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, ferr fail.Error) {
	r = nil
	defer fail.OnPanic(&ferr)

	if ctx == nil {
		return nil, fail.InvalidParameterCannotBeNilError("ctx")
	}
	if f == nil {
		return nil, fail.InvalidParameterError("f", "cannot be null value of 'resources.Feature'")
	}
	if t == nil {
		return nil, fail.InvalidParameterCannotBeNilError("t")
	}

	w, xerr := newWorker(f, t, installmethod.None, installaction.Add, nil)
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
		return r, fail.Wrap(xerr, "failed to add Feature '%s' on %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, nil
}

// Remove uninstalls the Feature
func (i *noneInstaller) Remove(ctx context.Context, f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, ferr fail.Error) {
	r = nil
	defer fail.OnPanic(&ferr)

	if f == nil {
		return nil, fail.InvalidParameterError("f", "cannot be null value of 'resources.Feature'")
	}
	if t == nil {
		return nil, fail.InvalidParameterError("t", "cannot be nil")
	}

	w, xerr := newWorker(f, t, installmethod.None, installaction.Add, nil)
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
		return r, fail.Wrap(xerr, "failed to remove Feature '%s' from %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, nil
}

// newNoneInstaller creates a new instance
func newNoneInstaller() Installer {
	return &noneInstaller{}
}
