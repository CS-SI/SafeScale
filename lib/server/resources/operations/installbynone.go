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

// noneInstaller is an installer using script to add and remove a feature
type noneInstaller struct{}

// Check checks if the feature is installed
func (i *noneInstaller) Check(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, xerr fail.Error) {
	r = nil
	defer fail.OnPanic(&xerr)

	if f == nil {
		return nil, fail.InvalidParameterError("f", "cannot be null value of 'resources.Feature'")
	}
	if t == nil {
		return nil, fail.InvalidParameterError("t", "cannot be nil")
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

// Add installs the feature using the install script in Specs
// 'values' contains the values associated with parameters as defined in specification file
func (i *noneInstaller) Add(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, xerr fail.Error) {
	r = nil
	defer fail.OnPanic(&xerr)

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

	if xerr = w.CanProceed(s); xerr != nil {
		logrus.Error(xerr.Error())
		return nil, xerr
	}

	if r, xerr = w.Proceed(v, s); xerr != nil {
		xerr = fail.Wrap(xerr, "failed to add Feature '%s' on %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	// // Forge a completed and successful results
	// out := &results{
	// 	t.GetName(): &unitResults{
	// 		"none": &stepResult{
	// 			completed: true,
	// 			success:   true,
	// 		},
	// 	},
	// }
	return r, xerr
}

// Remove uninstalls the feature
func (i *noneInstaller) Remove(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (r resources.Results, xerr fail.Error) {
	r = nil
	defer fail.OnPanic(&xerr)

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

	if xerr = w.CanProceed(s); xerr != nil {
		logrus.Error(xerr.Error())
		return nil, xerr
	}

	if r, xerr = w.Proceed(v, s); xerr != nil {
		xerr = fail.Wrap(xerr, "failed to remove Feature '%s' from %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}

	return r, xerr
	// // Forge a completed and successful results
	// out := &results{
	// 	t.GetName(): &unitResults{
	// 		"none": &stepResult{
	// 			completed: true,
	// 			success:   true,
	// 		},
	// 	},
	// }
	// return out, nil
}

// newNoneInstaller creates a new instanc
func newNoneInstaller() Installer {
	return &noneInstaller{}
}
