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

package resources

import (
	"context"
	"fmt"
	"strings"

	rscapi "github.com/CS-SI/SafeScale/v22/lib/backend/resources/api"
	"github.com/CS-SI/SafeScale/v22/lib/utils/data"
	"github.com/CS-SI/SafeScale/v22/lib/utils/options"
	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installaction"
	"github.com/CS-SI/SafeScale/v22/lib/backend/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v22/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// genericPackager is an object implementing the OS package management
// It handles package management on single host or entire cluster
type genericPackager struct {
	keyword       string
	method        installmethod.Enum
	checkCommand  alterCommandCB
	addCommand    alterCommandCB
	removeCommand alterCommandCB
}

// Check checks if the Feature is installed
func (g *genericPackager) Check(ctx context.Context, f *Feature, t Targetable, v data.Map[string, any], opts ...options.Option) (r rscapi.Results, ferr fail.Error) {
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

	yamlKey := "feature.install." + g.keyword + ".check"
	if !f.Specs().IsSet(yamlKey) {
		return nil, fail.SyntaxError("syntax error in Feature '%s' specification file (%s): no key '%s' found", f.GetName(), f.GetDisplayFilename(ctx), yamlKey)
	}

	o, xerr := options.New(opts...)
	if xerr != nil {
		return nil, xerr
	}

	s, xerr := options.ValueOrDefault(o, OptionFeatureSettings, rscapi.FeatureSettings{})
	if xerr != nil {
		return nil, xerr
	}

	worker, xerr := newWorker(ctx, f, t, g.method, installaction.Check, g.checkCommand)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	defer worker.Terminate()

	xerr = worker.CanProceed(ctx, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Info(xerr.Error())
		return nil, xerr
	}

	r, xerr = worker.Proceed(ctx, v, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return r, fail.Wrap(xerr, "failed to check if Feature '%s' is installed on %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}
	return r, nil
}

// Add installs the Feature using apt
func (g *genericPackager) Add(ctx context.Context, f *Feature, t Targetable, v data.Map[string, any], opts ...options.Option) (r rscapi.Results, ferr fail.Error) {
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

	yamlKey := "feature.install." + g.keyword + ".add"
	if !f.Specs().IsSet(yamlKey) {
		return nil, fail.SyntaxError("syntax error in Feature '%s' specification file (%s): no key '%s' found", f.GetName(), f.GetDisplayFilename(ctx), yamlKey)
	}

	o, xerr := options.New(opts...)
	if xerr != nil {
		return nil, xerr
	}

	s, xerr := options.ValueOrDefault(o, OptionFeatureSettings, rscapi.FeatureSettings{})
	if xerr != nil {
		return nil, xerr
	}

	worker, xerr := newWorker(ctx, f, t, g.method, installaction.Add, g.addCommand)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Println(xerr.Error())
		return nil, xerr
	}
	defer worker.Terminate()

	xerr = worker.CanProceed(ctx, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Info(xerr.Error())
		return nil, xerr
	}

	r, xerr = worker.Proceed(ctx, v, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return r, fail.Wrap(xerr, "failed to add Feature '%s' on %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}
	return r, nil
}

// Remove uninstalls the Feature using the RemoveScript script
func (g *genericPackager) Remove(ctx context.Context, f *Feature, t Targetable, v data.Map[string, any], opts ...options.Option) (r rscapi.Results, ferr fail.Error) {
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

	yamlKey := "feature.install." + g.keyword + ".remove"
	if !f.Specs().IsSet(yamlKey) {
		return nil, fail.SyntaxError("syntax error in Feature '%s' specification file (%s): no key '%s' found", f.GetName(), f.GetDisplayFilename(ctx), yamlKey)
	}

	o, xerr := options.New(opts...)
	if xerr != nil {
		return nil, xerr
	}

	s, xerr := options.ValueOrDefault(o, OptionFeatureSettings, rscapi.FeatureSettings{})
	if xerr != nil {
		return nil, xerr
	}

	worker, xerr := newWorker(ctx, f, t, g.method, installaction.Remove, g.removeCommand)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return nil, xerr
	}
	defer worker.Terminate()

	xerr = worker.CanProceed(ctx, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		logrus.Info(xerr.Error())
		return nil, xerr
	}

	r, xerr = worker.Proceed(ctx, v, s)
	xerr = debug.InjectPlannedFail(xerr)
	if xerr != nil {
		return r, fail.Wrap(xerr, "failed to remove Feature '%s' from %s '%s'", f.GetName(), t.TargetType(), t.GetName())
	}
	return r, nil
}

// aptInstaller is an installer using script to add and remove a Feature
type aptInstaller struct {
	genericPackager
}

// NewAptInstaller creates a new instance of Installer using script
func NewAptInstaller() Installer {
	return &aptInstaller{
		genericPackager: genericPackager{
			keyword: strings.ToLower(installmethod.Apt.String()),
			method:  installmethod.Apt,
			checkCommand: func(pkg string) string {
				return fmt.Sprintf("sudo dpkg-query -s '%s' &>/dev/null", pkg)
			},
			addCommand: func(pkg string) string {
				return fmt.Sprintf("sudo apt-get install -y '%s'", pkg)
			},
			removeCommand: func(pkg string) string {
				return fmt.Sprintf("sudo apt-get remove -y '%s'", pkg)
			},
		},
	}
}

// yumInstaller is an installer using yum to add and remove a Feature
type yumInstaller struct {
	genericPackager
}

// NewYumInstaller creates a new instance of Installer using script
func NewYumInstaller() Installer {
	return &yumInstaller{
		genericPackager: genericPackager{
			keyword: strings.ToLower(installmethod.Yum.String()),
			method:  installmethod.Yum,
			checkCommand: func(pkg string) string {
				return fmt.Sprintf("sudo rpm -q %s &>/dev/null", pkg)
			},
			addCommand: func(pkg string) string {
				return fmt.Sprintf("sudo yum install -y %s", pkg)
			},
			removeCommand: func(pkg string) string {
				return fmt.Sprintf("sudo yum remove -y %s", pkg)
			},
		},
	}
}

// dnfInstaller is an installer using yum to add and remove a Feature
type dnfInstaller struct {
	genericPackager
}

// NewDnfInstaller creates a new instance of Installer using script
func NewDnfInstaller() Installer {
	return &dnfInstaller{
		genericPackager: genericPackager{
			keyword: strings.ToLower(installmethod.Dnf.String()),
			method:  installmethod.Dnf,
			checkCommand: func(pkg string) string {
				return fmt.Sprintf("sudo dnf list installed %s &>/dev/null", pkg)
			},
			addCommand: func(pkg string) string {
				return fmt.Sprintf("sudo dnf install -y %s", pkg)
			},
			removeCommand: func(pkg string) string {
				return fmt.Sprintf("sudo dnf uninstall -y %s", pkg)
			},
		},
	}
}
