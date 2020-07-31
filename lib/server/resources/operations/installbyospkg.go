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
    "strings"

    "github.com/sirupsen/logrus"

    "github.com/CS-SI/SafeScale/lib/server/resources"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/installaction"
    "github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
    "github.com/CS-SI/SafeScale/lib/utils/data"
    "github.com/CS-SI/SafeScale/lib/utils/fail"
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

// Check checks if the feature is installed
func (g *genericPackager) Check(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, fail.Error) {
    if f.IsNull() {
        return nil, fail.InvalidParameterError("f", "cannot be nil")
    }
    if t == nil {
        return nil, fail.InvalidParameterError("t", "cannot be nil")
    }

    yamlKey := "feature.install." + g.keyword + ".check"
    if !f.(*feature).Specs().IsSet(yamlKey) {
        msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
        return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename(), yamlKey)
    }

    worker, xerr := newWorker(f, t, g.method, installaction.Check, g.checkCommand)
    if xerr != nil {
        return nil, xerr
    }
    if xerr = worker.CanProceed(s); xerr != nil {
        logrus.Info(xerr.Error())
        return nil, xerr
    }
    return worker.Proceed(v, s)
}

// Add installs the feature using apt
func (g *genericPackager) Add(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, fail.Error) {
    if f.IsNull() {
        return nil, fail.InvalidParameterError("f", "cannot be nil")
    }
    if t == nil {
        return nil, fail.InvalidParameterError("t", "cannot be nil")
    }

    yamlKey := "feature.install." + g.keyword + ".add"
    if !f.(*feature).Specs().IsSet(yamlKey) {
        msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
        return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename(), yamlKey)
    }

    worker, xerr := newWorker(f, t, g.method, installaction.Add, g.addCommand)
    if xerr != nil {
        logrus.Println(xerr.Error())
        return nil, xerr
    }
    if xerr = worker.CanProceed(s); xerr != nil {
        logrus.Info(xerr.Error())
        return nil, xerr
    }

    return worker.Proceed(v, s)
}

// Remove uninstalls the feature using the RemoveScript script
func (g *genericPackager) Remove(f resources.Feature, t resources.Targetable, v data.Map, s resources.FeatureSettings) (resources.Results, fail.Error) {
    if f.IsNull() {
        return nil, fail.InvalidParameterError("f", "cannot be nil")
    }
    if t == nil {
        return nil, fail.InvalidParameterError("t", "cannot be nil")
    }

    yamlKey := "feature.install." + g.keyword + ".remove"
    if !f.(*feature).Specs().IsSet(yamlKey) {
        msg := `syntax error in feature '%s' specification file (%s):
				no key '%s' found`
        return nil, fail.SyntaxError(msg, f.GetName(), f.GetDisplayFilename(), yamlKey)
    }

    worker, xerr := newWorker(f, t, g.method, installaction.Remove, g.removeCommand)
    if xerr != nil {
        return nil, xerr
    }
    if xerr = worker.CanProceed(s); xerr != nil {
        logrus.Info(xerr.Error())
        return nil, xerr
    }
    return worker.Proceed(v, s)
}

// aptInstaller is an installer using script to add and remove a feature
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

// yumInstaller is an installer using yum to add and remove a feature
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

// dnfInstaller is an installer using yum to add and remove a feature
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
