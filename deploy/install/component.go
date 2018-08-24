/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package install

import (
	"fmt"

	"github.com/CS-SI/SafeScale/deploy/install/api"
	"github.com/CS-SI/SafeScale/deploy/install/api/Method"

	"github.com/spf13/viper"
)

var (
	// EmptyValues corresponds to no values for the component
	EmptyValues = map[string]interface{}{}
)

// component contains the information about an installable component
type component struct {
	// displayName is the name of the service
	displayName string
	// fileName is the name of the specification file
	fileName string
	// embedded tells if the component is embedded in deploy
	embedded bool
	// Installers defines the installers available for the component
	installers map[Method.Enum]api.Installer
	// Dependencies lists other component(s) (by name) needed by this one
	dependencies []string
	// Management contains a string map of data that could be used to manage the component (if it makes sense)
	// This could be used to explain to Service object how to manage the component, to react as a service
	//Management map[string]interface{}
	// specs is the Viper instance containing component specification
	specs *viper.Viper
}

// NewComponent searches for a spec file name 'name' and initializes a new Component object
// with its content
func NewComponent(name string) (api.Component, error) {
	if name == "" {
		panic("name is empty!")
	}

	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale/components")
	v.AddConfigPath("$HOME/.config/safescale/components")
	v.AddConfigPath("/etc/safescale/components")
	v.SetConfigName(name)

	err := v.ReadInConfig()
	if err == nil {
		if !v.IsSet("component.name") {
			return nil, fmt.Errorf("syntax error in specification file: missing key 'name'")
		}
		if v.IsSet("component") {
			return &component{
				fileName:    name + ".yml",
				displayName: v.GetString("Name"),
				specs:       v,
			}, nil
		}
	}

	// Failed to find a spec file on filesystem, trying with embedded ones
	if component, ok := allEmbeddedMap[name]; ok {
		return component, nil
	}
	return nil, fmt.Errorf("failed to find a component named '%s'", name)
}

// installerOfMethod instanciates the right installer corresponding to the method
func (c *component) installerOfMethod(method Method.Enum) api.Installer {
	var installer api.Installer
	switch method {
	case Method.Script:
		installer = NewScriptInstaller()
	case Method.Apt:
		installer = NewAptInstaller()
	case Method.Yum:
		installer = NewYumInstaller()
	case Method.Dnf:
		installer = NewDnfInstaller()
	case Method.DCOS:
		installer = NewDcosInstaller()
		//	case Method.Ansible:
		//		installer = NewAnsibleInstaller()
		//	case Method.Helm:
		//		installer = NewHelmInstaller()
	}
	return installer
}

// DisplayName returns the name of the component
func (c *component) DisplayName() string {
	return c.displayName
}

// BaseFilename returns the name of the component specification file without '.yml'
func (c *component) BaseFilename() string {
	return c.fileName
}

// DisplayFilename returns the full file name, with [embedded] added at the end if the
// component is embedded.
func (c *component) DisplayFilename() string {
	filename := c.fileName + ".yml"
	if c.embedded {
		filename += " [embedded]"
	}
	return filename
}

// Specs returns the data from the spec file
func (c *component) Specs() *viper.Viper {
	return c.specs
}

// Applyable tells if the component is installable on the target
func (c *component) Applyable(target api.Target) bool {
	methods := target.GetMethods()
	for _, k := range methods {
		installer := c.installerOfMethod(k)
		if installer != nil {
			return true
		}
	}
	return false
}

// Check if component is installed on target
func (c *component) Check(target api.Target) (bool, api.CheckResults, error) {
	methods := target.GetMethods()
	var installer api.Installer
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("component.installing.%s", method.String())) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return false, api.CheckResults{}, fmt.Errorf("failed to find a way to check '%s'", c.DisplayName())
	}
	return installer.Check(c, target)
}

// Add installs the component on the target
func (c *component) Add(target api.Target, values map[string]interface{}) (bool, api.AddResults, error) {
	methods := target.GetMethods()
	var installer api.Installer
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("component.installing.%s", method.String())) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return false, api.AddResults{}, fmt.Errorf("failed to find a way to install '%s'", c.DisplayName())
	}
	return installer.Add(c, target, values)
}

// Remove uninstalls the component from the target
func (c *component) Remove(target api.Target) (bool, api.RemoveResults, error) {
	methods := target.GetMethods()
	var installer api.Installer
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("component.installing.%s", method.String())) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return false, api.RemoveResults{}, fmt.Errorf("failed to find a way to uninstall '%s'", c.DisplayName())
	}
	return installer.Remove(c, target)
}

// FakeComponent is a component already installed; it's used to tell if a specific component
// is installed, but disallows the ability to be installed or uninstalled.
// The goal is to be able to mark a component installed even if not installed by the package (because
// it's a requirement for a cluster management tool for example)
type FakeComponent struct {
	real component
}

// NewFakeComponent returns a fake component
func NewFakeComponent(name string) *FakeComponent {
	return &FakeComponent{
		real: component{
			displayName: name,
		},
	}
}

// Add errors the component can't be installed
func (c *FakeComponent) Add(target api.Target) error {
	return fmt.Errorf("component can't be installed")
}

// Remove errors the component can't be removed
func (c *FakeComponent) Remove(target api.Target) error {
	return fmt.Errorf("component can't be uninstalled")
}

// Applyable ...
func (c *FakeComponent) Applyable(target api.Target) bool {
	return c.real.Applyable(target)
}
