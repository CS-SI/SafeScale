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
	"log"
	"strings"

	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"

	"github.com/spf13/viper"
)

var (
	// EmptyValues corresponds to no values for the component
	EmptyValues = map[string]interface{}{}
)

// Variables defines the parameters a Installer may need
type Variables map[string]interface{}

// Component contains the information about an installable component
type Component struct {
	// displayName is the name of the service
	displayName string
	// fileName is the name of the specification file
	fileName string
	// embedded tells if the component is embedded in deploy
	embedded bool
	// Installers defines the installers available for the component
	installers map[Method.Enum]Installer
	// Dependencies lists other component(s) (by name) needed by this one
	//dependencies []string
	// Management contains a string map of data that could be used to manage the component (if it makes sense)
	// This could be used to explain to Service object how to manage the component, to react as a service
	//Management map[string]interface{}
	// specs is the Viper instance containing component specification
	specs *viper.Viper
}

// NewComponent searches for a spec file name 'name' and initializes a new Component object
// with its content
func NewComponent(name string) (*Component, error) {
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
			return &Component{
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
func (c *Component) installerOfMethod(method Method.Enum) Installer {
	var installer Installer
	switch method {
	case Method.Bash:
		installer = NewBashInstaller()
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
func (c *Component) DisplayName() string {
	return c.displayName
}

// BaseFilename returns the name of the component specification file without '.yml'
func (c *Component) BaseFilename() string {
	return c.fileName
}

// DisplayFilename returns the full file name, with [embedded] added at the end if the
// component is embedded.
func (c *Component) DisplayFilename() string {
	filename := c.fileName + ".yml"
	if c.embedded {
		filename += " [embedded]"
	}
	return filename
}

// Specs returns the data from the spec file
func (c *Component) Specs() *viper.Viper {
	return c.specs
}

// Applyable tells if the component is installable on the target
func (c *Component) Applyable(t Target) bool {
	methods := t.Methods()
	for _, k := range methods {
		installer := c.installerOfMethod(k)
		if installer != nil {
			return true
		}
	}
	return false
}

// Check if component is installed on target
// Check is ok if error is nil and Results.Successful() is true
func (c *Component) Check(t Target, v Variables) (Results, error) {
	methods := t.Methods()
	var installer Installer
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("component.install.%s", strings.ToLower(method.String()))) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to check '%s'", c.DisplayName())
	}

	//if debug
	if true {
		log.Printf("Checking if component '%s' is installed on %s '%s'...\n", c.DisplayName(), t.Type(), t.Name())
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err := checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	return installer.Check(c, t, v)
}

// Add installs the component on the target
// Installs succeeds if error == nil and Results.Successful() is true
func (c *Component) Add(t Target, v Variables) (Results, error) {
	methods := t.Methods()
	var (
		installer Installer
		i         uint8
	)
	for i = 1; i <= uint8(len(methods)); i++ {
		method := methods[i]
		if c.specs.IsSet(fmt.Sprintf("component.install.%s", strings.ToLower(method.String()))) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to install '%s'", c.DisplayName())
	}

	//if debug
	if false {
		log.Printf("Installing component '%s' on %s '%s'...\n", c.DisplayName(), t.Type(), t.Name())
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err := checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	return installer.Add(c, t, v)
}

// Remove uninstalls the component from the target
func (c *Component) Remove(t Target, v Variables) (Results, error) {
	methods := t.Methods()
	var installer Installer
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("component.install.%s", strings.ToLower(method.String()))) {
			installer = c.installerOfMethod(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return nil, fmt.Errorf("failed to find a way to uninstall '%s'", c.DisplayName())
	}
	//if debug
	if false {
		log.Printf("Removing component '%s' from %s '%s'...\n", c.DisplayName(), t.Type(), t.Name())
	}

	// Inits implicit parameters
	setImplicitParameters(t, v)

	// Checks required parameters have value
	err := checkParameters(c, v)
	if err != nil {
		return nil, err
	}

	return installer.Remove(c, t, v)
}

// FakeComponent is a component already installed; it's used to tell if a specific component
// is installed, but disallows the ability to be installed or uninstalled.
// The goal is to be able to mark a component installed even if not installed by the package (because
// it's a requirement for a cluster management tool for example)
type FakeComponent struct {
	real Component
}

// NewFakeComponent returns a fake component
func NewFakeComponent(name string) *FakeComponent {
	return &FakeComponent{
		real: Component{
			displayName: name,
		},
	}
}

// Add errors the component can't be installed
func (c *FakeComponent) Add(target Target) error {
	return fmt.Errorf("component can't be installed")
}

// Remove errors the component can't be removed
func (c *FakeComponent) Remove(target Target) error {
	return fmt.Errorf("component can't be uninstalled")
}

// Applyable ...
func (c *FakeComponent) Applyable(target Target) bool {
	return c.real.Applyable(target)
}
