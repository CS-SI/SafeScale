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
	"os"
	"time"

	"github.com/CS-SI/SafeScale/deploy/install/api"
	"github.com/CS-SI/SafeScale/deploy/install/api/Method"
	"github.com/CS-SI/SafeScale/system"
	"github.com/CS-SI/SafeScale/utils/brokeruse"

	"github.com/spf13/viper"
)

// NewComponent searches for a spec file name 'name' and initializes a new Component object
// with its content
func NewComponent(name string) (api.ComponentAPI, error) {
	if name == "" {
		panic("name is empty!")
	}

	v := viper.New()
	v.AddConfigPath(".")
	v.AddConfigPath("$HOME/.safescale/pkgs")
	v.AddConfigPath("$HOME/.config/safescale/pkgs")
	v.AddConfigPath("/etc/safescale/pkgs")
	v.SetConfigName(name)

	err := v.ReadInConfig()
	if err == nil {
		if v.IsSet("component") {
			return &Component{
				Name:  name,
				specs: v,
			}, nil
		}
	}

	// Failed to find a spec file on filesystem, trying with embedded ones
	if component, ok := allEmbeddedMap[name]; ok {
		return component, nil
	}
	return nil, fmt.Errorf("failed to find a component named '%s'", name)
}

// Component contains the information about an installable component
type Component struct {
	// Name is the name of the service
	Name string
	// AdminTool is the name of the admin tool (if there is one)
	AdminTool string
	// Installers defines the installers available for the component
	Installers map[Method.Enum]api.InstallerAPI
	// Dependencies lists other component(s) (by name) needed by this one
	//Dependencies []string
	// Management contains a string map of data that could be used to manage the component (if it makes sense)
	// This could be used to explain to Service object how to manage the component, to react as a service
	//Management map[string]interface{}

	// specs is the Viper instance containing component specification
	specs *viper.Viper
}

// GetName returns the name of the component
func (c *Component) GetName() string {
	return c.Name
}

// GetSpecs returns the data from the spec file
func (c *Component) GetSpecs() *viper.Viper {
	return c.specs
}

// Applyable tells if the component is installable on the target
func (c *Component) Applyable(target api.TargetAPI) bool {
	kinds := target.GetMethods()
	var found bool
	for _, k := range kinds {
		if _, found = c.Installers[k]; found {
			return true
		}
	}
	return false
}

// Check if component is installed on target
func (c *Component) Check(target api.TargetAPI) (bool, error) {
	methods := target.GetMethods()
	var installer api.InstallerAPI
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("component.installers.%s", method.String())) {
			installer = getInstaller(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return false, fmt.Errorf("failed to find a way to check '%s' on '%s'", c.Name, target.GetName())
	}
	return installer.Check(c, target)
}

// Add installs the component on the target
func (c *Component) Add(target api.TargetAPI) error {
	methods := target.GetMethods()
	var installer api.InstallerAPI
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("component.installers.%s", method.String())) {
			installer = getInstaller(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return fmt.Errorf("failed to find a way to install '%s' on '%s'", c.Name, target.GetName())
	}
	return installer.Add(c, target)
}

func getInstaller(method Method.Enum) api.InstallerAPI {
	var installer api.InstallerAPI
	switch method {
	case Method.Script:
		installer = NewScriptInstaller()
	case Method.Apt:
		installer = NewAptInstaller()
	case Method.Yum:
		installer = NewYumInstaller()
	case Method.Dnf:
		installer = NewDnfInstaller()
	}
	return installer
}

// Remove uninstalls the component from the target
func (c *Component) Remove(target api.TargetAPI) error {
	methods := target.GetMethods()
	var installer api.InstallerAPI
	for _, method := range methods {
		if c.specs.IsSet(fmt.Sprintf("component.installers.%s", method.String())) {
			installer = getInstaller(method)
			if installer != nil {
				break
			}
		}
	}
	if installer == nil {
		return fmt.Errorf("failed to find a way to uninstall '%s' on '%s'", c.Name, target.GetName())
	}
	return installer.Remove(c, target)
}

// FakeComponent is a component already installed; it's used to tell if a specific component
// is installed, but disallows the ability to be installed or uninstalled.
// The goal is to be able to mark a component installed even if not installed by the package (because
// it's a requirement for a cluster management tool for example)
type FakeComponent struct {
	component Component
}

// NewFakeComponent returns a fake component
func NewFakeComponent(name string) *FakeComponent {
	return &FakeComponent{
		component: Component{
			Name: name,
		},
	}
}

// Add errors the component can't be installed
func (c *FakeComponent) Add(target api.TargetAPI) error {
	return fmt.Errorf("component can't be installed")
}

// Remove errors the component can't be removed
func (c *FakeComponent) Remove(target api.TargetAPI) error {
	return fmt.Errorf("component can't be uninstalled")
}

// Applyable ...
func (c *FakeComponent) Applyable(target api.TargetAPI) bool {
	return c.component.Applyable(target)
}

func uploadStringToTargetFile(content string, target api.TargetAPI, filename string) error {
	if content == "" {
		panic("content is nil!")
	}
	if filename == "" {
		panic("filename is nil!")
	}
	f, err := system.CreateTempFileFromString(content)
	if err != nil {
		return err
	}
	to := fmt.Sprintf("%s:%s", target.GetName(), filename)
	err = brokeruse.SSHCopy(f.Name(), to, 5*time.Minute)
	os.Remove(f.Name())
	return err
}
