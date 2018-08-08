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
)

// Component contains the information about an installable component
type Component struct {
	// Name is the name of the service
	Name string
	// AdminTool is the name of the admin tool (if there is one)
	AdminTool string
	// Installers defines the installers available for the component
	Installers map[Method.Enum]api.InstallerAPI
	// Dependencies lists other component(s) (by name) needed by this one
	Dependencies []string
	// Management contains a string map of data that could be used to manage the component (if it makes sense)
	// This could be used to explain to Service object how to manage the component, to react as a service
	Management map[string]interface{}
}

// GetName returns the name of the component
func (c *Component) GetName() string {
	return c.Name
}

// Applyable tells if the component is installable on the target
func (c *Component) Applyable(target api.TargetAPI) bool {
	kinds := target.GetKinds()
	var found bool
	for _, k := range kinds {
		if _, found = c.Installers[k]; found {
			return true
		}
	}
	return false
}

// Add installs the component on the target
func (c *Component) Add(target api.TargetAPI) error {
	kinds := target.GetKinds()
	var installer api.InstallerAPI
	var found bool
	for _, k := range kinds {
		if installer, found = c.Installers[k]; found {
			break
		}
	}
	if installer == nil {
		return fmt.Errorf("failed to find a way to install '%s' on '%s'", c.Name, target.GetName())
	}
	return installer.Add(target)
}

// Remove uninstalls the component from the target
func (c *Component) Remove(target api.TargetAPI) error {
	kinds := target.GetKinds()
	var installer api.InstallerAPI
	var found bool
	for _, k := range kinds {
		if installer, found = c.Installers[k]; found {
			break
		}
	}
	if installer == nil {
		return fmt.Errorf("failed to find a way to uninstall '%s' on '%s'", c.Name, target.GetName())
	}
	return installer.Remove(target)
}

// FakeComponent is a component already installed; it's used to tell if a specific component
// is installed, but disallows the ability to be installed or uninstalled.
// The goal is to be able to mark a component installed even if not installed by the package (because
// it's a requirement for a cluster management tool for example)
type FakeComponent struct {
	component Component
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
