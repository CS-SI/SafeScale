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

package api

import (
	"fmt"

	"github.com/CS-SI/SafeScale/deploy/install/Method"
	"github.com/CS-SI/SafeScale/system"
)

// TargetAPI is an interface that target must satisfy to be able to install something
// on it
type TargetAPI interface {
	// GetName returns the name of the InstallTarget
	GetName() string
	// GetKinds returns a list of package kinds useable on the target
	GetKinds() []Method.Enum
	// GetSSHConfig returns a system.SSHConfig to access target
	GetSSHConfig() (system.SSHConfig, error)
	// List returns a list of installed component
	List() []string
}

// InstallerAPI defines the API of an Installer
type InstallerAPI interface {
	// GetName returns the name of the Installer
	GetName() string
	// Add executes installation of component
	Add(TargetAPI, ComponentAPI) error
	// Remove executes deletion of component
	Remove(TargetAPI, ComponentAPI) error
}

// Installer contains the information about an Installer
type Installer struct {
	// Name of the Installer
	Name string
}

// GetName ...
func (s *Installer) GetName() string {
	return s.Name
}

// ComponentAPI defines the API of an installable component
type ComponentAPI interface {
	// GetName ...
	GetName() string
	// Applyable if the service is installable on the target
	Applyable(TargetAPI) bool
	// Install ...
	Add(TargetAPI) error
	// Delete ...
	Delete(TargetAPI) error
	// State ...
	State(TargetAPI) error
	// Start ...
	Start(TargetAPI) error
	// Stop ...
	Stop(TargetAPI) error
}

// Component contains the information about an installable component
type Component struct {
	// Name is the name of the service
	Name string
	// Installers defines the installers available for the component
	Installers []InstallerAPI
	// Dependencies lists other component(s) (by name) needed by this one
	Dependencies []string
}

// GetName ...
func (s *Component) GetName() string {
	return s.Name
}

// Add ...
func (s *Component) Add(target TargetAPI) error {
	kinds := target.GetKinds()
	var installer InstallerAPI
	var found bool
	for _, k := range kinds {
		if installer, found = availables["All"][k]; found {
			break
		}
	}
	if installer == nil {
		return fmt.Errorf("failed to find a way to install '%s' on '%s'", s.Name, target.GetName())
	}
	return installer.Install(target, *s)
}

// Remove ...
func (s *Component) Remove(target TargetAPI) error {
	kinds := target.GetKinds()
	var installer InstallerAPI
	var found bool
	for _, k := range kinds {
		if installer, found = availables["All"][k]; found {
			break
		}
	}
	if installer == nil {
		return fmt.Errorf("failed to find a way to install '%s' on '%s'", s.Name, target.GetName())
	}
	return installer.Delete(target, *s)
}
