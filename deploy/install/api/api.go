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
	"strings"

	"github.com/CS-SI/SafeScale/deploy/install/api/Method"
	"github.com/spf13/viper"
)

// Target is an interface that target must satisfy to be able to install something
// on it
type Target interface {
	// GetMethods returns a list of installation methods useable on the target
	GetMethods() []Method.Enum
	// GetSSHConfig returns a system.SSHConfig to access target
	//GetSSHConfig() (system.SSHConfig, error)
	// List returns a list of installed component
	List() []string
}

// CheckState ...
type CheckState struct {
	Success bool
	Present bool
	Error   string
}

// CheckResults contains the result of a component Check
// In single host mode, the results are stored in PrivateNodes
// In cluster mode, all results are stored in appropriate fields
type CheckResults struct {
	Masters      map[string]CheckState
	PrivateNodes map[string]CheckState
	PublicNodes  map[string]CheckState
}

func (r CheckResults) Errors() string {
	errors := []string{}
	for _, i := range r.Masters {
		if !i.Success {
			errors = append(errors, i.Error)
		}
	}
	for _, i := range r.PrivateNodes {
		if !i.Success {
			errors = append(errors, i.Error)
		}
	}
	for _, i := range r.PublicNodes {
		if !i.Success {
			errors = append(errors, i.Error)
		}
	}
	return strings.Join(errors, "\n")
}

// AddResults contains the result of a component addition
type AddResults struct {
	Masters      map[string]error
	PrivateNodes map[string]error
	PublicNodes  map[string]error
}

// Errors returned all the errors contained in AddResults as a string
// one error per line
func (r AddResults) Errors() string {
	errors := []string{}
	for _, i := range r.Masters {
		if i != nil {
			errors = append(errors, i.Error())
		}
	}
	for _, i := range r.PrivateNodes {
		if i != nil {
			errors = append(errors, i.Error())
		}
	}
	for _, i := range r.PublicNodes {
		if i != nil {
			errors = append(errors, i.Error())
		}
	}
	return strings.Join(errors, "\n")
}

// RemoveResults contains the result of a component removal
type RemoveResults struct {
	AddResults
}

// Installer defines the API of an Installer
type Installer interface {
	// GetName returns the name of the Installer
	GetName() string
	// Check checks if the component is installed
	Check(Component, Target) (bool, CheckResults, error)
	// Add executes installation of component
	Add(Component, Target, map[string]interface{}) (bool, AddResults, error)
	// Remove executes deletion of component
	Remove(Component, Target) (bool, RemoveResults, error)
}

// InstallerParameters defines the parameters a Installer may need
type InstallerParameters map[string]interface{}

// InstallerMap keeps a map of available installer by Method
type InstallerMap map[Method.Enum]Installer

// Component defines the API of an installable component
type Component interface {
	// DisplayName ...
	DisplayName() string
	// ShortFileName ...
	BaseFilename() string
	// FullFilename ...
	DisplayFilename() string
	// Specs ...
	Specs() *viper.Viper
	// Applyable if the component is installable on the target
	Applyable(Target) bool
	// Check if a component is installed
	Check(Target) (bool, CheckResults, error)
	// Install ...
	Add(Target, map[string]interface{}) (bool, AddResults, error)
	// Remove ...
	Remove(Target) (bool, RemoveResults, error)
}
