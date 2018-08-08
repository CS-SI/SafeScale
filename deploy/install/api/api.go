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
	"github.com/CS-SI/SafeScale/deploy/install/api/Method"
)

// TargetAPI is an interface that target must satisfy to be able to install something
// on it
type TargetAPI interface {
	// GetName returns the name of the installation target
	GetName() string
	// GetKinds returns a list of packaging managers useable on the target
	GetKinds() []Method.Enum
	// GetSSHConfig returns a system.SSHConfig to access target
	//GetSSHConfig() (system.SSHConfig, error)
	// List returns a list of installed component
	List() []string
}

// InstallerAPI defines the API of an Installer
type InstallerAPI interface {
	// GetName returns the name of the Installer
	GetName() string
	// Add executes installation of component
	Add(TargetAPI) error
	// Remove executes deletion of component
	Remove(TargetAPI) error
}

// InstallerParameters defines the parameters a Installer may need
type InstallerParameters map[string]interface{}

// InstallerMap keeps a map of available installer by Method
type InstallerMap map[Method.Enum]InstallerAPI

// ComponentAPI defines the API of an installable component
type ComponentAPI interface {
	// GetName ...
	GetName() string
	// Applyable if the service is installable on the target
	Applyable(TargetAPI) bool
	// Install ...
	Add(TargetAPI) error
	// Remove ...
	Remove(TargetAPI) error
}
