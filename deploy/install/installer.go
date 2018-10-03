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

//go:generate mockgen -destination=../mocks/mock_installer.go -package=mocks github.com/CS-SI/SafeScale/deploy/install Installer

import "github.com/CS-SI/SafeScale/deploy/install/enums/Method"

// Installer defines the API of an Installer
type Installer interface {
	// GetName returns the name of the Installer
	GetName() string
	// Check checks if the component is installed
	Check(*Component, Target, Variables) (Results, error)
	// Add executes installation of component
	Add(*Component, Target, Variables) (Results, error)
	// Remove executes deletion of component
	Remove(*Component, Target, Variables) (Results, error)
}

// installerMap keeps a map of available installers sorted by Method
type installerMap map[Method.Enum]Installer
