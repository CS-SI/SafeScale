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

// Installer defines the API of an Installer
type Installer interface {
	// GetName returns the name of the Installer
	GetName() string
	// Check checks if the component is installed
	Check(*Component, Target, Variables) (bool, CheckResults, error)
	// Add executes installation of component
	Add(*Component, Target, Variables) (bool, AddResults, error)
	// Remove executes deletion of component
	Remove(*Component, Target, Variables) (bool, RemoveResults, error)
}

/* type InstallerStep interface {
	// ListHosts returns a list of host(s) concerned by the installation
	ListHosts(Component) ([]*pb.Host, error)
	// Do executes the step
	Do() error
}
*/
