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
	"github.com/CS-SI/SafeScale/deploy/install/api"
	"github.com/CS-SI/SafeScale/deploy/install/api/Method"
)

// HostTarget defines a target of type Host, satisfying TargetAPI
type HostTarget struct {
	Name string
}

// NewHostTarget ...
func NewHostTarget(name string) api.TargetAPI {
	if name == "" {
		panic("name is empty!")
	}

	return &HostTarget{
		Name: name,
	}
}

// GetName returns the name of the Target
func (t *HostTarget) GetName() string {
	return t.Name
}

// GetMethods returns a list of packaging managers useable on the target
func (t *HostTarget) GetMethods() []Method.Enum {
	methods := []Method.Enum{
		Method.Script,
	}
	// TODO: défines the managers available for a host to be able to get it there
	methods = append(methods, Method.Apt) // hardcoded, bad !
	return methods
}

// List returns a list of installed component
func (t *HostTarget) List() []string {
	var list []string
	return list
}
