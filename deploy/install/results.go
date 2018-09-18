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
	"strings"
)

// CheckState ...
type CheckState struct {
	Success bool
	Present bool
	Error   string
}

// CheckResults contains the result of a component Check
// In single host mode, the results are stored in PrivateNodes
// In cluster mode, all results are stored in appropriate fields
type CheckResults map[string]CheckState

// Errors joins all errors in CheckResults then returns the corresponding string
func (r CheckResults) Errors() string {
	errors := []string{}
	for k, i := range r {
		if !i.Success {
			errors = append(errors, i.Error+fmt.Sprintf(" on '%s'", k))
		}
	}
	return strings.Join(errors, "\n")
}

// stepErrors ...
type stepErrors map[string]error

// AddResults contains the result of a component addition
type AddResults map[string]stepErrors

// Errors returned all the errors contained in AddResults as a string
// one error per line
func (r AddResults) Errors() string {
	errors := []string{}
	for keyStep, stateStep := range r {
		for keyHost, err := range stateStep {
			if err != nil {
				errors = append(errors, err.Error()+fmt.Sprintf(" at step '%s' on '%s'", keyStep, keyHost))
			}
		}
	}
	return strings.Join(errors, "\n")
}

// RemoveResults contains the result of a component removal
type RemoveResults struct {
	AddResults
}
