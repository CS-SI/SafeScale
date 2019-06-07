/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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
	"strings"
)

// Results ...
type Results map[string]stepResults

// Successful ...
func (r Results) Successful() bool {
	if len(r) > 0 {
		for _, step := range r {
			if !step.Successful() {
				return false
			}
		}
	}
	return true
}

// AllErrorMessages ...
func (r Results) AllErrorMessages() string {
	output := ""
	for _, step := range r {
		val := strings.TrimSpace(step.ErrorMessages())
		if val != "" {
			output += val + "\n"
		}
	}
	return output
}

// ErrorMessagesOfStep ...
func (r Results) ErrorMessagesOfStep(name string) string {
	if step, ok := r[name]; ok {
		return step.ErrorMessages()
	}
	return ""
}

// ErrorMessagesOfHost ...
func (r Results) ErrorMessagesOfHost(name string) string {
	output := ""
	for _, step := range r {
		for h, e := range step {
			if h == name {
				val := e.Error().Error()
				if val != "" {
					output += val + "\n"
				}
			}
		}
	}
	return output
}

// ResultsOfStep ...
func (r Results) ResultsOfStep(name string) stepResults {
	if step, ok := r[name]; ok {
		return step
	}
	return stepResults{}
}

// Transpose reorganizes Results to be indexed by hosts (instead by steps normally)
func (r Results) Transpose() Results {
	t := Results{}
	for step, results := range r {
		for h, sr := range results {
			t[h] = stepResults{step: sr}
		}
	}
	return t
}

// Keys returns the keys of the Results
func (r Results) Keys() []string {
	keys := []string{}
	for k := range r {
		keys = append(keys, k)
	}
	return keys
}
