/*
 * Copyright 2018-2022, CS Systemes d'Information, http://csgroup.eu
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

package operations

import (
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/server/resources"
	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// unitResults contains the errors of the step for each host target
type unitResults map[string]resources.UnitResult

func (urs *unitResults) AddOne(key string, ur resources.UnitResult) {
	if len(*urs) == 0 {
		*urs = map[string]resources.UnitResult{}
	}
	(*urs)[key] = ur
}

// ErrorMessages returns a string containing all the errors registered
func (urs unitResults) ErrorMessages() string {
	output := ""
	for k, v := range urs {
		val := v.ErrorMessage()
		if val != "" {
			if output != "" {
				output += ", "
			}
			output += k + ": " + val
		}
	}
	return output
}

// Uncompleted returns an array of string of all keys where the script to run action wasn't completed
func (urs unitResults) Uncompleted() []string {
	var output []string
	for k, v := range urs {
		if !v.Completed() {
			output = append(output, k)
		}
	}
	return output
}

// Successful tells if all the steps have been successful
func (urs unitResults) Successful() bool {
	if urs == nil || len(urs) == 0 {
		return false
	}
	for _, v := range urs {
		if !v.Successful() {
			return false
		}
	}
	return true
}

// Completed tells if all the scripts corresponding to action have been completed.
func (urs unitResults) Completed() bool {
	if len(urs) == 0 {
		return false
	}
	for _, v := range urs {
		if !v.Completed() {
			return false
		}
	}
	return true
}

// Keys returns a slice of keys for the results
func (urs unitResults) Keys() []string {
	keys := make([]string, 0, len(urs))
	for k := range urs {
		keys = append(keys, k)
	}
	return keys
}

// ResultOfKey returns the result corresponding to the unit passed as parameter
func (urs unitResults) ResultOfKey(key string) resources.UnitResult {
	if r, ok := urs[key]; ok {
		return r
	}
	return &stepResult{}
}

// results ...
type results map[string]resources.UnitResults

// Add ...
func (r *results) Add(key string, urs resources.UnitResults) error {
	if len(*r) == 0 {
		*r = results{}
	}
	if urs == nil {
		return fail.InvalidParameterCannotBeNilError("urs")
	}

	(*r)[key] = urs
	return nil
}

// AddOne ...
func (r *results) AddOne(key, unitName string, ur resources.UnitResult) error {
	if *r == nil {
		*r = results{}
	}
	if ur == nil {
		return fail.InvalidParameterCannotBeNilError("ur")
	}
	if _, ok := (*r)[key]; !ok {
		(*r)[key] = &unitResults{}
	}
	(*r)[key].AddOne(unitName, ur)
	return nil
}

// Successful ...
func (r results) Successful() bool {
	if len(r) > 0 {
		for _, v := range r {
			if !v.Successful() {
				return false
			}
		}
	}
	return true
}

// AllErrorMessages ...
func (r results) AllErrorMessages() string {
	output := ""
	for _, v := range r {
		val := strings.TrimSpace(v.ErrorMessages())
		if val != "" {
			output += val + "\n"
		}
	}
	return output
}

// ErrorMessagesOfKey ...
func (r results) ErrorMessagesOfKey(key string) string {
	if step, ok := r[key]; ok {
		return step.ErrorMessages()
	}
	return ""
}

// ErrorMessagesOfUnit ...
func (r results) ErrorMessagesOfUnit(unitName string) (string, fail.Error) {
	output := ""
	for _, urs := range r {
		if urs != nil {
			rurs, ok := urs.(*unitResults)
			if !ok {
				return "", fail.InconsistentError("failed to cast urs to '*unitResults'")
			}
			for k, v := range *rurs {
				if k == unitName {
					val := v.Error().Error()
					if val != "" {
						output += val + "\n"
					}
				}
			}
		}
	}
	return output, nil
}

// ResultsOfKey ...
func (r results) ResultsOfKey(key string) resources.UnitResults {
	if ret, ok := r[key]; ok {
		return ret
	}
	return &unitResults{}
}

// Keys returns the keys of the Results
func (r results) Keys() []string {
	var keys []string
	for k := range r {
		keys = append(keys, k)
	}
	return keys
}
