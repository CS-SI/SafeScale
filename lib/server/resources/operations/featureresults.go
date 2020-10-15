/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

	"github.com/CS-SI/SafeScale/lib/server/resources"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// type unitResult struct {
// 	completed bool // if true, the script has been run to completion
// 	output    string
// 	success   bool  // if true, the script has been run successfully and the result is a success
// 	err       error // if an error occurred, contains the err
// }

// func (ur unitResult) Successful() bool {
// 	return ur.success
// }

// func (ur unitResult) Completed() bool {
// 	return ur.completed
// }

// func (ur unitResult) Error() error {
// 	return ur.err
// }

// func (ur unitResult) ErrorMessage() string {
// 	if ur.err != nil {
// 		return ur.err.Error()
// 	}
// 	return ""
// }

// unitResults contains the errors of the step for each host target
type unitResults map[string]resources.UnitResult

func (urs unitResults) AddSingle(key string, ur resources.UnitResult) {
	if _, ok := urs[key]; !ok {
		urs = map[string]resources.UnitResult{}
	}
	urs[key] = ur
}

// ErrorMessages returns a string containing all the errors registered
func (urs unitResults) ErrorMessages() string {
	output := ""
	for k, v := range urs {
		val := v.ErrorMessage()
		if val != "" {
			output += k + ": " + val + "\n"
		}
	}
	return output
}

// UncompletedEntries returns an array of string of all keys where the script
// to run action wasn't completed
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
	if urs == nil || len(urs) == 0 {
		return false
	}
	for _, v := range urs {
		if !v.Completed() {
			return false
		}
	}
	return true
}

// results ...
type results map[string]resources.UnitResults

// Add ...
func (r results) Add(key string, urs resources.UnitResults) error {
	if r == nil {
		r = results{}
	}
	if urs == nil {
		return fail.InvalidParameterError("urs", "cannot be nil")
	}

	r[key] = urs
	return nil
}

// AddUnit ...
func (r results) AddUnit(key, unitName string, ur resources.UnitResult) error {
	if r == nil {
		r = results{}
	}
	if ur == nil {
		return fail.InvalidParameterError("ur", "cannot be nil")
	}
	if _, ok := r[key]; !ok {
		r[key] = &unitResults{}
	}
	r[key].AddSingle(unitName, ur)
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

// ErrorMessagesOfStep ...
func (r results) ErrorMessagesOfKey(key string) string {
	if step, ok := r[key]; ok {
		return step.ErrorMessages()
	}
	return ""
}

// ErrorMessagesOfKey ...
func (r results) ErrorMessagesOfUnit(unitName string) string {
	output := ""
	for _, urs := range r {
		rurs := urs.(unitResults)
		for k, v := range rurs {
			if k == unitName {
				val := v.Error().Error()
				if val != "" {
					output += val + "\n"
				}
			}
		}
	}
	return output
}

// ResultsOfUnit ...
func (r results) ResultsOfUnit(unitName string) resources.UnitResults {
	newSrs := unitResults{}
	for _, urs := range r {
		rurs := urs.(unitResults)
		for k, v := range rurs {
			if k == unitName {
				newSrs.AddSingle(unitName, v)
			}
		}
	}
	return newSrs
}

// ResultsOfKey ...
func (r results) ResultsOfKey(key string) resources.UnitResults {
	if ret, ok := r[key]; ok {
		return ret
	}
	return unitResults{}
}

// Keys returns the keys of the Results
func (r results) Keys() []string {
	var keys []string
	for k := range r {
		keys = append(keys, k)
	}
	return keys
}
