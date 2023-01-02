/*
 * Copyright 2018-2023, CS Systemes d'Information, http://csgroup.eu
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

package installaction

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Enum is the type of an action
type Enum uint8

const (
	_ Enum = iota

	// Check represents a check action, to test if a feature is installed
	Check
	// Add represents an add action, to install a feature
	Add
	// Remove represents a remove action, to remove a feature
	Remove

	// // NextEnum marks the next value (or the max, depending the use)
	// NextEnum
)

var (
	stringMap = map[string]Enum{
		"check":  Check,
		"add":    Add,
		"remove": Remove,
	}

	enumMap = map[Enum]string{
		Check:  "Check",
		Add:    "Add",
		Remove: "Remove",
	}
)

// Parse returns an Enum corresponding to the string parameter
// If the string doesn't correspond to any Enum, returns an error (nil otherwise)
// This function is intended to be used to parse user input.
func Parse(v string) (Enum, error) {
	var (
		e  Enum
		ok bool
	)
	lowered := strings.ToLower(v)
	if e, ok = stringMap[lowered]; !ok {
		return e, fail.NotFoundError("failed to find a Action.Enum corresponding to '%s'", v)
	}
	return e, nil

}

// FromString returns an Enum corresponding to the string parameter
// This method is intended to be used from validated input.
func FromString(v string) (e Enum) {
	e, err := Parse(v)
	if err != nil {
		panic(err.Error())
	}
	return
}

// String returns a string representation of an Enum
func (e Enum) String() string {
	if str, found := enumMap[e]; found {
		return str
	}
	panic(fmt.Sprintf("failed to find a Action.Enum string corresponding to value '%d'!", e))
}
