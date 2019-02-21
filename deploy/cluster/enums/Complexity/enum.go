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

package Complexity

import (
	"fmt"
	"strings"
)

// Enum represents the complexity of a cluster
type Enum int

const (

	// Small is the simplest mode of cluster
	Small Enum = 1
	// Normal allows the cluster to be resistant to 1 master failure
	Normal Enum = 3
	// Large allows the cluster to be resistant to 2 master failures and is sized for high Large of agents
	Large Enum = 5
)

var (
	stringMap = map[string]Enum{
		"small":  Small,
		"normal": Normal,
		"large":  Large,
	}

	enumMap = map[Enum]string{
		Small:  "Small",
		Normal: "Normal",
		Large:  "Large",
	}
)

// Parse returns a Enum corresponding to the string parameter
// If the string doesn't correspond to any Enum, returns an error (nil otherwise)
// This function is intended to be used to parse user input.
func Parse(v string) (Enum, error) {
	var (
		e  Enum
		ok bool
	)
	lowered := strings.ToLower(v)
	if e, ok = stringMap[lowered]; !ok {
		return e, fmt.Errorf("failed to find a Complexity.Enum corresponding to '%s'", v)
	}
	return e, nil

}

// FromString returns a Enum corresponding to the string parameter
// This method is intended to be used from validated input.
func FromString(v string) (e Enum) {
	e, err := Parse(v)
	if err != nil {
		panic(err.Error())
	}
	return
}

// String returns a string representaton of an Enum
func (e Enum) String() string {
	if str, found := enumMap[e]; found {
		return str
	}
	panic(fmt.Sprintf("failed to find a Complexity.Enum string corresponding to value '%d'!", e))
}
