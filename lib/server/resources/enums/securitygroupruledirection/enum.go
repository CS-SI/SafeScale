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

package securitygroupruledirection

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

// Enum represents the way of a securitygroup rule (ingress or egress)
type Enum uint8

const (
	UNKNOWN Enum = iota
	INGRESS
	EGRESS
)

var (
	stringMap = map[string]Enum{
		"ingress": INGRESS,
		"egress":  EGRESS,
	}

	enumMap = map[Enum]string{
		UNKNOWN: "unknown",
		INGRESS: "ingress",
		EGRESS:  "egress",
	}
)

// Parse returns a Enum corresponding to the string parameter
// If the string doesn't correspond to any Enum, returns an error (nil otherwise)
// This function is intended to be used to parse user input.
func Parse(v string) (Enum, fail.Error) {
	var (
		e  Enum
		ok bool
	)
	lowered := strings.ToLower(v)
	if e, ok = stringMap[lowered]; !ok {
		return UNKNOWN, fail.NotFoundError("failed to find a securitygroupruledirection.Enum corresponding to '%s'", v)
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
	panic(fmt.Sprintf("failed to find a Action.Enum string corresponding to value '%d'!", e))
}
