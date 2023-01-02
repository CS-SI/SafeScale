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

package ipversion

import (
	"fmt"
	"net"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Enum is an enum defining IP versions
type Enum int

const (
	Unknown = iota
	// IPv4 is IP v4 version
	IPv4 Enum = 4
	// IPv6 is IP v6 version
	IPv6 Enum = 6
)

// Is checks the version of a IP address in string representation
func (e Enum) Is(str string) bool {
	ip := net.ParseIP(str)
	isV6 := ip != nil && strings.Contains(str, ":")
	switch e {
	case IPv4:
		return !isV6
	case IPv6:
		return isV6
	default:
		return false
	}
}

var (
	stringMap = map[string]Enum{
		"ipv4": IPv4,
		"ipv6": IPv6,
	}

	enumMap = map[Enum]string{
		Unknown: "unknown",
		IPv4:    "IPv4",
		IPv6:    "IPv6",
	}
)

// Parse returns an Enum corresponding to the string parameter
// If the string doesn't correspond to any Enum, returns an error (nil otherwise)
// This function is intended to be used to parse user input.
func Parse(v string) (Enum, fail.Error) {
	var (
		e  Enum
		ok bool
	)
	lowered := strings.ToLower(v)
	if e, ok = stringMap[lowered]; !ok {
		return Unknown, fail.NotFoundError("failed to find a ipversion.Enum corresponding to '%s'", v)
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
