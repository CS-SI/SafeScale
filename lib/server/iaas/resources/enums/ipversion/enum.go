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

package ipversion

import (
	"net"
	"strings"
)

//go:generate stringer -type=Enum

//Enum is an enum defining IP versions
type Enum int

const (
	//IPv4 is IP v4 version
	IPv4 Enum = 4
	//IPv6 is IP v6 version
	IPv6 Enum = 6
)

// Is checks the version of a IP address in string representaiton
func (i Enum) Is(str string) bool {
	ip := net.ParseIP(str)
	isV6 := ip != nil && strings.Contains(str, ":")
	switch i {
	case IPv4:
		return !isV6
	case IPv6:
		return isV6
	default:
		return false
	}
}
