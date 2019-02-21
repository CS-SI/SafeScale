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

package Method

import (
	"fmt"
	"strings"
)

type Enum uint8

const (
	_ Enum = iota

	// Apt is supported by target
	Apt
	// Yum is supported by target
	Yum
	// Dnf is supported by target
	Dnf
	// Bash is supported by target
	Bash
	// Ansible is supported by target
	Ansible
	// DCOS packager is supported by cluster target
	DCOS
	// Helm is supported by cluster target
	Helm

	// NextEnum marks the next value (or the max, depending the use)
	NextEnum
)

var (
	stringMap = map[string]Enum{
		"apt":     Apt,
		"yum":     Yum,
		"dnf":     Dnf,
		"bash":    Bash,
		"ansible": Ansible,
		"dcos":    DCOS,
		"helm":    Helm,
	}

	enumMap = map[Enum]string{
		Apt:     "Apt",
		Yum:     "Yum",
		Dnf:     "Dnf",
		Bash:    "Bash",
		Ansible: "Ansible",
		DCOS:    "DCOS",
		Helm:    "Helm",
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
		return e, fmt.Errorf("failed to find a Method.Enum corresponding to '%s'", v)
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
	panic(fmt.Sprintf("failed to find a Method.Enum string corresponding to value '%d'!", e))
}
