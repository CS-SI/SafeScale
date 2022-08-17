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

package installmethod

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Enum represents the type of a method
type Enum uint8

//goland:noinspection ALL
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
	// DCOS_deprecated packager is supported by cluster target
	DCOS_deprecated // nolint
	// Helm is supported by cluster target
	Helm
	// None does nothing; check always fail, add and remove always succeed
	None

	// NextEnum marks the next value (or the max, depending the use)
	NextEnum
)

var (
	stringMap = map[string]Enum{
		"apt":             Apt,
		"yum":             Yum,
		"dnf":             Dnf,
		"bash":            Bash,
		"ansible":         Ansible,
		"dcos_deprecated": DCOS_deprecated,
		"helm":            Helm,
		"none":            None,
	}

	enumMap = map[Enum]string{
		Apt:             "Apt",
		Yum:             "Yum",
		Dnf:             "Dnf",
		Bash:            "Bash",
		Ansible:         "Ansible",
		DCOS_deprecated: "DCOS (deprecated)",
		Helm:            "Helm",
		None:            "None",
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
		return e, fail.NotFoundError("failed to find a Method.Enum corresponding to '%s'", v)
	}
	return e, nil

}

// String returns a string representation of an Enum
func (e Enum) String() string {
	if str, found := enumMap[e]; found {
		return str
	}
	panic(fmt.Sprintf("failed to find a Method.Enum string corresponding to value '%d'!", e))
}
