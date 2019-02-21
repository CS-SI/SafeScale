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

	// Helm is supported by cluster target
	Helm
	// DCOS packager is supported by cluster target
	DCOS
	// Script is supported by target cluster
	Script
	// Ansible is supporter by target cluster
	Ansible

	// NextEnum marks the next value (or the max, depending the use)
	NextEnum
)

var (
	stringMap = map[string]Enum{
		"helm":    Helm,
		"DCOS":    DCOS,
		"bash":    Script,
		"ansible": Ansible,
	}

	enumMap = map[Enum]string{
		Helm:    "Helm",
		DCOS:    "DCOS",
		Script:  "Script",
		Ansible: "Ansible",
	}
)

// Parse returns a Method.Enum corresponding to the string parameter
func Parse(v string) (e Enum) {
	var found bool
	lowered := strings.ToLower(v)
	if e, found = stringMap[lowered]; !found {
		panic(fmt.Sprintf("Method.Enum '%s' doesn't exist!", v))
	}
	return
}

func (e Enum) String() string {
	if str, found := enumMap[e]; found {
		return str
	}
	panic(fmt.Sprintf("Method.Enum value '%d' doesn't have string match!", e))
}
