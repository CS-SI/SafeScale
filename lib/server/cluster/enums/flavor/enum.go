/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package flavor

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
)

// Enum represents the flavor of a cluster, in other words what technology is used behind the scene
type Enum int

const (
	_ Enum = iota
	// K8S for a pure Kubernetes cluster
	K8S = 2
	// BOH for a "Bunch Of Hosts", without cluster management
	BOH = 4
)

var (
	stringMap = map[string]Enum{
		"k8s": K8S,
		"boh": BOH,
	}

	enumMap = map[Enum]string{
		K8S: "K8S",
		BOH: "BOH",
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
		return e, fmt.Errorf("failed to find a flavor matching with '%s'", v)
	}
	return e, nil

}

// String returns a string representation of an Enum
func (e Enum) String() string {
	if str, found := enumMap[e]; found {
		return str
	}
	logrus.Errorf("failed to find a string matching with flavor.Enum '%d'!", e)
	return ""
}
