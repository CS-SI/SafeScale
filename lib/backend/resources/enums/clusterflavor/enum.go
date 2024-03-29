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

package clusterflavor

import (
	"fmt"
	"strings"

	"github.com/CS-SI/SafeScale/v22/lib/utils/fail"
)

// Enum represents the flavor of a cluster, in other words what technology is used behind the scene
type Enum int

const (
	_ Enum = iota
	// DCOS managed cluster
	// DCOS = 1

	// K8S for a pure Kubernetes cluster
	K8S = 2

	// SWARM for a pure docker swarm cluster
	// SWARM = 3

	// BOH for a "Bunch Of Hosts", without cluster management
	BOH = 4

	// OHPC for a OpenHPC cluster
	// OHPC = 5
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
		return e, fail.NotFoundError("failed to find a Flavor matching with '%s'", v)
	}
	return e, nil

}

// String returns a string representation of an Enum
func (e Enum) String() string {
	if str, found := enumMap[e]; found {
		return str
	}
	if e == 0 {
		return "UNDEFINED"
	}
	panic(fmt.Sprintf("failed to find a string matching with Flavor '%d'!", e))
}
