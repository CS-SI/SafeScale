/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package Flavor

import (
	"fmt"
	"strings"
)

//Enum represents the flavor of a cluster, in other words what technology is used behind the scene
type Enum int

const (
	_ Enum = iota
	// DCOS managed cluster
	DCOS
	// Kubernetes flavor for a pure Kubernetes cluster
	Kubernetes
	// Swarm flavor for a pure docker swarm cluster
	Swarm
	// BOH for a "Bunch Of Hosts", without cluster management
	BOH
)

var (
	parseMap = map[string]Enum{
		"dcos":       DCOS,
		"kubernetes": Kubernetes,
		"swarm":      Swarm,
		"boh":        BOH,
	}

	stringMap = map[Enum]string{
		DCOS:       "DCOS",
		Kubernetes: "Kubernetes",
		Swarm:      "Swarm",
		BOH:        "BOH",
	}
)

// Parse returns a Flavor.Enum corresponding to the content of the parameter
func Parse(v string) (e Enum, err error) {
	var found bool
	lowered := strings.ToLower(v)
	if e, found = parseMap[lowered]; found {
		err = nil
	} else {
		err = fmt.Errorf("Unknown Flavor '%s'", v)
	}
	return
}

func (e Enum) String() string {
	if str, found := stringMap[e]; found {
		return str
	}
	return ""
}
