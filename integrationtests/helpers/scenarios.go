//go:build disabled
// +build disabled

// //go:build integrationtests
// // +build integrationtests

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

package helpers

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type (
	ScenarioFunc func(*testing.T)

	section string

	Scenarios struct {
		sectionsOrder  []section
		scenariosOrder map[section][]string
		scenarios      map[section]map[string]ScenarioFunc
	}
)

var (
	scenarios = NewScenarios()
)

func InSection(label string) section {
	return section(label)
}

func (section section) AddScenario(scenario ScenarioFunc) section {
	if _, ok := scenarios.scenarios[section]; !ok {
		scenarios.scenarios[section] = make(map[string]ScenarioFunc)
	}
	scenarioName := runtime.FuncForPC(reflect.ValueOf(scenario).Pointer()).Name()
	lastPeriod := strings.LastIndex(scenarioName, ".")
	if lastPeriod < len(scenarioName) {
		scenarioName = scenarioName[lastPeriod+1:]
	}
	scenarios.scenarios[section][scenarioName] = scenario
	scenarios.scenariosOrder[section] = append(scenarios.scenariosOrder[section], scenarioName)

	return section
}

func NewScenarios() Scenarios {
	out := Scenarios{
		sectionsOrder: []section{
			"networks",
			"subnets",
			"hosts",
			"volumes",
			"shares",
			"features",
			"buckets",
			"clusters",
		},
		scenariosOrder: make(map[section][]string),
		scenarios:      make(map[section]map[string]ScenarioFunc),
	}

	return out
}

// // AddScenario adds a scenario to the list of scenarii to play
// func AddScenario(label, name string, scenario ScenarioFunc) {
// 	if _, ok := scenarios[label]; !ok {
// 		scenarios[label] = make(map[string]ScenarioFunc)
// 	}
// 	scenarioName := runtime.FuncForPC(reflect.ValueOf(scenario).Pointer()).Name()
// 	scenarios[label][scenarioName] = scenario
// }

// Run ...
func (s Scenarios) Run(t *testing.T) {
	ok := t.Run("setup", func(t *testing.T) { Setup(t) })
	require.True(t, ok)

	for _, section := range s.sectionsOrder {
		if len(scenarios.scenariosOrder[section]) > 0 {
			t.Run(string(section), func(t *testing.T) {
				for _, name := range scenarios.scenariosOrder[section] {
					t.Run(name, func(t *testing.T) {
						scenarios.scenarios[section][name](t)
					})
				}
			})
		}
	}
}

func RunScenarios(t *testing.T) {
	scenarios.Run(t)
}
