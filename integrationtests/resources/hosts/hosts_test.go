//go:build (integration && hosttests) || allintegration
// +build integration,hosttests allintegration

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

package hosts

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
)

func Test_BasicPublicHosts(t *testing.T) {
	helpers.InSection("hosts").Clear().AddScenario(BasicPublicHosts)
	helpers.RunScenarios(t)
}

func Test_BasicNormalHosts(t *testing.T) {
	helpers.InSection("hosts").Clear().AddScenario(BasicNormalHosts)
	helpers.RunScenarios(t)
}

func Test_ReadyToSSH(t *testing.T) {
	helpers.InSection("hosts").Clear().AddScenario(ReadyToSSH)
	helpers.RunScenarios(t)
}

func Test_StopStartReadyToSSH(t *testing.T) {
	helpers.InSection("hosts").Clear().AddScenario(StopStart)
	helpers.RunScenarios(t)
}
