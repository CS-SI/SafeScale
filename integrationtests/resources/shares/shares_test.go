//go:build disabled
// +build disabled

// //go:build integrationtests && !shares && !allintegration
// // +build integrationtests,!shares,!allintegration

/*
go:build integrationtests && !shares && !allintegration
 +build integrationtests,!shares,!allintegration
*/
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

package shares

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
)

func Test_ShareStandard(t *testing.T) {
	helpers.InSection("shares").AddScenario(Standard)
	helpers.RunScenarios(t)
}

func Test_ShareError(t *testing.T) {
	helpers.InSection("shares").AddScenario(ShareError)
	helpers.RunScenarios(t)
}

func Test_SharePartialError(t *testing.T) {
	helpers.InSection("shares").AddScenario(SharePartialError)
	helpers.RunScenarios(t)
}

func Test_UntilShare(t *testing.T) {
	helpers.InSection("shares").AddScenario(UntilShareCreated)
	helpers.RunScenarios(t)
}

func Test_ShareVolumeMounted(t *testing.T) {
	helpers.InSection("shares").AddScenario(SharePartialError)
	helpers.RunScenarios(t)
}
