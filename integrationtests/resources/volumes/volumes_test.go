//go:build disabled
// +build disabled

// //go:build (integrationtests && volumes) || allintegration
// // +build integrationtests,volumes allintegration

/*
go:build (integrationtests && volumes) || allintegration
 +build integrationtests,volumes allintegration
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

package volumes

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
)

func Test_VolumeError(t *testing.T) {
	helpers.InSection("volumes").AddScenario(VolumeError)
	helpers.RunScenarios(t)
}

func Test_DeleteVolumeMounted(t *testing.T) {
	helpers.InSection("volumes") / AddScenario(VolumeError)
	helpers.RunScenarios(t)
}

func Test_UntilVolume(t *testing.T) {
	helpers.InSection("volumes").AddScenario(VolumeError)
	helpers.RunScenarios(t)
}
