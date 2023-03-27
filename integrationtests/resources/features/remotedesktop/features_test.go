//go:build (integration && featuretests) || allintegration
// +build integration,featuretests allintegration

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

package remotedesktop

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
)

func Test_RemoteDesktop(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(RemoteDesktop)
	helpers.RunScenarios(t)
}

func Test_RemoteDesktopUbuntu18(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(RemoteDesktopUbuntu18)
	helpers.RunScenarios(t)
}

func Test_RemoteDesktopUbuntu22(t *testing.T) {
	// Disabled : cluster creation doesn't work for ubuntu22
	helpers.InSection("features").Clear().AddScenario(RemoteDesktopUbuntu22)
	helpers.RunScenarios(t)
}

func Test_RemoteDesktopCentos7(t *testing.T) {
	// Disabled : feature addition doesn't work for centos
	helpers.InSection("features").Clear().AddScenario(RemoteDesktopCentos7)
	helpers.RunScenarios(t)
}

func Test_RemoteDesktopFailedUserAlreadyExists(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(RemoteDesktopFailedUserAlreadyexists)
	helpers.RunScenarios(t)
}

func Test_RemoteDesktopCladm(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(RemoteDesktopCladm)
	helpers.RunScenarios(t)
}
