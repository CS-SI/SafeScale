//go:build (integration && featuretests) || allintegration
// +build integration,featuretests allintegration

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

package features

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
)

func Test_Docker(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(Docker)
	helpers.RunScenarios(t)
}

func Test_DockerNotGateway(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(DockerNotGateway)
	helpers.RunScenarios(t)
}

func Test_DockerCompose(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(DockerCompose)
	helpers.RunScenarios(t)
}

func Test_RemoteDesktopOnSingleHost(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(RemoteDesktopOnSingleHost)
	helpers.RunScenarios(t)
}

func Test_RemoteDesktopOnNormalHost(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(RemoteDesktopOnSubnetHost)
	helpers.RunScenarios(t)
}

func Test_ReverseProxy(t *testing.T) {
	helpers.InSection("features").Clear().AddScenario(ReverseProxy)
	helpers.RunScenarios(t)
}

func Test_NvidiaDocker(t *testing.T) {
	t.Skip("Test_NvidiaDocker not implemented")
	// TODO: Implement integration test
}
