//go:build (integrationtests && clusters) || allintegration
// +build integrationtests,clusters allintegration

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

package clusters

import (
	"testing"

	"github.com/CS-SI/SafeScale/v22/integrationtests/helpers"
	"github.com/CS-SI/SafeScale/v22/integrationtests/providers"
	"github.com/CS-SI/SafeScale/v22/integrationtests/resources/features"
)

func Test_ClusterK8S(t *testing.T) {
	helpers.InSection("clusters").AddScenario(ClusterK8S)
	helpers.RunScenarios()
}

func Test_Helm(t *testing.T) {
	helpers.InSection("clusters").AddScenario(features.Helm)
	helpers.RunScenarios(t, providers.CurrentProvider)
}

func Test_Kubernetes(t *testing.T) {
	helpers.InSection("clusters").AddScenario(features.Kubernetes)
	helpers.RunScenarios(t)
}
