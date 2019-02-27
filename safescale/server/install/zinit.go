/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package install

import (
	"fmt"

	"github.com/CS-SI/SafeScale/safescale/server/install/enums/Method"
)

func init() {

	allEmbedded = []*Feature{
		dockerFeature(),
		dockerComposeFeature(),
		nVidiaDockerFeature(),
		mpichOsPkgFeature(),
		mpichBuildFeature(),
		ohpcSlurmMasterFeature(),
		ohpcSlurmNodeFeature(),
		remoteDesktopFeature(),
		reverseProxyFeature(),
		kubernetesFeature(),
		proxycacheServerFeature(),
		proxycacheClientFeature(),
		apacheIgniteFeature(),
		//		elasticSearchFeature(),
		metricbeatFeature(),
		filebeatFeature(),
		helmFeature(),
		sparkFeature(),
	}

	for _, item := range allEmbedded {
		// allEmbeddedMap[item.BaseFilename()] = item
		allEmbeddedMap[item.DisplayName()] = item
		installers := item.specs.GetStringMap("feature.install")
		for k := range installers {
			method, err := Method.Parse(k)
			if err != nil {
				panic(fmt.Sprintf("syntax error in feature '%s' specification file (%s)! install method '%s' unknown!",
					item.DisplayName(), item.DisplayFilename(), k))
			}
			if _, found := availableEmbeddedMap[method]; !found {
				availableEmbeddedMap[method] = map[string]*Feature{
					item.DisplayName(): item,
					// item.BaseFilename(): item,
				}
			} else {
				availableEmbeddedMap[method][item.DisplayName()] = item
				// availableEmbeddedMap[method][item.BaseFilename()] = item
			}
		}
	}
}
