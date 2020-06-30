/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

package operations

import (
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
)

func init() {

	allEmbeddedFeatures = []*feature{
		dockerFeature(),
		ntpServerFeature(),
		ntpClientFeature(),
		ansibleFeature(),
		postgresql4platformFeature(),
		nVidiaDockerFeature(),
		// mpichOsPkgFeature(),
		// mpichBuildFeature(),
		// ohpcSlurmMasterFeature(),
		// ohpcSlurmNodeFeature(),
		remoteDesktopFeature(),
		postgres4gatewayFeature(),
		edgeproxy4networkFeature(),
		keycloak4platformFeature(),
		kubernetesFeature(),
		proxycacheServerFeature(),
		proxycacheClientFeature(),
		// apacheIgniteFeature(),
		// elasticsearchFeature(),
		// logstashFeature(),
		// metricbeatFeature(),
		// filebeatFeature(),
		// kibanaFeature(),
		k8shelm2Feature(),
		sparkmaster4platformFeature(),
		// elassandraFeature(),
		consul4platformFeature(),
		monitoring4platformFeature(),
		// geoserverFeature(),
	}

	for _, item := range allEmbeddedFeatures {
		itemName := item.GetName()

		// allEmbeddedMap[item.BaseFilename()] = item
		allEmbeddedFeaturesMap[itemName] = item
		installers := item.specs.GetStringMap("feature.install")
		for k := range installers {
			meth, err := installmethod.Parse(k)
			if err != nil {
				displayFilename := item.GetDisplayFilename()
				if displayFilename == "" {
					logrus.Errorf(fmt.Sprintf("syntax error in feature '%s' specification file, install method '%s' is unknown", itemName, k))
				} else {
					logrus.Errorf(fmt.Sprintf("syntax error in feature '%s' specification file (%s), install method '%s' is unknown", itemName, displayFilename, k))
				}
				continue
			}
			if _, found := availableEmbeddedFeaturesMap[meth]; !found {
				availableEmbeddedFeaturesMap[meth] = map[string]*feature{
					itemName: item,
				}
			} else {
				availableEmbeddedFeaturesMap[meth][itemName] = item
			}
		}
	}
}
