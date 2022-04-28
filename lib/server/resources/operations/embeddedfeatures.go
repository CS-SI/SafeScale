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

package operations

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/v21/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/v21/lib/utils/debug"
	"github.com/CS-SI/SafeScale/v21/lib/utils/fail"
)

const featureFileExt = ".yml"

var (
	availableEmbeddedFeaturesMap = map[installmethod.Enum]map[string]*FeatureFile{}
	allEmbeddedFeaturesMap       = map[string]*FeatureFile{}
	allEmbeddedFeatures          []*FeatureFile
)

func getSHA256Hash(text string) string {
	hasher := sha256.New()
	_, err := hasher.Write([]byte(text))
	if err != nil {
		return ""
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

//go:embed embeddedfeatures/*
var embeddedFeatures embed.FS

// loadSpecFile returns the content of the spec file of the feature named 'name'
func loadSpecFile(name string) (string, *viper.Viper, error) {
	name += featureFileExt
	tmplString, err := embeddedFeatures.ReadFile("embeddedfeatures/" + name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", nil, fail.Wrap(err, "failed to read embedded feature specification file '%s'", name)
	}

	logrus.Tracef("loaded feature %s:SHA256:%s", name, getSHA256Hash(string(tmplString)))

	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(bytes.NewBuffer([]byte(tmplString)))
	err = debug.InjectPlannedError(err)
	if err != nil {
		return "", nil, fail.Wrap(err, "syntax error in feature specification file '%s'", name)
	}

	// Validating content...
	if !v.IsSet("feature") {
		return "", nil, fail.SyntaxError("feature specification file '%s' must begin with 'feature:'", name)
	}
	if !v.IsSet("feature.install") {
		return "", nil, fail.SyntaxError("syntax error in feature specification file '%s': missing 'install'", name)
	}
	if len(v.GetStringMap("feature.install")) == 0 {
		return "", nil, fail.SyntaxError("syntax error in feature specification file '%s': 'install' defines no method", name)
	}
	return name, v, nil
}

// dockerFeature ...
func dockerFeature() *FeatureFile {
	name := "docker"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// dockerSwarmFeature ...
func dockerSwarmFeature() *FeatureFile {
	name := "docker-swarm"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// ntpServerFeature ...
func ntpServerFeature() *FeatureFile {
	name := "ntpserver"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// ntpServerFeature ...
func ntpClientFeature() *FeatureFile {
	name := "ntpclient"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// ansibleFeature from official repos ...
func ansibleFeature() *FeatureFile {
	name := "ansible"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// ansibleForClusterFeature  ...
func ansibleForClusterFeature() *FeatureFile {
	name := "ansible-for-cluster"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// certificateAuthorityFeature from official repos ...
func certificateAuthorityFeature() *FeatureFile {
	name := "certificateauthority"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// nVidiaDockerFeature ...
func nVidiaDockerFeature() *FeatureFile {
	name := "nvidiadocker"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// kubernetesFeature ...
func kubernetesFeature() *FeatureFile {
	name := "kubernetes"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// helm2Feature ...
func helm2Feature() *FeatureFile {
	name := "helm2"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// helm3Feature ...
func helm3Feature() *FeatureFile {
	name := "helm3"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// remoteDesktopFeature ...
func remoteDesktopFeature() *FeatureFile {
	name := "remotedesktop"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// proxycacheServerFeature ...
func proxycacheServerFeature() *FeatureFile {
	name := "proxycache-server"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// proxycacheClientFeature ...
func proxycacheClientFeature() *FeatureFile {
	name := "proxycache-client"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// postgres4gatewayFeature ...
func postgres4gatewayFeature() *FeatureFile {
	name := "postgres4gateway"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

// edgeproxy4subnetFeature ...
func edgeproxy4subnetFeature() *FeatureFile {
	name := "edgeproxy4subnet"
	filename, specs, err := loadSpecFile(name)
	err = debug.InjectPlannedError(err)
	if err != nil {
		panic(err.Error())
	}

	return newFeatureFile(filename, name, true, specs)
}

func init() {
	allEmbeddedFeatures = []*FeatureFile{
		dockerFeature(),
		dockerSwarmFeature(),
		ntpServerFeature(),
		ntpClientFeature(),
		ansibleFeature(),
		ansibleForClusterFeature(),
		certificateAuthorityFeature(),
		// postgresql4platformFeature(),
		nVidiaDockerFeature(),
		// mpichOsPkgFeature(),
		// mpichBuildFeature(),
		// ohpcSlurmMasterFeature(),
		// ohpcSlurmNodeFeature(),
		remoteDesktopFeature(),
		postgres4gatewayFeature(),
		edgeproxy4subnetFeature(),
		// keycloak4platformFeature(),
		kubernetesFeature(),
		proxycacheServerFeature(),
		proxycacheClientFeature(),
		// apacheIgniteFeature(),
		// elasticsearchFeature(),
		// logstashFeature(),
		// metricbeatFeature(),
		// filebeatFeature(),
		// kibanaFeature(),
		helm2Feature(),
		helm3Feature(),
		// sparkmaster4platformFeature(),
		// elassandraFeature(),
		// consul4platformFeature(),
		// monitoring4platformFeature(),
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
				displayFilename := item.DisplayFilename()
				if displayFilename == "" {
					logrus.Errorf(fmt.Sprintf("syntax error in feature '%s' specification file, install method '%s' is unknown", itemName, k))
				} else {
					logrus.Errorf(fmt.Sprintf("syntax error in feature '%s' specification file (%s), install method '%s' is unknown", itemName, displayFilename, k))
				}
				continue
			}
			if _, found := availableEmbeddedFeaturesMap[meth]; !found {
				availableEmbeddedFeaturesMap[meth] = map[string]*FeatureFile{
					itemName: item,
				}
			} else {
				availableEmbeddedFeaturesMap[meth][itemName] = item
			}
		}
	}
}
