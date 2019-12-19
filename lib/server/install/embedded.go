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
	"bytes"
	"fmt"

	"github.com/spf13/viper"

	rice "github.com/GeertJohan/go.rice"

	"github.com/CS-SI/SafeScale/lib/server/install/enums/method"
)

//go:generate rice embed-go

const featureFileExt = ".yml"

var (
	templateBox *rice.Box
	// emptyParams = map[string]interface{}{}

	availableEmbeddedMap = map[method.Enum]map[string]*Feature{}
	allEmbeddedMap       = map[string]*Feature{}
	allEmbedded          []*Feature
)

// loadSpecFile returns the content of the spec file of the feature named 'name'
func loadSpecFile(name string) (string, *viper.Viper, error) {
	if templateBox == nil {
		var err error
		templateBox, err = rice.FindBox("../../../features")
		if err != nil {
			return "", nil, fmt.Errorf("failed to open embedded feature specification folder: %s", err.Error())
		}
	}
	name += featureFileExt
	tmplString, err := templateBox.String(name)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read embedded feature speficication file '%s': %s", name, err.Error())
	}

	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(bytes.NewBuffer([]byte(tmplString)))
	if err != nil {
		return "", nil, fmt.Errorf("syntax error in feature specification file '%s': %s", name, err.Error())
	}

	// Validating content...
	if !v.IsSet("feature") {
		return "", nil, fmt.Errorf("feature specification file '%s' must begin with 'feature:'", name)
	}
	if !v.IsSet("feature.install") {
		return "", nil, fmt.Errorf("syntax error in feature specification file '%s': missing 'install'", name)
	}
	if len(v.GetStringMap("feature.install")) == 0 {
		return "", nil, fmt.Errorf("syntax error in feature specification file '%s': 'install' defines no method", name)
	}
	return name, v, nil
}

// dockerFeature ...
func dockerFeature() *Feature {
	name := "docker"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// // dockerComposeFeature ...
// func dockerComposeFeature() *Feature {
// 	name := "docker-compose"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &Feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// ntpServerFeature ...
func ntpServerFeature() *Feature {
	name := "ntpserver"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ntpServerFeature ...
func ntpClientFeature() *Feature {
	name := "ntpclient"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ansibleFeature from official repos ...
func ansibleFeature() *Feature {
	name := "ansible"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// postgresql4platformFeature feature. ...
func postgresql4platformFeature() *Feature {
	name := "postgresql4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// nVidiaDockerFeature ...
func nVidiaDockerFeature() *Feature {
	name := "nvidiadocker"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// kubernetesFeature ...
func kubernetesFeature() *Feature {
	name := "kubernetes"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// nexusFeature ...
func nexusFeature() *Feature { // nolint
	name := "nexus3"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// elasticsearchFeature ...
func elasticsearchFeature() *Feature {
	name := "elasticsearch"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// logstashFeature ...
func logstashFeature() *Feature {
	name := "logstash"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// helmFeature ...
func helmFeature() *Feature {
	name := "helm"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// sparkmaster4platformFeature ...
func sparkmaster4platformFeature() *Feature {
	name := "sparkmaster4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// remoteDesktopFeature ...
func remoteDesktopFeature() *Feature {
	name := "remotedesktop"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// mpichOsPkgFeature ...
func mpichOsPkgFeature() *Feature {
	name := "mpich-ospkg"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// mpichBuildFeature ...
func mpichBuildFeature() *Feature {
	name := "mpich-build"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ohpcSlurmMasterFeature ...
func ohpcSlurmMasterFeature() *Feature {
	name := "ohpc-slurm-master"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ohpcSlurmNodeFeature ...
func ohpcSlurmNodeFeature() *Feature {
	name := "ohpc-slurm-node"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// proxycacheServerFeature ...
func proxycacheServerFeature() *Feature {
	name := "proxycache-server"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// proxycacheClientFeature ...
func proxycacheClientFeature() *Feature {
	name := "proxycache-client"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// apacheIgniteFeature ...
func apacheIgniteFeature() *Feature {
	name := "apache-ignite"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// metricbeatFeature ...
func metricbeatFeature() *Feature {
	name := "metricbeat"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// filebeatFeature ...
func filebeatFeature() *Feature {
	name := "filebeat"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// postgres4gatewayFeature ...
func postgres4gatewayFeature() *Feature {
	name := "postgres4gateway"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// edgeproxy4networkFeature ...
func edgeproxy4networkFeature() *Feature {
	name := "edgeproxy4network"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// keycloak4platformFeature ...
func keycloak4platformFeature() *Feature {
	name := "keycloak4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// kibanaFeature ...
func kibanaFeature() *Feature {
	name := "kibana"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// elassandraFeature ...
func elassandraFeature() *Feature {
	name := "elassandra"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// consul4platformFeature ...
func consul4platformFeature() *Feature {
	name := "consul4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// monitoring4platformFeature ...
func monitoring4platformFeature() *Feature {
	name := "monitoring4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// geoserverFeature ...
func geoserverFeature() *Feature {
	name := "geoserver"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ListAvailables returns an array of availables features with the usable installers
// func ListAvailables() []string {
// 	var output []string
// 	for k, v := range allAvailables {
// 		line := k
// 		installers := v.Installers()
// 		if len > 0 {
// 			line += " ["
// 			for n, i := range installers {
// 				if n > 0 {
// 					line += ", "
// 				}
// 				line += i.GetName()
// 			}
// 			line += "]"
// 		}
// 		output = append(output, fmt.Sprintf("%s"))
// 	}
// 	return output
// }

// Note: init() moved in zinit.go, to be sure the init() of rice-box.go is called first
