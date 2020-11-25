/*
 * Copyright 2018-2020, CS Systemes d'Information, http://csgroup.eu
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

	rice "github.com/GeertJohan/go.rice"
	"github.com/spf13/viper"

	"github.com/CS-SI/SafeScale/lib/server/resources/enums/installmethod"
	"github.com/CS-SI/SafeScale/lib/utils/fail"
)

//go:generate rice embed-go

const featureFileExt = ".yml"

var (
	templateBox *rice.Box
	// emptyParams = map[string]interface{}{}

	availableEmbeddedFeaturesMap = map[installmethod.Enum]map[string]*feature{}
	allEmbeddedFeaturesMap       = map[string]*feature{}
	allEmbeddedFeatures          []*feature
)

// loadSpecFile returns the content of the spec file of the feature named 'name'
func loadSpecFile(name string) (string, *viper.Viper, error) {
	if templateBox == nil {
		var err error
		templateBox, err = rice.FindBox("../operations/features")
		if err != nil {
			return "", nil, fail.Wrap(err, "failed to open embedded feature specification folder")
		}
	}
	name += featureFileExt
	tmplString, err := templateBox.String(name)
	if err != nil {
		return "", nil, fail.Wrap(err, "failed to read embedded feature speficication file '%s'", name)
	}

	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(bytes.NewBuffer([]byte(tmplString)))
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
func dockerFeature() *feature {
	name := "docker"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// // dockerComposeFeature ...
// func dockerComposeFeature() *feature {
// 	name := "docker-compose"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error()
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// ntpServerFeature ...
func ntpServerFeature() *feature {
	name := "ntpserver"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ntpServerFeature ...
func ntpClientFeature() *feature {
	name := "ntpclient"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// ansibleFeature from official repos ...
func ansibleFeature() *feature {
	name := "ansible"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// postgresql4platformFeature feature. ...
func postgresql4platformFeature() *feature {
	name := "postgresql4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// nVidiaDockerFeature ...
func nVidiaDockerFeature() *feature {
	name := "nvidiadocker"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// kubernetesFeature ...
func kubernetesFeature() *feature {
	name := "kubernetes"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// // nexusFeature ...
// func nexusFeature() *feature { // nolint
// 	name := "nexus3"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// // elasticsearchFeature ...
// func elasticsearchFeature() *feature {
// 	name := "elasticsearch"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// // logstashFeature ...
// func logstashFeature() *feature {
// 	name := "logstash"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// k8shelm2Feature ...
func k8shelm2Feature() *feature {
	name := "k8s.helm2"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// sparkmaster4platformFeature ...
func sparkmaster4platformFeature() *feature {
	name := "sparkmaster4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// remoteDesktopFeature ...
func remoteDesktopFeature() *feature {
	name := "remotedesktop"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// // mpichOsPkgFeature ...
// func mpichOsPkgFeature() *feature {
// 	name := "mpich-ospkg"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// // mpichBuildFeature ...
// func mpichBuildFeature() *feature {
// 	name := "mpich-build"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// // ohpcSlurmMasterFeature ...
// func ohpcSlurmMasterFeature() *feature {
// 	name := "ohpc-slurm-master"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// // ohpcSlurmNodeFeature ...
// func ohpcSlurmNodeFeature() *feature {
// 	name := "ohpc-slurm-node"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// proxycacheServerFeature ...
func proxycacheServerFeature() *feature {
	name := "proxycache-server"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// proxycacheClientFeature ...
func proxycacheClientFeature() *feature {
	name := "proxycache-client"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// // apacheIgniteFeature ...
// func apacheIgniteFeature() *feature {
// 	name := "apache-ignite"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// // metricbeatFeature ...
// func metricbeatFeature() *feature {
// 	name := "metricbeat"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// // filebeatFeature ...
// func filebeatFeature() *feature {
// 	name := "filebeat"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// postgres4gatewayFeature ...
func postgres4gatewayFeature() *feature {
	name := "postgres4gateway"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// edgeproxy4networkFeature ...
func edgeproxy4networkFeature() *feature {
	name := "edgeproxy4network"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// keycloak4platformFeature ...
func keycloak4platformFeature() *feature {
	name := "keycloak4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// // kibanaFeature ...
// func kibanaFeature() *feature {
// 	name := "kibana"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// // elassandraFeature ...
// func elassandraFeature() *feature {
// 	name := "elassandra"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

// consul4platformFeature ...
func consul4platformFeature() *feature {
	name := "consul4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// monitoring4platformFeature ...
func monitoring4platformFeature() *feature {
	name := "monitoring4platform"
	filename, specs, err := loadSpecFile(name)
	if err != nil {
		panic(err.Error())
	}
	return &feature{
		displayName: name,
		fileName:    filename,
		embedded:    true,
		specs:       specs,
	}
}

// // geoserverFeature ...
// func geoserverFeature() *feature {
// 	name := "geoserver"
// 	filename, specs, err := loadSpecFile(name)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	return &feature{
// 		displayName: name,
// 		fileName:    filename,
// 		embedded:    true,
// 		specs:       specs,
// 	}
// }

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

// NOTE: init() moved in zinit.go, to be sure the init() of rice-box.go is called first
