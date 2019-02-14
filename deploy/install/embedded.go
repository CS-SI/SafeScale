/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"
)

//go:generate rice embed-go

var (
	templateBox *rice.Box
	emptyParams = map[string]interface{}{}

	availableEmbeddedMap = map[Method.Enum]map[string]*Feature{}
	allEmbeddedMap       = map[string]*Feature{}
	allEmbedded          = []*Feature{}
)

// loadSpecFile returns the content of the spec file of the feature named 'name'
func loadSpecFile(name string) (*viper.Viper, error) {
	if templateBox == nil {
		var err error
		templateBox, err = rice.FindBox("features")
		if err != nil {
			return nil, fmt.Errorf("failed to open embedded feature specification folder: %s", err.Error())
		}
	}
	name += ".yml"
	tmplString, err := templateBox.String(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read embedded feature speficication file '%s': %s", name, err.Error())
	}

	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(bytes.NewBuffer([]byte(tmplString)))
	if err != nil {
		return nil, fmt.Errorf("syntax error in feature specification file '%s': %s", name, err.Error())
	}

	// Validating content...
	if !v.IsSet("feature") {
		return nil, fmt.Errorf("feature specification file '%s' must begin with 'feature:'", name)
	}
	if !v.IsSet("feature.name") {
		return nil, fmt.Errorf("syntax error in feature specification file '%s': missing 'name'", name)
	}
	if v.GetString("feature.name") == "" {
		return nil, fmt.Errorf("syntax error in feature specification file '%s': name' can't be empty", name)
	}
	if !v.IsSet("feature.install") {
		return nil, fmt.Errorf("syntax error in feature specification file '%s': missing 'install'", name)
	}
	if len(v.GetStringMap("feature.install")) <= 0 {
		return nil, fmt.Errorf("syntax error in feature specification file '%s': 'install' defines no method", name)
	}
	return v, nil
}

// dockerFeature ...
func dockerFeature() *Feature {
	specs, err := loadSpecFile("docker")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "docker",
		specs:       specs,
	}
}

// dockerComposeFeature ...
func dockerComposeFeature() *Feature {
	specs, err := loadSpecFile("docker-compose")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "docker-compose",
		specs:       specs,
	}
}

// nVidiaDockerFeature ...
func nVidiaDockerFeature() *Feature {
	specs, err := loadSpecFile("nvidiadocker")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "nvidiadocker",
		specs:       specs,
	}
}

// kubernetesFeature ...
func kubernetesFeature() *Feature {
	specs, err := loadSpecFile("kubernetes")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "kubernetes",
		specs:       specs,
	}
}

// nexusFeature ...
func nexusFeature() *Feature {
	specs, err := loadSpecFile("nexus")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("name"),
		fileName:    "nexus",
		specs:       specs,
	}
}

// elasticSearchFeature ...
func elasticSearchFeature() *Feature {
	specs, err := loadSpecFile("elasticsearch")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "elasticsearch",
		specs:       specs,
	}
}

// helmFeature ...
func helmFeature() *Feature {
	specs, err := loadSpecFile("helm")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "helm",
		specs:       specs,
	}
}

// sparkFeature ...
func sparkFeature() *Feature {
	specs, err := loadSpecFile("spark")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "spark",
		specs:       specs,
	}
}

// reverseProxyFeature ...
func reverseProxyFeature() *Feature {
	specs, err := loadSpecFile("reverseproxy")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "reverseproxy",
		specs:       specs,
	}
}

// remoteDesktopFeature ...
func remoteDesktopFeature() *Feature {
	specs, err := loadSpecFile("remotedesktop")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "remotedesktop",
		specs:       specs,
	}
}

// mpichOsPkgFeature ...
func mpichOsPkgFeature() *Feature {
	specs, err := loadSpecFile("mpich-ospkg")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "mpich-ospkg",
		specs:       specs,
	}
}

// mpichBuildFeature ...
func mpichBuildFeature() *Feature {
	specs, err := loadSpecFile("mpich-build")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "mpich-build",
		specs:       specs,
	}
}

// ohpcSlurmMasterFeature ...
func ohpcSlurmMasterFeature() *Feature {
	specs, err := loadSpecFile("ohpc-slurm-master")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "ohpc-slurm-master",
		specs:       specs,
	}
}

// ohpcSlurmNodeFeature ...
func ohpcSlurmNodeFeature() *Feature {
	specs, err := loadSpecFile("ohpc-slurm-node")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "ohpc-slurm-node",
		specs:       specs,
	}
}

// proxycacheServerFeature ...
func proxycacheServerFeature() *Feature {
	specs, err := loadSpecFile("proxycache-server")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "proxycache-server",
		specs:       specs,
	}
}

// proxycacheClientFeature ...
func proxycacheClientFeature() *Feature {
	specs, err := loadSpecFile("proxycache-client")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "proxycache-client",
		specs:       specs,
	}
}

// apacheIgniteFeature ...
func apacheIgniteFeature() *Feature {
	specs, err := loadSpecFile("apache-ignite")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "apache-ignite",
		specs:       specs,
	}
}

// metricbeatFeature ...
func metricbeatFeature() *Feature {
	specs, err := loadSpecFile("metricbeat")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "metricbeat",
		specs:       specs,
	}
}

// filebeatFeature ...
func filebeatFeature() *Feature {
	specs, err := loadSpecFile("filebeat")
	if err != nil {
		panic(err.Error())
	}
	return &Feature{
		displayName: specs.GetString("feature.name"),
		fileName:    "filebeat",
		specs:       specs,
	}
}

// ListAvailables returns an array of availables features with the useable installers
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
