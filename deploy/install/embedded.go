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

	"github.com/CS-SI/SafeScale/deploy/install/enums/Method"

	"github.com/spf13/viper"

	rice "github.com/GeertJohan/go.rice"
)

var (
	templateBox *rice.Box
	emptyParams = map[string]interface{}{}

	availableEmbeddedMap = map[Method.Enum]map[string]*Component{}
	allEmbeddedMap       = map[string]*Component{}
	allEmbedded          = []*Component{}
)

// loadSpecFile returns the content of the spec file of the component named 'name'
func loadSpecFile(name string) (*viper.Viper, error) {
	if templateBox == nil {
		var err error
		templateBox, err = rice.FindBox("../install/components")
		if err != nil {
			return nil, fmt.Errorf("failed to open embedded component specification folder: %s", err.Error())
		}
	}
	name += ".yml"
	tmplString, err := templateBox.String(name)
	if err != nil {
		panic(fmt.Sprintf("failed to read embedded component speficication file '%s': %s", name, err.Error()))
	}

	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(bytes.NewBuffer([]byte(tmplString)))
	if err != nil {
		return nil, fmt.Errorf("syntax error in component specification file '%s': %s", name, err.Error())
	}

	// Validating content...
	if !v.IsSet("component") {
		return nil, fmt.Errorf("component specification file '%s' must begin with 'component:'", name)
	}
	if !v.IsSet("component.name") {
		return nil, fmt.Errorf("syntax error in component specification file '%s': missing 'name'", name)
	}
	if v.GetString("component.name") == "" {
		return nil, fmt.Errorf("syntax error in component specification file '%s': name' can't be empty", name)
	}
	if !v.IsSet("component.install") {
		return nil, fmt.Errorf("syntax error in component specification file '%s': missing 'install'", name)
	}
	if len(v.GetStringMap("component.install")) <= 0 {
		return nil, fmt.Errorf("syntax error in component specification file '%s': 'install' defines no method", name)
	}
	return v, nil
}

// dockerComponent ...
func dockerComponent() *Component {
	specs, err := loadSpecFile("docker")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "docker",
		specs:       specs,
	}
}

// nVidiaDockerComponent ...
func nVidiaDockerComponent() *Component {
	specs, err := loadSpecFile("nvidiadocker")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "nvidiadocker",
		specs:       specs,
	}
}

// kubernetesComponent ...
func kubernetesComponent() *Component {
	specs, err := loadSpecFile("kubernetes")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "kubernetes",
		specs:       specs,
	}
}

// nexusComponent ...
func nexusComponent() *Component {
	specs, err := loadSpecFile("nexus")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("name"),
		fileName:    "nexus",
		specs:       specs,
	}
}

// elasticSearchComponent ...
func elasticSearchComponent() *Component {
	specs, err := loadSpecFile("elasticsearch")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "elasticsearch",
		specs:       specs,
	}
}

// helmComponent ...
func helmComponent() *Component {
	specs, err := loadSpecFile("helm")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "helm",
		specs:       specs,
	}
}

// sparkComponent ...
func sparkComponent() *Component {
	specs, err := loadSpecFile("spark")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "spark",
		specs:       specs,
	}
}

// reverseProxyComponent ...
func reverseProxyComponent() *Component {
	specs, err := loadSpecFile("reverseproxy")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "reverseproxy",
		specs:       specs,
	}
}

// remoteDesktopComponent ...
func remoteDesktopComponent() *Component {
	specs, err := loadSpecFile("remotedesktop")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "remotedesktop",
		specs:       specs,
	}
}

// mpichOsPkgComponent ...
func mpichOsPkgComponent() *Component {
	specs, err := loadSpecFile("mpich-ospkg")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "mpich-ospkg",
		specs:       specs,
	}
}

// mpichBuildComponent ...
func mpichBuildComponent() *Component {
	specs, err := loadSpecFile("mpich-build")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "mpich-build",
		specs:       specs,
	}
}

// ohpcSlurmMasterComponent ...
func ohpcSlurmMasterComponent() *Component {
	specs, err := loadSpecFile("ohpc-slurm-master")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "ohpc-slurm-master",
		specs:       specs,
	}
}

// ohpcSlurmNodeComponent ...
func ohpcSlurmNodeComponent() *Component {
	specs, err := loadSpecFile("ohpc-slurm-node")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "ohpc-slurm-node",
		specs:       specs,
	}
}

// proxycacheServerComponent ...
func proxycacheServerComponent() *Component {
	specs, err := loadSpecFile("proxycache-server")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "proxycache-server",
		specs:       specs,
	}
}

// proxycacheClientComponent ...
func proxycacheClientComponent() *Component {
	specs, err := loadSpecFile("proxycache-client")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "proxycache-client",
		specs:       specs,
	}
}

// apacheIgniteComponent ...
func apacheIgniteComponent() *Component {
	specs, err := loadSpecFile("apache-ignite")
	if err != nil {
		panic(err.Error())
	}
	return &Component{
		displayName: specs.GetString("component.name"),
		fileName:    "apache-ignite",
		specs:       specs,
	}
}

// ListAvailables returns an array of availables components with the useable installers
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

func init() {

	allEmbedded = []*Component{
		dockerComponent(),
		nVidiaDockerComponent(),
		mpichOsPkgComponent(),
		mpichBuildComponent(),
		ohpcSlurmMasterComponent(),
		ohpcSlurmNodeComponent(),
		remoteDesktopComponent(),
		reverseProxyComponent(),
		kubernetesComponent(),
		proxycacheServerComponent(),
		proxycacheClientComponent(),
		apacheIgniteComponent(),
		//		elasticSearchComponent(),
		helmComponent(),
		sparkComponent(),
	}

	for _, item := range allEmbedded {
		allEmbeddedMap[item.BaseFilename()] = item
		allEmbeddedMap[item.DisplayName()] = item
		installers := item.Specs().GetStringMap("component.install")
		for k := range installers {
			method, err := Method.Parse(k)
			if err != nil {
				panic(fmt.Sprintf("syntax error in component '%s' specification file (%s)! install method '%s' unknown!",
					item.DisplayName(), item.DisplayFilename(), k))
			}
			if _, found := availableEmbeddedMap[method]; !found {
				availableEmbeddedMap[method] = map[string]*Component{
					item.DisplayName():  item,
					item.BaseFilename(): item,
				}
			} else {
				availableEmbeddedMap[method][item.DisplayName()] = item
				availableEmbeddedMap[method][item.BaseFilename()] = item
			}
		}
	}
}
