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

	txttmpl "text/template"

	"github.com/CS-SI/SafeScale/deploy/install/api"
	"github.com/CS-SI/SafeScale/deploy/install/api/Method"
	"github.com/CS-SI/SafeScale/utils/template"

	"github.com/spf13/viper"

	rice "github.com/GeertJohan/go.rice"
)

var (
	templateBox *rice.Box
	emptyParams = map[string]interface{}{}

	availableEmbeddedMap = map[Method.Enum]map[string]api.Component{}
	allEmbeddedMap       = map[string]api.Component{}
	allEmbedded          = []api.Component{}
)

// loadSpecFile returns the content of the spec file of the component named 'name'
func loadSpecFile(name string, params map[string]interface{}) (*viper.Viper, error) {
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
	tmplPrepared, err := txttmpl.New(name).Funcs(template.FuncMap).Parse(tmplString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse embedded component specification file '%s': %s", name, err.Error())
	}

	dataBuffer := bytes.NewBufferString("")
	err = tmplPrepared.Execute(dataBuffer, params)
	if err != nil {
		return nil, fmt.Errorf("failed to realize embedded component specification file '%s': %s", name, err.Error())
	}

	v := viper.New()
	v.SetConfigType("yaml")
	err = v.ReadConfig(bytes.NewBuffer(dataBuffer.Bytes()))
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
	if !v.IsSet("component.installing") {
		return nil, fmt.Errorf("syntax error in component specification file '%s': missing 'installing'", name)
	}
	if len(v.GetStringMap("component.installing")) <= 0 {
		return nil, fmt.Errorf("syntax error in component specification file '%s': 'installing' defines no method", name)
	}
	return v, nil
}

// dockerComponent ...
func dockerComponent() *component {
	specs, err := loadSpecFile("docker", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "docker",
		specs:       specs,
	}
}

// nVidiaDockerComponent ...
func nVidiaDockerComponent() *component {
	specs, err := loadSpecFile("nvidiadocker", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "nvidiadocker",
		specs:       specs,
	}
}

// kubernetesComponent ...
func kubernetesComponent() *component {
	specs, err := loadSpecFile("kubernetes", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "kubernetes",
		specs:       specs,
	}
}

// nexusComponent ...
func nexusComponent() *component {
	specs, err := loadSpecFile("nexus", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("name"),
		fileName:    "nexus",
		specs:       specs,
	}
}

// elasticSearchComponent ...
func elasticSearchComponent() *component {
	specs, err := loadSpecFile("elasticsearch", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "elasticsearch",
		specs:       specs,
	}
}

// helmComponent ...
func helmComponent() *component {
	specs, err := loadSpecFile("helm", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "helm",
		specs:       specs,
	}
}

// reverseProxyComponent ...
func reverseProxyComponent() *component {
	specs, err := loadSpecFile("reverseproxy", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "reverseproxy",
		specs:       specs,
	}
}

// xfceComponent ...
func xfceComponent() *component {
	specs, err := loadSpecFile("xfce", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "xfce",
		specs:       specs,
	}
}

// tigervncComponent ...
func tigervncComponent() *component {
	specs, err := loadSpecFile("tigervnc", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "tigervnc",
		specs:       specs,
	}
}

// remoteDesktopComponent ...
func remoteDesktopComponent() *component {
	specs, err := loadSpecFile("remotedesktop", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "remotedesktop",
		specs:       specs,
	}
}

// mpichOsPkgComponent ...
func mpichOsPkgComponent() *component {
	specs, err := loadSpecFile("mpich-ospkg", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "mpich-ospkg",
		specs:       specs,
	}
}

// mpichBuildComponent ...
func mpichBuildComponent() *component {
	specs, err := loadSpecFile("mpich-build", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	return &component{
		displayName: specs.GetString("component.name"),
		fileName:    "mpich-build",
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

	allEmbedded = []api.Component{
		dockerComponent(),
		nVidiaDockerComponent(),
		mpichOsPkgComponent(),
		mpichBuildComponent(),
		xfceComponent(),
		tigervncComponent(),
		remoteDesktopComponent(),
		//reverseProxyComponent(),
		//		kubernetesComponent(),
		//		elasticSearchComponent(),
		//		helmComponent(),
	}

	for _, item := range allEmbedded {
		allEmbeddedMap[item.ShortFileName()] = item
		allEmbeddedMap[item.DisplayName()] = item
		installers := item.Specs().GetStringMap("component.installing")
		for k := range installers {
			method, err := Method.Parse(k)
			if err != nil {
				panic(fmt.Sprintf("syntax error in component '%s' specification file (%s)! installing method '%s' unknown!",
					item.DisplayName(), item.FullFileName(), k))
			}
			if _, found := availableEmbeddedMap[method]; !found {
				availableEmbeddedMap[method] = map[string]api.Component{
					item.DisplayName():   item,
					item.ShortFileName(): item,
				}
			} else {
				availableEmbeddedMap[method][item.DisplayName()] = item
				availableEmbeddedMap[method][item.ShortFileName()] = item
			}
		}
	}
}
