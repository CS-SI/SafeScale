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

	availableEmbeddedMap = map[Method.Enum]map[string]api.ComponentAPI{}
	allEmbeddedMap       = map[string]api.ComponentAPI{}
	allEmbedded          = []api.ComponentAPI{}
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
	if !v.IsSet("component.installers") {
		return nil, fmt.Errorf("syntax error in component specification file '%s': missing 'installers'", name)
	}
	if len(v.GetStringMap("component.installers")) <= 0 {
		return nil, fmt.Errorf("syntax error in component specification file '%s': 'installers' defines no method", name)
	}
	return v, nil
}

// dockerComponent ...
func dockerComponent() *Component {
	specs, err := loadSpecFile("docker", emptyParams)
	if err != nil {
		panic(err.Error())
	}

	// si := install.NewScriptInstaller("Docker", api.InstallerParameters{
	// 	"AddScript":    getScript("install_Component_docker.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_Component_docker.sh", emptyParams),
	// 	"StartCommand": "systemctl start docker",
	// 	"StopCommand":  "systemctl stop docker",
	// 	"StateCommand": "systemctl status docker",
	// })

	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
	}
}

// nVidiaDockerComponent ...
func nVidiaDockerComponent() *Component {
	specs, err := loadSpecFile("nvidiadocker", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	// si := install.NewScriptInstaller("nVidiaDocker", api.InstallerParameters{
	// 	"AddScript":    getScript("install_Component_nvidia_docker.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_nvidia_docker.sh", emptyParams),
	// 	"StartCommand": "systemctl start nvidia-docker",
	// 	"StopCommand":  "systemctl stop nvidia-docker",
	// 	"StateCommand": "systemctl status nvidia-docker",
	// })
	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
	}
}

// kubernetesComponent ...
func kubernetesComponent() *Component {
	specs, err := loadSpecFile("kubernetes", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	// si := install.NewScriptInstaller("Kubernetes", api.InstallerParameters{
	// 	"AddScript":    getScript("install_kubernetes.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_kubernetes.sh", emptyParams),
	// 	"State":        "",
	// 	"Start":        "",
	// 	"Stop":         "",
	// })

	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
	}
}

// nexusComponent ...
func nexusComponent() *Component {
	specs, err := loadSpecFile("nexus", emptyParams)
	if err != nil {
		panic(err.Error())
	}

	// si := install.NewScriptInstaller("Nexus", api.InstallerParameters{
	// 	"AddScript":    getScript("install_nexus.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_nexus.sh", emptyParams),
	// 	"StateCommand": "",
	// 	"StartCommand": "",
	// 	"StopCommand":  "",
	// })

	return &Component{
		Name:  specs.GetString("name"),
		specs: specs,
	}
}

// elasticSearchComponent ...
func elasticSearchComponent() *Component {
	specs, err := loadSpecFile("elasticsearch", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	// si := install.NewScriptInstaller("ElasticSearch", api.InstallerParameters{
	// 	"AddScript":    getScript("install_elastic_search.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_elastic_search.sh", emptyParams),
	// 	"State":        "",
	// 	"Start":        "",
	// 	"Stop":         "",
	// })

	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
	}
}

// helmComponent ...
func helmComponent() *Component {
	specs, err := loadSpecFile("helm", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	// si := install.NewScriptInstaller("Helm", api.InstallerParameters{
	// 	"AddScript":    getScript("install_helm.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_helm.sh", emptyParams),
	// 	"State":        "",
	// 	"Start":        "",
	// 	"Stop":         "",
	// })

	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
	}
}

// reverseProxyComponent ...
func reverseProxyComponent() *Component {
	specs, err := loadSpecFile("reverseproxy", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	// si := install.NewScriptInstaller("ReverseProxy", api.InstallerParameters{
	// 	"AddScript":    getScript("install_Component_reverse_proxy.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_Component_reverse_proxy.sh", emptyParams),
	// 	"State":        "docker container ls | grep reverse-proxy",
	// 	"Stop":         "docker-compose -f /opt/SafeScale/docker-compose.yml down reverse-proxy",
	// 	"Start":        "docker-compose -f /opt/SafeScale/docker-compose.yml up -d reverse-proxy",
	// })

	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
	}
}

// remoteDesktopComponent ...
func remoteDesktopComponent() *Component {
	specs, err := loadSpecFile("remotedesktop", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	// si := install.NewScriptInstaller("RemoteDesktop", api.InstallerParameters{
	// 	"AddScript":    getScript("install_remote_desktop.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_remote_desktop.sh", emptyParams),
	// 	"State":        "docker container ls | grep guacamole",
	// 	"Stop":         "docker-compose -f /opt/SafeScale/docker-compose.yml down guacamole",
	// 	"Start":        "docker-compose -f /opt/SafeScale/docker-compose.yml up -d guacamole",
	// })

	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
	}
}

// mpichOsPkgComponent ...
func mpichOsPkgComponent() *Component {
	specs, err := loadSpecFile("mpich-ospkg", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	// si := install.NewScriptInstaller("MPICH", api.InstallerParameters{
	// 	"AddScript":    getScript("install_mpich.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_mpich.sh", emptyParams),
	// })

	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
	}
}

// mpichBuildComponent ...
func mpichBuildComponent() *Component {
	specs, err := loadSpecFile("mpich-build", emptyParams)
	if err != nil {
		panic(err.Error())
	}
	// si := install.NewScriptInstaller("MPICH", api.InstallerParameters{
	// 	"AddScript":    getScript("install_mpich.sh", emptyParams),
	// 	"RemoveScript": getScript("uninstall_mpich.sh", emptyParams),
	// })

	return &Component{
		Name:  specs.GetString("component.name"),
		specs: specs,
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

	allEmbedded = []api.ComponentAPI{
		dockerComponent(),
		nVidiaDockerComponent(),
		mpichOsPkgComponent(),
		mpichBuildComponent(),
		remoteDesktopComponent(),
		//reverseProxyComponent(),
		//		kubernetesComponent(),
		//		elasticSearchComponent(),
		//		helmComponent(),
	}

	for _, item := range allEmbedded {
		allEmbeddedMap[item.GetName()] = item
		installers := item.GetSpecs().GetStringMap("component.installers")
		for k := range installers {
			method, err := Method.Parse(k)
			if err != nil {
				panic(fmt.Sprintf("syntax error in component '%s' specification file! installer method '%s' unknown!",
					item.GetName(), k))
			}
			if _, found := availableEmbeddedMap[method]; !found {
				availableEmbeddedMap[method] = map[string]api.ComponentAPI{
					item.GetName(): item,
				}
			} else {
				availableEmbeddedMap[method][item.GetName()] = item
			}
		}
	}
}
