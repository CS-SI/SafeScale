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

package embedded

import (
	"bytes"
	"fmt"
	"html/template"

	"github.com/CS-SI/SafeScale/deploy/install"
	"github.com/CS-SI/SafeScale/deploy/install/api"
	"github.com/CS-SI/SafeScale/deploy/install/api/Method"
	"github.com/CS-SI/SafeScale/system"
	rice "github.com/GeertJohan/go.rice"
)

var (
	templateBox *rice.Box
	emptyParams = map[string]interface{}{}

	// Availables contains all the Component installers available
	availables map[Method.Enum]map[string]api.ComponentAPI
	all        map[string]api.ComponentAPI
)

// getScript returns the
func getScript(name string, params map[string]interface{}) string {
	commonTools, err := system.RealizeCommonTools()
	if err != nil {
		panic(fmt.Sprintf("failed to load script: %s!", err.Error()))
	}

	if templateBox == nil {
		var err error
		templateBox, err = rice.FindBox("../install/scripts")
		if err != nil {
			panic(fmt.Sprintf("failed to load script: %s!", err.Error()))
		}
	}
	tmplString, err := templateBox.String(name)
	if err != nil {
		panic(fmt.Sprintf("failed to load script: %s!", err.Error()))
	}
	tmplPrepared, err := template.New(name).Parse(tmplString)
	if err != nil {
		panic(fmt.Sprintf("failed to load script: %s!", err.Error()))
	}

	// Add some supplemental parameters
	params["CommonTools"] = commonTools

	dataBuffer := bytes.NewBufferString("")
	err = tmplPrepared.Execute(dataBuffer, params)
	if err != nil {
		panic(fmt.Sprintf("failed to load script: %s!", err.Error()))
	}
	return dataBuffer.String()
}

// dockerComponent ...
func dockerComponent() *install.Component {
	si := install.NewScriptInstaller("Docker", api.InstallerParameters{
		"AddScript":    getScript("install_Component_docker.sh", emptyParams),
		"RemoveScript": getScript("uninstall_Component_docker.sh", emptyParams),
		"StartCommand": "systemctl start docker",
		"StopCommand":  "systemctl stop docker",
		"StateCommand": "systemctl status docker",
	})

	return &install.Component{
		Name: "Docker",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
	}
}

// nVidiaDockerComponent ...
func nVidiaDockerComponent() *install.Component {
	si := install.NewScriptInstaller("nVidiaDocker", api.InstallerParameters{
		"AddScript":    getScript("install_Component_nvidia_docker.sh", emptyParams),
		"RemoveScript": getScript("uninstall_nvidia_docker.sh", emptyParams),
		"StartCommand": "systemctl start nvidia-docker",
		"StopCommand":  "systemctl stop nvidia-docker",
		"StateCommand": "systemctl status nvidia-docker",
	})

	return &install.Component{
		Name: "nVidiaDocker",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
	}
}

// kubernetesComponent ...
func kubernetesComponent() *install.Component {
	si := install.NewScriptInstaller("Kubernetes", api.InstallerParameters{
		"AddScript":    getScript("install_kubernetes.sh", emptyParams),
		"RemoveScript": getScript("uninstall_kubernetes.sh", emptyParams),
		"State":        "",
		"Start":        "",
		"Stop":         "",
	})

	return &install.Component{
		Name: "Kubernetes",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
	}
}

// nexusComponent ...
func nexusComponent() *install.Component {
	si := install.NewScriptInstaller("Nexus", api.InstallerParameters{
		"AddScript":    getScript("install_nexus.sh", emptyParams),
		"RemoveScript": getScript("uninstall_nexus.sh", emptyParams),
		"StateCommand": "",
		"StartCommand": "",
		"StopCommand":  "",
	})

	return &install.Component{
		Name: "Nexus",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
	}
}

// elasticSearchComponent ...
func elasticSearchComponent() *install.Component {
	si := install.NewScriptInstaller("ElasticSearch", api.InstallerParameters{
		"AddScript":    getScript("install_elastic_search.sh", emptyParams),
		"RemoveScript": getScript("uninstall_elastic_search.sh", emptyParams),
		"State":        "",
		"Start":        "",
		"Stop":         "",
	})

	return &install.Component{
		Name: "ElasticSearch",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
	}
}

// helmComponent ...
func helmComponent() *install.Component {
	si := install.NewScriptInstaller("Helm", api.InstallerParameters{
		"AddScript":    getScript("install_helm.sh", emptyParams),
		"RemoveScript": getScript("uninstall_helm.sh", emptyParams),
		"State":        "",
		"Start":        "",
		"Stop":         "",
	})

	return &install.Component{
		Name: "Helm",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
	}
}

// reverseProxyComponent ...
func reverseProxyComponent() *install.Component {
	si := install.NewScriptInstaller("ReverseProxy", api.InstallerParameters{
		"AddScript":    getScript("install_Component_reverse_proxy.sh", emptyParams),
		"RemoveScript": getScript("uninstall_Component_reverse_proxy.sh", emptyParams),
		"State":        "docker container ls | grep reverse-proxy",
		"Stop":         "docker-compose -f /opt/SafeScale/docker-compose.yml down reverse-proxy",
		"Start":        "docker-compose -f /opt/SafeScale/docker-compose.yml up -d reverse-proxy",
	})

	return &install.Component{
		Name: "ReverseProxy",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
		Dependencies: []string{
			"Docker|nVidiaDocker",
		},
	}
}

// remoteDesktopComponent ...
func remoteDesktopComponent() *install.Component {
	si := install.NewScriptInstaller("RemoteDesktop", api.InstallerParameters{
		"AddScript":    getScript("install_remote_desktop.sh", emptyParams),
		"RemoveScript": getScript("uninstall_remote_desktop.sh", emptyParams),
		"State":        "docker container ls | grep guacamole",
		"Stop":         "docker-compose -f /opt/SafeScale/docker-compose.yml down guacamole",
		"Start":        "docker-compose -f /opt/SafeScale/docker-compose.yml up -d guacamole",
	})

	return &install.Component{
		Name: "MPICH",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
		Dependencies: []string{
			"Docker|nVidiaDocker",
			"ReverseProxy",
		},
	}
}

// mpichComponent ...
func mpichComponent() *install.Component {
	si := install.NewScriptInstaller("MPICH", api.InstallerParameters{
		"AddScript":    getScript("install_mpich.sh", emptyParams),
		"RemoveScript": getScript("uninstall_mpich.sh", emptyParams),
	})

	return &install.Component{
		Name: "MPICH",
		Installers: api.InstallerMap{
			Method.Script: si,
		},
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
	availables = map[Method.Enum]map[string]api.ComponentAPI{
		Method.Script: map[string]api.ComponentAPI{
			"Docker":        dockerComponent(),
			"NVidiaDocker":  nVidiaDockerComponent(),
			"Kubernetes":    kubernetesComponent(),
			"ElasticSearch": elasticSearchComponent(),
			"Helm":          helmComponent(),
			"MPICH":         mpichComponent(),
		},
	}

	all = map[string]api.ComponentAPI{
		"Docker":        dockerComponent(),
		"NVidiaDocker":  nVidiaDockerComponent(),
		"Kubernetes":    kubernetesComponent(),
		"ElasticSearch": elasticSearchComponent(),
		"Helm":          helmComponent(),
		"MPICH":         mpichComponent(),
	}

}
