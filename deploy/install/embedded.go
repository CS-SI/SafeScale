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
	installapi "github.com/CS-SI/SafeScale/deploy/install/api"
)

var (
	// Availables contains all the service installers available
	Availables map[string]map[string]installapi.ComponentAPI

	dockerComponent = &Component{
		Name: "Docker",
		Installers: []installapi.InstallerAPI{
			NewScriptInstaller("docker"),
		},
	}

	nVidiaDockerComponent = &Component{
		Name: "NvidiaDocker",
		Installers: []InstallerAPI{
			NewScriptInstaller("nvidia_docker"),
		},
	}

	kubernetesComponent = &Component{
		Name: "Kubernetes",
		Installers: []InstallerAPI{
			//NewDCOSPackageInstaller("kubernetes"),
			NewScriptInstaller("kubernetes"),
		},
	}

	nexusComponent = &Component{
		Name: "Nexus",
		Installers: []InstallerAPI{
			NewScriptInstaller("nexus"),
		},
	}

	elasticSearchComponent = &Component{
		Name: "ElasticSearch",
		Installers: []InstallerAPI{
			//NewDCOSPackageInstaller("elastic"),
			NewScriptInstaller("elasticsearch"),
		},
	}

	helmComponent = &Component{
		Name: "Helm",
		Installers: []InstallerAPI{
			NewScriptInstaller("helm"),
		},
	}

	mpichComponent = &Component{
		Name: "MPICH",
		Installers: []InstallerAPI{
			NewScriptInstaller("mpich"),
		},
	}
)

func init() {
	Availables = map[string]map[string]ComponentAPI{
		// "DCOS": map[string]ComponentAPI{
		// 	"Kubernetes":    kubernetesComponent,
		// 	"ElasticSearch": elasticSearchComponent,
		// 	"Helm":          helmComponent,
		// },
		// "Helm": map[string]ComponentAPI{
		// 	"ElasticSearch": elasticSearchService,
		// },
		"Script": map[string]ComponentAPI{
			"Docker":        dockerComponent,
			"NVidiaDocker":  nVidiaDockerComponent,
			"Kubernetes":    kubernetesComponent,
			"ElasticSearch": elasticSearchComponent,
			"Helm":          helmComponent,
			"MPICH":         mpichComponent,
		},
		"All": map[string]ComponentAPI{
			"Docker":        dockerComponent,
			"NVidiaDocker":  nVidiaDockerComponent,
			"Kubernetes":    kubernetesComponent,
			"ElasticSearch": elasticSearchComponent,
			"Helm":          helmComponent,
			"MPICH":         mpichComponent,
		},
	}
}
