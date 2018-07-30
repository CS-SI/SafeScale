package install

import (
	"fmt"

	installapi "github.com/CS-SI/SafeScale/deploy/install/api"
)

var availables map[string]map[string]ComponentAPI

var (
	kubernetesComponent = &installapi.Component{
		Name: "Kubernetes",
		Installers: []installapi.InstallerAPI{
			installapi.NewDCOSPackageInstaller("kubernetes"),
			installapi.NewScriptInstaller("kubernetes"),
		},
	}

	nexusComponent = &installapi.Component{
		Name: "Nexus",
		Installers: []installapi.InstallerAPI{
			installapi.NewScriptInstaller("nexus"),
		},
	}

	elasticSearchComponent = &Component{
		Name: "ElasticSearch",
		Installers: []installapi.InstallerAPI{
			installapi.NewDCOSPackageInstaller("elastic"),
			installapi.NewScriptInstaller("elasticsearch"),
		},
	}

	helmComponent = &Component{
		Name: "Helm",
		Installers: []installapi.InstallerAPI{
			installapi.NewScriptInstaller("helm"),
		},
	}

	mpichComponent = &Component{
		Name: "MPICH",
		Installers: []installapi.InstallerAPI{
			installapi.NewScriptInstaller("mpich"),
		},
	}
)

func init() {
	availables = map[string]map[string]installapi.ComponentAPI{
		"DCOS": map[string]installapi.ComponentAPI{
			"Kubernetes":    kubernetesService,
			"ElasticSearch": elasticSearchService,
			"Helm":          helmService,
		},
		"Helm": map[string]installapi.ComponentAPI{
			"ElasticSearch": elasticSearchService,
		},
		"Script": map[string]installapi.ComponentAPI{
			"Docker":        dockerComponent,
			"nVidiaDocker":  nVidiaDockerComponent,
			"Kubernetes":    kubernetesComponent,
			"ElasticSearch": elasticSearchService,
			"Helm":          helmService,
			"MPICH":         mpichService,
		},
		"All": map[string]installapi.ComponentAPI{
			"Docker":        dockerComponent,
			"nVidiaDocker":  nVidiaDockerComponent,
			"Kubernetes":    kubernetesComponent,
			"ElasticSearch": elasticSearchComponent,
			"Helm":          helmComponent,
			"MPICH":         mpichComponent,
		},
	}
}

// ListAvailables returns an array of availables components with the useable installers
func ListAvailables() []string {
	var output []string
	for k, v := range availables["all"] {
		line := k
		installers := v.Installers()
		if len > 0 {
			line += " ["
			for n, i := range installers {
				if n > 0 {
					line += ", "
				}
				line += i.GetName()
			}
			line += "]"
		}
		output = append(output, fmt.Sprintf("%s"))
	}
	return output
}
