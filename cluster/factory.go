package cluster

import (
	"fmt"

	clusterapi "github.com/SafeScale/cluster/api"
	"github.com/SafeScale/cluster/api/Flavor"
	"github.com/SafeScale/cluster/dcos"
	"github.com/SafeScale/providers"
)

//Factory instantiate cluster managers
type Factory struct {
	flavors map[Flavor.Enum][]clusterapi.ClusterManagerAPI
}

//NewFactory creates a new service factory
func NewFactory() *Factory {
	flavors := make(map[Flavor.Enum][]clusterapi.ClusterManagerAPI)
	return &Factory{
		flavors: flavors,
	}
}

//GetManager returns the ClusterManager for the flavor and tenant passed as parameters
// If the ClusterManager doesn't exist yet, build it
func (f *Factory) GetManager(flavor Flavor.Enum, tenant string, client *providers.Service) (clusterapi.ClusterManagerAPI, error) {
	var clusterManager clusterapi.ClusterManagerAPI
	found := false
	listManagers := f.flavors[flavor]
	for _, m := range listManagers {
		if m.GetTenantName() == tenant {
			found = true
			clusterManager = m
			break
		}
	}
	if !found {
		switch flavor {
		case Flavor.DCOS:
			clusterManager = &dcos.Manager{
				ClusterManager: clusterapi.ClusterManager{
					Flavor:  flavor,
					Service: client,
					Tenant:  tenant,
				},
			}

			// Create Object Storage Container
			err := client.CreateContainer(clusterapi.DeployContainerName)
			if err != nil {
				return nil, fmt.Errorf("failed to create Object Storage '%s': %s", clusterapi.DeployContainerName, err.Error())
			}
		}
		f.flavors[flavor] = append(f.flavors[flavor], clusterManager)
	}
	return clusterManager, nil
}
