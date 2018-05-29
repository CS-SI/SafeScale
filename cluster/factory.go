package cluster
/*
* Copyright 2015-2018, CS Systemes d'Information, http://www.c-s.fr
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

import (
	"fmt"

	clusterapi "github.com/CS-SI/SafeScale/cluster/api"
	"github.com/CS-SI/SafeScale/cluster/api/Flavor"
	"github.com/CS-SI/SafeScale/cluster/dcos"
	"github.com/CS-SI/SafeScale/providers"
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
