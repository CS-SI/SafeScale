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

	clusterapi "github.com/SafeScale/perform/cluster/api"
	"github.com/SafeScale/perform/cluster/dcos"

	"github.com/SafeScale/providers"
)

//Factory instantiate cluster managers
type Factory struct {
	byTenants map[string]clusterapi.ClusterManagerAPI
}

//NewFactory creates a new service factory
func NewFactory() *Factory {
	tenantMap := make(map[string]clusterapi.ClusterManagerAPI)
	return &Factory{
		byTenants: tenantMap,
	}
}

//GetManager returns the ClusterManager for the flavor and tenant passed as parameters
// If the ClusterManager doesn't exist yet, build it
func (f *Factory) GetManager(tenant string) (clusterapi.ClusterManagerAPI, error) {
	var clusterManager clusterapi.ClusterManagerAPI
	if m, ok := f.byTenants[tenant]; ok {
		return m, nil
	}
	service, err := providers.GetService(tenant)
	if err != nil {
		return nil, fmt.Errorf("failed to get service for tenant '%s'", tenant)
	}
	clusterManager = &dcos.Manager{
		ClusterManager: clusterapi.ClusterManager{
			Service: service,
			Tenant:  tenant,
		},
	}

	// Create Object Storage Container
	err = service.CreateContainer(clusterapi.DeployContainerName)
	if err != nil {
		return nil, fmt.Errorf("failed to create Object Storage '%s': %s", clusterapi.DeployContainerName, err.Error())
	}
	f.byTenants[tenant] = clusterManager
	return clusterManager, nil
}
