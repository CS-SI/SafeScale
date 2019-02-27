/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package cluster

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/CS-SI/SafeScale/iaas"
	"github.com/CS-SI/SafeScale/iaas/resources"
	"github.com/CS-SI/SafeScale/safescale/client"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/api"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/controller"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/flavors/boh"
	"github.com/CS-SI/SafeScale/safescale/server/cluster/flavors/swarm"
	"github.com/CS-SI/SafeScale/utils"
)

// Get returns the Cluster instance corresponding to the cluster named 'name'
// TODO: rename to Inspect ?
func Get(name string) (api.Cluster, error) {
	tenant, err := client.New().Tenant.Get(client.DefaultExecutionTimeout)
	if err != nil {
		return nil, err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return nil, err
	}

	m, err := controller.NewMetadata(svc)
	if err != nil {
		return nil, err
	}
	err = m.Read(name)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return nil, resources.ResourceNotFoundError("cluster", name)
		}
		return nil, fmt.Errorf("failed to get information about Cluster '%s': %s", name, err.Error())
	}
	controller := m.Get()
	err = setBlueprint(controller)
	if err != nil {
		return nil, err
	}
	return controller, nil
}

// Load ...
func Load(name string) (api.Cluster, error) {
	tenant, err := client.New().Tenant.Get(client.DefaultExecutionTimeout)
	if err != nil {
		return nil, err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return nil, err
	}

	m, err := controller.NewMetadata(svc)
	if err != nil {
		return nil, err
	}
	err = m.Read(name)
	if err != nil {
		if _, ok := err.(utils.ErrNotFound); ok {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get information about Cluster '%s': %s", name, err.Error())
	}
	controller := m.Get()
	err = setBlueprint(controller)
	if err != nil {
		return nil, err
	}
	return controller, nil
}

func setBlueprint(controller *controller.Controller) error {
	flavor := controller.GetIdentity().Flavor
	switch flavor {
	case Flavor.DCOS:
		// err := controller.Restore(dcos.Blueprint(controller))
		// if err != nil {
		// 	return err
		// }
	case Flavor.BOH:
		err := controller.Restore(boh.Blueprint(controller))
		if err != nil {
			return err
		}
	// case Flavor.OHPC:
	// 	err := controller.Restore(ohpc.Blueprint(controller))
	// 	if err != nil {
	// 		return err
	// 	}
	// case Flavor.K8S:
	// 	err := controller.Restore(k8s.Blueprint(controller))
	// 	if err != nil {
	// 		return err
	// 	}
	case Flavor.SWARM:
		err := controller.Restore(swarm.Blueprint(controller))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("cluster Flavor '%s' not yet implemented", flavor.String())
	}
	return nil
}

// Create creates a cluster following the parameters of the request
func Create(req controller.Request) (api.Cluster, error) {
	log.Debugf(">>> safescale.server.cluster.factory::Create()")
	defer log.Debugf("<<< safescale.cluster.factory::Create()")

	// Validates parameters
	if req.Name == "" {
		panic("req.Name is empty!")
	}
	if req.CIDR == "" {
		panic("req.CIDR is empty!")
	}

	log.Printf("Creating infrastructure for cluster '%s'", req.Name)

	tenant, err := client.New().Tenant.Get(client.DefaultExecutionTimeout)
	if err != nil {
		return nil, err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return nil, err
	}

	controller := controller.NewController(svc)
	req.Tenant = tenant.Name
	switch req.Flavor {
	case Flavor.BOH:
		err = controller.Create(req, boh.Blueprint(controller))
		if err != nil {
			return nil, err
		}
	// case Flavor.DCOS:
	// 	err = controller.Create(req, dcos.Blueprint(controller))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// case Flavor.K8S:
	// 	err = controller.Create(req, k8s.Blueprint(controller))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// case Flavor.OHPC:
	// 	err = controller.Create(req, ohpc.Blueprint(controller))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	case Flavor.SWARM:
		err = controller.Create(req, swarm.Blueprint(controller))
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("cluster Flavor '%s' not yet implemented", req.Flavor.String())
	}

	log.Printf("Cluster '%s' created and initialized successfully", req.Name)
	return controller, nil
}

// Delete deletes the infrastructure of the cluster named 'name'
func Delete(name string) error {
	instance, err := Get(name)
	if err != nil {
		return fmt.Errorf("failed to find a cluster named '%s': %s", name, err.Error())
	}

	// Deletes all the infrastructure built for the cluster
	return instance.Delete()
}

// List lists the clusters already created
func List() ([]api.Cluster, error) {
	tenant, err := client.New().Tenant.Get(client.DefaultExecutionTimeout)
	if err != nil {
		return nil, err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return nil, err
	}

	var clusterList []api.Cluster
	m, err := controller.NewMetadata(svc)
	if err != nil {
		return clusterList, err
	}
	err = m.Browse(func(controller *controller.Controller) error {
		clusterList = append(clusterList, controller)
		return nil
	})
	return clusterList, err
}

// // Sanitize ...
// func Sanitize(svc *providers.Service, name string) error {
// m, err := controller.NewMetadata(svc)
// if err != nil {
// return err
// }
// found, err := m.Read(name)
// if err != nil {
// return fmt.Errorf("failed to get information about Cluster '%s': %s", name, err.Error())
// }
// if !found {
// return fmt.Errorf("cluster '%s' not found", name)
// }
//
// controller := m.Get()
// switch controller.GetIdentity().Flavor {
// case Flavor.DCOS:
// return dcos.Sanitize(m)
// default:
// return fmt.Errorf("Sanitization of cluster Flavor '%s' not available", clusterCore.Flavor.String())
// }
// }
