/*
 * Copyright 2018-2020, CS Systemes d'Information, http://www.c-s.fr
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

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster/api"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/flavor"
	"github.com/CS-SI/SafeScale/lib/server/cluster/flavors/boh"
	"github.com/CS-SI/SafeScale/lib/server/cluster/flavors/dcos"
	"github.com/CS-SI/SafeScale/lib/server/cluster/flavors/k8s"
	"github.com/CS-SI/SafeScale/lib/server/cluster/flavors/swarm"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
)

// Load ...
func Load(task concurrency.Task, name string) (api.Cluster, error) {
	tenant, err := client.New().Tenant.Get(temporal.GetExecutionTimeout())
	if err != nil {
		return nil, err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return nil, err
	}

	m, err := control.NewMetadata(svc)
	if err != nil {
		return nil, err
	}
	err = m.Read(task, name)
	if err != nil {
		if _, ok := err.(scerr.ErrNotFound); ok {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get information about Cluster '%s': %s", name, err.Error())
	}
	controller, err := m.Get()
	if err != nil {
		return nil, err
	}
	err = setForeman(task, controller)
	if err != nil {
		return nil, err
	}
	return controller, nil
}

func setForeman(task concurrency.Task, controller *control.Controller) error {
	f := controller.GetIdentity(task).Flavor
	switch f {
	case flavor.DCOS:
		return controller.Restore(task, control.NewForeman(controller, dcos.Makers))
	case flavor.BOH:
		return controller.Restore(task, control.NewForeman(controller, boh.Makers))
	// case flavor.OHPC:
	// 	controller.Restore(task, control.NewForeman(controller, ohpc.Makers))
	case flavor.K8S:
		return controller.Restore(task, control.NewForeman(controller, k8s.Makers))
	case flavor.SWARM:
		return controller.Restore(task, control.NewForeman(controller, swarm.Makers))
	default:
		return scerr.NotImplementedError(fmt.Sprintf("cluster Flavor '%s' not yet implemented", f.String()))
	}
}

// Create creates a cluster following the parameters of the request
func Create(task concurrency.Task, req control.Request) (_ api.Cluster, err error) {
	tracer := concurrency.NewTracer(task, "", true).WithStopwatch().GoingIn()
	defer tracer.OnExitTrace()()
	defer scerr.OnExitLogError(tracer.TraceMessage(""), &err)()

	// Validates parameters
	if req.Name == "" {
		return nil, scerr.InvalidParameterError("req.Name", "cannot be empty!")
	}
	if req.CIDR == "" {
		return nil, scerr.InvalidParameterError("req.CIDR", "cannot be empty!")
	}

	log.Infof("Creating infrastructure for cluster '%s'", req.Name)

	tenant, err := client.New().Tenant.Get(temporal.GetExecutionTimeout())
	if err != nil {
		return nil, err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return nil, err
	}

	controller, err := control.NewController(svc)
	if err != nil {
		return nil, err
	}
	req.Tenant = tenant.Name
	switch req.Flavor {
	case flavor.BOH:
		err = controller.Create(task, req, control.NewForeman(controller, boh.Makers))
		if err != nil {
			return nil, err
		}
	case flavor.DCOS:
		err = controller.Create(task, req, control.NewForeman(controller, dcos.Makers))
		if err != nil {
			return nil, err
		}
	case flavor.K8S:
		err = controller.Create(task, req, control.NewForeman(controller, k8s.Makers))
		if err != nil {
			return nil, err
		}
	// case flavor.OHPC:
	// 	err = control.Create(task, req, control.NewForema(controller, ohpc.Makers))
	// 	if err != nil {
	// 		return nil, err
	// 	}
	case flavor.SWARM:
		err = controller.Create(task, req, control.NewForeman(controller, swarm.Makers))
		if err != nil {
			return nil, err
		}
	default:
		return nil, scerr.NotImplementedError(fmt.Sprintf("cluster Flavor '%s' not yet implemented", req.Flavor.String()))
	}

	log.Infof("Cluster '%s' created and initialized successfully", req.Name)
	return controller, nil
}

// Delete deletes the infrastructure of the cluster named 'name'
func Delete(task concurrency.Task, name string) error {
	instance, err := Load(task, name)
	if err != nil {
		return fmt.Errorf("failed to find a cluster named '%s': %s", name, err.Error())
	}

	// Deletes all the infrastructure built for the cluster
	return instance.Delete(task)
}

// List lists the clusters already created
func List() (clusterList []api.Cluster, err error) {
	tenant, err := client.New().Tenant.Get(temporal.GetExecutionTimeout())
	if err != nil {
		return nil, err
	}
	svc, err := iaas.UseService(tenant.Name)
	if err != nil {
		return nil, err
	}

	m, err := control.NewMetadata(svc)
	if err != nil {
		return clusterList, err
	}

	err = m.Browse(func(controller *control.Controller) error {
		if controller.Identity.OK() {
			clusterList = append(clusterList, controller)
		}

		return nil
	})

	return clusterList, err
}

// // Sanitize ...
// func Sanitize(svc *providers.Service, name string) error {
// m, err := control.NewMetadata(svc)
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
// switch control.GetIdentity().Flavor {
// case flavor.DCOS:
// return dcos.Sanitize(m)
// default:
// return fmt.Errorf("Sanitization of cluster Flavor '%s' not available", clusterCore.flavor.String())
// }
// }
