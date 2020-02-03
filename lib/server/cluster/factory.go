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

	"github.com/CS-SI/SafeScale/lib/client"
	"github.com/CS-SI/SafeScale/lib/server/cluster/api"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	clusterpropsv1 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v1"
	clusterpropsv2 "github.com/CS-SI/SafeScale/lib/server/cluster/control/properties/v2"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/flavor"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/property"
	"github.com/CS-SI/SafeScale/lib/server/cluster/flavors/boh"
	"github.com/CS-SI/SafeScale/lib/server/cluster/flavors/k8s"
	"github.com/CS-SI/SafeScale/lib/server/iaas"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
	"github.com/CS-SI/SafeScale/lib/utils/data"
	"github.com/CS-SI/SafeScale/lib/utils/scerr"
	"github.com/CS-SI/SafeScale/lib/utils/temporal"
	"github.com/sirupsen/logrus"
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
		if _, ok := err.(*scerr.ErrNotFound); ok {
			return nil, err
		}
		return nil, fmt.Errorf("failed to get metadata for cluster '%s': %s", name, err.Error())
	}
	controller, err := m.Get()
	if err != nil {
		return nil, err
	}
	err = setForeman(task, controller)
	if err != nil {
		return nil, err
	}

	// From here, we can deal with legacy
	err = upgradePropertyNodesIfNeeded(task, controller)
	if err != nil {
		return nil, err
	}

	return controller, nil
}

func setForeman(task concurrency.Task, controller *control.Controller) error {
	f := controller.GetIdentity(task).Flavor
	switch f {
	case flavor.BOH:
		return controller.Restore(task, control.NewForeman(controller, boh.Makers))
	case flavor.K8S:
		return controller.Restore(task, control.NewForeman(controller, k8s.Makers))
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

	logrus.Infof("Creating infrastructure for cluster '%s'", req.Name)

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
	case flavor.K8S:
		err = controller.Create(task, req, control.NewForeman(controller, k8s.Makers))
		if err != nil {
			return nil, err
		}
	default:
		return nil, scerr.NotImplementedError(fmt.Sprintf("cluster Flavor '%s' not yet implemented", req.Flavor.String()))
	}

	logrus.Infof("Cluster '%s' created and initialized successfully", req.Name)
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
// case Flavor.DCOS:
// return dcos.Sanitize(m)
// default:
// return fmt.Errorf("Sanitization of cluster Flavor '%s' not available", clusterCore.Flavor.String())
// }
// }

// upgradePropertyNodesIfNeeded upgrade current Nodes to last Nodes (currently NodesV2)
func upgradePropertyNodesIfNeeded(t concurrency.Task, c *control.Controller) error {
	properties := c.GetProperties(t)
	if !properties.Lookup(property.NodesV2) {
		// Replace NodesV1 by NodesV2 properties
		return c.UpdateMetadata(t, func() error {
			return properties.LockForWrite(property.NodesV2).ThenUse(func(clonable data.Clonable) error {
				nodesV2 := clonable.(*clusterpropsv2.Nodes)

				return properties.LockForWrite(property.NodesV1).ThenUse(func(clonable data.Clonable) error {
					nodesV1, ok := clonable.(*clusterpropsv1.Nodes)
					if !ok {
						return fmt.Errorf("invalid metadata")
					}

					for _, v := range nodesV1.Masters {
						nodesV2.GlobalLastIndex++

						node := &clusterpropsv2.Node{
							ID:          v.ID,
							NumericalID: nodesV2.GlobalLastIndex,
							Name:        v.Name,
							PrivateIP:   v.PrivateIP,
							PublicIP:    v.PublicIP,
						}
						nodesV2.Masters = append(nodesV2.Masters, node)
					}
					for _, v := range nodesV1.PrivateNodes {
						nodesV2.GlobalLastIndex++

						node := &clusterpropsv2.Node{
							ID:          v.ID,
							NumericalID: nodesV2.GlobalLastIndex,
							Name:        v.Name,
							PrivateIP:   v.PrivateIP,
							PublicIP:    v.PublicIP,
						}
						nodesV2.PrivateNodes = append(nodesV2.PrivateNodes, node)
					}
					nodesV2.MasterLastIndex = nodesV1.MasterLastIndex
					nodesV2.PrivateLastIndex = nodesV1.PrivateLastIndex

					return nil
				})
			})
		})
	}
	return nil
}
