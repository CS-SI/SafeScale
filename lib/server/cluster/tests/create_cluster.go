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

package main

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"runtime"

	"github.com/CS-SI/SafeScale/lib/server/iaas/resources"
	"github.com/CS-SI/SafeScale/lib/server/cluster"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
)

// Run runs the deployment
func Run() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	clusterName := "test-cluster"
	instance, err := cluster.Get(concurrency.RootTask(), clusterName)
	if err != nil {
		if _, ok := err.(resources.ErrResourceNotFound); ok {
			logrus.Warnf("Cluster '%s' not found, creating it (this will take a while)\n", clusterName)
			instance, err = cluster.Create(concurrency.RootTask(), control.Request{
				Name:       clusterName,
				Complexity: Complexity.Small,
				//Complexity: Complexity.Normal,
				//Complexity: Complexity.Large,
				CIDR:   "192.168.0.0/28",
				Flavor: Flavor.DCOS,
			})
			if err != nil {
				fmt.Printf("Failed to create cluster: %s\n", err.Error())
				return
			}
		} else {
			fmt.Printf("Failed to load cluster '%s' parameters: %s\n", clusterName, err.Error())
			return
		}
	}

	state, err := instance.GetState(concurrency.RootTask())
	if err != nil {
		fmt.Println("Failed to get cluster state.")
		return
	}
	fmt.Printf("Cluster state: %s\n", state.String())

	// Creates a Private Agent Node
	_, err = instance.AddNode(concurrency.RootTask(), false, &resources.HostDefinition{
		Cores:    2,
		RAMSize:  7.0,
		DiskSize: 60,
	})
	if err != nil {
		fmt.Printf("Failed to create Private Agent Node: %s\n", err.Error())
		return
	}
}

func main() {
	Run()
}
