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
	"runtime"

	"github.com/CS-SI/SafeScale/lib/utils/scerr"

	"github.com/sirupsen/logrus"

	pb "github.com/CS-SI/SafeScale/lib"
	"github.com/CS-SI/SafeScale/lib/server/cluster"
	"github.com/CS-SI/SafeScale/lib/server/cluster/control"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/complexity"
	"github.com/CS-SI/SafeScale/lib/server/cluster/enums/flavor"
	"github.com/CS-SI/SafeScale/lib/utils/concurrency"
)

// Run runs the deployment
func Run() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	clusterName := "test-cluster"
	instance, err := cluster.Load(concurrency.RootTask(), clusterName)

	if _, ok := err.(scerr.ErrNotFound); ok {
		logrus.Warnf("Cluster '%s' not found, creating it (this will take a while)\n", clusterName)
		cinstance, cerr := cluster.Create(concurrency.RootTask(), control.Request{
			Name:       clusterName,
			Complexity: complexity.Small,
			//Complexity: complexity.Normal,
			//Complexity: complexity.Large,
			CIDR:   "192.168.0.0/28",
			Flavor: flavor.DCOS,
		})
		if cerr != nil {
			fmt.Printf("failed to create cluster: %s\n", cerr.Error())
			return
		}
		instance = cinstance
	} else if err != nil {
		fmt.Printf("failed to load cluster '%s' parameters: %s\n", clusterName, err.Error())
		return
	}

	state, err := instance.GetState(concurrency.RootTask())
	if err != nil {
		fmt.Println("failed to get cluster state.")
		return
	}
	fmt.Printf("Cluster state: %s\n", state.String())

	// Creates a Private Agent Node
	_, err = instance.AddNode(concurrency.RootTask(), &pb.HostDefinition{
		Sizing: &pb.HostSizing{
			MinCpuCount: 2,
			MaxCpuCount: 4,
			MinRamSize:  7.0,
			MaxRamSize:  16.0,
			MinDiskSize: 60,
		},
	})
	if err != nil {
		fmt.Printf("failed to create Private Agent Node: %s\n", err.Error())
		return
	}
}

func main() {
	Run()
}
