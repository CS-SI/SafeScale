package main
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
	"log"
	"runtime"

	"github.com/SafeScale/perform/cluster"
	clusterapi "github.com/SafeScale/perform/cluster/api"
	"github.com/SafeScale/perform/cluster/api/Complexity"
	"github.com/SafeScale/perform/cluster/api/Flavor"
	"github.com/SafeScale/perform/cluster/api/NodeType"

	pb "github.com/SafeScale/broker"
)

//Run runs the deployment
func Run() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	clusterName := "test-cluster"
	instance, err := cluster.Get(clusterName)
	if err != nil {
		fmt.Printf("Failed to load cluster '%s' parameters: %s\n", clusterName, err.Error())
		return
	}
	if instance == nil {
		log.Printf("Cluster '%s' not found, creating it (this will take a while)\n", clusterName)
		instance, err = cluster.Create(clusterapi.Request{
			Name:       clusterName,
			Complexity: Complexity.Dev,
			//Complexity: Complexity.Normal,
			//Complexity: Complexity.Volume,
			CIDR:   "192.168.0.0/28",
			Flavor: Flavor.DCOS,
		})
		if err != nil {
			fmt.Printf("Failed to create cluster: %s\n", err.Error())
			return
		}
	} else {
		fmt.Printf("Cluster '%s' already created.\n", clusterName)
	}

	state, err := instance.GetState()
	if err != nil {
		fmt.Println("Failed to get cluster state.")
		return
	}
	fmt.Printf("Cluster state: %s\n", state.String())

	// Creates a Private Agent Node
	_, err = instance.AddNode(NodeType.PrivateAgent, &pb.VMDefinition{
		CPUNumber: 2,
		RAM:       8.0,
		Disk:      60,
	})
	if err != nil {
		fmt.Printf("Failed to create Private Agent Node: %s\n", err.Error())
		return
	}
}

func main() {
	Run()
}
