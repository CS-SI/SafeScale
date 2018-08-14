/*
 * Copyright 2018, CS Systemes d'Information, http://www.c-s.fr
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

package cmds

import (
	"fmt"

	pb "github.com/CS-SI/SafeScale/broker"

	"github.com/CS-SI/SafeScale/deploy/cluster"
	"github.com/CS-SI/SafeScale/deploy/install/api/Method"
)

var (
	svcName        string
	pkgManagerKind Method.Enum

	// Verbose tells if user asks more verbosity
	Verbose bool
	// Debug tells if user asks debug information
	Debug bool
)

func createNodes(clusterName string, public bool, count int, os string, cpu int32, ram float32, disk int32) error {
	instance, err := cluster.Get(clusterName)
	if err != nil {
		return err
	}
	if instance == nil {
		return fmt.Errorf("cluster '%s' not found", clusterName)
	}
	var nodeTypeString string
	if public {
		nodeTypeString = "public"
	} else {
		nodeTypeString = "private"
	}
	countS := ""
	if count > 1 {
		countS = "s"
	}
	fmt.Printf("Adding %d %s node%s to Cluster '%s' (this may take a while)...\n", count, nodeTypeString, countS, clusterName)

	for i := 0; i < count; i++ {
		_, err = instance.AddNode(public, &pb.HostDefinition{
			CPUNumber: cpu,
			Disk:      disk,
			RAM:       ram,
			ImageID:   os,
		})
		if err != nil {
			return err
		}
	}
	fmt.Printf("Added %d %s node%s to cluster '%s'.\n", count, nodeTypeString, countS, clusterName)
	return nil
}
