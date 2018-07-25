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

package cmd

import (
	"fmt"

	"github.com/CS-SI/SafeScale/perform/cluster"
	clusterapi "github.com/CS-SI/SafeScale/perform/cluster/api"

	cli "github.com/jawher/mow.cli"
)

var (
	clusterName     *string
	clusterInstance clusterapi.ClusterAPI
)

// CommandCmd command
func CommandCmd(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME"
	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Command("dcos", "call dcos command on cluster", commandDcos)
	cmd.Command("kubectl", "call kubectl command on cluster", commandKubectl)
	cmd.Command("marathon", "call marathon command on cluster", commandMarathon)

	cmd.Before = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory option --cluster,-c <cluster name>")
			//cli.ShowSubcommandHelp(c)
			return
		}
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("failed to get cluster '%s' information: %s\n", *clusterName, err.Error())
			return
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found\n", *clusterName)
			return
		}
	}
}

func commandDcos(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		fmt.Println("not yet implemented")
	}
}

func commandKubectl(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		fmt.Println("not yet implemented")
	}
}

func commandMarathon(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		fmt.Println("not yet implemented")
	}
}
