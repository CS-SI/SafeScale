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

	"github.com/CS-SI/SafeScale/deploy/cluster"

	cli "github.com/jawher/mow.cli"
)

// DeployCmd command
func DeployCmd(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME"

	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Command("package pkg", "Deploy an operating system package on all nodes", deployPackageCmd)
	cmd.Command("service svc", "Deploy a service on the cluster", deployServiceCmd)
	cmd.Command("application app", "Deploy an application on the cluster", deployApplicationCmd)

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

// deployPackageCmd ...
func deployPackageCmd(cmd *cli.Cmd) {
	cmd.Spec = "-k"

	pkgManagerKind = cmd.StringOpt("kind k", "", "Kind of package manager; can be apt, yum, dnf")

	cmd.Command("check c", "Check if a package is installed on cluster nodes", deployPackageCheckCmd)

	cmd.Before = func() {
		if *pkgManagerKind == "" {
			fmt.Println("Invalid empty option --kind,-k")
			return
		}
	}
}

// deployPackageCheckCmd
func deployPackageCheckCmd(cmd *cli.Cmd) {
	cmd.Spec = "PKGNAME [-t]"

	pkgname := cmd.StringArg("PKGNAME", "", "Name of the package")

	cmd.Action = func() {
		if *pkgname == "" {
			fmt.Println("Invalid empty argument PKGNAME")
			return
		}
		fmt.Println("deployPackageCmd not yet implemented")
	}
}

// deployServiceCmd ...
func deployServiceCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("deployServiceCmd not yet implemented")
	}
}

func deployApplicationCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("deployApplicationCmd not yet implemented")
	}
}
