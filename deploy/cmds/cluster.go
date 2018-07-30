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
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/CS-SI/SafeScale/cluster"
	clusterapi "github.com/CS-SI/SafeScale/cluster/api"
	"github.com/CS-SI/SafeScale/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/cluster/api/Flavor"
	"github.com/CS-SI/SafeScale/deploy/cmds/ErrorCode"

	"github.com/CS-SI/SafeScale/utils"

	cli "github.com/jawher/mow.cli"
)

var (
	clusterName     *string
	clusterInstance clusterapi.ClusterAPI
)

// ClusterCmd command
func ClusterCmd(cmd *cli.Cmd) {
	//cmd.Spec = "CLUSTERNAME"

	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Command("ls list", "List available Clusters on the current tenant", func(cmd *cli.Cmd) {})
	cmd.Command("create", "Create cluster", clusterCreateCmd)
	cmd.Command("delete rm destroy", "Delete a cluster", clusterDeleteCmd)
	cmd.Command("inspect show", "Inspect a cluster", clusterInspectCmd)
	cmd.Command("stop", "Stop a cluster", clusterStopCmd)
	cmd.Command("start", "Start a cluster", clusterStartCmd)
	cmd.Command("state", "State of a cluster", clusterStateCmd)
	cmd.Command("expand grow", "Expand a cluster", clusterExpandCmd)
	cmd.Command("shrink reduce", "Shrink a cluster", clusterShrinkCmd)
	//cmd.Command("node", "Node management", NodeCmd)
	cmd.Command("command cmd", "Administrative command execution", clusterCommandCmd)
	cmd.Command("package pkg", "Install an OS package on all nodes of the same family (based on package manager)", clusterPackageCmd)
	cmd.Command("service svc", "Install a service (chosen from a predefined list) on the cluster", clusterServiceCmd)
	cmd.Command("run", "Install an application on the cluster", clusterRunCmd)

	cmd.Before = func() {
		if *clusterName == "list" || *clusterName == "ls" {
			clusterList()
		} else if *clusterName == "" {
			fmt.Println("Invalid empy argument CLUSTERNAME")
			cli.Exit(1)
		}
	}
}

func clusterList() {
	list, err := cluster.List()
	if err != nil {
		fmt.Printf("Could not get cluster list: %v\n", err)
		cli.Exit(int(ErrorCode.NotFound))
	}
	jsoned, err := json.Marshal(list)
	if err != nil {
		fmt.Printf("%v\n", err)
		cli.Exit(int(ErrorCode.Run))
	}
	var toFormat []interface{}
	err = json.Unmarshal(jsoned, &toFormat)
	if err != nil {
		fmt.Printf("%v\n", err)
		cli.Exit(int(ErrorCode.Run))
	}
	var formatted []interface{}
	for _, value := range toFormat {
		formatted = append(formatted, formatClusterConfig(value))
	}
	jsoned, err = json.Marshal(formatted)
	if err != nil {
		fmt.Printf("%v\n", err)
		cli.Exit(int(ErrorCode.Run))
	}
	fmt.Println(string(jsoned))
	cli.Exit(int(ErrorCode.OK))
}

func formatClusterConfig(value interface{}) map[string]interface{} {
	item := value.(map[string]interface{})

	e := Flavor.Enum(int(item["Flavor"].(float64)))
	item["FlavorLabel"] = e.String()

	c := Complexity.Enum(int(item["Complexity"].(float64)))
	item["ComplexityLabel"] = c.String()

	s := ClusterState.Enum(int(item["State"].(float64)))
	item["StateLabel"] = s.String()

	delete(item, "PrivateNodeIDs")
	delete(item, "PublicNodeIDs")

	return item
}

func clusterInspectCmd(cmd *cli.Cmd) {
	//cmd.Spec = "CLUSTERNAME"

	//clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid argument CLUSTERNAME")
			cli.Exit(int(ErrorCode.InvalidArgument))
		}
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("Could not inspect cluster '%s': %s\n", *clusterName, err.Error())
			cli.Exit(int(ErrorCode.Run))
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found.\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}
		err = outputClusterConfig(clusterInstance.GetConfig())
		if err != nil {
			fmt.Printf("%v\n", err)
		}
		cli.Exit(int(ErrorCode.OK))
	}
}

func outputClusterConfig(result interface{}) error {
	jsoned, err := json.Marshal(result)
	if err != nil {
		return err
	}

	var toFormat map[string]interface{}
	err = json.Unmarshal(jsoned, &toFormat)
	if err != nil {
		return err
	}

	formatted := formatClusterConfig(toFormat)
	delete(formatted, "AdditionalInfo")
	jsoned, err = json.Marshal(formatted)
	if err != nil {
		return err
	}
	fmt.Println(string(jsoned))
	return nil
}

func clusterCreateCmd(cmd *cli.Cmd) {
	cmd.Spec = "-F -N [-C][-k]"

	complexityStr := cmd.StringOpt("C complexity", "Normal", "Complexity of the cluster; can be DEV, NORMAL (default), VOLUME")
	cidr := cmd.StringOpt("N cidr", "192.168.0.0/24", "CIDR of the network (default: 192.168.0.0/24)")
	keep := cmd.BoolOpt("k keep-on-failure", false, "if set, don't delete resources on failure (default: false)")
	flavorStr := cmd.StringOpt("F flavor", "", "Flavor of Cluster; can be DCOS, BOH (Bunch Of Hosts)")

	cmd.Action = func() {
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.Run))
		}
		if clusterInstance != nil {
			fmt.Printf("cluster '%s' already exists.\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}

		complexity, err := Complexity.FromString(*complexityStr)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.InvalidOption))
		}
		flavor := Flavor.Parse(*flavorStr)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.InvalidOption))
		}
		clusterInstance, err = cluster.Create(clusterapi.Request{
			Name:          *clusterName,
			Complexity:    complexity,
			CIDR:          *cidr,
			Flavor:        flavor,
			KeepOnFailure: *keep,
		})
		if err != nil {
			if clusterInstance != nil {
				clusterInstance.Delete()
			}
			fmt.Printf("failed to create cluster: %s", err.Error())
			cli.Exit(int(ErrorCode.Run))
		}

		jsoned, err := json.Marshal(clusterInstance.GetConfig())
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.Run))
		}
		var toFormat map[string]interface{}
		err = json.Unmarshal(jsoned, &toFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.Run))
		}
		formatted := formatClusterConfig(toFormat)
		delete(formatted, "PrivateNodeIDs")
		delete(formatted, "PublicNodeIDs")
		jsoned, err = json.Marshal(formatted)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.Run))
		}
		fmt.Println(string(jsoned))
		cli.Exit(int(ErrorCode.OK))
	}
}

func clusterDeleteCmd(cmd *cli.Cmd) {
	cmd.Spec = "[-f]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	force := cmd.BoolOpt("f force", false, "Force deletion")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			cli.Exit(int(ErrorCode.InvalidArgument))
		}
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.RPC))
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}
		if !*force && !utils.UserConfirmed(fmt.Sprintf("Are you sure to delete Cluster '%s'", *clusterName)) {
			fmt.Println("Aborted.")
			cli.Exit(0)
		}
		err = cluster.Delete(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.RPC))
		}

		fmt.Printf("Cluster '%s' deleted.\n", *clusterName)
		cli.Exit(int(ErrorCode.OK))
	}
}

func clusterStopCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.RPC))
		}
		if clusterInstance == nil {
			fmt.Printf("Cluster '%s' not found.\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}
		err = clusterInstance.Stop()
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.RPC))
		}
		fmt.Printf("Cluster '%s' stopped.\n", *clusterName)
		cli.Exit(int(ErrorCode.OK))
	}
}

func clusterStartCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.InvalidArgument))
		}
		if clusterInstance == nil {
			fmt.Printf("Cluster '%s' not found.\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}
		err = clusterInstance.Start()
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.RPC))
		}

		fmt.Printf("Cluster '%s' started.\n", *clusterName)
		cli.Exit(int(ErrorCode.OK))
	}
}

func clusterStateCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		var err error
		clusterInstance, err := cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("Could not inspect cluster '%s': %v\n", *clusterName, err)
			cli.Exit(int(ErrorCode.RPC))
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found.\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}
		state, err := clusterInstance.GetState()
		out, _ := json.Marshal(map[string]interface{}{
			"Name":       *clusterName,
			"State":      state,
			"StateLabel": state.String(),
		})
		fmt.Println(string(out))
		cli.Exit(int(ErrorCode.OK))
	}
}

func clusterExpandCmd(cmd *cli.Cmd) {
	//cmd.Spec = "[-n] [-p] [-c] [-r] [-d] [-g]"
	cmd.Spec = "[-n][-p][-c][-r][-d]"

	count := cmd.IntOpt("n count", 1, "Number of nodes to create")
	public := cmd.BoolOpt("p public", false, "Attach public IP address to node (default: false)")
	cpu := cmd.IntOpt("c cpu", 2, "Number of CPU for the Host (default: 2)")
	ram := cmd.StringOpt("r ram", "7.0", "RAM for the host (default: 7 GB)")
	disk := cmd.IntOpt("d disk", 100, "System disk size for the host (default: 100 GB)")
	//gpu := cmd.BoolOpt("g gpu", false, "With GPU")

	cmd.Action = func() {
		ramF, err := strconv.ParseFloat(*ram, 32)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.InvalidOption))
		}

		finalCPU := int32(*cpu)
		finalDisk := int32(*disk)
		finalRAM := float32(ramF)
		err = createNodes(*clusterName, *public, *count, finalCPU, finalRAM, finalDisk)
		if err != nil {
			fmt.Printf("%v\n", err)
			cli.Exit(int(ErrorCode.RPC))
		}
		cli.Exit(int(ErrorCode.OK))
	}
}

func clusterShrinkCmd(cmd *cli.Cmd) {
	cmd.Spec = "[-n][-p]"

	count := cmd.IntOpt("n count", 1, "Number of node(s) to delete (default: 1)")
	public := cmd.BoolOpt("p public", false, "Delete a public node if set (default: false)")

	cmd.Action = func() {
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v", err)
			cli.Exit(int(ErrorCode.RPC))
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found.", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}

		var nodeTypeString string
		if *public {
			nodeTypeString = "public"
		} else {
			nodeTypeString = "private"
		}
		var countS string
		if *count > 1 {
			countS = "s"
		}
		present := clusterInstance.CountNodes(*public)
		if *count > int(present) {
			fmt.Printf("can't delete %d %s node%s, the cluster contains only %d of them", *count, nodeTypeString, countS, present)
			cli.Exit(int(ErrorCode.InvalidOption))
		}

		msg := fmt.Sprintf("Are you sure to delete %d %s node%s from Cluster %s", *count, nodeTypeString, countS, *clusterName)
		if !utils.UserConfirmed(msg) {
			fmt.Println("Aborted.")
			cli.Exit(int(ErrorCode.OK))
		}

		fmt.Printf("Deleting %d %s node%s from Cluster '%s' (this may take a while)...\n", *count, nodeTypeString, countS, *clusterName)
		for i := 0; i < *count; i++ {
			err = clusterInstance.DeleteLastNode(*public)
			if err != nil {
				fmt.Printf("Failed to delete node #%d: %s", i+1, err.Error())
				cli.Exit(int(ErrorCode.RPC))
			}
		}

		fmt.Printf("%d %s node%s successfully deleted from cluster '%s'.\n", *count, nodeTypeString, countS, *clusterName)
		cli.Exit(int(ErrorCode.OK))
	}
}

// clusterPackageCmd ...
func clusterPackageCmd(cmd *cli.Cmd) {
	cmd.Spec = "-k"

	pkgManagerKind = cmd.StringOpt("kind k", "", "Kind of package manager; can be apt, yum, dnf")

	cmd.Command("check c", "Check if a package is installed on cluster nodes", clusterPackageCheckCmd)

	cmd.Before = func() {
		if *pkgManagerKind == "" {
			fmt.Println("Invalid empty option --kind,-k")
			//cli.ShowSubcommandHelp(c)
			cli.Exit(int(ErrorCode.InvalidOption))
		}
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("failed to get cluster '%s' information: %s\n", *clusterName, err.Error())
			cli.Exit(int(ErrorCode.RPC))
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}
		cli.Exit(int(ErrorCode.OK))
	}
}

// clusterPackagCheckCmd
func clusterPackageCheckCmd(cmd *cli.Cmd) {
	cmd.Spec = "PKGNAME [-t]"

	pkgname := cmd.StringArg("PKGNAME", "", "Name of the package")

	cmd.Action = func() {
		if *pkgname == "" {
			fmt.Println("Invalid empty argument PKGNAME")
			cli.Exit(int(ErrorCode.InvalidArgument))
		}
		fmt.Println("deployPackageCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

// clusterServiceCmd ...
func clusterServiceCmd(cmd *cli.Cmd) {
	cmd.Spec = "SVCNAME"

	clusterServiceName = cmd.StringArg("SVCNAME", "", "Name of the service")

	cmd.Command("available avail", "Lists available services", clusterServiceAvailableCmd)
	cmd.Command("check", "Checks if the state of the service (installed, running, ...)", clusterServiceCheckCmd)
	cmd.Command("install", "Installs the service on the cluster", clusterServiceInstallCmd)
	cmd.Command("delete rm destroy", "Removes a service from the cluster", clusterServiceDeleteCmd)
	cmd.Command("stop", "Stops a service on the cluster", clusterServiceStopCmd)
	cmd.Command("start", "Starts a service on the cluster", clusterServiceStartCmd)

	cmd.Before = func() {
		if *clusterName == "" {
			fmt.Println("Invalid empty argument CLUSTERNAME")
			//cli.ShowSubcommandHelp(c)
			cli.Exit(int(ErrorCode.InvalidArgument))
		}
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("failed to get cluster '%s' information: %s\n", *clusterName, err.Error())
			cli.Exit(int(ErrorCode.RPC))
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}
		cli.Exit(int(ErrorCode.OK))
	}
}

func clusterServiceAvailableCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("clusterServiceAvailableCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterServiceCheckCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("clusterServiceCheckCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterServiceInstallCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("clusterServiceInstallCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterServiceDeleteCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("clusterServiceDeleteCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterServiceStopCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("clusterServiceStopCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterServiceStartCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("clusterServiceStartCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

// clusterCommandCmd command
func clusterCommandCmd(cmd *cli.Cmd) {
	cmd.Command("dcos", "call dcos command on cluster", clusterCommandDcosCmd)
	cmd.Command("kubectl", "call kubectl command on cluster", clusterCommandKubectlCmd)
	cmd.Command("marathon", "call marathon command on cluster", clusterCommandMarathonCmd)

	cmd.Before = func() {
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("failed to get cluster '%s' information: %s\n", *clusterName, err.Error())
			cli.Exit(int(ErrorCode.RPC))
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found\n", *clusterName)
			cli.Exit(int(ErrorCode.NotFound))
		}
		fmt.Println("not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterCommandDcosCmd(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		config := clusterInstance.GetConfig()
		if config.Flavor != Flavor.DCOS {
			fmt.Printf("Can't call dcos on this cluster, its flavor isn't DCOS (%s).\n", config.Flavor.String())
			cli.Exit(int(ErrorCode.NotApplicable))
		}
		fmt.Println("clusterCommandDcosCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterCommandKubectlCmd(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		fmt.Println("clusterCommandKubectlCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterCommandMarathonCmd(cmd *cli.Cmd) {
	cmd.Spec = "-- [ARG...]"

	cmd.Action = func() {
		fmt.Println("clusterCommandMarathonCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}

func clusterRunCmd(cmd *cli.Cmd) {
	cmd.Action = func() {
		fmt.Println("clusterRunCmd not yet implemented")
		cli.Exit(int(ErrorCode.NotImplemented))
	}
}
