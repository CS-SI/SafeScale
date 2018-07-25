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
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/CS-SI/SafeScale/perform/cluster"
	clusterapi "github.com/CS-SI/SafeScale/perform/cluster/api"
	"github.com/CS-SI/SafeScale/perform/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Flavor"

	cli "github.com/jawher/mow.cli"
)

// ClusterCmd command
func ClusterCmd(cmd *cli.Cmd) {
	cmd.Command("ls list", "List available Clusters on the current tenant", clusterList)
	cmd.Command("create", "Create cluster", clusterCreate)
	cmd.Command("delete rm destroy", "Delete a cluster", clusterDelete)
	cmd.Command("inspect show", "Inspect a cluster", clusterInspect)
	cmd.Command("stop", "Stop a cluster", clusterStop)
	cmd.Command("start", "Start a cluster", clusterStart)
	cmd.Command("state", "State of a cluster", clusterState)
	cmd.Command("expand grow", "Expand a cluster", clusterExpand)
	cmd.Command("shrink reduce", "Shrink a cluster", clusterShrink)
	cmd.Command("node", "Node management", NodeCmd)
	cmd.Command("command cmd", "Command execution", CommandCmd)
}

func clusterList(cmd *cli.Cmd) {
	cmd.Action = func() {
		list, err := cluster.List()
		if err != nil {
			fmt.Printf("Could not get cluster list: %v\n", err)
			return
		}
		jsoned, err := json.Marshal(list)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		var toFormat []interface{}
		err = json.Unmarshal(jsoned, &toFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		var formatted []interface{}
		for _, value := range toFormat {
			formatted = append(formatted, formatClusterConfig(value))
		}
		jsoned, err = json.Marshal(formatted)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		fmt.Println(string(jsoned))
	}
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

func clusterInspect(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME"

	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Invalid empty argument CLUSTERNAME")
			return
		}
		instance, err := cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("Could not inspect cluster '%s': %s\n", *clusterName, err.Error())
			return
		}
		if instance == nil {
			fmt.Printf("cluster '%s' not found.\n", *clusterName)
			return
		}

		err = outputClusterConfig(instance.GetConfig())
		if err != nil {
			fmt.Printf("%v\n", err)
		}
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

	jsoned, err = json.Marshal(formatted)
	if err != nil {
		return err
	}
	fmt.Println(string(jsoned))
	return nil
}

func clusterCreate(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME -F [-C] [-N] [-k]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	complexityStr := cmd.StringOpt("C complexity", "Normal", "Complexity of the cluster; can be DEV, NORMAL (default), VOLUME")
	cidr := cmd.StringOpt("N cidr", "192.168.0.0/24", "CIDR of the network (default: 192.168.0.0/24)")
	keep := cmd.BoolOpt("k keep-on-failure", false, "if set, don't delete resources on failure (default: false)")
	flavorStr := cmd.StringOpt("F flavor", "", "Flavor of Cluster; can be DCOS, BOH (Bunch Of Hosts)")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}
		instance, err := cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		if clusterInstance != nil {
			fmt.Printf("cluster '%s' already exists.\n", *clusterName)
			return
		}

		complexity, err := Complexity.FromString(*complexityStr)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		flavor := Flavor.Parse(*flavorStr)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		instance, err = cluster.Create(clusterapi.Request{
			Name:          *clusterName,
			Complexity:    complexity,
			CIDR:          *cidr,
			Flavor:        flavor,
			KeepOnFailure: *keep,
		})
		if err != nil {
			if instance != nil {
				instance.Delete()
			}
			fmt.Printf("failed to create cluster: %s", err.Error())
			return
		}

		jsoned, err := json.Marshal(instance.GetConfig())
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		var toFormat map[string]interface{}
		err = json.Unmarshal(jsoned, &toFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		formatted := formatClusterConfig(toFormat)
		delete(formatted, "PrivateNodeIDs")
		delete(formatted, "PublicNodeIDs")
		jsoned, err = json.Marshal(formatted)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		fmt.Println(string(jsoned))
	}
}

func clusterDelete(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME [-f]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	force := cmd.BoolOpt("f force", false, "Force deletion")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}

		instance, err := cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		if instance == nil {
			fmt.Printf("cluster '%s' not found\n", *clusterName)
			return
		}
		if !*force && !userConfirmed(fmt.Sprintf("Are you sure to delete Cluster '%s'", *clusterName)) {
			fmt.Println("Aborted.")
			return
		}
		err = cluster.Delete(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		fmt.Printf("Cluster '%s' deleted.\n", *clusterName)
	}
}

func clusterStop(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME"

	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}

		instance, err := cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		if instance == nil {
			fmt.Printf("Cluster '%s' not found.\n", *clusterName)
			return
		}
		err = instance.Stop()
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		fmt.Printf("Cluster '%s' stopped.\n", *clusterName)
	}
}

func clusterStart(cmd *cli.Cmd) {
	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}

		instance, err := cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		if instance == nil {
			fmt.Printf("Cluster '%s' not found.\n", *clusterName)
			return
		}
		err = instance.Start()
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		fmt.Printf("Cluster '%s' started.\n", *clusterName)
	}
}

func clusterState(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME"

	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}

		instance, err := cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("Could not inspect cluster '%s': %v\n", *clusterName, err)
			return
		}
		if instance == nil {
			fmt.Printf("cluster '%s' not found.\n", *clusterName)
			return
		}
		state, err := instance.GetState()
		out, _ := json.Marshal(map[string]string{"state": state.String()})
		fmt.Println(string(out))
	}
}

func clusterExpand(cmd *cli.Cmd) {
	//cmd.Spec = "CLUSTERNAME [-n] [-p] [-c] [-r] [-d] [-g]"
	cmd.Spec = "CLUSTERNAME [-n] [-p] [-c] [-r] [-d]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	count := cmd.IntOpt("n count", 1, "Number of nodes to create")
	public := cmd.BoolOpt("p public", false, "Attach public IP address to node (default: false)")
	cpu := cmd.IntOpt("c cpu", 2, "Number of CPU for the Host (default: 2)")
	ram := cmd.StringOpt("r ram", "7.0", "RAM for the host (default: 7 GB)")
	disk := cmd.IntOpt("d disk", 100, "System disk size for the host (default: 100 GB)")
	//gpu := cmd.BoolOpt("g gpu", false, "With GPU")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}
		ramF, err := strconv.ParseFloat(*ram, 32)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		finalCPU := int32(*cpu)
		finalDisk := int32(*disk)
		finalRAM := float32(ramF)
		err = createNodes(*clusterName, *public, *count, finalCPU, finalRAM, finalDisk)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
	}
}

func clusterShrink(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME [-n] [-p]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	count := cmd.IntOpt("n count", 1, "Number of node(s) to delete (default: 1)")
	public := cmd.BoolOpt("p public", false, "Delete a public node if set (default: false)")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}

		instance, err := cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v", err)
			return
		}
		if instance == nil {
			fmt.Printf("cluster '%s' not found.", *clusterName)
			return
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
		present := instance.CountNodes(*public)
		if *count > int(present) {
			fmt.Printf("can't delete %d %s node%s, the cluster contains only %d of them", *count, nodeTypeString, countS, present)
			return
		}

		msg := fmt.Sprintf("Are you sure to delete %d %s node%s from Cluster %s", *count, nodeTypeString, countS, *clusterName)
		if !userConfirmed(msg) {
			fmt.Println("Aborted.")
			return
		}

		fmt.Printf("Deleting %d %s node%s from Cluster '%s' (this may take a while)...\n", *count, nodeTypeString, countS, *clusterName)
		for i := 0; i < *count; i++ {
			err = instance.DeleteLastNode(*public)
			if err != nil {
				fmt.Printf("Failed to delete node #%d: %s", i+1, err.Error())
				return
			}
		}

		fmt.Printf("%d %s node%s successfully deleted from cluster '%s'.\n", *count, nodeTypeString, countS, *clusterName)
	}
}
