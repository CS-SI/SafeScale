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

	"github.com/CS-SI/SafeScale/utils/brokeruse"

	"github.com/CS-SI/SafeScale/perform/cluster"

	cli "github.com/jawher/mow.cli"
)

// NodeCmd configures arguments for command "perform node"
func NodeCmd(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME"

	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Command("list ls", "List nodes", nodeList)
	cmd.Command("create", "Create a new node", nodeCreate)
	cmd.Command("inspect show", "Inspect a node", nodeInspect)
	cmd.Command("stop", "Stop a node", nodeStop)
	cmd.Command("start", "Start a node", nodeStart)
	cmd.Command("state", "Get state of a node", nodeState)
	cmd.Command("delete rm destroy", "Delete a specific node from cluster", nodeDelete)

	cmd.Before = func() {
		if *clusterName == "" {
			fmt.Println("Invalid empty argument CLUSTERNAME")
			//cli.ShowSubcommandHelp(c)
			return
		}
		var err error
		clusterInstance, err = cluster.Get(*clusterName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		if clusterInstance == nil {
			fmt.Printf("cluster '%s' not found.", *clusterName)
			return
		}
	}
}

func nodeCreate(cmd *cli.Cmd) {
	cmd.Spec = "NODENAME [-n] [-p] [-C] [-R] [-D] [--gpu]"

	nodeName := cmd.StringArg("NODENAME", "", "Name of the node")
	count := cmd.IntOpt("count n", 1, "How many nodes to create")
	public := cmd.BoolOpt("public p", false, "Attach public IP address to node")
	cpu := cmd.IntOpt("cpu C", 2, "Number of CPU for the host")
	ram := cmd.StringOpt("ram R", "7.0", "RAM for the host")
	disk := cmd.IntOpt("disk D", 100, "Disk space for the host")
	//gpu := cmd.BoolOpt("gpu", false, "With GPU")

	cmd.Action = func() {
		if *nodeName == "" {
			fmt.Printf("Invalid empty argument NODENAME")
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
		}
	}
}

func nodeDelete(cmd *cli.Cmd) {
	cmd.Spec = "NODENAME"

	nodeName := cmd.StringArg("NODENAME", "", "Name or ID of the node to delete")

	cmd.Action = func() {
		if *nodeName == "" {
			fmt.Printf("Invalid empty argument NODENAME")
			return
		}

		found := clusterInstance.SearchNode(*nodeName, true)
		if !found {
			found = clusterInstance.SearchNode(*nodeName, false)
		}
		if !found {
			fmt.Printf("node '%s' isn't a node of the cluster '%s'\n", *nodeName, *clusterName)
			return
		}
		host, err := brokeruse.GetVM(*nodeName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}

		msg := fmt.Sprintf("Are you sure to delete Cluster Node identified by '%s' in Cluster '%s'", *nodeName, *clusterName)
		if !userConfirmed(msg) {
			fmt.Println("Aborted.")
			return
		}
		err = clusterInstance.DeleteSpecificNode(*nodeName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		fmt.Printf("Node '%s' of cluster '%s' deleted.", host.Name, *clusterName)
	}
}

func nodeList(cmd *cli.Cmd) {
	public := cmd.BoolOpt("public p", false, "If used, lists Public nodes; otherwise lists private nodes")

	cmd.Action = func() {
		list := clusterInstance.ListNodes(*public)
		out, _ := json.Marshal(list)
		fmt.Println(string(out))
	}
}

func nodeInspect(cmd *cli.Cmd) {
	cmd.Spec = "NODENAME"

	nodeName := cmd.StringArg("NODENAME", "", "Name of the node")

	cmd.Action = func() {
		node, err := clusterInstance.GetNode(*nodeName)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		byteOutput, err := json.Marshal(node)
		if err != nil {
			fmt.Printf("%v\n", err)
			return
		}
		fmt.Println(string(byteOutput))
	}
}

func nodeStop(cmd *cli.Cmd) {
	cmd.Spec = "NODENAME"

	//nodeName := cmd.StringArg("NODENAME", "", "Name or ID of the node")

	cmd.Action = func() {
		/*	node, err := instance.GetNode(*nodeName)
			if err != nil {
				return err
			}
			err = node.Stop()
			if err != nil {
				return err
			}
			fmt.Printf("Node '%s' of cluster '%s' stopped.\n", *nodeName, *clusterName)
		*/
		fmt.Println("Not yet implemented")
	}
}

func nodeStart(cmd *cli.Cmd) {
	cmd.Spec = "NODENAME"

	//nodeName := cmd.StringArg("NODENAME", "", "Name or ID of the node")

	cmd.Action = func() {
		/*
			if *nodeName == "" {
				fmt.Println("Invalid empty value for argument NODENAME")
				//cli.ShowSubcommandHelp(c)
				return
			}
			node, err := instance.GetNode(*nodeName)
			if err != nil {
				return err
			}
			err = node.Start()
			if err != nil {
				return err
			}

			fmt.Printf("Node '%s' of cluster '%s' started.\n", *nodeName, *clusterName)
		*/
		fmt.Println("not yet implemented")
	}
}

func nodeState(cmd *cli.Cmd) {
	cmd.Spec = "NODENAME"

	//nodeName := cmd.StringArg("NODENAME", "", "Name or ID of the node")

	cmd.Action = func() {
		/*if *nodeName == "" {
			fmt.Println("Invalid empty value for argument NODENAME")
			//cli.ShowSubcommandHelp(c)
			return
		}
		node, err := instance.GetNode(*nodeName)
		if err != nil {
			return err
		}
		if node == nil {
			return fmt.Errorf("Node '%s' not found in cluster '%s'", *nodeName, *clusterName)
		}
		state, err := node.GetState()
		out, _ := json.Marshal(map[string]string{"state": state.String()})
		fmt.Println(string(out))
		*/
		fmt.Println("not yet implemented")
	}
}
