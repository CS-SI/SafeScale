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
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/utils/brokeruse"

	"github.com/CS-SI/SafeScale/perform/cluster"
	clusterapi "github.com/CS-SI/SafeScale/perform/cluster/api"
	"github.com/CS-SI/SafeScale/perform/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Flavor"

	"github.com/urfave/cli"
)

// ClusterCmd command
var ClusterCmd = cli.Command{
	Name:  "cluster",
	Usage: "cluster COMMAND",
	Subcommands: []cli.Command{
		clusterList,
		clusterCreate,
		clusterDelete,
		clusterInspect,
		clusterState,
		clusterStop,
		clusterStart,
		clusterState,
		clusterNode,
		clusterKubectl,
	},
}

var clusterNode = cli.Command{
	Name:      "node",
	Usage:     "cluster node COMMAND",
	ArgsUsage: "<cluster name>",
	Subcommands: []cli.Command{
		clusterNodeAdd,
		clusterNodeDelete,
		clusterNodeList,
	},
}

var clusterList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available Clusters on the current tenant",
	Action: func(c *cli.Context) error {
		list, err := cluster.List()
		if err != nil {
			return fmt.Errorf("Could not get cluster list: %v", err)
		}
		out, _ := json.Marshal(list)
		fmt.Println(string(out))

		return nil
	},
}

var clusterInspect = cli.Command{
	Name:      "inspect",
	Usage:     "inspect Cluster",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("Could not inspect cluster '%s': %s", clusterName, err.Error())
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}

		byteOutput, err := json.Marshal(instance.GetConfig())
		if err != nil {
			return err
		}
		var output map[string]interface{}
		err = json.Unmarshal(byteOutput, &output)
		if err != nil {
			return err
		}

		output["State"] = ClusterState.Enum(int(output["State"].(float64))).String()
		output["Flavor"] = Flavor.Enum(int(output["Flavor"].(float64))).String()
		output["Complexity"] = Complexity.Enum(int(output["Complexity"].(float64))).String()
		delete(output, "Keypair")
		delete(output, "PrivateNodeIDs")
		delete(output, "PublicNodeIDs")
		byteOutput, err = json.Marshal(output)
		if err != nil {
			return err
		}

		fmt.Println(string(byteOutput))
		return nil
	},
}

var clusterCreate = cli.Command{
	Name:      "create",
	Usage:     "create a new cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "complexity, C",
			Value: "Normal",
			Usage: "Complexity of the cluster; can be DEV, NORMAL, VOLUME",
		},
		cli.StringFlag{
			Name:  "cidr, N",
			Value: "192.168.0.0/24",
			Usage: "CIDR of the network",
		},
		cli.BoolFlag{
			Name:  "keep-on-failure, k",
			Usage: "Doesn't delete resources on failure",
		},
		// cli.StringFlag{
		// 	Name:  "flavor, F",
		// 	Value: "DCOS",
		// 	Usage: "Flavor of cluster",
		// },
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		if instance != nil {
			return fmt.Errorf("cluster '%s' already exists.", clusterName)
		}

		complexity, err := Complexity.FromString(c.String("complexity"))
		if err != nil {
			return err
		}
		instance, err = cluster.Create(clusterapi.Request{
			Name:          clusterName,
			Complexity:    complexity,
			CIDR:          c.String("cidr"),
			Flavor:        Flavor.DCOS,
			KeepOnFailure: c.Bool("keep-on-failure"),
		})
		if err != nil {
			if instance != nil {
				instance.Delete()
			}
			return fmt.Errorf("failed to create cluster: %s", err.Error())
		}

		out, _ := json.Marshal(instance.GetConfig())
		fmt.Println(string(out))

		return nil
	},
}

var clusterNodeAdd = cli.Command{
	Name:      "add",
	Usage:     "add a node to cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "count, n",
			Value: 1,
			Usage: "How many nodes to add",
		},
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "Affect public IP address to node",
		},
		cli.IntFlag{
			Name:  "cpu, c",
			Value: 2,
			Usage: "Number of CPU for the VM",
		},
		cli.Float64Flag{
			Name:  "ram, r",
			Value: 8,
			Usage: "RAM for the VM",
		},
		cli.IntFlag{
			Name:  "disk, d",
			Value: 100,
			Usage: "Disk space for the VM",
		},
		cli.BoolFlag{
			Name:   "gpu",
			Usage:  "With GPU",
			Hidden: true,
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found.", clusterName)
		}
		public := c.Bool("public")
		var nodeTypeString string
		if public {
			nodeTypeString = "public"
		} else {
			nodeTypeString = "private"
		}
		count := uint16(c.Int("count"))
		countS := ""
		if count > 1 {
			countS = "s"
		}
		fmt.Printf("Adding %d %s node%s to Cluster '%s' (this may take a while)...\n", count, nodeTypeString, countS, clusterName)

		for i := 0; i < int(c.Int("count")); i++ {
			_, err = instance.AddNode(public, &pb.VMDefinition{
				CPUNumber: int32(c.Int("cpu")),
				Disk:      int32(c.Float64("disk")),
				RAM:       float32(c.Float64("ram")),
			})
			if err != nil {
				return fmt.Errorf("Failed to add node #%d: %s", i+1, err.Error())
			}
		}

		fmt.Printf("Added %d %s node%s to cluster '%s'.\n", count, nodeTypeString, countS, clusterName)
		return nil
	},
}

var clusterNodeDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "destroy"},
	Usage:     "delete last added node(s) from cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "count, n",
			Value: 1,
			Usage: "Number of node(s) to delete",
		},
		cli.StringFlag{
			Name:  "id, i",
			Usage: "ID of the specific node to delete",
		},
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "Public node",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found.", clusterName)
		}

		vmID := c.String("id")
		if vmID != "" {
			found := instance.SearchNode(vmID, true)
			if !found {
				found = instance.SearchNode(vmID, false)
			}
			if !found {
				return fmt.Errorf("node '%s' isn't a node of the cluster '%s'", vmID, clusterName)
			}
			vm, err := brokeruse.GetVM(vmID)
			if err != nil {
				return err
			}

			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Are you sure to delete Cluster Node identified by '%s' in Cluster '%s' ? (y/N): ", vmID, clusterName)
			resp, _ := reader.ReadString('\n')
			resp = strings.ToLower(strings.TrimSuffix(resp, "\n"))
			if resp == "y" {
				err = instance.DeleteSpecificNode(vmID)
				if err != nil {
					return err
				}
				fmt.Printf("Node '%s' of cluster '%s' deleted.", vm.Name, clusterName)
			} else {
				fmt.Println("Aborted.")
			}
			return nil
		}

		public := c.Bool("public")
		var nodeTypeString string
		if public {
			nodeTypeString = "public"
		} else {
			nodeTypeString = "private"
		}
		count := uint(c.Int("count"))
		var countS string
		if count > 1 {
			countS = "s"
		}
		present := instance.CountNodes(public)
		if count > present {
			return fmt.Errorf("can't delete %d %s node%s, the cluster contains only %d of them", count, nodeTypeString, countS, present)
		}

		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Are you sure to delete %d %s node%s from Cluster %s ? (y/N): ", int(count), nodeTypeString, countS, clusterName)
		resp, _ := reader.ReadString('\n')
		resp = strings.ToLower(strings.TrimSuffix(resp, "\n"))
		if resp == "y" {
			fmt.Printf("Deleting %d %s node%s from Cluster '%s' (this may take a while)...\n", count, nodeTypeString, countS, clusterName)
			for i := 0; i < int(count); i++ {
				err = instance.DeleteLastNode(public)
				if err != nil {
					return fmt.Errorf("Failed to delete node #%d: %s", i+1, err.Error())
				}
			}

			fmt.Printf("%d %s node%s successfully deleted from cluster '%s'.\n", count, nodeTypeString, countS, clusterName)
		} else {
			fmt.Println("Aborted.")
		}
		return nil
	},
}

var clusterNodeList = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "List nodes in Cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "If used, lists Public nodes; otherwise lists private nodes",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}

		list := instance.ListNodes(c.Bool("public"))

		out, _ := json.Marshal(list)
		fmt.Println(string(out))

		return nil
	},
}

var clusterDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm", "destroy"},
	Usage:     "Delete cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "force delete",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found.", clusterName)
		}
		if !c.Bool("force") {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Are you sure to delete Cluster '%s' ? (y/N): ", clusterName)
			resp, _ := reader.ReadString('\n')
			resp = strings.ToLower(strings.TrimSuffix(resp, "\n"))
			if resp != "y" {
				fmt.Println("Aborted.")
				return nil
			}
		}
		err = cluster.Delete(clusterName)
		if err != nil {
			return err
		}

		fmt.Printf("Cluster '%s' deleted.\n", clusterName)
		return nil
	},
}

var clusterStop = cli.Command{
	Name:      "stop",
	Usage:     "Stop the cluster",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		instance, err := cluster.Get(c.Args().First())
		if err != nil {
			return err
		}
		err = instance.Stop()
		if err != nil {
			return err
		}
		fmt.Printf("Cluster '%s' stopped.\n", c.Args().First())

		return nil
	},
}

var clusterStart = cli.Command{
	Name:      "start",
	Usage:     "Start the cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "name, n",
			Usage: "Name of the cluster",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		instance, err := cluster.Get(c.Args().First())
		if err != nil {
			return nil
		}
		err = instance.Start()
		if err != nil {
			return err
		}

		fmt.Printf("Cluster '%s' started.\n", c.Args().First())

		return nil
	},
}

var clusterState = cli.Command{
	Name:      "state",
	Usage:     "Returns the current state of a cluster",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("Could not inspect cluster '%s': %v", clusterName, err)
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}
		state, err := instance.GetState()
		out, _ := json.Marshal(map[string]string{"state": state.String()})
		fmt.Println(string(out))

		return nil
	},
}

var clusterKubectl = cli.Command{
	Name:      "kubectl",
	Usage:     "cluster node COMMAND",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		clusterName := c.Args().First()
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("Could not inspect cluster '%s': %v", clusterName, err)
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}
		state, err := instance.GetState()
		out, _ := json.Marshal(map[string]string{"state": state.String()})
		fmt.Println(string(out))

		return nil
	},
}
