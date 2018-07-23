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

	pb "github.com/CS-SI/SafeScale/broker"
	"github.com/CS-SI/SafeScale/utils/brokeruse"

	"github.com/CS-SI/SafeScale/perform/cluster"

	"github.com/urfave/cli"
)

var NodeCmd = cli.Command{
	Name:  "node",
	Usage: "node COMMAND",
	//ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cluster, c",
			Usage: "Name of the cluster",
		},
	},
	Subcommands: []cli.Command{
		nodeList,
		nodeCreate,
		nodeInspect,
		nodeStop,
		nodeStart,
		nodeState,
		nodeDelete,
	},
}

var nodeCreate = cli.Command{
	Name:  "create",
	Usage: "add a node to cluster",
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
			Usage: "Number of CPU for the host",
		},
		cli.Float64Flag{
			Name:  "ram, r",
			Value: 8,
			Usage: "RAM for the host",
		},
		cli.IntFlag{
			Name:  "disk, d",
			Value: 100,
			Usage: "Disk space for the host",
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
		clusterName := c.String("cluster")
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

var nodeDelete = cli.Command{
	Name:    "delete",
	Aliases: []string{"rm", "destroy"},
	Usage:   "delete last added node(s), or a specific node, from cluster",
	//ArgsUsage: "<cluster name>",
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
		clusterName := c.String("cluster")
		if clusterName == "" {
			fmt.Println("Missing mandatory argument --cluster <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found.", clusterName)
		}

		count := uint(c.Int("count"))
		hostID := c.String("id")
		if hostID != "" {
			if count > 1 {
				fmt.Println("parameter --count,-n can't be used with --id,-i. Ignored.")
			}
			found := instance.SearchNode(hostID, true)
			if !found {
				found = instance.SearchNode(hostID, false)
			}
			if !found {
				return fmt.Errorf("node '%s' isn't a node of the cluster '%s'", hostID, clusterName)
			}
			host, err := brokeruse.GetVM(hostID)
			if err != nil {
				return err
			}

			msg := fmt.Sprintf("Are you sure to delete Cluster Node identified by '%s' in Cluster '%s'", hostID, clusterName)
			if !userConfirmed(msg) {
				fmt.Println("Aborted.")
				return nil
			}
			err = instance.DeleteSpecificNode(hostID)
			if err != nil {
				return err
			}
			fmt.Printf("Node '%s' of cluster '%s' deleted.", host.Name, clusterName)
		} else {
			public := c.Bool("public")
			var nodeTypeString string
			if public {
				nodeTypeString = "public"
			} else {
				nodeTypeString = "private"
			}
			var countS string
			if count > 1 {
				countS = "s"
			}
			present := instance.CountNodes(public)
			if count > present {
				return fmt.Errorf("can't delete %d %s node%s, the cluster contains only %d of them", count, nodeTypeString, countS, present)
			}

			msg := fmt.Sprintf("Are you sure you want to delete %d %s node%s from Cluster %s", int(count), nodeTypeString, countS, clusterName)
			if !userConfirmed(msg) {
				fmt.Println("Aborted.")
				return nil
			}
			fmt.Printf("Deleting %d %s node%s from Cluster '%s' (this may take a while)...\n", count, nodeTypeString, countS, clusterName)
			for i := 0; i < int(count); i++ {
				err = instance.DeleteLastNode(public)
				if err != nil {
					return fmt.Errorf("Failed to delete node #%d: %s", i+1, err.Error())
				}
			}

			fmt.Printf("%d %s node%s successfully deleted from cluster '%s'.\n", count, nodeTypeString, countS, clusterName)
		}
		return nil
	},
}

var nodeList = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List nodes in Cluster",
	//ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cluster, n",
			Usage: "Name of the cluster",
		},
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "If used, lists Public nodes; otherwise lists private nodes",
		},
	},
	Action: func(c *cli.Context) error {
		clusterName := c.String("cluster")
		if clusterName == "" {
			fmt.Println("Missing mandatory argument --cluster,-c <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
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

var nodeInspect = cli.Command{
	Name:      "inspect",
	Usage:     "inspect node",
	ArgsUsage: "<node name|id>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cluster, n",
			Usage: "Name of the cluster",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <node name|id>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Node name|id required")
		}
		nodeName := c.Args().First()
		clusterName := c.String("cluster")
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("Could not inspect node '%s' of cluster '%s': %s", nodeName, clusterName, err.Error())
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}

		node, err := instance.GetNode(nodeName)
		if err != nil {
			return err
		}
		byteOutput, err := json.Marshal(node)
		if err != nil {
			return err
		}
		fmt.Println(string(byteOutput))
		return nil
	},
}

var nodeStop = cli.Command{
	Name:      "stop",
	Usage:     "Stop the node",
	ArgsUsage: "<node name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "cluster, n",
			Usage: "Name of the cluster",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <node name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		/*nodeName := c.Args().First()
		clusterName := c.String("cluster")
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		node, err := instance.GetNode(nodeName)
		if err != nil {
			return err
		}
		err = node.Stop()
		if err != nil {
			return err
		}
		fmt.Printf("Node '%s' of cluster '%s' stopped.\n", nodeName, clusterName)
		*/
		fmt.Println("Not yet implemented")
		return nil
	},
}

var nodeStart = cli.Command{
	Name:      "start",
	Usage:     "Start the node",
	ArgsUsage: "<node name|id>",
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "cluster, n",
			Usage: "Name of the cluster",
		},
	},
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <node name|id>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		/*nodeName := c.Args().First()
		clusterName := c.String("cluster")
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return err
		}
		node, err := instance.GetNode(nodeName)
		if err != nil {
			return err
		}
		err = node.Start()
		if err != nil {
			return err
		}

		fmt.Printf("Node '%s' of cluster '%s' started.\n", nodeName, clusterName)
		*/
		fmt.Println("not yet implemented")
		return nil
	},
}

var nodeState = cli.Command{
	Name:      "state",
	Usage:     "Returns the current state of a node",
	ArgsUsage: "<node name|id>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <node name|id>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Node name required")
		}
		nodeName := c.Args().First()
		clusterName := c.String("cluster")
		instance, err := cluster.Get(clusterName)
		if err != nil {
			return fmt.Errorf("Could not get state of node '%s' from cluster '%s': %v", nodeName, clusterName, err)
		}
		if instance == nil {
			return fmt.Errorf("cluster '%s' not found", clusterName)
		}
		node, err := instance.GetNode(nodeName)
		if err != nil {
			return err
		}
		if node == nil {
			return fmt.Errorf("Node '%s' not found in cluster '%s'", nodeName, clusterName)
		}
		/*state, err := node.GetState()
		out, _ := json.Marshal(map[string]string{"state": state.String()})
		fmt.Println(string(out))
		*/
		fmt.Println("not yet implemented")
		return nil
	},
}
