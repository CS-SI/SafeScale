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
	"log"

	pb "github.com/CS-SI/SafeScale/broker"

	"github.com/CS-SI/SafeScale/perform/cluster"
	clusterapi "github.com/CS-SI/SafeScale/perform/cluster/api"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/perform/cluster/api/Flavor"
	"github.com/CS-SI/SafeScale/perform/cluster/api/NodeType"

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
		clusterStop,
		clusterStart,
		clusterState,
		clusterNode,
	},
}

var clusterNode = cli.Command{
	Name:      "node",
	Usage:     "cluster node COMMAND",
	ArgsUsage: "<cluster name>",
	Subcommands: []cli.Command{
		clusterNodeAdd,
		clusterNodeDelete,
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
		instance, err := cluster.Get(c.Args().First())
		if err != nil {
			return fmt.Errorf("Could not inspect cluster '%s': %v", c.Args().First(), err)
		}
		out, _ := json.Marshal(instance.GetDefinition())
		fmt.Println(string(out))

		return nil
	},
}

var clusterCreate = cli.Command{
	Name:      "create",
	Usage:     "create a new cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "complexity",
			Value: "Normal",
			Usage: "Complexity of the cluster; can be DEV, NORMAL, VOLUME",
		},
		cli.StringFlag{
			Name:  "cidr",
			Value: "192.168.0.0/24",
			Usage: "CIDR of the network",
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
		if instance != nil {
			return fmt.Errorf("cluster '%s' already exists.", clusterName)
		}
		log.Printf("Cluster '%s' not found, creating it (this will take a while)\n", clusterName)
		complexity, err := Complexity.FromString(c.String("complexity"))
		if err != nil {
			return err
		}
		instance, err = cluster.Create(clusterapi.Request{
			Name:       clusterName,
			Complexity: complexity,
			CIDR:       c.String("cidr"),
			Flavor:     Flavor.DCOS,
		})
		if err != nil {
			return fmt.Errorf("Failed to create cluster: %s", err.Error())
		}

		out, _ := json.Marshal(instance.GetDefinition())
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
			Name:  "count",
			Value: 1,
			Usage: "How many nodes to add",
		},
		cli.BoolFlag{
			Name:  "public",
			Usage: "Affect public IP address to node",
		},
		cli.IntFlag{
			Name:  "cpu",
			Value: 2,
			Usage: "Number of CPU for the VM",
		},
		cli.Float64Flag{
			Name:  "ram",
			Value: 8,
			Usage: "RAM for the VM",
		},
		cli.IntFlag{
			Name:  "disk",
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
			return fmt.Errorf("Cluster '%s' not found.", clusterName)
		}
		public := c.Bool("public")
		var nodeType NodeType.Enum
		var nodeTypeString string
		if public {
			nodeType = NodeType.PublicAgent
			nodeTypeString = "public"
		} else {
			nodeType = NodeType.PrivateAgent
			nodeTypeString = "private"
		}
		count := uint16(c.Int("count"))
		countS := ""
		if count > 1 {
			countS = "s"
		}
		fmt.Printf("Adding %d %s node%s to Cluster '%s' (this may take a while)...\n", count, nodeTypeString, countS, clusterName)

		for i := 0; i < int(c.Int("count")); i++ {
			_, err = instance.AddNode(nodeType, &pb.VMDefinition{
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
	Aliases:   []string{"rm"},
	Usage:     "delete last added node(s) from cluster",
	ArgsUsage: "<cluster name>",
	Flags: []cli.Flag{
		cli.IntFlag{
			Name:  "count",
			Value: 1,
			Usage: "Number of node(s) to delete",
		},
		cli.BoolFlag{
			Name:  "public",
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
			return fmt.Errorf("Cluster '%s' not found.", clusterName)
		}
		public := c.Bool("public")
		var nodeType NodeType.Enum
		var nodeTypeString string
		if public {
			nodeType = NodeType.PublicAgent
			nodeTypeString = "public"
		} else {
			nodeType = NodeType.PrivateAgent
			nodeTypeString = "private"
		}
		count := uint(c.Int("count"))
		var countS string
		if count > 1 {
			countS = "s"
		}
		present := instance.CountNodes(public)
		if count > present {
			return fmt.Errorf("Can't delete %d %s node%s, the cluster contains only %d.", count, nodeTypeString, countS, present)
		}

		fmt.Printf("Deleting %d %s node%s from Cluster '%s' (this may take a while)...\n", count, nodeTypeString, countS, clusterName)
		for i := 0; i < int(count); i++ {
			err = instance.DeleteNode(nodeType)
			if err != nil {
				return fmt.Errorf("Failed to delete node #%d: %s", i+1, err.Error())
			}
		}

		fmt.Printf("%d %s node%s successfully deleted from cluster '%s'.\n", count, nodeTypeString, countS, clusterName)
		return nil
	},
}

var clusterDelete = cli.Command{
	Name:      "delete",
	Aliases:   []string{"rm"},
	Usage:     "Delete cluster",
	ArgsUsage: "<cluster name>",
	Action: func(c *cli.Context) error {
		if c.NArg() != 1 {
			fmt.Println("Missing mandatory argument <cluster name>")
			cli.ShowSubcommandHelp(c)
			return fmt.Errorf("Cluster name required")
		}
		err := cluster.Delete(c.Args().First())
		if err != nil {
			return err
		}

		fmt.Printf("Cluster '%s' deleted.\n", c.Args().First())

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
	Usage:     "Get cluster state",
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
		state, err := instance.GetState()
		if err != nil {
			return err
		}

		fmt.Printf("Cluster '%s' state : %s\n", c.Args().First(), state.String())

		return nil
	},
}
