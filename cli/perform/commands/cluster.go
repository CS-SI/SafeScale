/*
 * Copyright 2018-2019, CS Systemes d'Information, http://www.c-s.fr
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

package commands

import (
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"
)

// ClusterListCommand handles 'perform list'
var ClusterListCommand = cli.Command{
	Name:     "list",
	Aliases:  []string{"ls"},
	Category: "Cluster",

	Action: func(c *cli.Context) error {
		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster list"))
		log.Debugf("Calling '%s'", cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterInspectCommand handles 'perform <clustername inspect'
var ClusterInspectCommand = cli.Command{
	Name:     "inspect",
	Aliases:  []string{"show", "get"},
	Category: "Cluster",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster inspect %s", clusterName))
		return runCommand(cmdStr)
	},
}

// ClusterCreateCommand handles 'perform <clustername> create"
var ClusterCreateCommand = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "Creates a cluster",
	ArgsUsage: "CLUSTERNAME",
	Category:  "Cluster",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> state`,
	// 		Description: `
	// Gets the state of the cluster <clustername>.`,
	// 	},

	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "complexity, C",
			Usage: "Defines the sizing of the cluster: Small, Normal, Large (default: Normal)",
		},
		cli.StringFlag{
			Name:  "flavor, F",
			Usage: "Defines the type of the cluster; can be BOH, SWARM, OHPC, DCOS, K8S (default: K8S)",
		},
		cli.BoolFlag{
			Name:  "keep-on-failure, k",
			Usage: "If used, the resources are not deleted on failure (default: not set)",
		},
		cli.StringFlag{
			Name:  "cidr, N",
			Usage: "Defines the CIDR of the network to use with cluster (default: 192.168.0.0/16)",
		},
		cli.StringSliceFlag{
			Name:  "disable",
			Usage: "Allows to disable addition of default features",
		},
		cli.StringFlag{
			Name:  "os",
			Usage: "Defines the operating system to use",
		},
		cli.UintFlag{
			Name:  "cpu",
			Usage: "Defines the number of cpu of masters and nodes in the cluster",
		},
		cli.Float64Flag{
			Name:  "ram",
			Usage: "Defines the size of RAM of masters and nodes in the cluster (in GB)",
		},
		cli.UintFlag{
			Name:  "disk",
			Usage: "Defines the size of system disk of masters and nodes (in GB)",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		complexityStr := c.String("complexity")
		if complexityStr == "" {
			complexityStr = "Normal"
		}
		cidr := c.String("cidr")
		keep := c.Bool("keep-on-failure")
		cpu := c.Uint("cpu")
		ram := c.Float64("ram")
		disk := c.Uint("disk")

		// Create cluster with deploy
		cmdStr := fmt.Sprintf("safescale cluster create %s -F DCOS -C %s -N %s --cpu %d --ram %f --disk %d",
			clusterName, complexityStr, cidr, cpu, ram, disk)
		if keep {
			cmdStr += " -k"
		}
		cmdStr = RebrandCommand(cmdStr)
		err = runCommand(cmdStr)
		if err != nil {
			return err
		}

		// Installs feature Spark
		cmdStr = fmt.Sprintf("safescale cluster add-feature %s sparkmaster", clusterName)
		err = runCommand(cmdStr)
		if err != nil {
			return err
		}

		// Done
		return nil
	},
}

// ClusterDeleteCommand handles 'perform <clustername> delete'
var ClusterDeleteCommand = cli.Command{
	Name:      "delete",
	Aliases:   []string{"destroy", "remove", "rm"},
	ArgsUsage: "CLUSTERNAME",
	Category:  "Cluster",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "assume-yes, yes, y",
		},
		cli.BoolFlag{
			Name: "force, f",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		yes := c.Bool("assume-yes")

		cmdStr := fmt.Sprintf("safescale cluster rm %s", clusterName)
		if yes {
			cmdStr += " -y"
		}
		cmdStr = RebrandCommand(cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterStopCommand handles 'perform <clustername> stop'
var ClusterStopCommand = cli.Command{
	Name:     "stop",
	Aliases:  []string{"freeze"},
	Category: "Cluster",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster stop %s", clusterName))
		return runCommand(cmdStr)
	},
}

// ClusterStartCommand handles 'perform <clustername> start'
var ClusterStartCommand = cli.Command{
	Name:     "start",
	Aliases:  []string{"unfreeze", "boot"},
	Category: "Cluster",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster start %s", clusterName))
		return runCommand(cmdStr)
	},
}

// ClusterStateCommand handles 'perform state CLUSTERNAME'
var ClusterStateCommand = cli.Command{
	Name:     "state",
	Category: "Cluster",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster state %s", clusterName))
		return runCommand(cmdStr)
	},
}

// ClusterExpandCommand handles 'perform <clustername> expand'
var ClusterExpandCommand = cli.Command{
	Name:     "expand",
	Category: "Cluster",

	Flags: []cli.Flag{
		cli.UintFlag{
			Name:  "count, n",
			Usage: "Define the number of nodes wanted (default: 1)",
			Value: 1,
		},
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "If used, the node(s) will have public IP address (default: no)",
		},
		cli.StringFlag{
			Name:  "os",
			Usage: "Define the Operating System wanted",
		},
		cli.UintFlag{
			Name:  "cpu",
			Usage: "Define the number of cpu for new node(s); default: number used at cluster creation",
			Value: 0,
		},
		cli.Float64Flag{
			Name:  "ram",
			Usage: "Define the size of RAM for new node(s) (in GB); default: size used at cluster creation",
			Value: 0.0,
		},
		cli.UintFlag{
			Name:  "disk",
			Usage: "Define the size of system disk for new node(s) (in GB); default: size used at cluster creation",
			Value: 0,
		},
		cli.BoolFlag{
			Name:   "gpu",
			Usage:  "Ask for gpu capable host; default: no",
			Hidden: true,
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		count := c.Uint("count")
		if count == 0 {
			count = 1
		}
		public := c.Bool("public")
		gpu := c.Bool("gpu")
		los := c.String("os")
		cpu := c.Uint("cpu")
		ram := c.Float64("ram")
		disk := c.Uint("disk")

		cmdStr := fmt.Sprintf("safescale cluster expand %s -n %d", clusterName, count)
		if public {
			cmdStr += " -p"
		}
		if gpu {
			cmdStr += " --gpu"
		}
		if los != "" {
			cmdStr += " --os " + los
		}
		if cpu > 0 {
			cmdStr += fmt.Sprintf(" --cpu %d", cpu)
		}
		if ram > 0.0 {
			cmdStr += fmt.Sprintf(" --ram %f ", ram)
		}
		if disk > 0 {
			cmdStr += fmt.Sprintf(" --disk %d", disk)
		}
		cmdStr = RebrandCommand(cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterShrinkCommand handles 'perform <clustername> shrink'
var ClusterShrinkCommand = cli.Command{
	Name:        "shrink",
	Usage:       "shrink CLUSTERNAME",
	Description: "Removes node(s) from the cluster (starting from the last added)",
	Category:    "Cluster",

	Flags: []cli.Flag{
		cli.UintFlag{
			Name:  "count, n",
			Usage: "Define the number of nodes wanted (default: 1)",
			Value: 1,
		},
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "If used, the node(s) will have public IP address (default: no)",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		count := c.Uint("count")
		if count == 0 {
			count = 1
		}
		public := c.Bool("public")

		cmdStr := fmt.Sprintf("safescale cluster shrink %s -n %d", clusterName, count)
		if public {
			cmdStr += " -p"
		}
		cmdStr = RebrandCommand(cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterCallCommand handles 'perform dcos CLUSTERNAME'
var ClusterCallCommand = cli.Command{
	Name:  "call",
	Usage: "call [options] CLUSTERNAME COMMAND [PARAM ...]",
	Description: `
Calls a COMMAND on the designated target of the cluster CLUSTERNAME.
By default, the target is any available master (--any-master).

Note:
Everything after COMMAND will be considered a parameter of the COMMAND.
`,
	Category: "Cluster",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name: "any-master, m",
		},
		cli.BoolFlag{
			Name: "all-masters, a",
		},
		cli.StringFlag{
			Name: "master",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		anyMaster := c.Bool("any-master")
		allMasters := c.Bool("all-masters")
		master := c.String("master")
		target := ""
		if allMasters {
			target = "-a"
		} else if master != "" {
			target = "--master " + master
		}
		if anyMaster || target == "" {
			target = "-m"
		}

		args := c.Args()
		tail := args.Tail()
		command := args.Get(1)

		cmdStr := fmt.Sprintf("safescale cluster call %s %s %s %s", target, clusterName, command, strings.Join(tail[1:], " "))
		cmdStr = RebrandCommand(cmdStr)
		log.Debugf("Calling '%s'", cmdStr)
		return runCommand(cmdStr)
	},
}
