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

package cmds

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"
)

// ClusterDeleteNodeCommand ...
var ClusterDeleteNodeCommand = cli.Command{
	Name:     "delete-node",
	Aliases:  []string{"destroy-node", "remove-node", "rm-node"},
	Usage:    "Deletes a node of the cluster",
	Category: "Node",

	Action: func(c *cli.Context) error {
		yes := c.Bool("assume-yes")
		force := c.Bool("force")
		cmdStr := fmt.Sprintf("safescale cluster delete-node %s %s", clusterName, nodeName)
		if yes {
			cmdStr += " -y"
		}
		if force {
			cmdStr += " -f"
		}
		cmdStr = RebrandCommand(cmdStr)
		log.Debugf("Calling '%s'", cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterListNodesCommand ...
var ClusterListNodesCommand = cli.Command{
	Name:     "list-node",
	Aliases:  []string{"ls-node", "list-nodes", "ls-nodes"},
	Usage:    "List nodes in the cluster",
	Category: "Node",

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "If set, list only public nodes",
		},
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "If set, list all type of nodes (overcomes --public)",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractNodeArgument(c)
		if err != nil {
			return err
		}

		public := c.Bool("public")
		all := c.Bool("all")

		cmdStr := fmt.Sprintf("safescale cluster ls-nodes %s", clusterName)
		if all {
			cmdStr += " -a"
		} else if public {
			cmdStr += " -p"
		}
		cmdStr = RebrandCommand(cmdStr)
		log.Debugf("Calling '%s'", cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterInspectNodeCommand ...
var ClusterInspectNodeCommand = cli.Command{
	Name:     "inspect-node",
	Aliases:  []string{"show-node", "get-node"},
	Usage:    "Inspects a node of the cluster",
	Category: "Node",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractNodeArgument(c)
		if err != nil {
			return err
		}

		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster inspect-node %s %s", clusterName, nodeName))
		log.Debugf("Calling '%s'", cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterStopNodeCommand ...
var ClusterStopNodeCommand = cli.Command{
	Name:      "stop-node",
	Aliases:   []string{"freeze-node"},
	Usage:     "Stops a node of the cluster",
	ArgsUsage: "CLUSTERNAME NODENAME",
	Category:  "Node",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractNodeArgument(c)
		if err != nil {
			return err
		}

		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster stop-node %s %s", clusterName, nodeName))
		log.Debugf("Calling '%s'", cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterStartNodeCommand ...
var ClusterStartNodeCommand = cli.Command{
	Name:      "start-node",
	Aliases:   []string{"unfreeze-node"},
	Usage:     "Stars a node of the cluster",
	ArgsUsage: "CLUSTERNAME NODENAME",
	Category:  "Node",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractNodeArgument(c)
		if err != nil {
			return err
		}

		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster start-node %s %s", clusterName, nodeName))
		log.Debugf("Calling '%s'", cmdStr)
		return runCommand(cmdStr)
	},
}

// ClusterProbeNodeCommand ...
var ClusterProbeNodeCommand = cli.Command{
	Name:      "probe-node",
	Usage:     "Determines the state of a node of the cluster",
	ArgsUsage: "CLUSTERNAME NODENAME",
	Category:  "Node",

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractNodeArgument(c)
		if err != nil {
			return err
		}

		cmdStr := RebrandCommand(fmt.Sprintf("safescale cluster probe-node %s %s", clusterName, nodeName))
		log.Debugf("Calling '%s'", cmdStr)
		return runCommand(cmdStr)
	},
}
