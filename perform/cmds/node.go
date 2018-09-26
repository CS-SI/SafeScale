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
	"os"

	"github.com/CS-SI/SafeScale/utils/cli"
	"github.com/CS-SI/SafeScale/utils/cli/ExitCode"
)

// nodeCommand configures arguments for command "perform <clustername> node"
var nodeCommand = &cli.Command{
	Keyword: "node",

	Commands: []*cli.Command{
		nodeListCommand,
		nodeCreateCommand,
		nodeInspectCommand,
		nodeStopCommand,
		nodeStartCommand,
		nodeStateCommand,
		nodeDeleteCommand,
	},

	Before: func(c *cli.Command) {
		if !c.IsKeywordSet("list,ls") {
			nodeName := c.StringArgument("<node name or id>", "")

			if nodeName == "" {
				fmt.Println("Invalid argument <node name or id>")
				//cli.ShowSubcommandHelp(c)
				os.Exit(int(ExitCode.InvalidArgument))
			}
		}
	},

	Help: &cli.HelpContent{},
}

// nodeCreateCommand ...
var nodeCreateCommand = &cli.Command{
	Keyword: "create",

	Process: func(c *cli.Command) {
		count := c.IntOption("count n", "<count>", 1)
		public := c.Flag("public p", false)
		cpu := c.IntOption("cpu C", "<number of cpu>", 2)
		ram := c.FloatOption("ram R", "<ram size>", 7.0)
		disk := c.IntOption("disk D", "<disk size>", 100)
		//gpu := c.Flag("gpu", false, "With GPU")

		cmdStr := fmt.Sprintf("deploy cluster %s expand -n %d --cpu %d --ram %f --disk %d",
			clusterName, count, int32(cpu), float32(ram), int32(disk))
		if public {
			cmdStr += " -p"
		}
		cmdStr = RebrandCommand(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// nodeDeleteCommand ...
var nodeDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Process: func(c *cli.Command) {
		yes := c.Flag("y assume-yes", false)
		cmdStr := fmt.Sprintf("deploy cluster %s node %s delete", clusterName, nodeName)
		if yes {
			cmdStr += " -y"
		}
		cmdStr = RebrandCommand(cmdStr)
		fmt.Println(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// nodeListCommand ...
var nodeListCommand = &cli.Command{
	Keyword: "list",
	Aliases: []string{"ls"},

	Process: func(c *cli.Command) {
		public := c.Flag("public p", false)

		cmdStr := fmt.Sprintf("deploy cluster %s node list", clusterName)
		if public {
			cmdStr += " -p"
		}
		cmdStr = RebrandCommand(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// nodeInspectCommand ...
var nodeInspectCommand = &cli.Command{
	Keyword: "inspect",

	Process: func(c *cli.Command) {
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster %s node %s inspect", clusterName, nodeName))
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// nodeStopCommand ...
var nodeStopCommand = &cli.Command{
	Keyword: "stop",
	Aliases: []string{"freeze"},

	Process: func(c *cli.Command) {
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster %s node %s stop", clusterName, nodeName))
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// nodeStartCommand ...
var nodeStartCommand = &cli.Command{
	Keyword: "start",
	Aliases: []string{"unfreeze"},

	Process: func(c *cli.Command) {
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster %s node %s start", clusterName, nodeName))
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// nodeStateCommand ...
var nodeStateCommand = &cli.Command{
	Keyword: "state",

	Process: func(c *cli.Command) {
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster %s node %s state", clusterName, nodeName))
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}
