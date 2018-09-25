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
	"strings"

	"github.com/CS-SI/SafeScale/utils/cli"
	"github.com/CS-SI/SafeScale/utils/cli/ExitCode"
)

func populateClusterName(c *cli.Command) {
	clusterName := c.StringArgument("<clustername>", "")
	if clusterName == "" {
		fmt.Println("Invalid argument <clustername>")
		os.Exit(int(ExitCode.InvalidArgument))
	}

}

// ClusterInspectCommand handles 'perform <clustername inspect'
var ClusterInspectCommand = &cli.Command{
	Keyword: "inspect",

	Process: func(c *cli.Command) {
		populateClusterName(c)
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster %s inspect", clusterName))
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// ClusterCreateCommand handles 'perform <clustername> create"
var ClusterCreateCommand = &cli.Command{
	Keyword: "create",

	Process: func(c *cli.Command) {
		populateClusterName(c)

		complexityStr := c.StringOption("C complexity", "<complexity>", "Normal")
		cidr := c.StringOption("N cidr", "<cidr>", "192.168.0.0/24")
		keep := c.Flag("k keep-on-failure", false)
		cpu := c.IntOption("cpu", "<cpu>", 4)
		ram := c.FloatOption("ram", "<ram>", 7.0)
		disk := c.IntOption("disk", "<disk>", 100)

		// Create cluster with deploy
		cmdStr := fmt.Sprintf("deploy cluster %s create -F DCOS -C %s -N %s --cpu %d --ram %f --disk %d",
			clusterName, complexityStr, cidr, cpu, ram, disk)
		if keep {
			cmdStr += " -k"
		}
		cmdStr = RebrandCommand(cmdStr)
		retcode := runCommand(cmdStr)
		if retcode != 0 {
			os.Exit(retcode)
		}

		// Installs component Spark
		cmdStr = fmt.Sprintf("deploy cluster %s component spark add", clusterName)
		retcode = runCommand(cmdStr)
		if retcode != 0 {
			os.Exit(retcode)
		}

		// Done
		os.Exit(retcode)
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] cluster <clustername> state`,
		Description: `
Gets the state of the cluster <clustername>.`,
	},
}

// ClusterDeleteCommand handles 'perform <clustername> delete'
var ClusterDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Process: func(c *cli.Command) {
		populateClusterName(c)

		yes := c.Flag("y assume-yes", false)

		cmdStr := fmt.Sprintf("deploy cluster %s rm", clusterName)
		if yes {
			cmdStr += " -y"
		}
		cmdStr = RebrandCommand(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// ClusterStopCommand handles 'perform <clustername> stop'
var ClusterStopCommand = &cli.Command{
	Keyword: "stop",
	Aliases: []string{"freeze"},

	Process: func(c *cli.Command) {
		populateClusterName(c)

		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster %s stop", clusterName))
		os.Exit(runCommand(cmdStr))
	},
}

// ClusterStartCommand handles 'perform <clustername> start'
var ClusterStartCommand = &cli.Command{
	Keyword: "start",
	Aliases: []string{"unfreeze"},

	Process: func(c *cli.Command) {
		populateClusterName(c)

		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster %s start", clusterName))
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// ClusterStateCommand handles 'perform <clustername> state'
var ClusterStateCommand = &cli.Command{
	Keyword: "state",

	Process: func(c *cli.Command) {
		populateClusterName(c)

		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster %s state", clusterName))
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// ClusterExpandCommand handles 'perform <clustername> expand'
var ClusterExpandCommand = &cli.Command{
	Keyword: "expand",

	Process: func(c *cli.Command) {
		populateClusterName(c)

		count := c.IntOption("n count", "<count>", 1)
		public := c.Flag("p public", false)
		//gpu := c.Flag("g gpu", false)

		cmdStr := fmt.Sprintf("deploy cluster %s expand -n %d", clusterName, count)
		if public {
			cmdStr += " -p"
		}
		// if *gpu {
		// 	cmdStr += " --gpu"
		// }
		cmdStr = RebrandCommand(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// ClusterShrinkCommand handles 'perform <clustername> shrink'
var ClusterShrinkCommand = &cli.Command{
	Keyword: "shrink",

	Process: func(c *cli.Command) {
		populateClusterName(c)

		count := c.IntOption("n count", "<count>", 1)
		public := c.Flag("p public", false)

		cmdStr := fmt.Sprintf("deploy cluster %s shrink -n %d", clusterName, count)
		if public {
			cmdStr += " -p"
		}
		cmdStr = RebrandCommand(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// ClusterDcosCommand handles 'perform <clustername> dcos'
var ClusterDcosCommand = &cli.Command{
	Keyword: "dcos",

	Process: func(c *cli.Command) {
		populateClusterName(c)

		args := c.StringSliceArgument("<arg>", []string{})
		cmdStr := fmt.Sprintf("deploy cluster %s dcos", clusterName)
		if len(args) > 0 {
			cmdStr += " -- " + strings.Join(args, " ")
		}
		cmdStr = RebrandCommand(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// ClusterKubectlCommand handles 'perform <clustername> kubectl'
var ClusterKubectlCommand = &cli.Command{
	Keyword: "kubectl",

	Process: func(c *cli.Command) {
		populateClusterName(c)

		args := c.StringSliceArgument("<arg>", []string{})
		cmdStr := fmt.Sprintf("deploy cluster %s kubectl", clusterName)
		if len(args) > 0 {
			cmdStr += " -- " + strings.Join(args, " ")
		}
		cmdStr = RebrandCommand(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}

// ClusterMarathonCommand handles 'perform <clustername> marathon'
var ClusterMarathonCommand = &cli.Command{
	Keyword: "marathon",

	Process: func(c *cli.Command) {
		populateClusterName(c)

		args := c.StringSliceArgument("<arg>", []string{})
		cmdStr := fmt.Sprintf("deploy cluster %s marathon", clusterName)
		if len(args) > 0 {
			cmdStr += " -- " + strings.Join(args, " ")
		}
		cmdStr = RebrandCommand(cmdStr)
		os.Exit(runCommand(cmdStr))
	},

	Help: &cli.HelpContent{},
}
