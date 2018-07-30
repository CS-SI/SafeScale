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

	cli "github.com/jawher/mow.cli"
)

// InspectCmd ...
func InspectCmd(c *cli.Cmd) {
	c.Spec = "CLUSTERNAME"

	clusterName = c.StringArg("CLUSTERNAME", "", "Name of the cluster")

	c.Action = func() {
		if *clusterName == "" {
			fmt.Println("Invalid empty argument CLUSTERNAME")
			return
		}
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster inspect %s", *clusterName))
		fmt.Println(cmdStr)
	}
}

// CreateCmd ...
func CreateCmd(cmd *cli.Cmd) {
	//cmd.Spec = "CLUSTERNAME -F [-C] [-N] [-k]"
	cmd.Spec = "CLUSTERNAME [-F][-C][-N][-k][--os][--cpu][--ram][--disk]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	flavorStr := cmd.StringOpt("F flavor", "", "Flavor of Cluster; can be DCOS, BOH (Bunch Of Hosts)")
	complexityStr := cmd.StringOpt("C complexity", "Normal", "Complexity of the cluster; can be DEV, NORMAL (default), VOLUME")
	cidr := cmd.StringOpt("N cidr", "192.168.0.0/24", "CIDR of the network (default: 192.168.0.0/24)")
	keep := cmd.BoolOpt("k keep-on-failure", false, "if set, don't delete resources on failure (default: false)")
	os := cmd.StringOpt("os", "", "operating system (if supported by flavor")
	cpu := cmd.StringOpt("cpu", "", "Number of CPU of the Nodes")
	ram := cmd.StringOpt("ram", "", "Ram size of the nodes (in GB)")
	disk := cmd.StringOpt("disk", "", "Disk size of system disk (in GB)")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}

		cmdStr := fmt.Sprintf("deploy cluster create %s", *clusterName)
		if *flavorStr == "" {
			*flavorStr = "DCOS"
		}
		cmdStr += fmt.Sprintf(" -F %s", *flavorStr)

		if *complexityStr != "" {
			cmdStr += fmt.Sprintf(" -C %s", *complexityStr)
		}
		if *cidr != "" {
			cmdStr += fmt.Sprintf(" -N %s", *cidr)
		}
		if *keep {
			cmdStr += fmt.Sprintf(" -k")
		}
		if *os != "" {
			cmdStr += fmt.Sprintf(" --os %s", *os)
		}
		if *cpu != "" {
			cmdStr += fmt.Sprintf(" --cpu %s", *cpu)
		}
		if *ram != "" {
			cmdStr += fmt.Sprintf(" --ram %s", *ram)
		}
		if *disk != "" {
			cmdStr += fmt.Sprintf(" --disk %s", *disk)
		}
		cmdStr = RebrandCommand(cmdStr)
		fmt.Println(cmdStr)
	}
}

// DeleteCmd ...
func DeleteCmd(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME [-f]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	force := cmd.BoolOpt("f force", false, "Force deletion")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}
		cmdStr := fmt.Sprintf("deploy cluster delete %s", *clusterName)
		if *force {
			cmdStr += fmt.Sprintf(" -f")
		}
		cmdStr = RebrandCommand(cmdStr)
		fmt.Println(cmdStr)
	}
}

// StopCmd ...
func StopCmd(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME"

	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster stop %s", *clusterName))
		fmt.Println(cmdStr)
	}
}

// StartCmd ...
func StartCmd(cmd *cli.Cmd) {
	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster start %s", *clusterName))
		fmt.Println(cmdStr)
	}
}

// StateCmd ...
func StateCmd(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME"

	clusterName = cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}
		cmdStr := RebrandCommand(fmt.Sprintf("deploy cluster state %s", *clusterName))
		fmt.Println(cmdStr)
	}
}

// ExpandCmd ...
func ExpandCmd(cmd *cli.Cmd) {
	//cmd.Spec = "CLUSTERNAME [-n] [-p] [-c] [-r] [-d] [-g]"
	cmd.Spec = "CLUSTERNAME [-n] [-p] [-c] [-r] [-d]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	count := cmd.IntOpt("n count", 1, "Number of nodes to create")
	public := cmd.BoolOpt("p public", false, "Attach public IP address to node (default: false)")
	os := cmd.StringOpt("os", "", "Operating System")
	cpu := cmd.StringOpt("cpu", "", "Number of CPU for the Host (default: 2)")
	ram := cmd.StringOpt("ram", "", "RAM for the host (default: 7 GB)")
	disk := cmd.StringOpt("disk", "", "System disk size for the host (default: 100 GB)")
	//gpu := cmd.BoolOpt("g gpu", false, "With GPU")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Missing or invalid mandatory argument CLUSTERNAME")
			return
		}
		cmdStr := fmt.Sprintf("%sdeploy cluster expand %s", RebrandingPrefix, *clusterName)
		if *count > 1 {
			cmdStr += fmt.Sprintf(" -n %d", *count)
		}
		if *public {
			cmdStr += " -p"
		}
		if *cpu != "" {
			cmdStr += " --cpu " + *cpu
		}
		if *ram != "" {
			cmdStr += " --ram " + *ram
		}
		if *disk != "" {
			cmdStr += " --disk " + *disk
		}
		if *os != "" {
			cmdStr += " --os " + *os
		}
		// if *gpu {
		// 	cmdStr += " --gpu"
		// }
		cmdStr = RebrandCommand(cmdStr)
		fmt.Println(cmdStr)
	}
}

// ShrinkCmd ...
func ShrinkCmd(cmd *cli.Cmd) {
	cmd.Spec = "CLUSTERNAME [-n] [-p]"

	clusterName := cmd.StringArg("CLUSTERNAME", "", "Name of the cluster")
	count := cmd.IntOpt("n count", 1, "Number of node(s) to delete (default: 1)")
	public := cmd.BoolOpt("p public", false, "Delete a public node if set (default: false)")

	cmd.Action = func() {
		if *clusterName == "" {
			fmt.Println("Invalid empty argument CLUSTERNAME")
			return
		}

		cmdStr := fmt.Sprintf("deploy cluster shrink %s", *clusterName)
		if *public {
			cmdStr += " -p"
		}
		if *count > 1 {
			cmdStr += fmt.Sprintf(" -n %d", *count)
		}
		cmdStr = RebrandCommand(cmdStr)
		fmt.Println(cmdStr)
	}
}
