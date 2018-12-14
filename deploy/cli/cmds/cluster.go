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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli"

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"
	"github.com/CS-SI/SafeScale/deploy/cluster"
	"github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/core"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/enums/Flavor"
	"github.com/CS-SI/SafeScale/deploy/install"
	"github.com/CS-SI/SafeScale/utils"
	clitools "github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/enums/ExitCode"
)

const (
	ubuntu1604 = "Ubuntu 16.04"
)

var (
	clusterName string
	// clusterServiceName *string
	clusterInstance api.Cluster
)

// ClusterCommand command
var ClusterCommand = cli.Command{
	Name:      "cluster",
	Aliases:   []string{"datacenter", "dc"},
	Usage:     "create and manage cluster",
	ArgsUsage: "COMMAND",
	Subcommands: []cli.Command{
		clusterNodeCommand,
		clusterListCommand,
		clusterCreateCommand,
		clusterDeleteCommand,
		clusterInspectCommand,
		clusterStateCommand,
		//clusterSshCommand,
		clusterStartCommand,
		clusterStopCommand,
		clusterExpandCommand,
		clusterShrinkCommand,
		clusterDcosCommand,
		clusterKubectlCommand,
		clusterCheckFeatureCommand,
		clusterAddFeatureCommand,
		clusterDeleteFeatureCommand,
	},
}

func extractClusterArgument(c *cli.Context) error {
	if !c.Command.HasName("list") {
		if c.NArg() < 1 {
			fmt.Fprintf(os.Stderr, "Missing mandatory argument CLUSTERNAME")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}
		clusterName = c.Args().First()
		if clusterName == "" {
			fmt.Fprintf(os.Stderr, "Invalid argument CLUSTERNAME")
			_ = cli.ShowSubcommandHelp(c)
			return clitools.ExitOnInvalidArgument()
		}

		var err error
		clusterInstance, err = cluster.Get(clusterName)
		if c.Command.HasName("create") && clusterInstance != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Duplicate, fmt.Sprintf("Cluster '%s' already exists.\n", clusterName))
		}
		if err != nil {
			msg := fmt.Sprintf("Failed to query for cluster '%s': %s\n", clusterName, err.Error())
			return clitools.ExitOnRPC(msg)
		}
	}
	return nil
}

// clusterListCommand handles 'deploy cluster list'
var clusterListCommand = cli.Command{
	Name:    "list",
	Aliases: []string{"ls"},
	Usage:   "List available clusters",

	Action: func(c *cli.Context) error {
		list, err := cluster.List()
		if err != nil {
			return clitools.ExitOnRPC(fmt.Sprintf("Failed to get cluster list: %v", err))
		}
		jsoned, err := json.Marshal(list)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		var toFormat []interface{}
		err = json.Unmarshal(jsoned, &toFormat)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, fmt.Sprintf("Failed to interpret list: %s", err.Error()))
		}
		var formatted []interface{}
		for _, value := range toFormat {
			core := value.(map[string]interface{})["Core"]
			formatted = append(formatted, formatClusterConfig(core))
		}
		jsoned, err = json.Marshal(formatted)
		if err != nil {
			fmt.Printf("%v\n", err)
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, fmt.Sprintf("Failed to convert list to json: %s", err.Error()))
		}
		fmt.Println(string(jsoned))
		return nil
	},
}

// formatClusterConfig...
func formatClusterConfig(value interface{}) map[string]interface{} {
	core := value.(map[string]interface{})
	e := Flavor.Enum(int(core["flavor"].(float64)))
	core["flavor_label"] = e.String()

	c := Complexity.Enum(int(core["complexity"].(float64)))
	core["complexity_label"] = c.String()

	s := ClusterState.Enum(int(core["state"].(float64)))
	core["state_label"] = s.String()

	if !Debug {
		delete(core, "infos")
		delete(core, "extensions")
		delete(core, "private_node_ids")
		delete(core, "public_node_ids")
		delete(core, "keypair")
	}

	return core
}

// clusterInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterInspectCommand = cli.Command{
	Name:      "inspect",
	Aliases:   []string{"show", "get"},
	Usage:     "inspect CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",
	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> inspect`,
	// 		Description: `
	// Displays information about the cluster 'clustername'.`,
	// 	},
	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = outputClusterConfig()
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		return nil
	},
}

// outputClusterConfig displays cluster configuration after filtering and completing some fields
func outputClusterConfig() error {
	toFormat, err := convertStructToMap(clusterInstance.GetConfig())
	if err != nil {
		return err
	}
	formatted := formatClusterConfig(toFormat)

	jsoned, err := json.Marshal(formatted)
	if err != nil {
		return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
	}
	fmt.Println(string(jsoned))
	return nil
}

// convertStructToMap converts a struct to its equivalent in map[string]interface{},
// with fields converted to string and used as keys
func convertStructToMap(src interface{}) (map[string]interface{}, error) {
	jsoned, err := json.Marshal(src)
	if err != nil {
		return map[string]interface{}{}, err
	}
	var toFormat map[string]interface{}
	err = json.Unmarshal(jsoned, &toFormat)
	if err != nil {
		return map[string]interface{}{}, err
	}

	// Add information not directly in cluster GetConfig()
	feature, err := install.NewFeature("remotedesktop")
	found := false
	if err == nil {
		target := install.NewClusterTarget(clusterInstance)
		var results install.Results
		results, err := feature.Check(target, install.Variables{}, install.Settings{})
		found = err == nil && results.Successful()
		if found {
			brkclt := brokerclient.New().Host
			remoteDesktops := []string{}
			gwPublicIP := clusterInstance.GetConfig().PublicIP
			for _, id := range clusterInstance.ListMasterIDs() {
				host, err := brkclt.Inspect(id, brokerclient.DefaultExecutionTimeout)
				if err != nil {
					return nil, err
				}
				remoteDesktops = append(remoteDesktops, fmt.Sprintf("https://%s/remotedesktop/%s/", gwPublicIP, host.Name))
			}
			toFormat["remote_desktop"] = remoteDesktops
		}
	}
	if !found {
		toFormat["remote_desktop"] = fmt.Sprintf("Remote Desktop not installed. To install it, execute 'deploy cluster %s feature remotedesktop add'.", clusterName)
	}
	toFormat["admin_login"] = "cladm"

	return toFormat, nil
}

// clusterCreateCmd handles 'deploy cluster <clustername> create'
var clusterCreateCommand = cli.Command{
	Name:      "create",
	Aliases:   []string{"new"},
	Usage:     "create a cluster",
	ArgsUsage: "CLUSTERNAME: name of the cluster to create",

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
			complexityStr = "Small"
		}
		complexity, err := Complexity.Parse(complexityStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --complexity|-C: %s\n", err.Error())
			return clitools.ExitOnInvalidOption(msg)
		}

		flavorStr := c.String("flavor")
		if flavorStr == "" {
			flavorStr = "K8S"
		}
		flavor, err := Flavor.Parse(flavorStr)
		if err != nil {
			msg := fmt.Sprintf("Invalid option --flavor|-F: %s\n", err.Error())
			return clitools.ExitOnInvalidOption(msg)
		}

		keep := c.Bool("keep-on-failure")

		cidr := c.String("cidr")
		if cidr == "" {
			cidr = "192.168.0.0/16"
		}

		disable := c.StringSlice("disable")
		disableFeatures := map[string]struct{}{}
		for _, v := range disable {
			disableFeatures[v] = struct{}{}
		}

		los := c.String("os")
		if flavor == Flavor.DCOS {
			// DCOS forces to use RHEL/CentOS/CoreOS, and we've chosen to use CentOS, so ignore --os option
			los = ""
		}

		cpu := int32(c.Uint("cpu"))
		ram := float32(c.Float64("ram"))
		disk := int32(c.Uint("disk"))

		var nodesDef *pb.HostDefinition
		if cpu > 0 || ram > 0.0 || disk > 0 || los != "" {
			nodesDef = &pb.HostDefinition{
				CPUNumber: cpu,
				RAM:       ram,
				Disk:      disk,
				ImageID:   los,
			}
		}
		clusterInstance, err = cluster.Create(core.Request{
			Name:                    clusterName,
			Complexity:              complexity,
			CIDR:                    cidr,
			Flavor:                  flavor,
			KeepOnFailure:           keep,
			NodesDef:                nodesDef,
			DisabledDefaultFeatures: disableFeatures,
		})
		if err != nil {
			if clusterInstance != nil {
				clusterInstance.Delete()
			}
			msg := fmt.Sprintf("failed to create cluster: %s\n", err.Error())
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, msg)
		}

		toFormat, err := convertStructToMap(clusterInstance.GetConfig())
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		formatted := formatClusterConfig(toFormat)
		if !Debug {
			delete(formatted, "PrivateNodeIDs")
			delete(formatted, "PublicNodeIDs")
		}
		jsoned, err := json.Marshal(formatted)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		fmt.Println(string(jsoned))
		return nil
	},
}

// clusterDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterDeleteCommand = cli.Command{
	Name:      "delete",
	Aliases:   []string{"destroy", "remove", "rm"},
	Usage:     "delete CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> delete|destroy|remove|rm [-y]`,
	// 		Options: []string{`
	// options:
	//   -y,--assume-yes  Don't ask for confirmation`,
	// 		},
	// 		Description: `
	// Delete a cluster.`,
	// 	},

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
		force := c.Bool("force")

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete Cluster '%s'", clusterName)) {
			fmt.Println("Aborted.")
			return nil
		}
		if force {
			log.Println("'-f,--force' does nothing yet")
		}

		err = clusterInstance.Delete()
		if err != nil {
			return clitools.ExitOnRPC(err.Error())
		}

		fmt.Printf("Cluster '%s' deleted.\n", clusterName)
		return nil
	},
}

// clusterStopCmd handles 'deploy cluster <clustername> stop'
var clusterStopCommand = cli.Command{
	Name:      "stop",
	Aliases:   []string{"freeze", "halt"},
	Usage:     "stop CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> stop|freeze`,
	// 		Description: `
	// Stop the cluster (make it unavailable for duty).`,
	// 	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		err = clusterInstance.Stop()
		if err != nil {
			return clitools.ExitOnRPC(err.Error())
		}
		fmt.Printf("Cluster '%s' stopped.\n", clusterName)
		return nil
	},
}

var clusterStartCommand = cli.Command{
	Name:      "start",
	Aliases:   []string{"unfreeze"},
	Usage:     "start CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",
	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> start|unfreeze`,
	// 		Options: []string{`
	// options:
	//   --force, -f Force Don't ask for confirmation`,
	// 		},
	// 		Description: `
	// Start the cluster (make it available for duty).`,
	// 	},
	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = clusterInstance.Start()
		if err != nil {
			return clitools.ExitOnRPC(err.Error())
		}
		fmt.Printf("Cluster '%s' started.\n", clusterName)
		return nil
	},
}

// clusterStateCmd handles 'deploy cluster <clustername> state'
var clusterStateCommand = cli.Command{
	Name:      "state",
	Usage:     "state CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> state`,
	// 		Description: `
	// Get the cluster state.`,
	// 	},
	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		state, err := clusterInstance.GetState()
		if err != nil {
			msg := fmt.Sprintf("failed to get cluster state: %s", err.Error())
			return clitools.ExitOnRPC(msg)
		}
		out, _ := json.Marshal(map[string]interface{}{
			"Name":       clusterName,
			"State":      state,
			"StateLabel": state.String(),
		})
		fmt.Println(string(out))
		return nil
	},
}

// clusterExpandCmd handles 'deploy cluster <clustername> expand'
var clusterExpandCommand = cli.Command{
	Name:      "expand",
	Usage:     "expand CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> expand [{command options}] [{host options}]`,
	// 		Options: []string{
	// 			`
	// command options:
	//   --count,-n <number of nodes> Instructs to expand cluster with <number> of new nodes
	//   --public,-p                  Allocates public IP address(es) to node(s)`,
	// 			`
	// host options:
	//   --os <operating system> (default: Ubuntu 16.04)
	//   --cpu <number of cpus> (default: 4)
	//   --ram <ram size) (default: 15 GB)
	//   --disk <disk size> (default: 100 GB)`,
	// 		},
	// 		Description: `
	// Expand the cluster by adding nodes.`,
	// 	},

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

		count := int(c.Uint("count"))
		if count == 0 {
			count = 1
		}
		public := c.Bool("public")
		los := c.String("os")
		cpu := int32(c.Uint("cpu"))
		ram := float32(c.Float64("ram"))
		disk := int32(c.Uint("disk"))
		//gpu := c.Bool("gpu")
		_ = c.Bool("gpu")

		// err := createNodes(clusterName, public, count, los, cpu, ram, disk)
		var nodeRequest *pb.HostDefinition
		if los != "" || cpu > 0 || ram > 0.0 || disk > 0 {
			nodeRequest = &pb.HostDefinition{
				CPUNumber: cpu,
				RAM:       ram,
				Disk:      disk,
				ImageID:   los,
			}
		}
		hosts, err := clusterInstance.AddNodes(count, public, nodeRequest)
		if err != nil {
			return clitools.ExitOnRPC(err.Error())
		}
		jsoned, _ := json.Marshal(&hosts)
		fmt.Println(string(jsoned))
		return nil
	},
}

// clusterShrinkCommand handles 'deploy cluster <clustername> shrink'
var clusterShrinkCommand = cli.Command{
	Name:      "shrink",
	Usage:     "shrink CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> shrink [{command options}]`,
	// 		Options: []string{
	// 			`
	// command options:
	//   -n,--count <number of nodes>  Number of nodes to delete from the cluster`,
	// 		},
	// 		Description: `
	// Shrink cluster by removing last added node(s).`,
	// 	},

	Flags: []cli.Flag{
		cli.UintFlag{
			Name:  "count, n",
			Usage: "Define the number of nodes to remove; default: 1",
			Value: 1,
		},
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "Tell if the node(s) to remove has(ve) to be public; default: no",
		},
		cli.BoolFlag{
			Name:  "assume-yes, yes, y",
			Usage: "Don't ask deletion confirmation",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		count := c.Uint("count")
		public := c.Bool("public")
		yes := c.Bool("yes")

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
		present := clusterInstance.CountNodes(public)
		if count > present {
			msg := fmt.Sprintf("can't delete %d %s node%s, the cluster contains only %d of them", count, nodeTypeString, countS, present)
			return clitools.ExitOnInvalidOption(msg)
		}

		if !yes {
			msg := fmt.Sprintf("Are you sure you want to delete %d %s node%s from Cluster %s", count, nodeTypeString, countS, clusterName)
			if !utils.UserConfirmed(msg) {
				fmt.Println("Aborted.")
				return nil
			}
		}

		fmt.Printf("Deleting %d %s node%s from Cluster '%s' (this may take a while)...\n", count, nodeTypeString, countS, clusterName)
		var msgs []string
		availableMaster, err := clusterInstance.FindAvailableMaster()
		if err != nil {
			return err
		}
		for i := uint(0); i < count; i++ {
			err := clusterInstance.DeleteLastNode(public, availableMaster)
			if err != nil {
				msgs = append(msgs, fmt.Sprintf("Failed to delete node #%d: %s", i+1, err.Error()))
			}
		}
		if len(msgs) > 0 {
			return clitools.ExitOnRPC(strings.Join(msgs, "\n"))
		}
		fmt.Printf("%d %s node%s successfully deleted from cluster '%s'.\n", count, nodeTypeString, countS, clusterName)
		return nil
	},
}

var clusterDcosCommand = cli.Command{
	Name:      "dcos",
	Category:  "Administrative commands",
	Usage:     "dcos CLUSTERNAME [COMMAND ...]",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> dcos [<arg>...]`,
	// 		Description: `
	// Executes DCOS cli on an available DCOS master.
	// Is meaningful only for a cluster using DCOS flavor.`,
	// 	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		config := clusterInstance.GetConfig()
		if config.Flavor != Flavor.DCOS {
			msg := fmt.Sprintf("Can't call dcos on this cluster, its flavor isn't DCOS (%s).\n", config.Flavor.String())
			return clitools.ExitOnErrorWithMessage(ExitCode.NotApplicable, msg)
		}
		args := c.Args().Tail()
		cmdStr := "sudo -u cladm -i dcos " + strings.Join(args, " ")
		return executeCommand(cmdStr)
	},
}

var clusterKubectlCommand = cli.Command{
	Name:      "kubectl",
	Category:  "Administrative commands",
	Usage:     "kubectl CLUSTERNAME [COMMAND ...]",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> kubectl [-- <arg>...]`,
	// 		Description: `
	// Executes kubectl cli on the cluster.
	// Is meaningful only for a cluster where Kubernetes service is installed and running.`,
	// 	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		args := c.Args().Tail()
		cmdStr := "sudo -u cladm -i kubectl " + strings.Join(args, " ")
		return executeCommand(cmdStr)
	},
}

var clusterRunCommand = cli.Command{
	Name:      "run",
	Aliases:   []string{"execute", "exec"},
	Usage:     "run CLUSTERNAME COMMAND",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster list,ls
	//        {{.ProgName}} [options] cluster <clustername> run args[,args...]`,
	// 	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		fmt.Println()
		return clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "clusterRunCmd not yet implemented")
	},
}

func executeCommand(command string) error {
	masters := clusterInstance.ListMasterIDs()
	if len(masters) <= 0 {
		msg := fmt.Sprintf("No masters found for the cluster '%s'", clusterInstance.GetName())
		return clitools.ExitOnErrorWithMessage(ExitCode.Run, msg)
	}
	brokerssh := brokerclient.New().Ssh
	for i, m := range masters {
		retcode, stdout, stderr, err := brokerssh.Run(m, command, brokerclient.DefaultConnectionTimeout, 5*time.Minute)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to execute command on master #%d: %s", i+1, err.Error())
			if i+1 < len(masters) {
				fmt.Fprintln(os.Stderr, "Trying another master...")
			}
		}
		if retcode != 0 {
			output := stdout
			if output != "" {
				output += "\n"
			}
			output += stderr
			// fmt.Fprintf(os.Stderr, "Run on master #%d, retcode=%d\n%s\n", i+1, retcode, output)
			return clitools.ExitOnRPC(output)
		}
		fmt.Println(stdout)
		return nil
	}

	return clitools.ExitOnRPC("failed to find an available master server to execute the command.")
}

// clusterAddFeatureCommand handles 'deploy cluster add-feature CLUSTERNAME FEATURENAME'
var clusterAddFeatureCommand = cli.Command{
	Name:      "add-feature",
	Aliases:   []string{"install-feature"},
	Usage:     "add-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",

	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
		cli.BoolFlag{
			Name:  "skip-proxy",
			Usage: "Disables reverse proxy rules",
		},
	},

	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}

		feature, err := install.NewFeature(featureName)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.\n", featureName)
			return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg)
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := install.Settings{}
		settings.SkipProxy = c.Bool("skip-proxy")

		target := install.NewClusterTarget(clusterInstance)
		results, err := feature.Add(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error installing feature '%s' on cluster '%s': %s\n", featureName, clusterName, err.Error())
			return clitools.ExitOnRPC(msg)
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Failed to install feature '%s' on cluster '%s'", featureName, clusterName)
			if Debug || Verbose {
				msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
			}
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, msg)
		}

		fmt.Printf("Feature '%s' installed successfully on cluster '%s'\n", featureName, clusterName)
		return nil
	},
}

// clusterCheckFeatureCommand handles 'deploy cluster check-feature CLUSTERNAME FEATURENAME'
var clusterCheckFeatureCommand = cli.Command{
	Name:      "check-feature",
	Aliases:   []string{"verify-feature"},
	Usage:     "check-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
	},
	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}
		feature, err := install.NewFeature(featureName)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.\n", featureName)
			return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg)
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := install.Settings{}

		target := install.NewClusterTarget(clusterInstance)
		results, err := feature.Check(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error checking if feature '%s' is installed on '%s': %s\n", featureName, clusterName, err.Error())
			return clitools.ExitOnRPC(msg)
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Feature '%s' not found on cluster '%s'", featureName, clusterName)
			if Verbose || Debug {
				msg += fmt.Sprintf(":\n%s", results.AllErrorMessages())
			}
		}
		fmt.Printf("Feature '%s' found on cluster '%s'\n", featureName, clusterName)
		return nil
	},
}

// clusterFeatureDeleteCommand handles 'deploy host <host name or id> package <pkgname> delete'
var clusterDeleteFeatureCommand = cli.Command{
	Name:      "delete-feature",
	Aliases:   []string{"destroy-feature", "remove-feature", "rm-feature", "uninstall-feature"},
	Usage:     "delete-feature CLUSTERNAME FEATURENAME",
	ArgsUsage: "CLUSTERNAME FEATURENAME",
	Flags: []cli.Flag{
		cli.StringSliceFlag{
			Name:  "param, p",
			Usage: "Allow to define content of feature parameters",
		},
	},
	Action: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}
		err = extractFeatureArgument(c)
		if err != nil {
			return err
		}
		feature, err := install.NewFeature(featureName)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		if feature == nil {
			msg := fmt.Sprintf("Failed to find a feature named '%s'.\n", featureName)
			return clitools.ExitOnErrorWithMessage(ExitCode.NotFound, msg)
		}

		values := install.Variables{}
		params := c.StringSlice("param")
		for _, k := range params {
			res := strings.Split(k, "=")
			if len(res[0]) > 0 {
				values[res[0]] = strings.Join(res[1:], "=")
			}
		}

		settings := install.Settings{}
		// TODO: Reverse proxy rules are not yet purged when feature is removed, but current code
		// will try to apply them... Quick fix: Setting SkipProxy to true prevent this
		settings.SkipProxy = true

		target := install.NewClusterTarget(clusterInstance)
		results, err := feature.Remove(target, values, settings)
		if err != nil {
			msg := fmt.Sprintf("Error uninstalling feature '%s' on '%s': %s\n", featureName, clusterName, err.Error())
			return clitools.ExitOnRPC(msg)
		}
		if !results.Successful() {
			msg := fmt.Sprintf("Failed to delete feature '%s' from cluster '%s'", featureName, clusterName)
			if Verbose || Debug {
				msg += fmt.Sprintf(":\n%s\n", results.AllErrorMessages())
			}
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, msg)
		}
		fmt.Printf("Feature '%s' deleted successfully from cluster '%s'\n", featureName, clusterName)
		return nil
	},
}

// clusterNodeCommand handles 'deploy cluster <name> node'
var clusterNodeCommand = cli.Command{
	Name: "node",

	Subcommands: []cli.Command{
		clusterNodeListCommand,
		clusterNodeInspectCommand,
		clusterNodeStartCommand,
		clusterNodeStopCommand,
		clusterNodeStateCommand,
	},

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> COMMAND
	//        {{.ProgName}} [options] cluster <clustername> node list|ls`,
	// 		Commands: `
	//   list|ls         Lists nodes in cluster
	//   inspect         Displays information about the node
	//   stop|freeze     Stops the node
	//   start|unfreeze  Delete a Cluster
	//   state           Returns current state of the node`,
	// 		Description: `
	// Deploy a new cluster <clustername> or something on the cluster <clustername>.`,
	// 		Footer: `
	// Run 'deploy cluster COMMAND --help' for more information on a command.`,
	// 	},

	Before: func(c *cli.Context) error {
		err := extractClusterArgument(c)
		if err != nil {
			return err
		}

		if !c.Command.HasName("list") {
			hostName = c.Args().Get(1)
			if hostName == "" {
				fmt.Fprintln(os.Stderr, "missing mandatory argument HOSTNAME")
				_ = cli.ShowSubcommandHelp(c)
				return clitools.ExitOnInvalidArgument()
			}

			var err error
			hostInstance, err = brokerclient.New().Host.Inspect(hostName, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				msg := fmt.Sprintf("Failed to list nodes of cluster '%s'", clusterName)
				return clitools.ExitOnRPC(msg)
			}
		}

		return nil
	},
}

// clusterNodeListCommand handles 'deploy cluster node list CLUSTERNAME'
var clusterNodeListCommand = cli.Command{
	Name:      "list",
	Aliases:   []string{"ls"},
	Usage:     "list CLUSTERNAME",
	ArgsUsage: "CLUSTERNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node list|ls`,
	// 		Description: `
	// List nodes in the clusters.`,
	// 	},

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "public, p",
			Usage: "If set, list public nodes. Otherwise list private nodes.",
		},
		cli.BoolFlag{
			Name:  "all, a",
			Usage: "If set, list all nodes, being private or public. Take precedence over --public",
		},
	},

	Action: func(c *cli.Context) error {
		public := c.Bool("public")
		all := c.Bool("all")

		broker := brokerclient.New().Host
		formatted := []map[string]interface{}{}

		if all || !public {
			listPriv := clusterInstance.ListNodeIDs(false)
			for _, i := range listPriv {
				host, err := broker.Inspect(i, brokerclient.DefaultExecutionTimeout)
				if err != err {
					msg := fmt.Sprintf("Failed to get data for node '%s': %s. Ignoring.", i, err.Error())
					fmt.Println(msg)
					log.Warnln(msg)
					continue
				}
				formatted = append(formatted, map[string]interface{}{
					"name":   host.Name,
					"public": false,
				})
			}
		}

		if all || public {
			listPub := clusterInstance.ListNodeIDs(true)
			for _, i := range listPub {
				host, err := broker.Inspect(i, brokerclient.DefaultExecutionTimeout)
				if err != err {
					msg := fmt.Sprintf("failed to get data for node '%s': %s. Ignoring.", i, err.Error())
					fmt.Println(msg)
					log.Warnln(msg)
					continue
				}
				formatted = append(formatted, map[string]interface{}{
					"name":   host.Name,
					"public": true,
				})
			}
		}

		jsoned, err := json.Marshal(formatted)
		if err != nil {
			log.Errorln(err.Error())
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		fmt.Println(string(jsoned))
		return nil
	},
}

// formatNodeConfig...
func formatNodeConfig(value interface{}) map[string]interface{} {
	core := value.(map[string]interface{})
	return core
}

// clusterNodeInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterNodeInspectCommand = cli.Command{
	Name:      "inspect",
	Usage:     "node inspect CLUSTERNAME HOSTNAME",
	ArgsUsage: "CLUSTERNAME is the name of the cluster\nHOSTNAME is the hostname of the host resource inside the cluster (ie. for a cluster called 'demo', hostname is 'node-1' and host resourcename is 'demo-node-1')",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node <hostname> inspect`,
	// 		Description: `
	// Displays information about the node <hostname> of cluster <clustername>.`,
	// 	},

	Action: func(c *cli.Context) error {
		host, err := brokerclient.New().Host.Inspect(hostName, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			return clitools.ExitOnRPC(err.Error())
		}

		jsoned, err := json.Marshal(host)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}

		toFormat := map[string]interface{}{}
		err = json.Unmarshal(jsoned, &toFormat)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}

		jsoned, err = json.Marshal(toFormat)
		if err != nil {
			return clitools.ExitOnErrorWithMessage(ExitCode.Run, err.Error())
		}
		fmt.Printf(string(jsoned))
		return nil
	},
}

// clusterNodeDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterNodeDeleteCommand = &cli.Command{
	Name:    "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> node <nodename> delete|destroy|remove|rm [-y]`,
	// 		Options: []string{`
	// options:
	//   -y,--assume-yes  Don't ask for confirmation`,
	// 		},
	// 		Description: `
	// Delete the node <nodename> from the cluster <clustername>.`,
	// 	},

	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "yes, assume-yes, y",
			Usage: "If set, respond automatically yes to all questions",
		},
		cli.BoolFlag{
			Name:  "force, f",
			Usage: "If set, force node deletion no matter what (ie. metadata inconsistency)",
		},
	},

	Action: func(c *cli.Context) error {
		yes := c.Bool("yes")
		force := c.Bool("force")

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure you want to delete the node '%s' of the cluster '%s'", hostName, clusterName)) {
			fmt.Println("Aborted.")
			return nil
		}
		if force {
			log.Println("'-f,--force' does nothing yet")
		}

		err := clusterInstance.Delete()
		if err != nil {
			return clitools.ExitOnRPC(err.Error())
		}

		fmt.Printf("Node '%s' of cluster '%s' deleted successfully.\n", hostName, clusterName)
		return nil
	},
}

// clusterNodeStopCmd handles 'deploy cluster <clustername> node <nodename> stop'
var clusterNodeStopCommand = cli.Command{
	Name:    "stop",
	Aliases: []string{"freeze"},
	Usage:   "node stop CLUSTERNAME HOSTNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: deploy [options] cluster <clustername> stop|freeze`,
	// 		Description: `
	// Stop the cluster (make it unavailable for duty).`,
	// 	},

	Action: func(c *cli.Context) error {
		return clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "Not yet implemented")
	},
}

// clusterNodeStartCmd handles 'deploy cluster <clustername> node <nodename> start'
var clusterNodeStartCommand = cli.Command{
	Name:    "start",
	Aliases: []string{"unfreeze"},

	//Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> start|unfreeze`,
	// 		Options: []string{`
	// options:
	//   --force, -f Force Don't ask for confirmation`,
	// 		},
	// 		Description: `
	// Start the node <nodename> of the cluster <clustername>.`,
	// 	},

	Action: func(c *cli.Context) error {
		return clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "Not yet implemented")
	},
}

// clusterNodeStateCmd handles 'deploy cluster <clustername> state'
var clusterNodeStateCommand = cli.Command{
	Name:  "state",
	Usage: "node state CLUSTERNAME HOSTNAME",

	// 	Help: &cli.HelpContent{
	// 		Usage: `
	// Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> state`,
	// 		Description: `
	// Get the state of the node <nodename> of the cluster <clustername>.`,
	// 	},

	Action: func(c *cli.Context) error {
		return clitools.ExitOnErrorWithMessage(ExitCode.NotImplemented, "Not yet implemented")
	},
}
