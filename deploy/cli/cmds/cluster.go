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
	"log"
	"os"
	"strings"
	"time"

	"github.com/CS-SI/SafeScale/deploy/cluster"

	clusterapi "github.com/CS-SI/SafeScale/deploy/cluster/api"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/ClusterState"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Complexity"
	"github.com/CS-SI/SafeScale/deploy/cluster/api/Flavor"

	"github.com/CS-SI/SafeScale/utils"
	"github.com/CS-SI/SafeScale/utils/brokeruse"
	cli "github.com/CS-SI/SafeScale/utils/cli"
	"github.com/CS-SI/SafeScale/utils/cli/ExitCode"
)

const (
	ubuntu1604 = "Ubuntu 16.04"
)

var (
	clusterName        string
	clusterServiceName *string
	clusterInstance    clusterapi.ClusterAPI
)

// ClusterCommand handles 'deploy cluster'
var ClusterCommand = &cli.Command{
	Keyword: "cluster",

	Commands: []*cli.Command{
		clusterListCommand,
		clusterCreateCommand,
		clusterInspectCommand,
		clusterDeleteCommand,
		clusterExpandCommand,
		clusterShrinkCommand,
		clusterDcosCommand,
		clusterKubectlCommand,
		clusterMarathonCommand,
	},

	Process: func(c *cli.Command) {
		if !c.IsKeywordSet("list,ls") {
			clusterName = c.StringArgument("<clustername>", "")
			if clusterName == "" {
				fmt.Println("Invalid argument <clustername>")
				os.Exit(int(ExitCode.InvalidArgument))
			}

			var err error
			clusterInstance, err = cluster.Get(clusterName)
			if err != nil {
				fmt.Printf("%v\n", err)
				os.Exit(int(ExitCode.RPC))
			}
			if !c.IsKeywordSet("create") {
				if clusterInstance == nil {
					fmt.Printf("Cluster '%s' not found.\n", clusterName)
					os.Exit(int(ExitCode.NotFound))
				}
			} else {
				if clusterInstance != nil {
					fmt.Printf("Cluster '%s' already exists.\n", clusterName)
					os.Exit(int(ExitCode.Duplicate))
				}
			}
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> COMMAND
       {{.ProgName}} [options] cluster list|ls`,
		Commands: `
  create                    Creates a cluster
  inspect                   Display detailed information on a cluster
  delete,destroy,remove,rm  Delete a Cluster`,
		Description: `
Deploy a new cluster <clustername> or something on the cluster <clustername>.`,
		Footer: `
Run 'deploy cluster COMMAND --help' for more information on a command.`,
	},
}

// clusterListCommand handles 'deploy cluster list'
var clusterListCommand = &cli.Command{
	Keyword: "list",
	Aliases: []string{"ls"},

	Process: func(c *cli.Command) {
		list, err := cluster.List()
		if err != nil {
			fmt.Printf("Could not get cluster list: %v\n", err)
			os.Exit(int(ExitCode.NotFound))
		}
		jsoned, err := json.Marshal(list)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.Run))
		}
		var toFormat []interface{}
		err = json.Unmarshal(jsoned, &toFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.Run))
		}
		var formatted []interface{}
		for _, value := range toFormat {
			formatted = append(formatted, formatClusterConfig(value))
		}
		jsoned, err = json.Marshal(formatted)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.Run))
		}
		fmt.Println(string(jsoned))
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster list|ls`,
		Description: `
List available clusters.`,
	},
}

// formatClusterConfig...
func formatClusterConfig(value interface{}) map[string]interface{} {
	item := value.(map[string]interface{})

	e := Flavor.Enum(int(item["Flavor"].(float64)))
	item["FlavorLabel"] = e.String()

	c := Complexity.Enum(int(item["Complexity"].(float64)))
	item["ComplexityLabel"] = c.String()

	s := ClusterState.Enum(int(item["State"].(float64)))
	item["StateLabel"] = s.String()

	if !Debug {
		delete(item, "AdditionalInfo")
		delete(item, "PrivateNodeIDs")
		delete(item, "PublicNodeIDs")
		delete(item, "Keypair")
	}

	return item
}

// clusterInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterInspectCommand = &cli.Command{
	Keyword: "inspect",

	Process: func(c *cli.Command) {
		err := outputClusterConfig(clusterInstance.GetConfig())
		if err != nil {
			fmt.Printf("%v\n", err)
		}
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> inspect`,
		Description: `
Displays information about the cluster 'clustername'.`,
	},
}

// outputClusterConfig displays cluster configuration after filtering and completing some fields
func outputClusterConfig(result interface{}) error {
	toFormat, err := convertStructToMap(result)
	if err != nil {
		return err
	}
	formatted := formatClusterConfig(toFormat)

	jsoned, err := json.Marshal(formatted)
	if err != nil {
		return err
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
	return toFormat, nil
}

// clusterCreateCmd handles 'deploy cluster <clustername> create'
var clusterCreateCommand = &cli.Command{
	Keyword: "create",

	Process: func(c *cli.Command) {
		complexityStr := c.StringOption("-C,--complexity", "<complexity>", "Normal")
		complexity, err := Complexity.Parse(complexityStr)
		if err != nil {
			fmt.Printf("Invalid option --complexity,-C: %s\n", err.Error())
			os.Exit(int(ExitCode.InvalidOption))
		}

		flavorStr := c.StringOption("-F,--flavor", "<flavor>", "BOH")
		flavor, err := Flavor.Parse(flavorStr)
		if err != nil {
			fmt.Printf("Invalid option --flavor,-F: %s\n", err.Error())
			os.Exit(int(ExitCode.InvalidOption))
		}

		keep := c.Flag("-k,--keep-on-failure", false)

		cidr := c.StringOption("-N,--cidr", "<cidr>", "")
		if cidr == "" {
			fmt.Printf("Invalid option -N,--cidr\n")
			os.Exit(int(ExitCode.InvalidOption))
		}

		clusterInstance, err = cluster.Create(clusterapi.Request{
			Name:          clusterName,
			Complexity:    complexity,
			CIDR:          cidr,
			Flavor:        flavor,
			KeepOnFailure: keep,
		})
		if err != nil {
			if clusterInstance != nil {
				clusterInstance.Delete()
			}
			fmt.Printf("failed to create cluster: %s", err.Error())
			os.Exit(int(ExitCode.Run))
		}

		// jsoned, err := json.Marshal(clusterInstance.GetConfig())
		// if err != nil {
		// 	fmt.Printf("%v\n", err)
		// 	os.Exit(int(ExitCode.Run))
		// }
		// var toFormat map[string]interface{}
		// err = json.Unmarshal(jsoned, &toFormat)
		// if err != nil {
		// 	fmt.Printf("%v\n", err)
		// 	os.Exit(int(ExitCode.Run))
		// }
		toFormat, err := convertStructToMap(clusterInstance.GetConfig())
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.Run))
		}
		formatted := formatClusterConfig(toFormat)
		if !Debug {
			delete(formatted, "PrivateNodeIDs")
			delete(formatted, "PublicNodeIDs")
		}
		jsoned, err := json.Marshal(formatted)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.Run))
		}
		fmt.Println(string(jsoned))
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> create {cluster options} {host options}`,
		Options: []string{
			`
cluster options:
  -N,--cidr <cidr>                To specify the CIDR of the associated network created with cluster
  [-F,--flavor <flavor>]          To specify the management of cluster; can be DCOS or BOH (Bunch Of Hosts) (default: BOH)
  [-C,--complexity <complexity>]  To fix the cluster complexity; can be Dev, Normal, Volume (default: Normal)
  [-k,--keep-on-failure]          Keep resources on failure`,
			`
host options:
  --os <operating system> To specify linux distribution (default: Ubuntu 16.04)
  --cpu <number of cpus> To specify number of CPU (default: 4)
  --ram <ram size) To specify RAM size in GB (default: 15)
  --disk <disk size> To specify system disk size in GB (default: 100)`,
		},
		Description: `
Creates a new cluster.`,
	},
}

// clusterDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Process: func(c *cli.Command) {
		yes := c.Flag("-y,--assume-yes", false)
		force := c.Flag("-f,--force", false)

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure to delete Cluster '%s'", clusterName)) {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
		if force {
			log.Println("'-f,--force' does nothing yet")
		}

		err := clusterInstance.Delete()
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.RPC))
		}

		fmt.Printf("Cluster '%s' deleted.\n", clusterName)
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] cluster <clustername> delete|destroy|remove|rm [-y]`,
		Options: []string{`
options:
  -y,--assume-yes  Don't ask for confirmation`,
		},
		Description: `
Delete a cluster.`,
	},
}

// clusterStopCmd handles 'deploy cluster <clustername> stop'
var clusterStopCommand = &cli.Command{
	Keyword: "stop",
	Aliases: []string{"freeze"},

	Process: func(c *cli.Command) {
		err := clusterInstance.Stop()
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.RPC))
		}
		fmt.Printf("Cluster '%s' stopped.\n", clusterName)
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] cluster <clustername> stop|freeze`,
		Description: `
Stop the cluster (make it unavailable for duty).`,
	},
}

// clusterStartCmd handles 'deploy cluster <clustername> start'
var clusterStartCommand = &cli.Command{
	Keyword: "start",
	Aliases: []string{"unfreeze"},

	Process: func(c *cli.Command) {
		err := clusterInstance.Start()
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.RPC))
		}

		fmt.Printf("Cluster '%s' started.\n", clusterName)
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> start|unfreeze`,
		Options: []string{`
options:
  --force, -f Force Don't ask for confirmation`,
		},
		Description: `
Start the cluster (make it available for duty).`,
	},
}

// clusterStateCmd handles 'deploy cluster <clustername> state'
var clusterStateCommand = &cli.Command{
	Keyword: "state",

	Process: func(c *cli.Command) {
		state, err := clusterInstance.GetState()
		if err != nil {
			fmt.Printf("failed to get cluster state: %s", err.Error())
			os.Exit(int(ExitCode.RPC))
		}
		out, _ := json.Marshal(map[string]interface{}{
			"Name":       clusterName,
			"State":      state,
			"StateLabel": state.String(),
		})
		fmt.Println(string(out))
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> state`,
		Description: `
Get the cluster state.`,
	},
}

// clusterExpandCmd handles 'deploy cluster <clustername> expand'
var clusterExpandCommand = &cli.Command{
	Keyword: "expand",

	Process: func(c *cli.Command) {
		count := c.IntOption("-n,--count", "<count>", 1)
		public := c.Flag("-p,--public", false)
		los := c.StringOption("--os", "<os>", ubuntu1604)
		cpu := int32(c.IntOption("--cpu", "<cpu>", 2))
		ram := float32(c.FloatOption("--ram", "<ram>", 7.0))
		disk := int32(c.IntOption("--disk", "<disk>", 100))
		//gpu := c.Flag("--gpu", false)
		_ = c.Flag("--gpu", false)

		err := createNodes(clusterName, public, count, los, cpu, ram, disk)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.RPC))
		}
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] cluster <clustername> expand [{command options}] [{host options}]`,
		Options: []string{
			`
command options:
  --count,-n <number of nodes> Instructs to expand cluster with <number> of new nodes
  --public,-p                  Allocates public IP address(es) to node(s)`,
			`
host options:
  --os <operating system> (default: Ubuntu 16.04)
  --cpu <number of cpus> (default: 4)
  --ram <ram size) (default: 15 GB)
  --disk <disk size> (default: 100 GB)`,
		},
		Description: `
Expand the cluster by adding nodes.`,
	},
}

// clusterShrinkCommand handles 'deploy cluster <clustername> shrink'
var clusterShrinkCommand = &cli.Command{
	Keyword: "shrink",

	Process: func(c *cli.Command) {
		count := c.IntOption("-n,--count", "<count>", 1)
		public := c.Flag("-p,--public", false)

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
		if count > int(present) {
			fmt.Printf("can't delete %d %s node%s, the cluster contains only %d of them", count, nodeTypeString, countS, present)
			os.Exit(int(ExitCode.InvalidOption))
		}

		msg := fmt.Sprintf("Are you sure to delete %d %s node%s from Cluster %s", count, nodeTypeString, countS, clusterName)
		if !utils.UserConfirmed(msg) {
			fmt.Println("Aborted.")
			os.Exit(int(ExitCode.OK))
		}

		fmt.Printf("Deleting %d %s node%s from Cluster '%s' (this may take a while)...\n", count, nodeTypeString, countS, clusterName)
		for i := 0; i < count; i++ {
			err := clusterInstance.DeleteLastNode(public)
			if err != nil {
				fmt.Printf("Failed to delete node #%d: %s", i+1, err.Error())
				os.Exit(int(ExitCode.RPC))
			}
		}

		fmt.Printf("%d %s node%s successfully deleted from cluster '%s'.\n", count, nodeTypeString, countS, clusterName)
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> shrink [{command options}]`,
		Options: []string{
			`
command options:
  -n,--count <number of nodes>  Number of nodes to delete from the cluster`,
		},
		Description: `
Shrink cluster by removing last added node(s).`,
	},
}

// clusterPackageCommand handles 'deploy cluster <clustername> package'
var clusterPackageCommand = &cli.Command{
	Keyword: "package",
	Aliases: []string{"pkg"},

	Commands: []*cli.Command{
		clusterPackageAddCommand,
		clusterPackageCheckCommand,
		clusterPackageDeleteCommand,
	},

	Before: func(c *cli.Command) {
		// Preprocessing for 'deploy cluster package'
		pkgName := c.StringArgument("<pkgname>", "")
		if pkgName == "" {
			fmt.Println("Invalid argument <pkgname>")
			os.Exit(int(ExitCode.InvalidArgument))
		}

		pkgManagerKind := c.StringOption("-K,--kind", "<kind>", "")
		if pkgManagerKind == "" {
			fmt.Println("missing or invalid mandatory option '-K,--kind'")
			os.Exit(int(ExitCode.InvalidArgument))
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> package|pkg <pkgname> -K <kind> COMMAND`,
		Options: []string{
			`
Commands:
  check        To check if package is installed and on what nodes
  add,install  Installs specific package to all nodes of the cluster
  delete,destroy,remove,rm,uninstall  Uninstall a package from all nodes of the cluster`,
			`
Package options:
  -K,--kind  Filters the nodes on the package manager used by the Linux distribution`,
		},
		Description: `
Manages package on all (filtered on package manager) nodes of the cluster <clustername> .`,
	},
}

// clusterPackageAddCommand handles 'deploy cluster <clustername> package <pkgname> add'
var clusterPackageAddCommand = &cli.Command{
	Keyword: "add",

	Process: func(c *cli.Command) {
		fmt.Println("clusterPackageAddCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// clusterPackageCheckCommand handles 'deploy cluster <clustername> package <pkgname> check'
var clusterPackageCheckCommand = &cli.Command{
	Keyword: "check",

	Process: func(c *cli.Command) {
		fmt.Println("clusterPackageCheckCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// clusterPackageDeleteCmd handles 'deploy cluster <clustername> package <pkgname> delete'
var clusterPackageDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Process: func(c *cli.Command) {
		fmt.Println("clusterPackageDeleteCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

// clusterServiceCommand handles 'deploy cluster <clustername> service'
var clusterServiceCommand = &cli.Command{
	Keyword: "service",
	Aliases: []string{"svc"},

	Commands: []*cli.Command{
		clusterServiceAddCommand,
		clusterServiceAvailableCommand,
		clusterServiceCheckCommand,
		clusterServiceDeleteCommand,
		clusterServiceStartCommand,
		clusterServiceStateCommand,
		clusterServiceStopCommand,
	},

	Before: func(c *cli.Command) {
		svcName := c.StringArgument("<svcname>", "")
		if svcName == "" {
			fmt.Println("Invalid argument <svcname>")
			os.Exit(int(ExitCode.InvalidArgument))
		}
	},

	Help: &cli.HelpContent{},
}

var clusterServiceAvailableCommand = &cli.Command{
	Keyword: "available",
	Aliases: []string{"avail"},

	Process: func(c *cli.Command) {
		fmt.Println("clusterServiceAvailableCommand not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

var clusterServiceCheckCommand = &cli.Command{
	Keyword: "check",

	Process: func(c *cli.Command) {
		fmt.Println("clusterServiceCheckCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

var clusterServiceAddCommand = &cli.Command{
	Keyword: "add",

	Process: func(c *cli.Command) {
		fmt.Println("clusterServiceAddCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

var clusterServiceDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Process: func(c *cli.Command) {
		fmt.Println("clusterServiceDeleteCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

var clusterServiceStartCommand = &cli.Command{
	Keyword: "start",

	Process: func(c *cli.Command) {
		fmt.Println("clusterServiceStartCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{ .ProgName }} [options] cluster <clustername> start`,
		Description: `
Starts a cluster (make it available for duty).`,
	},
}

var clusterServiceStateCommand = &cli.Command{
	Keyword: "state",

	Process: func(c *cli.Command) {
		fmt.Println("clusterServiceStateCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] cluster <clustername> state`,
		Description: `
Gets the state of the cluster <clustername>.`,
	},
}

var clusterServiceStopCommand = &cli.Command{
	Keyword: "stop",

	Process: func(c *cli.Command) {
		fmt.Println("clusterServiceStopCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{},
}

var clusterDcosCommand = &cli.Command{
	Keyword: "dcos",

	Process: func(c *cli.Command) {
		config := clusterInstance.GetConfig()
		if config.Flavor != Flavor.DCOS {
			fmt.Printf("Can't call dcos on this cluster, its flavor isn't DCOS (%s).\n", config.Flavor.String())
			os.Exit(int(ExitCode.NotApplicable))
		}
		args := c.StringSliceArgument("<arg>", []string{})

		cmdStr := "sudo -u cladm -i dcos " + strings.Join(args, " ")
		executeCommand(cmdStr)
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] cluster <clustername> dcos [<arg>...]`,
		Description: `
Executes DCOS cli on an available DCOS master.
Is meaningful only for a cluster using DCOS flavor.`,
	},
}

var clusterKubectlCommand = &cli.Command{
	Keyword: "kubectl",

	Process: func(c *cli.Command) {
		args := c.StringSliceArgument("<arg>", []string{})

		cmdStr := "sudo -u cladm -i kubectl " + strings.Join(args, " ")
		executeCommand(cmdStr)
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] cluster <clustername> kubectl [-- <arg>...]`,
		Description: `
Executes kubectl cli on the cluster.
Is meaningful only for a cluster where Kubernetes service is installed and running.`,
	},
}

var clusterMarathonCommand = &cli.Command{
	Keyword: "marathon",

	Process: func(c *cli.Command) {
		args := c.StringSliceArgument("<arg>", []string{})

		cmdStr := "sudo -u cladm -i marathon " + strings.Join(args, " ")
		executeCommand(cmdStr)
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> marathon [<arg>...]`,
		Description: `
Executes Marathon cli on an available master.
Is meaningful only for a cluster using DCOS flavor.`,
	},
}

var clusterRunCommand = &cli.Command{
	Keyword: "run",
	Aliases: []string{"execute", "exec"},

	Process: func(c *cli.Command) {
		fmt.Println("clusterRunCmd not yet implemented")
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster list,ls
       {{.ProgName}} [options] cluster <clustername> COMMAND`,
		Commands: `
  list,ls
  create
  inspect
  delete,destroy,remove,rm  Delete the cluster`,
	},
}

func executeCommand(command string) (int, string, string, error) {
	masters, err := clusterInstance.GetMasters()
	if err != nil {
		fmt.Printf("Failed to get masters for the cluster '%s': %s", clusterInstance.GetName(), err.Error())
		os.Exit(int(ExitCode.Run))
	}
	for i, m := range masters {
		retcode, _, stderr, err := brokeruse.SSHRun(m, command, 5*time.Minute)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to execute command on master #%d: %s", i+1, err.Error())
			if i+1 < len(masters) {
				fmt.Fprintln(os.Stderr, "Trying another master...")
			}
		}
		if retcode != 0 {
			fmt.Fprintf(os.Stderr, "Command failed on master #%d: %s", i+1, stderr)
			os.Exit(int(ExitCode.RPC))
		}
		os.Exit(int(ExitCode.OK))
	}

	fmt.Println("failed to find an available master server to execute the command.")
	os.Exit(int(ExitCode.RPC))

	return 0, "", "", nil
}
