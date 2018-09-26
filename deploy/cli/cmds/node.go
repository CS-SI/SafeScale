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

	pb "github.com/CS-SI/SafeScale/broker"
	brokerclient "github.com/CS-SI/SafeScale/broker/client"

	"github.com/CS-SI/SafeScale/utils"
	cli "github.com/CS-SI/SafeScale/utils/cli"
	"github.com/CS-SI/SafeScale/utils/cli/ExitCode"
)

var (
	nodeName     string
	nodeInstance *pb.Host
)

// clusterNodeCommand handles 'deploy cluster <name> node'
var clusterNodeCommand = &cli.Command{
	Keyword: "node",

	Commands: []*cli.Command{
		clusterNodeListCommand,
		clusterNodeInspectCommand,
	},

	Before: func(c *cli.Command) {
		if !c.IsKeywordSet("list,ls") {
			nodeName = c.StringArgument("<nodename>", "")
			if nodeName == "" {
				fmt.Println("Invalid argument <nodename>")
				os.Exit(int(ExitCode.InvalidArgument))
			}

			var err error
			nodeInstance, err = brokerclient.New().Host.Inspect(nodeName, brokerclient.DefaultExecutionTimeout)
			if err != nil {
				fmt.Printf("%s\n", err.Error())
				os.Exit(int(ExitCode.RPC))
			}
		}
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> COMMAND
       {{.ProgName}} [options] cluster <clustername> node list|ls`,
		Commands: `
  list|ls         Lists nodes in cluster
  inspect         Displays information about the node
  stop|freeze     Stops the node
  start|unfreeze  Delete a Cluster
  state           Returns current state of the node`,
		Description: `
Deploy a new cluster <clustername> or something on the cluster <clustername>.`,
		Footer: `
Run 'deploy cluster COMMAND --help' for more information on a command.`,
	},
}

// clusterNodeListCommand handles 'deploy cluster list'
var clusterNodeListCommand = &cli.Command{
	Keyword: "list",
	Aliases: []string{"ls"},

	Process: func(c *cli.Command) {
		listPriv := clusterInstance.ListNodeIDs(false)
		listPub := clusterInstance.ListNodeIDs(true)
		broker := brokerclient.New().Host
		formatted := []map[string]interface{}{}
		for _, i := range listPriv {
			host, err := broker.Inspect(i, brokerclient.DefaultExecutionTimeout)
			if err != err {
				fmt.Fprintf(os.Stderr, "failed to get data for node '%s': %s. Ignoring.", i, err.Error())
				continue
			}
			formatted = append(formatted, map[string]interface{}{
				"name":   host.Name,
				"public": false,
			})
		}
		for _, i := range listPub {
			host, err := broker.Inspect(i, brokerclient.DefaultExecutionTimeout)
			if err != err {
				fmt.Fprintf(os.Stderr, "failed to get data for node '%s': %s. Ignoring.", i, err.Error())
				continue
			}
			formatted = append(formatted, map[string]interface{}{
				"name":   host.Name,
				"public": true,
			})
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
Usage: {{.ProgName}} [options] cluster <clustername> node list|ls`,
		Description: `
List nodes in the clusters.`,
	},
}

// formatNodeConfig...
func formatNodeConfig(value interface{}) map[string]interface{} {
	core := value.(map[string]interface{})
	return core
}

// clusterNodeInspectCmd handles 'deploy cluster <clustername> inspect'
var clusterNodeInspectCommand = &cli.Command{
	Keyword: "inspect",

	Process: func(c *cli.Command) {
		host, err := brokerclient.New().Host.Inspect(nodeName, brokerclient.DefaultExecutionTimeout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to get node information")
			os.Exit(int(ExitCode.RPC))
		}

		jsoned, err := json.Marshal(host)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.Run))
		}

		toFormat := map[string]interface{}{}
		err = json.Unmarshal(jsoned, &toFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.Run))
		}

		jsoned, err = json.Marshal(toFormat)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(int(ExitCode.Run))
		}
		fmt.Fprintf(os.Stdout, string(jsoned))
		os.Exit(int(ExitCode.OK))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> inspect`,
		Description: `
Displays information about the node <nodename> of cluster <clustername>.`,
	},
}

// clusterNodeDeleteCmd handles 'deploy cluster <clustername> delete'
var clusterNodeDeleteCommand = &cli.Command{
	Keyword: "delete",
	Aliases: []string{"destroy", "remove", "rm"},

	Process: func(c *cli.Command) {
		yes := c.Flag("-y,--assume-yes", false)
		force := c.Flag("-f,--force", false)

		if !yes && !utils.UserConfirmed(fmt.Sprintf("Are you sure to delete the node '%s' of the cluster '%s'", nodeName, clusterName)) {
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
Usage: deploy [options] cluster <clustername> node <nodename> delete|destroy|remove|rm [-y]`,
		Options: []string{`
options:
  -y,--assume-yes  Don't ask for confirmation`,
		},
		Description: `
Delete the node <nodename> from the cluster <clustername>.`,
	},
}

// clusterNodeStopCmd handles 'deploy cluster <clustername> node <nodename> stop'
var clusterNodeStopCommand = &cli.Command{
	Keyword: "stop",
	Aliases: []string{"freeze"},

	Process: func(c *cli.Command) {
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: deploy [options] cluster <clustername> stop|freeze`,
		Description: `
Stop the cluster (make it unavailable for duty).`,
	},
}

// clusterNodeStartCmd handles 'deploy cluster <clustername> node <nodename> start'
var clusterNodeStartCommand = &cli.Command{
	Keyword: "start",
	Aliases: []string{"unfreeze"},

	Process: func(c *cli.Command) {
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> start|unfreeze`,
		Options: []string{`
options:
  --force, -f Force Don't ask for confirmation`,
		},
		Description: `
Start the node <nodename> of the cluster <clustername>.`,
	},
}

// clusterNodeStateCmd handles 'deploy cluster <clustername> state'
var clusterNodeStateCommand = &cli.Command{
	Keyword: "state",

	Process: func(c *cli.Command) {
		os.Exit(int(ExitCode.NotImplemented))
	},

	Help: &cli.HelpContent{
		Usage: `
Usage: {{.ProgName}} [options] cluster <clustername> node <nodename> state`,
		Description: `
Get the state of the node <nodename> of the cluster <clustername>.`,
	},
}
