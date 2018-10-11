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

package main

import (
	"time"

	"github.com/CS-SI/SafeScale/utils/cli"

	"github.com/CS-SI/SafeScale/perform/cmds"

	_ "github.com/CS-SI/SafeScale/providers/cloudwatt"      // Imported to initialise provider cloudwatt
	_ "github.com/CS-SI/SafeScale/providers/flexibleengine" // Imported to initialise provider flexibleengine
	_ "github.com/CS-SI/SafeScale/providers/opentelekom"    // Imported to initialise provider opentelekom
	_ "github.com/CS-SI/SafeScale/providers/ovh"            // Imported to initialise provider ovh
)

const (
	address           = "localhost:50051"
	timeoutCtxDefault = 10 * time.Second
	timeoutCtxHost    = 2 * time.Minute
)

var (
	globalOptions string = `
	Global options:
	  -v,--verbose        Enable verbosity
	  -d,--debug          Enable debug suplemental information
	  --rebrand <prefix>  Prefix used when command is rebranded
	                      (ex: <prefix>="wrapper " when {{.ProgName}} is called 'wrapper {{.ProgName}}')
	`

	completeUsage string = `
	Usage: perform version
		   perform help <command>
		   perform [-vd][--rebrand <prefix>] <clustername> create [-N <cidr>][-C <complexity>][-k][--cpu <cpu>][--ram <ram>][--disk <disk>]
		   perform [-vd][--rebrand <prefix>] <clustername> (delete|destroy|remove|rm) [-y]
		   perform [-vd][--rebrand <prefix>] <clustername> (start|stop|state|inspect)
		   perform [-vd][--rebrand <prefix>] <clustername> shrink [-n <count>]
		   perform [-vd][--rebrand <prefix>] <clustername> expand [-n <count>]
		   perform [-vd][--rebrand <prefix>] <clustername> (feature|pkg) <pkgname> (check|add|install|remove|delete|destroy|rm)
		   perform [-vd][--rebrand <prefix>] <clustername> (service|svc) <svcname> (check|add|install|remove|delete|destroy|rm|uninstall)
		   perform [-vd][--rebrand <prefix>] <clustername> (service|svc) <svcname> (start|state|stop|pause|resume)
		   perform [-vd][--rebrand <prefix>] (dcos|marathon|kubectl) [-- <arg>...]

	Options:
	  -C --complexity <complexity>  Defines complexity
	  -d --debug                    Enable debug suplemental information
	  -f --force                    Force action even when an error occured
	  -h --help                     Print help message
	  -k --keep-on-failure          Don't delete the resources on failure
	  -N --cidr <cidr>              Defines CIDR
	  -v --verbose                  Enable verbosity
	  -y --assume-yes               Automatically responds y to question
	  --cpu <cpu>                   Defines number of CPU of host
	  --disk <disk>                 Defines system disk size
	  --ram <ram>                   Defines ram size
	  --rebrand <prefix>            Prefix to use for each external call of SafeScale command`
)

func main() {
	app := cli.NewApp(completeUsage, &cli.Command{
		Keyword: "perform",

		Commands: []*cli.Command{
			cmds.FeatureCommand,
			cmds.ServiceCommand,
			cmds.ClusterCreateCommand,
			cmds.ClusterInspectCommand,
			cmds.ClusterDeleteCommand,
			cmds.ClusterStartCommand,
			cmds.ClusterStopCommand,
			cmds.ClusterStateCommand,
			cmds.ClusterExpandCommand,
			cmds.ClusterShrinkCommand,
			cmds.ClusterDcosCommand,
			cmds.ClusterMarathonCommand,
			cmds.ClusterKubectlCommand,
		},

		Help: &cli.HelpContent{
			Usage: `
Usage: {{.ProgName}} [options] <command>
            `,
			Commands: `
  create                    Creates a cluster
  inspect                   Displays cluster information
  delete,destroy,remove,rm  Deletes a cluster
  start                     Start a cluster
  stop                      Stops a cluster
  state                     State of the cluster
  expand                    Expands the cluster by adding nodes
  shrink                    Shrinks the cluster by removing nodes
  dcos                      Executes dcos command
  marathon                  Executes marathon command
  kubectl                   Executes kubectl command`,
			Options: []string{
				globalOptions,
			},
		},
	})
	app.Run(nil)
}
